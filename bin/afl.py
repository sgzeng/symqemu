#!/usr/bin/env python3

import atexit
import copy
import logging
import functools
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import time
import threading
try:
   import queue
except ImportError:
   import Queue as queue

import executor as executor
import minimizer as minimizer
import utils as utils
import redis

DEFAULT_TIMEOUT = 30
MAX_TIMEOUT = 10 * 60 # 10 minutes
TARGET_FILE = utils.AT_FILE

MAX_ERROR_REPORTS = 30
MAX_CRASH_REPORTS = 30
MAX_FLIP_NUM = 512
# minimum number of hang files to increase timeout
MIN_HANG_FILES = 30

logger = logging.getLogger('mazerunner.afl')

def get_score(testcase):
    # New coverage is the best
    score1 = testcase.endswith("+cov")
    # NOTE: seed files are not marked with "+cov"
    # even though it contains new coverage
    score2 = "orig:" in testcase
    # Smaller size is better
    score3 = -os.path.getsize(testcase)
    # Since name contains id, so later generated one will be chosen earlier
    score4 = testcase
    return (score1, score2, score3, score4)

def testcase_compare(a, b):
    a_score = get_score(a)
    b_score = get_score(b)
    return 1 if a_score > b_score else -1

def mkdir(dirp):
    if not os.path.exists(dirp):
        os.makedirs(dirp)

def check_so_file():
    for SO_file in SO.values():
        if not os.path.exists(SO_file):
            # Maybe updating now.. please wait
            logger.debug("Cannot find pintool. Maybe updating?")
            time.sleep(3 * 60)

        if not os.path.exists(SO_file):
            FATAL("Cannot find SO file!")

def get_afl_cmd(fuzzer_stats):
    with open(fuzzer_stats) as f:
        for l in f:
            if l.startswith("command_line"):
                # format= "command_line: [cmd]"
                return l.lstrip('command_line :').strip().split()


class RedisQueue(object):
    def __init__(self, name, dbNum, namespace='queue'):
        self.db= redis.Redis(host='127.0.0.1', port=6379, db=dbNum)
        self.key = '%s:%s' %(namespace, name)
 
    def qsize(self):
        return self.db.llen(self.key)
 
    def put(self, item):
        self.db.rpush(self.key, item)
 
    def get_wait(self, timeout=None):
        item = self.db.blpop(self.key, timeout=timeout)
        # if item:
        #     item = item[1]
        return item
 
    def get_nowait(self):
        item = self.db.lpop(self.key)

class AFLExecutorState(object):
    def __init__(self):
        self.hang = set()
        self.processed = set()
        self.timeout = DEFAULT_TIMEOUT
        self.done = set()
        self.index = 0
        self.num_error_reports = 0
        self.num_crash_reports = 0
        self.crashes = {}

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __getstate__(self):
        return self.__dict__

    def clear(self):
        self.hang = set()
        self.processed = set()

    def increase_timeout(self):
        old_timeout = self.timeout
        if self.timeout < MAX_TIMEOUT:
            self.timeout *= 2
            logger.debug("Increase timeout %d -> %d"
                         % (old_timeout, self.timeout))
        else:
            # Something bad happened, but wait until AFL resolves it
            logger.debug("Hit the maximum timeout")
            # Back to default timeout not to slow down fuzzing
            self.timeout = DEFAULT_TIMEOUT

        # sleep for a minutes to wait until AFL resolves it
        time.sleep(60)

        # clear state for restarting
        self.clear()

    def tick(self):
        old_index = self.index
        self.index += 1
        return old_index

    def get_num_processed(self):
        return len(self.processed) + len(self.hang) + len(self.done)

class AFLExecutor(object):
    def __init__(self, cmd, netoptions, input, output, afl, name, ce_path, version, filename=None, mail=None, asan_bin=None, redisDB=None, deli=None, pkglen=None, cleanscript=None):
        self.agent = version
        self.rqueue = RedisQueue('seedQ', redisDB)
        self.cmd = cmd
        self.netoptions = netoptions
        self.source_opts = utils.SOURCE_STDIN
        if not netoptions is None:
            self.source_opts = utils.SOURCE_NET
        self.seed_dir = input
        self.output = output
        self.afl = afl
        self.name = name
        self.ce_path = ce_path
        self.dbNum = redisDB
        self.deli = deli
        self.pkglen = pkglen
        self.cleanScript = cleanscript
        self.filename = ".cur_input" if filename is None else filename
        self.mail = mail
        self.set_asan_cmd(asan_bin)
        self.tmp_exploit_dir = tempfile.mkdtemp()
        self.tmp_explore_dir = tempfile.mkdtemp()
        cmd, afl_path, qemu_mode = self.parse_fuzzer_stats()
        self.minimizer = minimizer.TestcaseMinimizer(
            cmd, afl_path, self.output, qemu_mode, self.source_opts)
        self.import_state()
        self.make_dirs()
        atexit.register(self.cleanup)

    @property
    def cur_exploit_input(self):
        return os.path.realpath(os.path.join(self.my_dir, ".cur_exploit_input"))

    @property
    def cur_explore_input(self):
        return os.path.realpath(os.path.join(self.my_dir, ".cur_explore_input"))

    @property
    def afl_dir(self):
        return os.path.join(self.output, self.afl)

    @property
    def afl_queue(self):
        return os.path.join(self.afl_dir, "queue")

    @property
    def my_dir(self):
        return os.path.join(self.output, self.name)

    @property
    def my_queue(self):
        return os.path.join(self.my_dir, "queue")

    @property
    def my_hangs(self):
        return os.path.join(self.my_dir, "hangs")

    @property
    def my_errors(self):
        return os.path.join(self.my_dir, "errors")

    @property
    def metadata(self):
        return os.path.join(self.my_dir, "metadata")

    @property
    def bitmap(self):
        return os.path.join(self.my_dir, "bitmap")

    @property
    def dictionary(self):
        return os.path.join(self.my_dir, "dictionary")

    def set_asan_cmd(self, asan_bin):
        symbolizer = ""
        for e in [
                "/usr/bin/llvm-symbolizer",
                "/usr/bin/llvm-symbolizer-3.4",
                "/usr/bin/llvm-symbolizer-3.8"]:
            if os.path.exists(e):
                symbolizer = e
                break
        os.putenv("ASAN_SYMBOLIZER_PATH", symbolizer)
        os.putenv("ASAN_OPTIONS", "symbolize=1")

        if asan_bin and os.path.exists(asan_bin):
            self.asan_cmd = [asan_bin] + self.cmd[1:]
        else:
            self.asan_cmd = None

    def make_dirs(self):
        mkdir(self.tmp_exploit_dir)
        mkdir(self.tmp_explore_dir)
        mkdir(self.my_queue)
        mkdir(self.my_hangs)
        mkdir(self.my_errors)

    def parse_fuzzer_stats(self):
        cmd = get_afl_cmd(os.path.join(self.afl_dir, "fuzzer_stats"))
        assert cmd is not None
        index = cmd.index("--")
        return cmd[index+1:], os.path.dirname(cmd[0]), '-Q' in cmd

    def import_state(self):
        if os.path.exists(self.metadata):
            with open(self.metadata, "rb") as f:
                self.state = pickle.load(f)
        else:
            self.state = AFLExecutorState()

    def sync_files(self):
        files = []
        for name in os.listdir(self.afl_queue):
            path = os.path.join(self.afl_queue, name)
            if os.path.isfile(path):
                if "+cov" in name:
                    files.append(path)

        files = list(set(files) - self.state.processed)
        return files

    def run_target(self, ce_path, skipEpisodeNum, targetBA, cur_input, tmp_dir):
        # Trigger linearlize to remove complicate expressions
        q = executor.Executor(ce_path, self.cmd, self.netoptions, skipEpisodeNum, targetBA, self.dbNum, self.deli, self.pkglen, cur_input, self.my_dir, tmp_dir, bitmap=self.bitmap)
        ret = q.run(self.state.timeout)
        logger.debug("Total=%d s, Emulation=%d s, Solver=%d s, Return=%d"
                     % (ret.total_time,
                        ret.emulation_time,
                        ret.solving_time,
                        ret.returncode))
        return q, ret

    def handle_by_return_code(self, res, fp):
        retcode = res.returncode
        if retcode in [124, -9]: # killed
            shutil.copy2(fp, os.path.join(self.my_hangs, os.path.basename(fp)))
            self.state.hang.add(fp)
        else:
            self.state.done.add(fp)

        # segfault or abort
        if (retcode in [128 + 11, -11, 128 + 6, -6, 255]):
            shutil.copy2(fp, os.path.join(self.my_errors, os.path.basename(fp)))
            self.report_error(fp, res.log)
            return True
        return False

    def get_seeds_priority(self, log):
        priority_sq = {}
        i = 0
        loglines = log.splitlines()
        for line in loglines:
            i += 1
            if "skip_episode_num_" in line and "seedNum" in loglines[i]:
                priority = int(line.lstrip("[STAT] skip_episode_num_:").strip())
                seedName = loglines[i].lstrip("[STAT] seedNum:").strip()
                priority_sq[seedName] = priority
        return priority_sq

    def get_info_from_pin(self, log):
        skip_episode_num_ = -1
        target_BA = "0_0"
        currOffset = 0
        for line in log.splitlines():
            if "skip_episode_num_:" in line:
                skip_episode_num_ = int(line.lstrip("[STAT] skip_episode_num_:").strip())
            if "target_BA:" in line:
                target_BA = line.lstrip("[STAT] target_BA:").strip()
            if "currOffset:" in line:
                currOffset = int(line.lstrip("[STAT] currOffset:").strip())
        return skip_episode_num_, target_BA, currOffset

    def increase_input_size(self, input):
        curr_size = os.path.getsize(input)
        # Set a threshold, we don't want it becomes too large
        if curr_size < 2048:
            with open(input, "a+") as input_file:
                input_file.write('A' * curr_size)

    def send_mail(self, subject, info, attach=None):
        if attach is None:
            attach = []

        cmd = ["mail"]
        for path in attach:
            cmd += ["-A", path]
        cmd += ["-s", "[qsym-report] %s" % subject]
        cmd.append(self.mail)

        info = copy.copy(info)
        info["CMD"] = " ".join(self.cmd)

        text = "\n" # skip cc
        for k, v in info.iteritems():
            text += "%s\n" % k
            text += "-" * 30 + "\n"
            text += "%s" % v + "\n" * 3
        try:
            devnull = open(os.devnull, "wb")
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=devnull, stderr=devnull)
            proc.communicate(text)
        except OSError:
            pass
        finally:
            devnull.close()

    def check_crashes(self):
        for fuzzer in os.listdir(self.output):
            crash_dir = os.path.join(self.output, fuzzer, "crashes")
            if not os.path.exists(crash_dir):
                continue

            # initialize if it's first time to see the fuzzer
            if not fuzzer in self.state.crashes:
                self.state.crashes[fuzzer] = -1

            for name in sorted(os.listdir(crash_dir)):
                # skip readme
                if name == "README.txt":
                    continue

                # read id from the format "id:000000..."
                num = int(name[3:9])
                if num > self.state.crashes[fuzzer]:
                    self.report_crash(os.path.join(crash_dir, name))
                    self.state.crashes[fuzzer] = num

    def report_error(self, fp, log):
        logger.debug("Error is occured...\nLog:%s" % log)
        # if no mail, then stop
        if self.mail is None:
            return

        # don't do too much
        if self.state.num_error_reports >= MAX_ERROR_REPORTS:
            return

        self.state.num_error_reports += 1
        self.send_mail("Error found", {"LOG": log}, [fp])

    def report_crash(self, fp):
        logger.debug("Crash is found: %s" % fp)

        # if no mail, then stop
        if self.mail is None:
            return

        # don't do too much
        if self.state.num_crash_reports >= MAX_CRASH_REPORTS:
            return

        self.state.num_crash_reports += 1
        info = {}
        if self.asan_cmd is not None:
            stdout, stderr = utils.run_command(
                    ["timeout", "-k", "5", "5"] + self.asan_cmd,
                    fp)
            info["STDOUT"] = stdout
            info["STDERR"] = stderr
        self.send_mail("Crash found", info, [fp])

    def export_state(self):
        with open(self.metadata, "wb") as f:
            pickle.dump(self.state, f)

    def cleanup(self):
        try:
            self.export_state()
            shutil.rmtree(self.tmp_dir)
            os.system(self.cleanScript)
        except:
            pass

    def handle_empty_files(self):
        self.state.done.clear()
        self.state.processed.clear()
        if len(self.state.hang) > MIN_HANG_FILES:
            self.state.increase_timeout()
        else:
            logger.debug("Sleep for getting files")
            time.sleep(5)

    def receive_seeds(self, seedBufferQ):
        while True:
            # learn from interesting +cov seeds from afl seed queue
            cov_seeds = self.sync_files()
            for cv in cov_seeds:
                self.state.processed.add(cv)
                # logger.debug("fetching a task from AFL seed queue: " + cv)
                seedBufferQ.put((0, cv))
            # scan from redis db
            task = self.rqueue.get_nowait()
            while task:
                logger.debug("fetching a task from exploit agent: " + str(task))
                self.minimizer.update_seedMap(task)
                seedinfo = self.rqueue.db.hgetall(task)
                seedBufferQ.put(seedinfo['priority'], seedinfo)
                task = self.rqueue.get_nowait()
            time.sleep(10)

# without the help of explore agent, it never go to loop 17
# the diversity set is only increased when there is a new unique episode hash
# if we keep getting error, the diversity set is not updated.
    def RL_exploit_agent(self, fp): 
        while fp is not None:
            logger.debug("\nRun exploit agent: input=%s" % fp)
            new_seed = self.run_exploit(fp)
            if os.path.isfile(new_seed):
                fp = new_seed
            # self.check_crashes()

    def RL_explore_agent(self, seedBufferQ):
        while True:
            while not seedBufferQ.empty():
                if seedBufferQ.qsize() > 512:
                    logger.warning("explore_agent: seed BufferQ is too large")
                task = seedBufferQ.get()
                follow_input = task[1]
                if os.path.isfile(follow_input):
                    logger.debug("\nRun explore agent: ({}, {}) ".format(task[0], task[1]))
                    logger.debug("explore_agent: seedBufferQ size: %d" % seedBufferQ.qsize())
                    self.run_explore(follow_input, seedBufferQ)
                    if not self.cleanScript is None:
                        os.system(self.cleanScript)
            time.sleep(5)
            logger.debug("Sleeping...")

    def run(self):
        # initail seed
        fp = None
        seedBufferQ = queue.PriorityQueue()
        for seed in os.listdir(self.seed_dir):
            seed_path = os.path.join(self.seed_dir, seed)
            if os.path.isfile(seed_path):
                fp = seed_path
                seedBufferQ.put((0, fp))

        if self.agent == 'exploit':
            self.RL_exploit_agent(fp)
        if self.agent == 'explore':
            taskQProcess = threading.Thread(target=self.receive_seeds, name='taskQProcess', args=(seedBufferQ, ))
            taskQProcess.start()
            self.RL_explore_agent(seedBufferQ)

    def run_explore(self, fp, seedBufferQ):

        # copy the test case
        shutil.copy2(fp, self.cur_explore_input)

        skipEpisodeNum = -1
        targetBA = "follow"
        q, ret = self.run_target(self.ce_path, skipEpisodeNum, targetBA, self.cur_explore_input, self.tmp_explore_dir)
        self.handle_by_return_code(ret, fp)
        # priority_sq = self.get_seeds_priority(ret.log)
        index = self.state.tick()
        target = os.path.basename(fp)[:len("id:......")]
        # handle flipped branches
        for testcase in q.get_testcases():
            # if not os.path.isfile(testcase) or os.path.basename(testcase) not in priority_sq:
            if not os.path.isfile(testcase):
                continue
            if not self.minimizer.check_testcase(testcase):
                # Remove if it's not interesting testcases
                os.unlink(testcase)
                continue
            index = self.state.tick()
            filename = os.path.join(self.my_queue, "id:%06d,explore:%s,fliped%06d,time:%.0lf" 
                                    % (index, target, 0, time.time()*1000))
            shutil.copy2(testcase, filename)
            self.minimizer.update_seedMap(filename)
            logger.debug("Generated explore seed to " + filename)
            seedBufferQ.put((0, filename))

    def run_exploit(self, fp):

        # copy the test case
        shutil.copy2(fp, self.cur_exploit_input)

        skipEpisodeNum = -1
        targetBA = "0_0"
        flipNum = 0

        # we don't want to go too deep
        index = self.state.tick()
        while flipNum < MAX_FLIP_NUM:
            q, ret = self.run_target(self.ce_path, skipEpisodeNum, targetBA, self.cur_exploit_input, self.tmp_exploit_dir)
            self.handle_by_return_code(ret, fp)
            skipEpisodeNum, targetBA, currOffset = self.get_info_from_pin(ret.log)
            priority_sq = self.get_seeds_priority(ret.log)
            cur_input_size = os.path.getsize(self.cur_exploit_input)
            if currOffset >= cur_input_size - 1:
                self.increase_input_size(self.cur_exploit_input)
            if not self.cleanScript is None:
                os.system(self.cleanScript)
            # handle flipped branches
            target = os.path.basename(fp)[:len("id:......")]
            for testcase in q.get_testcases():
                if not os.path.isfile(testcase) or os.path.basename(testcase) not in priority_sq:
                    continue
                if not self.minimizer.check_testcase(testcase):
                    # Remove if it's not interesting testcases
                    os.unlink(testcase)
                    continue
                filename = os.path.join(self.my_queue, "id:%06d,explore:%s-exploit,fliped%06d,time:%.0lf" 
                                        % (index, target, flipNum, time.time()*1000))
                shutil.copy2(testcase, filename)
                self.minimizer.update_seedMap(filename)
                logger.debug("Generated explore seed to " + filename)
                self.rqueue.put(filename)
                seedinfo = {'priority': priority_sq[os.path.basename(testcase)]}
                self.rqueue.db.hmset(filename, seedinfo)
                index = self.state.tick()

            if skipEpisodeNum < 0 or targetBA == "0_0":
                break
            logger.debug("Restart from begining\n")
            flipNum += 1
        
        new_seed = os.path.join(self.my_queue,
                    "id:%06d,exploit,fliped%06d,time:%.0lf" % (index, flipNum, time.time()*1000))
        if self.minimizer.check_testcase(self.cur_exploit_input):
            shutil.copy2(self.cur_exploit_input, new_seed)
            self.minimizer.update_seedMap(new_seed)
            logger.debug("Generated exploit seed to " + new_seed)
            # for debug
            with open(os.path.join(self.output, "rl.log"), mode='a+') as mylog:
                mylog.write("Generated new seed to " + new_seed + "\n")
            if flipNum > MAX_FLIP_NUM:
                logger.debug("the exploit agent flipped too many branches, handled over to the explore agent")
                self.rqueue.put(new_seed)
                seedinfo = {'priority': 0}
                self.rqueue.db.hmset(new_seed, seedinfo)
                
        if flipNum == 0:
            logger.debug("the exploit agent did not flip any branches, sleeping for 1s")
            time.sleep(1)
        return new_seed
