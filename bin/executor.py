#!/usr/bin/env python3

import copy
import logging
import json
import os
import platform
import subprocess
import time
import threading
import socket

from utils import *

l = logging.getLogger('mazerunner.Executor')
US_TO_S = float(1000 ** 2)
LOG_SMT_HEADER = " [STAT] SMT:"

class ExecutorResult(object):
    def __init__(self, start_time, end_time, returncode, log):
        self.returncode = returncode
        self.total_time = end_time - start_time
        self.log = log
        self.calc_solving_time(log, end_time)

    @property
    def emulation_time(self):
        return self.total_time - self.solving_time

    def calc_solving_time(self, log, end_time):
        # This function is dependent on logging mechanism of qsym
        # So if you fix the log function, you should fix this, too
        self.solving_time = 0
        for l in reversed(log.splitlines()):
            if l.startswith(LOG_SMT_HEADER):
                obj = json.loads(l[len(LOG_SMT_HEADER):])
                assert('solving_time' in obj)
                if 'start_time' in obj:
                    # If solving started, but not terminated
                    self.solving_time = (end_time * 10 ** 6) - obj['start_time']
                self.solving_time += obj['solving_time']
                break
        self.solving_time /= US_TO_S
        # This could be happened due to incorrect measurement
        self.solving_time = min(self.solving_time, self.total_time)

class Executor(object):
    def __init__(self, ce_path, cmd, netoptions, skipEpisodeNum, targetBA, dbNum, deli, plen, input_file, qsym_output_dir, pin_output_dir,  
            bitmap=None, argv=None):
        self.ce_path = ce_path
        self.cmd = cmd
        self.source_opts = SOURCE_STDIN
        if not netoptions is None:
            self.source_opts = SOURCE_NET
            self.parse_network_interface(netoptions) 
        self.skipEpisodeNum = str(skipEpisodeNum)
        self.targetBA = targetBA
        self.dbNum = dbNum
        self.plen = plen
        self.deli = deli
        self.input_file = input_file
        self.pin_output_dir = pin_output_dir
        self.qsym_output_dir = qsym_output_dir
        self.bitmap = bitmap
        self.argv = [] if argv is None else argv

        self.testcase_dir = self.get_testcase_dir()
        self.set_opts()

    @property
    def last_testcase_dir(self):
        return os.path.join(self.pin_output_dir, "qsym-last")

    @property
    def status_file(self):
        return os.path.join(self.pin_output_dir, "status")

    @property
    def log_file(self):
        return os.path.join(self.testcase_dir, "sym.log")

    @property
    def testcase_directory(self):
        return self.testcase_dir

    def check_elf32(self):
        # assume cmd[0] is always the target binary (?)
        if os.path.exists(self.cmd[0]):
            with open(self.cmd[0], 'rb') as f:
               d = f.read(5)
               return len(d) > 4 and d[4] == 1
        return False

    def gen_cmd(self, timeout):
        cmd = []
        if timeout:
            cmd += ["timeout", "-k", str(10), str(timeout)+'s']
        cmd += [self.ce_path]
        return cmd + self.cmd

    def gen_env(self):
        symqemu_env = os.environ.copy()
        symqemu_env["MAZERUNNER_DELIMITER"] = self.deli
        symqemu_env["MAZERUNNER_SKIP_EPISODE_NUM"] = str(self.skipEpisodeNum)
        symqemu_env["MAZERUNNER_TARGET_BRANCH_ACTION"] = self.targetBA
        symqemu_env["MAZERUNNER_PACKAGE_LENGTH"] = self.plen
        symqemu_env["MAZERUNNER_redis_dbNum"] = str(self.dbNum)
        if self.source_opts == SOURCE_NET:
            symqemu_env["SYMCC_INPUT_FILE"] = self.input_file
            symqemu_env["MAZERUNNER_INPUT_SOURCE"] = str(SOURCE_NET)
        symqemu_env["SYMCC_OUTPUT_DIR"] = self.testcase_dir
        symqemu_env["SYMCC_LOG_FILE"] = os.path.abspath(os.path.join(self.qsym_output_dir, "rl.log"))
        symqemu_env["SYMCC_ENABLE_LINEARIZATION"] = "1"
        if self.bitmap:
            symqemu_env["SYMCC_AFL_COVERAGE_MAP"] = self.bitmap
        # l.debug(symqemu_env)
        return symqemu_env

    def parse_network_interface(self, netoptions):
        if netoptions is None:
            return
        self.transport_layer = netoptions.rpartition('://')[0].strip()
        self.ip = netoptions.rpartition('://')[-1].split('/')[0].strip()
        p_str = netoptions.rpartition('://')[-1].split('/')[-1].strip()
        self.port = int(p_str)

    def parse_input(self, input):
        pkgs = []
        pkg_len = int(self.plen)
        if pkg_len > 0:
            if pkg_len >= input.size():
                pkgs.append(input)
            else:
                pkgs = [input[i:i+pkg_len] for i in range(0, len(input), pkg_len)]
        else:
            delimiter = bytes([int(self.deli, 16)])
            pkgs = [p+delimiter for p in input.split(delimiter)]
        return pkgs

    def netSend(self, input, MAXTRY=10):
        for i in range(0, MAXTRY):
            try:
                if self.transport_layer == 'tcp':
                    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #tcp
                else:
                    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #udp
                s.connect((self.ip, self.port))
                pkgs = self.parse_input(input)
                for p in pkgs:
                    # l.debug("sending pkg: " + p.decode("utf-8"))
                    s.sendall(input)
                s.close()
                return
            except ConnectionError:
                time.sleep(1)
                continue

    def run(self, timeout=None):
        cmd = self.gen_cmd(None)
        start_time = time.time()

        l.debug("Executing %s" % ' '.join(cmd))
        proc = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env = self.gen_env())
        if self.source_opts == SOURCE_NET:
            socketClient = threading.Thread(target=self.netSend, name='socketClient', args=(self.stdin,))
            socketClient.start()
            proc.wait()
            socketClient.join()
        else:
            stdout, stderr = proc.communicate(self.stdin)
        end_time = time.time()
        return ExecutorResult(
                start_time,
                end_time,
                proc.returncode,
                self.read_log_file())

    def read_log_file(self):
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                return f.read()
        else:
            return ""

    def import_status(self):
        if not os.path.exists(self.status_file):
            return 0
        else:
            with open(self.status_file, "r") as f:
                return json.load(f)

    def export_status(self, status):
        with open(self.status_file, "w") as f:
            json.dump(status, f)

    def get_testcase_dir(self):
        status = self.import_status()
        next_testcase_dir = os.path.join(
                self.pin_output_dir, "qsym-out-%d" % status)
        while os.path.exists(next_testcase_dir):
            status += 1
            next_testcase_dir = os.path.join(
                self.pin_output_dir, "qsym-out-%d" % status)
        os.mkdir(next_testcase_dir)

        # Make last_testcase_dir to point to the next_testcase_dir
        if os.path.lexists(self.last_testcase_dir):
            os.remove(self.last_testcase_dir)
        os.symlink(os.path.abspath(next_testcase_dir), self.last_testcase_dir)

        # Update status file to point next_testcase_dir
        status += 1
        self.export_status(status)
        return next_testcase_dir

    def set_opts(self):
        self.cmd, self.stdin = fix_at_file(self.cmd, self.input_file)

    def get_testcases(self):
        for name in sorted(os.listdir(self.testcase_dir)):
            if name == "stat":
                continue
            if name == "pin.log":
                continue
            path = os.path.join(self.testcase_dir, name)
            yield path
