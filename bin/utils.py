#!/usr/bin/env python3

import copy
import subprocess
import sys
import termcolor

AT_FILE = "@@"
SOURCE_STDIN = 0
SOURCE_FILE = 1
SOURCE_NET = 2

def FATAL(msg):
    print(termcolor.colored(msg, 'red'))
    sys.exit(-1)

def fix_at_file(cmd, testcase):
    cmd = copy.copy(cmd)
    if AT_FILE in cmd:
        idx = cmd.index(AT_FILE)
        cmd[idx] = testcase
        stdin = None
    else:
        with open(testcase, "rb") as f:
            stdin = f.read()

    return cmd, stdin

def run_command(cmd, testcase):
    cmd, stdin = fix_at_file(cmd, testcase)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate(stdin)
