#!/usr/bin/env python3
import atexit
import argparse
import logging
import functools
import hashlib
import json
import os
import pickle
import shutil
import subprocess as sp
import sys
import tempfile
import time

from executor import Executor
from minimizer import TestcaseMinimizer
from utils import *
import afl as afl

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-o", dest="output", required=True, help="AFL output directory")
    p.add_argument("-c", dest="clean", default=None, help="clean script after each run")
    p.add_argument("-v", dest="version", required=True, help="RL agent type")
    p.add_argument("-i", dest="input", required=True, help="initial seed directory")
    p.add_argument("-n", dest="name", required=True, help="name of the concolic executor")
    p.add_argument("-p", dest="path", required=True, help="full path of the concolic executor")
    p.add_argument("-net", dest="netoptions", default=None, help="client network interface if input coming from network socket")
    p.add_argument("-a", dest="afl", default="afl-master", help="AFL name")
    p.add_argument("-f", dest="filename", default=None)
    p.add_argument("-m", dest="mail", default=None)
    p.add_argument("-b", dest="asan_bin", default=None)
    p.add_argument("-db", dest="redisDB", default="0")
    p.add_argument("-deli", dest="deli", default="0xa")
    p.add_argument("-pkglen", dest="pkglen", default="0")
    p.add_argument("cmd", nargs="+", help="cmdline, use %s to denote a file" % AT_FILE)
    return p.parse_args()

def check_args(args):
    if not os.path.exists(args.output):
        raise ValueError('no such directory')

def main():
    args = parse_args()
    check_args(args)
    if (not args.clean is None) and (not os.path.isfile(args.clean)):
        args.clean = os.path.join('./', args.clean)
    e = afl.AFLExecutor(args.cmd, args.netoptions, args.input, args.output, args.afl,
            args.name, args.path, args.version, args.filename, args.mail, args.asan_bin, args.redisDB, args.deli, args.pkglen, args.clean)
    try:
        e.run()
    finally:
        e.cleanup()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
