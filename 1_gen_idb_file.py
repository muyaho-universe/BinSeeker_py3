#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Disassemble all .o files using IDA


import config
import os
import subprocess
import glob

for bin_path in config.STEP1_PORGRAM_ARR:
    print("bin_path:", bin_path)
    paths = glob.glob(config.O_DIR + str(os.sep) + bin_path + "/*/*")
    print("paths:", paths)
    for file_path in paths:
        if file_path.endswith(".idb") or file_path.endswith(".asm") or file_path.endswith(".i64"):
            continue
        if file_path.endswith(".id0") or file_path.endswith(".id1") or file_path.endswith(".id2") or file_path.endswith(".til") or file_path.endswith(".nam"):
            os.remove(file_path)
        else:
            message = os.popen('file ' + file_path).read()
            if "32" in message or "i386" in message:
                print(config.IDA32_DIR + " -B \"" + file_path + "\"")
                subprocess.call(config.IDA32_DIR + " -B \"" + file_path + "\"", shell=True)
            else:
                print(config.IDA64_DIR + " -B \"" + file_path + "\"")
                subprocess.call(config.IDA64_DIR + " -B \"" + file_path + "\"", shell=True)
