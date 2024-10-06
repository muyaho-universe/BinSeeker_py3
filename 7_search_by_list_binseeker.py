#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import csv
import os
import config
import glob
import shutil

# 파일 디렉토리를 비우고 다시 생성
shutil.rmtree(config.SEARCH_RESULT_VULSEEKER_DIR)
os.mkdir(config.SEARCH_RESULT_VULSEEKER_DIR)

# 모든 tfrecord 파일 필터링
filters = glob.glob(os.path.join(config.SEARCH_VULSEEKER_TFRECORD_DIR, "*", "*.tfrecord"))
for tfrecord in filters:
    # 경로에서 CVE 디렉토리, 검색 프로그램, 검색 및 CVE 수 추출
    cve_dir = os.path.basename(os.path.dirname(tfrecord))
    tfrecord_filename = os.path.basename(tfrecord)[:-9]  # 확장자를 제외한 파일 이름
    search_program = tfrecord_filename.split("__NUM__")[0]
    search_num, cve_num = tfrecord_filename.split("__NUM__")[1].split("#")

    # 시스템 명령어 실행
    command = f"./7_search_model_vulseeker.py '{tfrecord}' {cve_dir} {cve_num} {search_num} '{search_program}'"
    os.system(command)

print("finish!!!")
