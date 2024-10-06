#!/usr/bin/env python3
# _*_ coding: utf-8 _*_

import csv
import os
import glob
import random
import config

# Generate the number of blocks in the training set function
# block_num_min < block_num <= block_num_max
# if block_num_max = -1, ignore this setting, do not consider block numbers
block_num_max = -1
block_num_min = -1

# Number of positive and negative samples
pos_num = 1
neg_num = 1

train_dataset_num = config.TRAIN_DATASET_NUM
test_dataset_num = int(train_dataset_num / 10)
vaild_dataset_num = int(train_dataset_num / 10)

func_list_file = config.DATASET_DIR + os.sep + "function_list" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "].csv"
train_file = config.DATASET_DIR + os.sep + "train" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "].csv"
test_file = config.DATASET_DIR + os.sep + "test" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "].csv"
vaild_file = config.DATASET_DIR + os.sep + "vaild" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "].csv"

func_list_fp = open(func_list_file, "w")

index_uuid = dict()
index_count = 0
for program in config.STEP3_PORGRAM_ARR:
    tempdir = config.FEA_DIR + os.sep + str(program)
    filters = glob.glob(config.FEA_DIR + os.sep + str(program) + os.sep + "*")
    for i in filters:
        if os.path.isdir(i):
            index_uuid.setdefault(str(index_count), i.split(os.sep)[-1])
            print(index_count)
            index_count += 1

func_list_arr = []
func_list_dict = {}
for k, v in index_uuid.items():
    if not os.path.exists(config.FEA_DIR + os.sep + str(program) + os.sep + v + "/functions_list.csv"):
        continue
    with open(config.FEA_DIR + os.sep + str(program) + os.sep + v + "/functions_list_fea.csv", "r") as fp:
        print("gen_dataset:", config.FEA_DIR + os.sep + str(program) + os.sep + v + "/functions_list.csv")
        for line in csv.reader(fp):
            print(line)
            if line[0] == "":
                continue
            if block_num_max > 0:
                if not (int(line[1]) > block_num_min and int(line[1]) <= block_num_max):
                    continue
            if line[0] in func_list_dict:
                value = func_list_dict.pop(line[0])
                value = value + "," + line[4] + os.sep + line[5] + os.sep + line[0]
                func_list_dict.setdefault(line[0], value)
            else:
                value = line[4] + os.sep + line[5] + os.sep + line[0]
                func_list_arr.append(line[0])
                func_list_dict.setdefault(line[0], value)

# Shuffle the function list
random.shuffle(func_list_arr)

# Split into test, train, and validation sets
func_list_test = []
func_list_train = []
func_list_vaild = []
for i in range(len(func_list_arr)):
    if i % 12 == 0:
        func_list_test.append(func_list_arr[i])
    elif i % 12 == 1:
        func_list_vaild.append(func_list_arr[i])
    else:
        func_list_train.append(func_list_arr[i])

train_fp = open(train_file, "w")
test_fp = open(test_file, "w")
vaild_fp = open(vaild_file, "w")

count = 0  # Track total samples
cur_num = 0  # Track current round's positive/negative samples

# Generate training dataset
while count < train_dataset_num:
    # Generate positive example
    if cur_num < pos_num:
        random_func = random.sample(func_list_train, 1)
        value = func_list_dict.get(random_func[0])
        select_list = value.split(',')
        if len(select_list) < 2:
            continue
        selected_list = random.sample(select_list, 2)
        train_fp.write(selected_list[0] + "," + selected_list[1] + ",1\n")
    # Generate negative example
    elif cur_num < pos_num + neg_num:
        random_func = random.sample(func_list_train, 2)
        value1 = func_list_dict.get(random_func[0])
        select_list1 = value1.split(',')
        value2 = func_list_dict.get(random_func[1])
        select_list2 = value2.split(',')
        selected_list1 = random.sample(select_list1, 1)
        selected_list2 = random.sample(select_list2, 1)
        train_fp.write(selected_list1[0] + "," + selected_list2[0] + ",-1\n")
    cur_num += 1
    count += 1
    if cur_num == pos_num + neg_num:
        cur_num = 0

count = 0
cur_num = 0

# Generate test dataset
while count < test_dataset_num:
    if cur_num < pos_num:
        random_func = random.sample(func_list_test, 1)
        value = func_list_dict.get(random_func[0])
        select_list = value.split(',')
        if len(select_list) < 2:
            continue
        selected_list = random.sample(select_list, 2)
        test_fp.write(selected_list[0] + "," + selected_list[1] + ",1\n")
    elif cur_num < pos_num + neg_num:
        random_func = random.sample(func_list_test, 2)
        value1 = func_list_dict.get(random_func[0])
        select_list1 = value1.split(',')
        value2 = func_list_dict.get(random_func[1])
        select_list2 = value2.split(',')
        selected_list1 = random.sample(select_list1, 1)
        selected_list2 = random.sample(select_list2, 1)
        test_fp.write(selected_list1[0] + "," + selected_list2[0] + ",-1\n")
    cur_num += 1
    count += 1
    if cur_num == pos_num + neg_num:
        cur_num = 0

count = 0
cur_num = 0

# Generate validation dataset
while count < vaild_dataset_num:
    if cur_num < pos_num:
        random_func = random.sample(func_list_vaild, 1)
        value = func_list_dict.get(random_func[0])
        select_list = value.split(',')
        if len(select_list) < 2:
            continue
        selected_list = random.sample(select_list, 2)
        vaild_fp.write(selected_list[0] + "," + selected_list[1] + ",1\n")
    elif cur_num < pos_num + neg_num:
        random_func = random.sample(func_list_vaild, 2)
        value1 = func_list_dict.get(random_func[0])
        select_list1 = value1.split(',')
        value2 = func_list_dict.get(random_func[1])
        select_list2 = value2.split(',')
        selected_list1 = random.sample(select_list1, 1)
        selected_list2 = random.sample(select_list2, 1)
        vaild_fp.write(selected_list1[0] + "," + selected_list2[0] + ",-1\n")
    cur_num += 1
    count += 1
    if cur_num == pos_num + neg_num:
        cur_num = 0
