#!/usr/bin/env python3
# _*_ coding: utf-8 _*_

import tensorflow as tf
import numpy as np
import csv
import os
import time
import networkx as nx
import itertools
import config

# ===========  global parameters  ===========
T = 5  # iteration
N = 2  # embedding_depth
D = 8  # dimensional
P = 64  # embedding_size
B = 10  # mini-batch
lr = 0.0001  # learning_rate
epochs = 10
is_debug = True

# Directory setup
data_folder = config.FEA_DIR
train_file = config.DATASET_DIR + os.sep + "train" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "].csv"
test_file = config.DATASET_DIR + os.sep + "test" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "].csv"
valid_file = config.DATASET_DIR + os.sep + "vaild" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "].csv"

PREFIX = "_" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "]"
TRAIN_TFRECORD = config.TFRECORD_VULSEEKER_DIR_DIR + os.sep + "train_" + PREFIX + ".tfrecord"
TEST_TFRECORD = config.TFRECORD_VULSEEKER_DIR_DIR + os.sep + "test_" + PREFIX + ".tfrecord"
VALID_TFRECORD = config.TFRECORD_VULSEEKER_DIR_DIR + os.sep + "valid_" + PREFIX + ".tfrecord"

print(TRAIN_TFRECORD)

# ==================== load the function pairs list ===================
def load_dataset():
    """Load the pairs list for training, testing, validation."""
    train_pair, train_label = load_csv_as_pair(train_file)
    valid_pair, valid_label = load_csv_as_pair(valid_file)
    test_pair, test_label = load_csv_as_pair(test_file)

    return train_pair, train_label, valid_pair, valid_label, test_pair, test_label

def load_csv_as_pair(pair_label_file):
    """Load each CSV file which records the pairs list for learning and its label (1 or -1)."""
    pair_list = []
    label_list = []
    with open(pair_label_file, "r") as fp:
        pair_label = csv.reader(fp)
        for line in pair_label:
            pair_list.append([line[0], line[1]])
            label_list.append(int(line[2]))

    return pair_list, label_list

# =============== convert the real data to training data ==============
def construct_learning_dataset(uid_pair_list):
    """Construct pairs dataset to train the model."""
    print("     start generating adj matrix pairs...")
    cfgs_1, cfgs_2, dfgs_1, dfgs_2 = generate_graph_pairs(uid_pair_list)

    print("     start generating features pairs...")
    feas_1, feas_2, max_size, num1, num2 = generate_features_pair(uid_pair_list)

    return cfgs_1, cfgs_2, dfgs_1, dfgs_2, feas_1, feas_2, num1, num2, max_size

def generate_graph_pairs(uid_pair_list):
    """Construct all the function pairs' CFG matrix."""
    cfgs_1 = []
    cfgs_2 = []
    dfgs_1 = []
    dfgs_2 = []
    count = 0
    for uid_pair in uid_pair_list:
        if is_debug:
            count += 1
            print(f"         {count:04d} cfg, [ {uid_pair[0]} , {uid_pair[1]} ]")
        
        graph_cfg = nx.read_adjlist(os.path.join(config.FEA_DIR, uid_pair[0] + "_cfg.txt"))
        adj_arr = np.array(nx.to_numpy_matrix(graph_cfg, dtype=float))
        adj_str = adj_arr.astype(np.str_)
        cfgs_1.append(",".join(list(itertools.chain.from_iterable(adj_str))))

        graph_dfg = nx.read_adjlist(os.path.join(data_folder, uid_pair[0] + "_dfg.txt"))
        graph = graph_dfg.copy()
        for node in graph.nodes():
            if not graph_cfg.has_node(node):
                graph_dfg.remove_node(node)
        graph_dfg.add_nodes_from(graph_cfg)
        adj_arr = np.array(nx.to_numpy_matrix(graph_dfg, dtype=float))
        adj_str = adj_arr.astype(np.str_)
        dfgs_1.append(",".join(list(itertools.chain.from_iterable(adj_str))))

        graph_cfg = nx.read_adjlist(os.path.join(data_folder, uid_pair[1] + "_cfg.txt"))
        adj_arr = np.array(nx.to_numpy_matrix(graph_cfg, dtype=float))
        adj_str = adj_arr.astype(np.str_)
        cfgs_2.append(",".join(list(itertools.chain.from_iterable(adj_str))))

        graph_dfg = nx.read_adjlist(os.path.join(data_folder, uid_pair[1] + "_dfg.txt"))
        graph = graph_dfg.copy()
        for node in graph.nodes():
            if not graph_cfg.has_node(node):
                graph_dfg.remove_node(node)
        graph_dfg.add_nodes_from(graph_cfg)
        adj_arr = np.array(nx.to_numpy_matrix(graph_dfg, dtype=float))
        adj_str = adj_arr.astype(np.str_)
        dfgs_2.append(",".join(list(itertools.chain.from_iterable(adj_str))))

    return cfgs_1, cfgs_2, dfgs_1, dfgs_2

def generate_features_pair(uid_pair_list):
    """Construct each function pairs' block feature map."""
    feas_1 = []
    feas_2 = []
    num1 = []
    num2 = []
    node_length = []
    count = 0
    for uid_pair in uid_pair_list:
        if is_debug:
            count += 1
            print(f"         {count:04d} feature, [ {uid_pair[0]} , {uid_pair[1]} ]")

        node_vector = []
        block_feature_dic = {}
        with open(os.path.join(config.FEA_DIR, uid_pair[0] + "_fea.csv"), "r") as fp:
            for line in csv.reader(fp):
                if line[0] == "":
                    continue
                block_feature = [float(x) for x in (line[8:15])]
                print(line[0], block_feature)
                block_feature_dic.setdefault(str(line[0]), block_feature)

        graph_cfg = nx.read_adjlist(os.path.join(data_folder, uid_pair[0] + "_cfg.txt"))
        for node in graph_cfg.nodes():
            node_vector.append(block_feature_dic[node])
        node_length.append(len(node_vector))
        num1.append(len(node_vector))
        node_arr = np.array(node_vector)
        node_str = node_arr.astype(np.str_)
        feas_1.append(",".join(list(itertools.chain.from_iterable(node_str))))

        node_vector = []
        block_feature_dic = {}
        with open(os.path.join(data_folder, uid_pair[1] + "_fea.csv"), "r") as fp:
            for line in csv.reader(fp):
                if line[0] == "":
                    continue
                block_feature = [float(x) for x in (line[8:15])]
                block_feature_dic.setdefault(str(line[0]), block_feature)

        graph_cfg = nx.read_adjlist(os.path.join(data_folder, uid_pair[1] + "_cfg.txt"))
        for node in graph_cfg.nodes():
            node_vector.append(block_feature_dic[node])
        node_length.append(len(node_vector))
        num2.append(len(node_vector))
        node_arr = np.array(node_vector)
        node_str = node_arr.astype(np.str_)
        feas_2.append(",".join(list(itertools.chain.from_iterable(node_str))))

    return feas_1, feas_2, np.max(node_length), np.array(num1), np.array(num2)

# ========================== the main function ========================
data_time = time.time()
train_pair, train_label, valid_pair, valid_label, test_pair, test_label = load_dataset()
print("1. loading pairs list time", time.time() - data_time, "(s)")

# Construct training dataset
cons_time = time.time()
train_cfg_1, train_cfg_2, train_dfg_1, train_dfg_2, train_fea_1, train_fea_2, train_num1, train_num2, train_max = construct_learning_dataset(train_pair)

node_list = np.full(len(train_label), train_max, dtype=int)
writer = tf.io.TFRecordWriter(TRAIN_TFRECORD)
for item1, item2, item3, item4, item5, item6, item7, item8, item9, item10 in zip(
        train_label, train_cfg_1, train_cfg_2, train_dfg_1, train_dfg_2, train_fea_1, train_fea_2, train_num1, train_num2, node_list):
    example = tf.train.Example(
        features=tf.train.Features(
            feature={
                'label': tf.train.Feature(int64_list=tf.train.Int64List(value=[item1])),
                'cfg_1': tf.train.Feature(bytes_list=tf.train.BytesList(value=[item2.encode()])),
                'cfg_2': tf.train.Feature(bytes_list=tf.train.BytesList(value=[item3.encode()])),
                'dfg_1': tf.train.Feature(bytes_list=tf.train.BytesList(value=[item4.encode()])),
                'dfg_2': tf.train.Feature(bytes_list=tf.train.BytesList(value=[item5.encode()])),
                'fea_1': tf.train.Feature(bytes_list=tf.train.BytesList(value=[item6.encode()])),
                'fea_2': tf.train.Feature(bytes_list=tf.train.BytesList(value=[item7.encode()])),
                'num1': tf.train.Feature(int64_list=tf.train.Int64List(value=[item8])),
                'num2': tf.train.Feature(int64_list=tf.train.Int64List(value=[item9])),
                'max': tf.train.Feature(int64_list=tf.train.Int64List(value=[item10]))
            }
        ))
    writer.write(example.SerializeToString())
writer.close()

# You can similarly update the validation and test sections.
