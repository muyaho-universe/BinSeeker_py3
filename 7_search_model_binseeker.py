#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tensorflow as tf
import numpy as np
import os
import config
import sys
import operator

# ===========  global parameters  ===========

T = 5  # iteration
N = 2  # embedding_depth
P = 64  # embedding_size
D = 16   # dimensional, feature num
B = 1  # mini-batch
lr = 0.0001  # learning_rate
max_iter = 100
decay_steps = 10  # decay steps
decay_rate = 0.0001  # decay rate
snapshot = 1
is_debug = True

def structure2vec(mu_prev, cdfg, x, name="structure2vec"):
    """Construct pairs dataset to train the model."""
    with tf.compat.v1.variable_scope(name):
        W_1 = tf.compat.v1.get_variable('W_1', [D, P], tf.float32, 
                                        tf.compat.v1.truncated_normal_initializer(mean=0.0, stddev=0.1))

        P_CDFG_1 = tf.compat.v1.get_variable('P_CDFG_1', [P, P], tf.float32, 
                                             tf.compat.v1.truncated_normal_initializer(mean=0.0, stddev=0.1))
        P_CDFG_2 = tf.compat.v1.get_variable('P_CDFG_2', [P, P], tf.float32, 
                                             tf.compat.v1.truncated_normal_initializer(mean=0.0, stddev=0.1))
        L_CFG = tf.reshape(tf.matmul(cdfg, mu_prev, transpose_a=True), (-1, P))  # v_num * P
        S_CDFG = tf.reshape(tf.matmul(tf.nn.relu(tf.matmul(L_CFG, P_CDFG_2)), P_CDFG_1), (-1, P))

        return tf.tanh(tf.add(tf.reshape(tf.matmul(tf.reshape(x, (-1, D)), W_1), (-1, P)), S_CDFG))

def structure2vec_net(cdfgs, x, v_num):
    with tf.compat.v1.variable_scope("structure2vec_net") as structure2vec_net:
        B_mu_5 = tf.Variable(tf.zeros(shape=[0, P]), trainable=False)
        w_2 = tf.compat.v1.get_variable('w_2', [P, P], tf.float32, 
                                        tf.compat.v1.truncated_normal_initializer(mean=0.0, stddev=0.1))
        for i in range(B):
            cur_size = tf.cast(v_num[i][0], tf.int32)
            mu_0 = tf.reshape(tf.zeros(shape=[2 * cur_size, P]), (2 * cur_size, P))
            cdfg = tf.slice(cdfgs[i], [0, 0], [cur_size * 2, 2 * cur_size])
            fea = tf.slice(x[i], [0, 0], [cur_size * 2, D])
            mu_1 = structure2vec(mu_0, cdfg, fea)
            structure2vec_net.reuse_variables()
            mu_2 = structure2vec(mu_1, cdfg, fea)
            mu_3 = structure2vec(mu_2, cdfg, fea)
            mu_4 = structure2vec(mu_3, cdfg, fea)
            mu_5 = structure2vec(mu_4, cdfg, fea)

            B_mu_5 = tf.concat([B_mu_5, tf.matmul(tf.reshape(tf.reduce_sum(mu_5, 0), (1, P)), w_2)], 0)

        return B_mu_5

def cal_distance(model1, model2):
    a_b = tf.reduce_sum(tf.reshape(tf.reduce_prod(tf.concat([tf.reshape(model1, (1, -1)),
                                                             tf.reshape(model2, (1, -1))], 0), 0), (B, P)), 1, keepdims=True)
    a_norm = tf.sqrt(tf.reduce_sum(tf.square(model1), 1, keepdims=True))
    b_norm = tf.sqrt(tf.reduce_sum(tf.square(model2), 1, keepdims=True))
    distance = a_b / tf.reshape(tf.reduce_prod(tf.concat([tf.reshape(a_norm, (1, -1)),
                                                          tf.reshape(b_norm, (1, -1))], 0), 0), (B, 1))
    return distance

def read_and_decode(filename):
    filename_queue = tf.compat.v1.train.string_input_producer([filename])
    reader = tf.compat.v1.TFRecordReader()
    _, serialized_example = reader.read(filename_queue)
    features = tf.io.parse_single_example(serialized_example, features={
        'cfg_1': tf.io.FixedLenFeature([], tf.string),
        'cfg_2': tf.io.FixedLenFeature([], tf.string),
        'dfg_1': tf.io.FixedLenFeature([], tf.string),
        'dfg_2': tf.io.FixedLenFeature([], tf.string),
        'fea_1': tf.io.FixedLenFeature([], tf.string),
        'fea_2': tf.io.FixedLenFeature([], tf.string),
        'num1': tf.io.FixedLenFeature([], tf.int64),
        'num2': tf.io.FixedLenFeature([], tf.int64),
        'max': tf.io.FixedLenFeature([], tf.int64),
        'label': tf.io.FixedLenFeature([], tf.string)})

    label = features['label']
    cfg_1 = features['cfg_1']
    cfg_2 = features['cfg_2']
    dfg_1 = features['dfg_1']
    dfg_2 = features['dfg_2']
    num1 = tf.cast(features['num1'], tf.int32)
    fea_1 = features['fea_1']
    num2 = tf.cast(features['num2'], tf.int32)
    fea_2 = features['fea_2']
    max_num = tf.cast(features['max'], tf.int32)

    return label, cfg_1, cfg_2, dfg_1, dfg_2, fea_1, fea_2, num1, num2, max_num

def get_batch(label, cfg_str1, cfg_str2, dfg_str1, dfg_str2, fea_str1, fea_str2, num1, num2, max_num):
    y = np.reshape(label, [B, 1])

    v_num_1 = []
    v_num_2 = []
    for i in range(B):
        v_num_1.append([int(num1[i])])
        v_num_2.append([int(num2[i])])

    cdfg_1 = []
    cdfg_2 = []
    for i in range(B):
        cfg_arr = np.array(cfg_str1[i].split(','))
        cfg_adj = np.reshape(cfg_arr, (int(num1[i]), int(num1[i])))
        cfg_ori1 = cfg_adj.astype(np.float32)
        cfg_ori1.resize(int(max_num[i]), int(max_num[i]), refcheck=False)
        dfg_arr = np.array(dfg_str1[i].split(','))
        dfg_adj = np.reshape(dfg_arr, (int(num1[i]), int(num1[i])))
        dfg_ori1 = dfg_adj.astype(np.float32)
        dfg_ori1.resize(int(max_num[i]), int(max_num[i]), refcheck=False)
        cdfg_zero = np.zeros([int(max_num[i]), int(max_num[i])])
        cdfg_cfg = np.concatenate([cfg_ori1, cdfg_zero], axis=1)
        cdfg_dfg = np.concatenate([cdfg_zero, dfg_ori1], axis=1)
        cdfg_vec1 = np.concatenate([cdfg_cfg, cdfg_dfg], axis=0)
        cdfg_1.append(cdfg_vec1.tolist())

        cfg_arr = np.array(cfg_str2[i].split(','))
        cfg_adj = np.reshape(cfg_arr, (int(num2[i]), int(num2[i])))
        cfg_ori2 = cfg_adj.astype(np.float32)
        cfg_ori2.resize(int(max_num[i]), int(max_num[i]), refcheck=False)
        dfg_arr = np.array(dfg_str2[i].split(','))
        dfg_adj = np.reshape(dfg_arr, (int(num2[i]), int(num2[i])))
        dfg_ori2 = dfg_adj.astype(np.float32)
        dfg_ori2.resize(int(max_num[i]), int(max_num[i]), refcheck=False)
        cdfg_zero = np.zeros([int(max_num[i]), int(max_num[i])])
        cdfg_cfg = np.concatenate([cfg_ori2, cdfg_zero], axis=1)
        cdfg_dfg = np.concatenate([cdfg_zero, dfg_ori2], axis=1)
        cdfg_vec2 = np.concatenate([cdfg_cfg, cdfg_dfg], axis=0)
        cdfg_2.append(cdfg_vec2.tolist())

    fea_1 = []
    fea_2 = []
    for i in range(B):
        fea_arr = np.array(fea_str1[i].split(','))
        fea_ori = fea_arr.astype(np.float32)
        fea_ori1 = np.resize(fea_ori, (np.max(v_num_1), D))
        fea_temp1 = np.concatenate([fea_ori1, fea_ori1], axis=1)
        fea_vec1 = np.resize(fea_temp1, (np.max(v_num_1) * 2, D))
        fea_1.append(fea_vec1)

        fea_arr = np.array(fea_str2[i].split(','))
        fea_ori = fea_arr.astype(np.float32)
        fea_ori2 = np.resize(fea_ori, (np.max(v_num_2), D))
        fea_temp2 = np.concatenate([fea_ori2, fea_ori2], axis=1)
        fea_vec2 = np.resize(fea_temp2, (np.max(v_num_2) * 2, D))
        fea_2.append(fea_vec2)

    return y, cdfg_1, cdfg_2, fea_1, fea_2, v_num_1, v_num_2

# 4. Construct the network
# Initializing the variables
init = tf.compat.v1.global_variables_initializer()
global_step = tf.Variable(0, trainable=False)
learning_rate = tf.compat.v1.train.exponential_decay(lr, global_step, decay_steps, decay_rate, staircase=True)

v_num_left = tf.compat.v1.placeholder(tf.float32, shape=[B, 1], name='v_num_left')
cdfg_left = tf.compat.v1.placeholder(tf.float32, shape=([B, None, None]), name='cdfg_left')
fea_left = tf.compat.v1.placeholder(tf.float32, shape=([B, None, D]), name='fea_left')

v_num_right = tf.compat.v1.placeholder(tf.float32, shape=[B, 1], name='v_num_right')
cdfg_right = tf.compat.v1.placeholder(tf.float32, shape=([B, None, None]), name='cdfg_right')
fea_right = tf.compat.v1.placeholder(tf.float32, shape=([B, None, D]), name='fea_right')

labels = tf.compat.v1.placeholder(tf.string, shape=([B, 1]), name='gt')

dropout_f = tf.compat.v1.placeholder(tf.float32)

with tf.compat.v1.variable_scope("siamese") as siamese:
    model1 = structure2vec_net(cdfg_left, fea_left, v_num_left)
    siamese.reuse_variables()
    model2 = structure2vec_net(cdfg_right, fea_right, v_num_right)

dis = cal_distance(model1, model2)

# TFRecord 파일을 처리하기 위한 코드
tfrecord_filename = sys.argv[1]
cve_dir = sys.argv[2]
cve_num = sys.argv[3]
search_num = sys.argv[4]
search_program = sys.argv[5]

list_search_label, list_search_cfg_1, list_search_cfg_2, list_search_dfg_1, list_search_dfg_2, list_search_fea_1, \
list_search_fea_2, list_search_num1, list_search_num2, list_search_max = read_and_decode(tfrecord_filename)

batch_search_label, batch_search_cfg_1, batch_search_cfg_2, batch_search_dfg_1, batch_search_dfg_2, batch_search_fea_1, \
batch_search_fea_2, batch_search_num1, batch_search_num2, batch_search_max  \
    = tf.compat.v1.train.batch([list_search_label, list_search_cfg_1, list_search_cfg_2, list_search_dfg_1, 
                                list_search_dfg_2, list_search_fea_1, list_search_fea_2, list_search_num1, 
                                list_search_num2, list_search_max], batch_size=B, capacity=B)

# 모델 복원 및 예측 처리
init_opt = tf.compat.v1.global_variables_initializer()
saver = tf.compat.v1.train.Saver()

with tf.compat.v1.Session() as sess:
    saver.restore(sess, config.MODEL_VULSEEKER_DIR + os.sep + config.STEP7_SEARCH_VULSEEKER_MODEL)
    coord = tf.compat.v1.train.Coordinator()
    threads = tf.compat.v1.train.start_queue_runners(sess=sess, coord=coord)
    total_batch = int(int(search_num) / int(cve_num))

    search_result = {}
    search_result_arr = {}
    for m in range(total_batch):
        predicts = 0
        predicts_arr = ""
        for version in range(int(cve_num)):
            search_label, search_cfg_1, search_cfg_2, search_dfg_1, search_dfg_2, search_fea_1, search_fea_2, \
            search_num1, search_num2, search_max = sess.run([batch_search_label, batch_search_cfg_1, 
                                                             batch_search_cfg_2, batch_search_dfg_1, 
                                                             batch_search_dfg_2, batch_search_fea_1, 
                                                             batch_search_fea_2, batch_search_num1, 
                                                             batch_search_num2, batch_search_max])
            y, cdfg_1, cdfg_2, fea_1, fea_2, v_num_1, v_num_2 = get_batch(search_label, search_cfg_1, 
                                                                           search_cfg_2, search_dfg_1, search_dfg_2, 
                                                                           search_fea_1, search_fea_2, search_num1, 
                                                                           search_num2, search_max)
            predict = dis.eval(feed_dict={cdfg_left: cdfg_1, fea_left: fea_1, v_num_left: v_num_1, 
                                          cdfg_right: cdfg_2, fea_right: fea_2, v_num_right: v_num_2, 
                                          labels: y, dropout_f: 1.0})
            predicts += predict[0][0]
            predicts_arr += str(predict[0][0]) + ","
        predicts /= int(cve_num)
        print(m, y[0][0], predicts)
        search_result.setdefault(y[0][0], predicts)
        search_result_arr.setdefault(y[0][0], predicts_arr)

    search_result_sorted = sorted(search_result.items(), key=operator.itemgetter(1), reverse=True)
    print(search_result_sorted)
    
    if not os.path.exists(config.SEARCH_RESULT_VULSEEKER_DIR + os.sep + cve_dir):
        os.mkdir(config.SEARCH_RESULT_VULSEEKER_DIR + os.sep + cve_dir)

    result_file = config.SEARCH_RESULT_VULSEEKER_DIR + os.sep + cve_dir + os.sep + str(search_program) + ".csv"
    with open(result_file, 'w') as result_fp:
        for key, value in search_result_sorted:
            result_fp.write(f"{key.split('###')[0]},{value},{key.split('###')[1]},{search_result_arr.get(key)},\n")

    coord.request_stop()
    coord.join(threads)
