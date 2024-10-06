#!/usr/bin/env python3
# _*_ coding: utf-8 _*_

import tensorflow as tf
import numpy as np
import csv
import time
from sklearn.metrics import roc_curve, auc
import os
import config

# ===========  global parameters  ===========

T = 100  # iteration
N = 2  # embedding_depth
P = 64  # embedding_size
D = 8  # dimensional, feature num
B = 1  # mini-batch
lr = 0.0001  # learning_rate
max_iter = 100  # iteration
decay_steps = 10  # decay steps
decay_rate = 0.0001  # decay rate
snapshot = 1
is_debug = True

train_num = config.TRAIN_DATASET_NUM
valid_num = int(train_num / 10)
test_num = int(train_num / 10)

PREFIX = "" + str(config.TRAIN_DATASET_NUM) + "_[" + '_'.join(config.STEP3_PORGRAM_ARR) + "]"
TRAIN_TFRECORD = config.TFRECORD_VULSEEKER_DIR + os.sep + "train_" + PREFIX + ".tfrecord"
TEST_TFRECORD = config.TFRECORD_VULSEEKER_DIR + os.sep + "test_" + PREFIX + ".tfrecord"
VALID_TFRECORD = config.TFRECORD_VULSEEKER_DIR + os.sep + "valid_" + PREFIX + ".tfrecord"
print("VALID_TFRecord", VALID_TFRECORD)


def structure2vec(mu_prev, cdfg, x, name="structure2vec"):
    with tf.variable_scope(name):
        W_1 = tf.get_variable('W_1', [D, P], tf.float32, tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
        P_CDFG_1 = tf.get_variable('P_CDFG_1', [P, P], tf.float32, tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
        P_CDFG_2 = tf.get_variable('P_CDFG_2', [P, P], tf.float32, tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
        L_CFG = tf.reshape(tf.matmul(cdfg, mu_prev, transpose_a=True), (-1, P))
        S_CDFG = tf.reshape(tf.matmul(tf.nn.relu(tf.matmul(L_CFG, P_CDFG_2)), P_CDFG_1), (-1, P))

        return tf.tanh(tf.add(tf.reshape(tf.matmul(tf.reshape(x, (-1, D)), W_1), (-1, P)), S_CDFG))


def structure2vec_net(cdfgs, x, v_num):
    with tf.variable_scope("structure2vec_net") as structure2vec_net:
        B_mu_5 = tf.Variable(tf.zeros(shape=[0, P]), trainable=False)
        w_2 = tf.get_variable('w_2', [P, P], tf.float32, tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
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


def calculate_auc(labels, predicts):
    fpr, tpr, thresholds = roc_curve(labels, predicts, pos_label=1)
    AUC = auc(fpr, tpr)
    print("auc:", AUC)
    return AUC


def contrastive_loss(labels, distance):
    loss = tf.cast(tf.reduce_sum(tf.square(distance - labels)), tf.float32)
    return loss


def compute_accuracy(prediction, labels):
    accu = 0.0
    threshold = 0.5
    for i in range(len(prediction)):
        if labels[i][0] == 1:
            if prediction[i][0] > threshold:
                accu += 1.0
        else:
            if prediction[i][0] < threshold:
                accu += 1.0
    acc = accu / len(prediction)
    return acc


def cal_distance(model1, model2):
    a_b = tf.reduce_sum(tf.reshape(tf.reduce_prod(tf.concat([tf.reshape(model1, (1, -1)), tf.reshape(model2, (1, -1))], 0), 0), (B, P)), 1, keepdims=True)
    a_norm = tf.sqrt(tf.reduce_sum(tf.square(model1), 1, keepdims=True))
    b_norm = tf.sqrt(tf.reduce_sum(tf.square(model2), 1, keepdims=True))
    distance = a_b / tf.reshape(tf.reduce_prod(tf.concat([tf.reshape(a_norm, (1, -1)), tf.reshape(b_norm, (1, -1))], 0), 0), (B, 1))
    return distance


def read_and_decode(filename):
    filename_queue = tf.train.string_input_producer([filename])
    reader = tf.TFRecordReader()
    _, serialized_example = reader.read(filename_queue)

    features = tf.parse_single_example(serialized_example, features={
        'label': tf.FixedLenFeature([], tf.int64),
        'cfg_1': tf.FixedLenFeature([], tf.string),
        'cfg_2': tf.FixedLenFeature([], tf.string),
        'dfg_1': tf.FixedLenFeature([], tf.string),
        'dfg_2': tf.FixedLenFeature([], tf.string),
        'fea_1': tf.FixedLenFeature([], tf.string),
        'fea_2': tf.FixedLenFeature([], tf.string),
        'num1': tf.FixedLenFeature([], tf.int64),
        'num2': tf.FixedLenFeature([], tf.int64),
        'max': tf.FixedLenFeature([], tf.int64)})

    label = tf.cast(features['label'], tf.int32)
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

    # Padding matrix lengths
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

    # Padding feature lengths
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


# TensorFlow and further code remains the same

# 4. Construct the network
# Initializing the variables
# Siamese network major part

# Initialize the variables
init = tf.compat.v1.global_variables_initializer()
global_step = tf.Variable(0, trainable=False)
learning_rate = tf.compat.v1.train.exponential_decay(lr, global_step, decay_steps, decay_rate, staircase=True)

v_num_left = tf.compat.v1.placeholder(tf.float32, shape=[B, 1], name='v_num_left')
cdfg_left = tf.compat.v1.placeholder(tf.float32, shape=([B, None, None]), name='cdfg_left')
fea_left = tf.compat.v1.placeholder(tf.float32, shape=([B, None, D]), name='fea_left')

v_num_right = tf.compat.v1.placeholder(tf.float32, shape=[B, 1], name='v_num_right')
cdfg_right = tf.compat.v1.placeholder(tf.float32, shape=([B, None, None]), name='cdfg_right')
fea_right = tf.compat.v1.placeholder(tf.float32, shape=([B, None, D]), name='fea_right')

labels = tf.compat.v1.placeholder(tf.float32, shape=([B, 1]), name='gt')

dropout_f = tf.compat.v1.placeholder(tf.float32)

with tf.compat.v1.variable_scope("siamese") as siamese:
    model1 = structure2vec_net(cdfg_left, fea_left, v_num_left)
    siamese.reuse_variables()
    model2 = structure2vec_net(cdfg_right, fea_right, v_num_right)

dis = cal_distance(model1, model2)
loss = contrastive_loss(labels, dis)
optimizer = tf.compat.v1.train.AdamOptimizer(learning_rate=learning_rate).minimize(loss)

# Train, valid, test set batching and decoding
list_train_label, list_train_cfg_1, list_train_cfg_2, list_train_dfg_1, list_train_dfg_2, list_train_fea_1, \
list_train_fea_2, list_train_num1, list_train_num2, list_train_max = read_and_decode(TRAIN_TFRECORD)

batch_train_label, batch_train_cfg_1, batch_train_cfg_2, batch_train_dfg_1, batch_train_dfg_2, batch_train_fea_1, \
batch_train_fea_2, batch_train_num1, batch_train_num2, batch_train_max = tf.compat.v1.train.batch(
    [list_train_label, list_train_cfg_1, list_train_cfg_2, list_train_dfg_1, list_train_dfg_2,
     list_train_fea_1, list_train_fea_2, list_train_num1, list_train_num2, list_train_max],
    batch_size=B, capacity=10)

list_valid_label, list_valid_cfg_1, list_valid_cfg_2, list_valid_dfg_1, list_valid_dfg_2, list_valid_fea_1, \
list_valid_fea_2, list_valid_num1, list_valid_num2, list_valid_max = read_and_decode(VALID_TFRECORD)

batch_valid_label, batch_valid_cfg_1, batch_valid_cfg_2, batch_valid_dfg_1, batch_valid_dfg_2, batch_valid_fea_1, \
batch_valid_fea_2, batch_valid_num1, batch_valid_num2, batch_valid_max = tf.compat.v1.train.batch(
    [list_valid_label, list_valid_cfg_1, list_valid_cfg_2, list_valid_dfg_1, list_valid_dfg_2,
     list_valid_fea_1, list_valid_fea_2, list_valid_num1, list_valid_num2, list_valid_max],
    batch_size=B, capacity=10)

list_test_label, list_test_cfg_1, list_test_cfg_2, list_test_dfg_1, list_test_dfg_2, list_test_fea_1, \
list_test_fea_2, list_test_num1, list_test_num2, list_test_max = read_and_decode(TEST_TFRECORD)

batch_test_label, batch_test_cfg_1, batch_test_cfg_2, batch_test_dfg_1, batch_test_dfg_2, batch_test_fea_1, \
batch_test_fea_2, batch_test_num1, batch_test_num2, batch_test_max = tf.compat.v1.train.batch(
    [list_test_label, list_test_cfg_1, list_test_cfg_2, list_test_dfg_1, list_test_dfg_2,
     list_test_fea_1, list_test_fea_2, list_test_num1, list_test_num2, list_test_max],
    batch_size=B, capacity=10)

# Initialize session and training
init_opt = tf.compat.v1.global_variables_initializer()
saver = tf.compat.v1.train.Saver()

os.environ["CUDA_VISIBLE_DEVICES"] = "0,2,3"

with tf.compat.v1.Session() as sess:
    writer = tf.compat.v1.summary.FileWriter('logs/', sess.graph)
    sess.run(init_opt)
    
    if config.SETP5_IF_RESTORE_VULSEEKER_MODEL:
        saver.restore(sess, config.MODEL_VULSEEKER_DIR + os.sep + config.STEP5_VULSEEKER_MODEL_TO_RESTORE)

    coord = tf.train.Coordinator()
    threads = tf.compat.v1.train.start_queue_runners(sess=sess, coord=coord)

    # Training cycle
    iter = 0
    while iter < max_iter:
        iter += 1
        avg_loss = 0.
        avg_acc = 0.
        total_batch = int(train_num / B)
        start_time = time.time()

        for i in range(total_batch):
            train_label, train_cfg_1, train_cfg_2, train_dfg_1, train_dfg_2, train_fea_1, train_fea_2, \
            train_num1, train_num2, train_max = sess.run(
                [batch_train_label, batch_train_cfg_1, batch_train_cfg_2, batch_train_dfg_1, batch_train_dfg_2,
                 batch_train_fea_1, batch_train_fea_2, batch_train_num1, batch_train_num2, batch_train_max])

            y, cdfg_1, cdfg_2, fea_1, fea_2, v_num_1, v_num_2 = get_batch(
                train_label, train_cfg_1, train_cfg_2, train_dfg_1, train_dfg_2, train_fea_1, train_fea_2, 
                train_num1, train_num2, train_max)

            _, loss_value, predict = sess.run([optimizer, loss, dis], feed_dict={
                cdfg_left: cdfg_1, fea_left: fea_1, v_num_left: v_num_1,
                cdfg_right: cdfg_2, fea_right: fea_2, v_num_right: v_num_2,
                labels: y, dropout_f: 0.9})

            tr_acc = compute_accuracy(predict, y)
            if is_debug:
                print(f'     {i}    tr_acc {tr_acc:.2f}')
            avg_loss += loss_value
            avg_acc += tr_acc * 100
        duration = time.time() - start_time

        if iter % snapshot == 0:
            # Validation
            avg_loss = 0.
            avg_acc = 0.
            valid_start_time = time.time()

            for m in range(2):  # Reduce validation set for quick check
                valid_label, valid_cfg_1, valid_cfg_2, valid_dfg_1, valid_dfg_2, valid_fea_1, valid_fea_2, \
                valid_num1, valid_num2, valid_max = sess.run(
                    [batch_valid_label, batch_valid_cfg_1, batch_valid_cfg_2, batch_valid_dfg_1, batch_valid_dfg_2,
                     batch_valid_fea_1, batch_valid_fea_2, batch_valid_num1, batch_valid_num2, batch_valid_max])

                y, cdfg_1, cdfg_2, fea_1, fea_2, v_num_1, v_num_2 = get_batch(
                    valid_label, valid_cfg_1, valid_cfg_2, valid_dfg_1, valid_dfg_2, valid_fea_1, valid_fea_2, 
                    valid_num1, valid_num2, valid_max)

                predict = dis.eval(feed_dict={
                    cdfg_left: cdfg_1, fea_left: fea_1, v_num_left: v_num_1,
                    cdfg_right: cdfg_2, fea_right: fea_2, v_num_right: v_num_2,
                    labels: y, dropout_f: 0.9})

                tr_acc = compute_accuracy(predict, y)
                avg_loss += loss.eval(feed_dict={labels: y, dis: predict})
                avg_acc += tr_acc * 100
                if is_debug:
                    print(f'     tr_acc {tr_acc:.2f}')
            duration = time.time() - valid_start_time
            print(f'valid set, {iter},  time, {duration:.2f}, loss, {avg_loss:.5f}, acc, {avg_acc:.2f}')

            saver.save(sess, config.MODEL_VULSEEKER_DIR + os.sep + f"vulseeker-model{PREFIX}_{iter}.ckpt")

            # Test model on a small batch
            total_labels = []
            total_predicts = []
            avg_loss = 0.
            avg_acc = 0.
            test_total_batch = 2  # Test on smaller batch size for quick results
            start_time = time.time()

            for m in range(test_total_batch):
                test_label, test_cfg_1, test_cfg_2, test_dfg_1, test_dfg_2, \
                test_fea_1, test_fea_2, test_num1, test_num2, test_max = sess.run(
                    [batch_test_label, batch_test_cfg_1, batch_test_cfg_2, batch_test_dfg_1, batch_test_dfg_2,
                     batch_test_fea_1, batch_test_fea_2, batch_test_num1, batch_test_num2, batch_test_max])

                y, cdfg_1, cdfg_2, fea_1, fea_2, v_num_1, v_num_2 = get_batch(
                    test_label, test_cfg_1, test_cfg_2, test_dfg_1, test_dfg_2,
                    test_fea_1, test_fea_2, test_num1, test_num2, test_max)

                predict = dis.eval(feed_dict={
                    cdfg_left: cdfg_1, fea_left: fea_1, v_num_left: v_num_1,
                    cdfg_right: cdfg_2, fea_right: fea_2, v_num_right: v_num_2,
                    labels: y, dropout_f: 1.0})

                tr_acc = compute_accuracy(predict, y)
                avg_loss += loss.eval(feed_dict={labels: y, dis: predict})
                avg_acc += tr_acc * 100
                total_labels.append(y)
                total_predicts.append(predict)
                if is_debug:
                    print(f'     {m}    tr_acc {tr_acc:.2f}')

            duration = time.time() - start_time
            total_labels = np.reshape(total_labels, (-1))
            total_predicts = np.reshape(total_predicts, (-1))
            print(calculate_auc(total_labels, total_predicts))
            print(f'test set, time, {duration:.2f}, loss, {avg_loss:.5f}, acc, {avg_acc:.2f}')

    # Save the final model
    saver.save(sess, config.MODEL_VULSEEKER_DIR + os.sep + f"vulseeker-model{PREFIX}_final.ckpt")

    coord.request_stop()
    coord.join(threads)
