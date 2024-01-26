
# -*- coding: utf-8 -*-
import copy
import os
from keras.models import Sequential
from keras.layers import LSTM, Dense, Lambda, Flatten
from keras.layers import Dropout, RepeatVector, TimeDistributed, Dense
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import random
from sklearn.metrics import confusion_matrix
from sklearn.metrics import mean_squared_error
import string
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from common_utils import Sequential_Input_LSTM_transpose as Sequential_Input_LSTM

np.set_printoptions(threshold=30)
print("test run count")
# print(random.randint(0,10000))


df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])
malicious_df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])


def fetch_dataset():
    global df, malicious_df
    benign_df = pd.read_csv("output/merge_npy/benignV2_final_without_multi_index.csv", header=[0], low_memory=False)
    benign_df['Label'] = 0
    benign_df = benign_df.drop(['RawTimestamp', 'src', 'dst'], axis=1)
    # benign_df.to_csv("output/final_benign_dataset.csv", index=False)
    print(len(benign_df))
    
    malicious_df = pd.read_csv("output/temp/maliciousv2_final_without_multi_index.csv", header=[0], low_memory=False)
    malicious_df['Label'] = 1
    malicious_df = malicious_df.drop(['RawTimestamp', 'src', 'dst'], axis=1)
    # malicious_df.to_csv("output/final_malicious_dataset.csv", index=False)
    benign_len = len(benign_df)
    malicious_len = len(malicious_df)
    random_malicious_start = random.randint(0, malicious_len - benign_len - 1)
    print("random start value ", random_malicious_start)
    
    print("benign length", benign_len)
    print("malicious length", malicious_len)
    
    # df = pd.concat([benign_df, malicious_df.loc[random_malicious_start: random_malicious_start + benign_len]])
    df = benign_df

fetch_dataset() 


print(df)


def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


current_time = "_".join(str(datetime.strptime(str(datetime.now()), "%Y-%m-%d %H:%M:%S.%f")).split())
output_path = f"output/lstm_anomaly_{current_time}"

print("Creating directory", output_path) 
os.makedirs(output_path)


from keras import backend as K

def custom_mse(y_true, y_pred):
    # Custom MSE implementation
    # print(y_true, y_pred)
    return K.mean(K.square(y_pred - y_true[0]), axis=-1)

def model(data_df, timestep, number_of_lstm_nodes):
    X, y = Sequential_Input_LSTM(data_df, timestep, predict_next=True)
    # X[np.isnan(X)] = 0
    # y[np.isnan(y)] = 0
    
    X = np.asarray(X).astype('float32')
    y = np.asarray(y).astype('float32')

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)
    
    np.save(f"{output_path}/X_train_{timestep}_timesteps.npy", X_train)
    np.save(f"{output_path}/X_test_{timestep}_timesteps.npy", X_test)
    np.save(f"{output_path}/y_train_{timestep}_timesteps.npy", y_train)
    np.save(f"{output_path}/y_test_{timestep}_timesteps.npy", y_test)
    
    # print("count unique values for y.")
    # print(np.unique(y_train, return_counts=True))
    # print(np.unique(y, return_counts=True))

    print(len(X_train))

    
    model = Sequential()
    model.add(Dense(units=number_of_lstm_nodes, activation='relu', input_shape=(4, timestep))) 
    model.add(LSTM(units=number_of_lstm_nodes, return_sequences=True))
    model.add(Dropout(rate=0.1))
    model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    model.add(Dropout(rate=0.1))
    model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    model.add(Dropout(rate=0.1))
    model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    model.add(Dense(units=timestep, activation='linear'))
    
    # print(model.summary())
    
    model.compile(optimizer='adam', loss='mse')
    
    print(model.summary())
    
    print("training lstm")
    model.fit(X_train, y_train, epochs=10, batch_size=64, verbose=2)
    
    model_name = f"model_time_step_{timestep}_nodes_{number_of_lstm_nodes}.h5"
    print("saving model as ", model_name)
    model.save(f'{output_path}/{model_name}')
    
    print("training lstm done!!")
    y_pred = model.predict(X_test, verbose=2)
    
    print("X_test", X_test)
    
    print("y_test", y_test)

    print("y_pred", y_pred)
    
    print("y_pred 0 ", y_pred[0][0])
    
    print("y_test 0 ", y_test[0][0])
    
    print("diff 0 ", y_test[0][0] - y_pred[0][0])
    
    benign_mse = []
    malicious_mse = []
    mal_X, mal_y = Sequential_Input_LSTM(malicious_df, timestep, predict_next=True)
    y_pred_mal = model.predict(mal_X, verbose=2)
    
    for i in range(len(y_pred)):
        mse = np.mean(np.square(y_test[i][0] - y_pred[i][0]))
        benign_mse.append(mse)
    # print("Mean Squared Error:", sorted(benign_mse)[0:20])
    
    benign_mse = sorted(benign_mse)
    percentage = 90
    index_cutoff = int(len(benign_mse) * (percentage / 100))
    benign_mse = benign_mse[:index_cutoff]
    
    
    xs, ys = zip(*sorted(zip(range(len(benign_mse)), benign_mse)))
    plt.plot(xs, ys)
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_benign_label_sorted_{lstm_nodes}.png")
    plt.clf()
    
    for i in range(len(y_pred_mal)):
        mse = np.mean(np.square(mal_y[i][:4] - y_pred_mal[i][:4]))
        malicious_mse.append(mse)
    # print("Mean Squared Error:", malicious_mse)
    malicious_mse = sorted(malicious_mse)
    percentage = 90
    index_cutoff = int(len(malicious_mse) * (percentage / 100))
    malicious_mse = malicious_mse[:index_cutoff]
    
    # xs, ys = zip(*sorted(zip(range(len(malicious_mse)), malicious_mse)))
    # plt.plot(xs, ys)
    # # plt.plot(range(len(y_pred)), sorted(benign_mse), color="blue")
    # # malicious_mse_90 = sorted(malicious_mse)[:int(0.5 * len(malicious_mse))]
    # # plt.plot(range(len(malicious_mse)), malicious_mse, marker='o', color="red")
    # plt.xlabel('count')
    # plt.ylabel('mse')
    # plt.savefig(f"{output_path}/mse_label_{lstm_nodes}.png")
    # plt.clf()
    
    xs, ys = zip(*sorted(zip(range(len(malicious_mse)), malicious_mse)))
    plt.plot(xs, ys)
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_malicious_label_sorted_{lstm_nodes}_nodes_{timestep}.png")
    plt.clf()
    
    xs, ys = zip(*sorted(zip(range(len(malicious_mse)), malicious_mse)))
    plt.plot(xs, ys, label='Malicious', color='orange')
    xs, ys = zip(*sorted(zip(range(len(malicious_mse), len(malicious_mse) + len(benign_mse)), sorted(benign_mse))))
    plt.plot(xs, ys, label='Benign', color='blue')
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_label_combined_sorted_{lstm_nodes}_nodes_{timestep}.png")
    plt.clf()

    #create histogram with density curve overlaid
    sns_plot = sns.displot(benign_mse, kde=True, bins=500)
    # fig = sns_plot.get_figure()
    sns_plot.savefig(f"{output_path}/sns_benign_plot_{lstm_nodes}_nodes_{timestep}.png")
    
    #create histogram with density curve overlaid
    sns_plot = sns.displot(malicious_mse, kde=True, bins=500)
    # fig = sns_plot.get_figure()
    sns_plot.savefig(f"{output_path}/sns_malicious_plot_{lstm_nodes}_nodes_{timestep}.png")
    
    # For anomaly detection, you can set a threshold for classifying high MSE as anomalies.
    threshold = 0.1  # Adjust as needed
    anomalies = np.where(np.array(malicious_mse) > threshold, 1, 0)
    
    print("y_pred_bool", anomalies)
    print(np.unique(anomalies, return_counts=True))
    # print(np.unique(y, return_counts=True))

    # print(classification_report(y_test, anomalies))
    # print(confusion_matrix(y_test, anomalies))
    accuracy = np.sum(y_test == anomalies) / len(y_test)
    print(accuracy, y_test)
    return accuracy

# Anomaly detection for different LSTM nodes
all_accuracies_anomaly = []
for lstm_nodes in [4096]: #[1024, 2048, 4096, 8192]:
    accuracies_anomaly = []
    for timestep in range(8, 9):
        accu = model(df, timestep=timestep, number_of_lstm_nodes=lstm_nodes)
        accuracies_anomaly.append(accu)
    all_accuracies_anomaly.append(accuracies_anomaly)
    # plt.plot(range(1, 11), accuracies_anomaly, marker='o')
    # plt.xlabel('Time Step')
    # plt.ylabel('Accuracy')
    # plt.savefig(f"{output_path}/anomaly_accuracy_10_epoch_nodes_{lstm_nodes}.png")
    # plt.clf()