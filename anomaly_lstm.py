
# -*- coding: utf-8 -*-
import copy
import os
from keras.models import Sequential
from keras.layers import LSTM, Dense, Conv1D, MaxPooling2D, Flatten
from common_utils import Sequential_Input_LSTM

import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import random
from sklearn.metrics import confusion_matrix
import string
import matplotlib.pyplot as plt

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
    df = benign_df
    # df = pd.concat([benign_df, malicious_df.loc[random_malicious_start: random_malicious_start + benign_len]])
    # print(df)
    print("reddy")

fetch_dataset() 


print(df)

def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


from datetime import datetime
current_time = "_".join(str(datetime.strptime(str(datetime.now()), "%Y-%m-%d %H:%M:%S.%f")).split())
output_path = f"output/anomaly_lstm_{current_time}"

print("Creating directory", output_path) 
os.makedirs(output_path)

def model(data_df, timestep, number_of_lstm_nodes):
    X, y = Sequential_Input_LSTM(data_df, timestep)
    X[np.isnan(X)] = 0
    y[np.isnan(y)] = 0
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)
    np.save(f"{output_path}/X_train_{timestep}_timesteps.npy", X_train)
    np.save(f"{output_path}/X_test_{timestep}_timesteps.npy", X_test)
    np.save(f"{output_path}/y_train_{timestep}_timesteps.npy", y_train)
    np.save(f"{output_path}/y_test_{timestep}_timesteps.npy", y_test)

    print("count unique values for y.")
    print(np.unique(y_train, return_counts=True))
    print(np.unique(y, return_counts=True))


    print(len(X_train))

    print(X_train.shape)  # Check the shape of your input data
    print(y_train.shape)  # Check the shape of your target data

    number_of_filters = 2048
    model = Sequential()
    model.add(Conv1D(filters=number_of_filters, kernel_size=(3), activation='relu', input_shape=(timestep, 4)))
    # model.add(MaxPooling2D(pool_size=(2, 2)))
    # model.add(Conv2D(filters=number_of_filters, kernel_size=(3, 3), activation='relu'))
    # model.add(MaxPooling2D(pool_size=(2, 2)))
    model.add(Flatten())
    model.add(Dense(units=number_of_filters, activation='relu'))
    model.add(Dense(units=number_of_filters, activation='relu'))
    model.add(Dense(units=4, activation='linear'))


    model.compile(optimizer='adam', loss='mean_squared_error')
    
    print(model.summary())

    print("training")
    model.fit(X_train, y_train, epochs=1, batch_size=64, verbose=2)
    
    random_string = generate_random_string(6)
    model_name = f"model_time_step_{timestep}_nodes_{number_of_lstm_nodes}_{random_string}.h5"
    print("saving model as ", model_name)
    model.save(f'{output_path}/{model_name}')
    
    print("training lstm done!!")
    y_pred = model.predict(X_test, verbose=2)
    
    print("X_test", X_test)
    
    print("y_test", y_test)

    print("y_pred", y_pred)
    
    print("y_pred 0 ", y_pred[0][0])
    
    benign_mse = []
    malicious_mse = []
    mal_X, mal_y = Sequential_Input_LSTM(malicious_df, timestep, predict_next=True)
    y_pred_mal = model.predict(mal_X[:len(y_test)], verbose=2)
    
    for i in range(len(y_pred)):
        mse = np.mean(np.square(y_test[i] - y_pred[i][0]))
        benign_mse.append(mse)
    print("Mean Squared Error:", sorted(benign_mse)[:20])
    
    
    
    for i in range(len(y_pred)):
        mse = np.mean(np.square(mal_y[i] - y_pred_mal[i][0]))
        malicious_mse.append(mse)
    # print("Mean Squared Error:", sorted(malicious_mse))
    
    
    plot_x = [i for i in range(2 * len(y_pred))]
    
    plt.plot(plot_x[:len(y_pred)], sorted(benign_mse), color="blue")
    # plt.plot(range(len(y_pred), 2 * len(y_pred)), sorted(malicious_mse), marker='o', color="red")
    # plt.xlabel('count')
    # plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_label_{lstm_nodes}.png")
    plt.clf()
    
    
all_accuracies = []
for lstm_nodes in [1024]:
    accuracies = []
    for timestep in range(5,6):
        accu = model(df, timestep=timestep, number_of_lstm_nodes=lstm_nodes)
        print("accu", accu)
        accuracies.append(accu)
    all_accuracies.append(accuracies)
    # plt.plot(range(1, 11), accuracies, marker='o')
    # plt.xlabel('Time Step')
    # plt.ylabel('Accuracy')
    # plt.savefig(f"{output_path}/lstm_accuracy_10_epoch_nodes_{lstm_nodes}.png")
    # plt.clf()

print("all_accuracies", all_accuracies)
