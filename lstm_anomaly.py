
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
    
    # df = pd.concat([benign_df, malicious_df.loc[random_malicious_start: random_malicious_start + benign_len]])
    df = benign_df
    # print(df)
    print("reddy")

fetch_dataset() 


print(df)



# data_df['Label']= data_df['Label'].astype('int64')
# data_df['Number of Packets']= data_df['Number of Packets'].astype('int64')
# data_df['Direction']= data_df['Direction'].astype('int64')
# data_df['Size']= data_df['Size'].astype('int64')
# data_df['Duration']= data_df['Duration'].astype('float')

# print(data_df.dtypes)
# print(data_df.head)
# print(data_df.shape)

# np.save('output/11/totaldata.npy', data_df)

def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


output_path = f"output/lstm_{generate_random_string(4)}"

print("Creating directory", output_path) 
os.makedirs(output_path)


def Sequential_Input_LSTM(total_data_df, time_step_size, predict_next=False):
    yy = total_data_df['Label'].replace(to_replace="Benign", value="0").replace(to_replace="Malicious", value="1").astype('int64')
    XX = total_data_df.drop(['Label'], axis=1)

    df_x_np = XX.to_numpy()
    df_y_np = yy.to_numpy()

    X = []
    y = []

    for i in range(0, len(df_x_np) - time_step_size):
        if predict_next:
            row = [a for a in df_x_np[i:i + time_step_size]]
            next_row = [a for a in df_x_np[i + 1]]

            if (np.isnan(row).all()) or (np.isnan(next_row).all()):
                continue

            X.append(row)
            y.append(next_row)
        else:
            row = [a for a in df_x_np[i:i + time_step_size]]
            if (np.isnan(row).all()):
                continue
            X.append(row)
            label = df_y_np[i + time_step_size]
            y.append(label)

    return np.array(X), np.array(y)

# ...

from keras import backend as K

def custom_mse(y_true, y_pred):
    # Custom MSE implementation
    # print(y_true, y_pred)
    return K.mean(K.square(y_pred - y_true[0]), axis=-1)

def model(data_df, timestep, number_of_lstm_nodes):
    X, y = Sequential_Input_LSTM(data_df, timestep, predict_next=True)
    X[np.isnan(X)] = 0
    y[np.isnan(y)] = 0

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)

    print("count unique values for y.")
    print(np.unique(y_train, return_counts=True))
    print(np.unique(y, return_counts=True))

    print(len(X_train))

    model = Sequential()
    model.add(Dense(units=number_of_lstm_nodes, activation='relu', input_shape=(timestep, 4))) 
    model.add(LSTM(units=number_of_lstm_nodes))
    # model.add(Dropout(rate=0.1))
    # model.add(RepeatVector(1))
    # model.add(LSTM(units=number_of_lstm_nodes, activation='relu', return_sequences=True))
    model.add(Dropout(rate=0.1))
    model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    model.add(Dropout(rate=0.1))
    model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    model.add(Dropout(rate=0.1))
    model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    # model.add(Lambda(lambda x: x[0])) 
    model.add(Dense(units=4, activation='linear'))
    # model.add(Flatten())
    model.compile(optimizer='adam', loss='mse')
    
    print(model.summary())
    
    print("training lstm")
    model.fit(X_train, y_train, epochs=1, batch_size=64, verbose=2)
    
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
    # print("Mean Squared Error:", benign_mse)
    
    
    
    for i in range(len(y_pred)):
        mse = np.mean(np.square(mal_y[i] - y_pred_mal[i][0]))
        malicious_mse.append(mse)
    # print("Mean Squared Error:", malicious_mse)
    
    plt.plot(range(len(y_pred)), sorted(benign_mse), marker='o', color="blue")
    plt.plot(range(len(y_pred), 2 * len(y_pred)), sorted(malicious_mse), marker='o', color="red")
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_label_{lstm_nodes}.png")
    plt.clf()
    
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
for lstm_nodes in [2048]: #[1024, 2048, 4096, 8192]:
    accuracies_anomaly = []
    for timestep in range(5, 6):
        accu = model(df, timestep=timestep, number_of_lstm_nodes=lstm_nodes)
        accuracies_anomaly.append(accu)
    all_accuracies_anomaly.append(accuracies_anomaly)
    # plt.plot(range(1, 11), accuracies_anomaly, marker='o')
    # plt.xlabel('Time Step')
    # plt.ylabel('Accuracy')
    # plt.savefig(f"{output_path}/anomaly_accuracy_10_epoch_nodes_{lstm_nodes}.png")
    # plt.clf()