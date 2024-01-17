
# -*- coding: utf-8 -*-
import copy
import os
from keras.models import Sequential
from keras.layers import LSTM, Dense
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

def Sequential_Input_LSTM(total_data_df, time_step_size):
    
    yy = total_data_df['Label'].replace(to_replace="Benign",value="0").replace(to_replace="Malicious",value="1").astype('int64')
    XX = total_data_df.drop(['Label'], axis=1)
    
    df_x_np = XX.to_numpy()
    df_y_np = yy.to_numpy()    
    
    X = []
    y = []
    
    for i in range(0, len(df_x_np) - time_step_size, time_step_size):
        row = [a for a in df_x_np[i:i + time_step_size]]
        if (np.isnan(row).all()): 
            # print(row)
            continue
        X.append(row)
        label = df_y_np[i + time_step_size]
        y.append(label)
        
    return np.array(X), np.array(y)

df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])


def fetch_dataset():
    global df
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
    
    df = pd.concat([benign_df, malicious_df.loc[random_malicious_start: random_malicious_start + benign_len]])
    # print(df)
    print("reddy")

fetch_dataset() 


print(df)


def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def model(data_df, timestep, number_of_lstm_nodes):
    X, y = Sequential_Input_LSTM(data_df, timestep)
    X[np.isnan(X)] = 0
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    print("count unique values for y.")
    print(np.unique(y_train, return_counts=True))
    print(np.unique(y, return_counts=True))


    print(len(X_train))

    model = Sequential()
    model.add(Dense(units=4056, activation='relu', input_shape=(timestep, 4))) 
    model.add(LSTM(units=number_of_lstm_nodes))
    model.add(Dense(units=4056, activation='relu'))
    model.add(Dense(units=4056, activation='relu'))
    model.add(Dense(units=1, activation='linear'))

    model.compile(optimizer='adam', loss='mse')

    print("training")
    model.fit(X_train, y_train, epochs=10, batch_size=64)
    
    random_string = generate_random_string(6)
    model_name = f"model_time_step_{timestep}_{random_string}.h5"
    
    print("saving model as ", model_name)
    
    model.save(f'output/model/{model_name}')
    
    y_pred = model.predict(X_test, batch_size=32, verbose=1)
    plot_x = [i for i in range(len(y_pred))]
    
    z_pred = [x for _,x in sorted(zip(y_test, y_pred))]
    plt.plot(plot_x, z_pred, color="red")
    plt.savefig(f"output/logs/lstm/lstm_10_epoch_{timestep}.png")

    print("y_pred", y_pred)

    # y_pred_bool = np.argmax(y_pred, axis=1)
    y_pred_bool = np.where(y_pred > 0.8, 1, 0)
    
    print("y_pred_bool", y_pred_bool)
    print(np.unique(y, return_counts=True))

    print(classification_report(y_test, y_pred_bool))
    print(confusion_matrix(y_test, y_pred_bool))
    
timestep = 2
model(df, timestep=timestep, number_of_lstm_nodes=4056)

