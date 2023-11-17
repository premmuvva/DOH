
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
print("test run count")
print(random.randint(0,10000))

def Sequential_Input_LSTM(df, input_sequence):
    
    yy = data_df['Label'].replace(to_replace="Benign",value="0").replace(to_replace="Malicious",value="1").astype('int64')
    XX = data_df.drop(['Label'], axis=1)
    
    df_x_np = XX.to_numpy()
    df_y_np = yy.to_numpy()
    
    print(yy)
    print(df_y_np)
    
    X = []
    y = []
    
    for i in range(0, len(df_x_np) - input_sequence, input_sequence):
        row = [a for a in df_x_np[i:i + input_sequence]]
        X.append(row)
        label = df_y_np[i + input_sequence]
        y.append(label)
        
    return np.array(X), np.array(y)



data_folder = '/Users/reddy/Documents/classes/thesis/dga-detection/data-processing/'

benign_df = pd.read_csv(data_folder + "beign.csv")
benign_df['Label'] = 0
malicious_df = pd.read_csv(data_folder + "malicious.csv")
malicious_df['Label'] = 1

# data_df = malicious_df
data_df = pd.concat([malicious_df, benign_df], ignore_index=True)

# duplicate = int(len(malicious_df)/len(data_df))
# print(duplicate)
# for i in range(duplicate):
    # data_df = data_df.append(benign_df)
data_df = data_df.drop(['Timestamp', 'src', 'dst'], axis=1)
data_df['Label']= data_df['Label'].astype('int64')

print(data_df.dtypes)
print(data_df.head)
print(data_df.shape)

np.save('data.npy', data_df)


def model(timestep, number_of_lstm_nodes):
    X, y = Sequential_Input_LSTM(data_df, timestep)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    print("count unique values for y.")
    print(np.unique(y_train, return_counts=True))
    print(np.unique(y, return_counts=True))


    print(len(X_train))

    model = Sequential()
    model.add(LSTM(units=number_of_lstm_nodes, input_shape=(50, 6)))
    model.add(Dense(units=1))

    # binary_crossentropy
    model.compile(optimizer='adam', loss='mse')

    print("training")
    model.fit(X_train, y_train, epochs=10, batch_size=32)

    y_pred = model.predict(X_test, batch_size=32, verbose=1)

    # print(y_pred)

    y_pred_bool = np.argmax(y_pred, axis=1)

    # print(y_pred_bool)

    print(classification_report(y_test, y_pred_bool))
    
timestep = 50
model(timestep=timestep, number_of_lstm_nodes=216)





# print(len(data_df))
# print(len(data_df.groupby(data_df.index // 10)))


    # X = np.asarray(X).astype('float32')

    # print(XX[0:2])

    # X = [XX[i:i+50] for i in range(0,len(XX),50)]
    # y = [yy[i] for i in range(0,len(yy),50)]

    # print(X)