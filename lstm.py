
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
# print(random.randint(0,10000))

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

def generate_dataset():
    data_folder = 'output/'
    global df
    data_df = pd.read_csv(data_folder + "begging.csv", index_col=[0,1], skipinitialspace=True)

    i = 0
    
    for date, new_df in data_df.groupby(level=0):
        if i % 20 == 0:
            print(len(df))
            df.to_csv("output/malicious_dataset.csv", index=True)
        #     break
        i += 1;
        new_df = data_df.loc[date].T
        df = pd.concat([df, new_df])
        # print(len(new_df))
        
    print(df)

def fetch_dataset():
    global df
    benign_df = pd.read_csv("output/benign_dataset.csv", header=[0], index_col=0)
    benign_df['Label'] = 0
    benign_df = benign_df.drop(['RawTimestamp', 'src', 'dst'], axis=1)
    benign_df.to_csv("output/final_benign_dataset.csv", index=True)
    
    malicious_df = pd.read_csv("output/benign_dataset.csv", header=[0], index_col=0)
    malicious_df['Label'] = 1
    malicious_df = malicious_df.drop(['RawTimestamp', 'src', 'dst'], axis=1)
    malicious_df.to_csv("output/final_malicious_dataset.csv", index=True)
    print("benign length", len(benign_df))
    print("malicious length", len(malicious_df))
    df = pd.concat([benign_df, malicious_df])
    print(df)
    print("reddy")

fetch_dataset() 
# generate_dataset() 

# benign_df = load_npy('output/11/begign.npy')
# df['Label'] = 0
# # malicious_df = pd.read_csv(data_folder + "malicious.npy")
# malicious_df = load_npy('output/11/malicious.npy')
# malicious_df['Label'] = 1

# # data_df = malicious_df
# data_df = pd.concat([malicious_df, benign_df], ignore_index=True)
# loaded_data = np.load('output/11/totaldata.npy', allow_pickle=True)  # Set allow_pickle=True if the data contains objects

# columns = ['Number of Packets', 'Direction', 'Size', 'Duration', 'Label']


# df = df.drop(['RawTimestamp', 'src', 'dst'], axis=1)


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

def model(data_df, timestep, number_of_lstm_nodes):
    X, y = Sequential_Input_LSTM(data_df, timestep)
    X[np.isnan(X)] = 0
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    print("count unique values for y.")
    print(np.unique(y_train, return_counts=True))
    print(np.unique(y, return_counts=True))


    print(len(X_train))

    model = Sequential()
    model.add(Dense(units=4056, activation='relu', input_shape=(5, 4))) 
    model.add(LSTM(units=number_of_lstm_nodes))
    model.add(Dense(units=4056, activation='relu'))
    model.add(Dense(units=4056, activation='relu'))
    model.add(Dense(units=1, activation='linear'))
    model.compile(optimizer='adam', loss='mse')

    print("training")
    model.fit(X_train, y_train, epochs=5, batch_size=32)
    
    random_string = generate_random_string(6)
    model_name = f"model_{random_string}.h5"
    model.save(f'output/model/{model_name}')
    
    y_pred = model.predict(X_test, batch_size=32, verbose=1)
    plot_x = [i for i in range(len(y_pred))]
    
    z_pred = [x for _,x in sorted(zip(y_test, y_pred))]
    plt.plot(plot_x, z_pred, color="red")
    plt.savefig("plotFinalResults.png")
    # plt.plot(plot_x, y_test, color="blue")
    # plt.savefig("plotFinalResults1.png")

    print("y_pred", y_pred)

    # y_pred_bool = np.argmax(y_pred, axis=1)
    y_pred_bool = np.where(y_pred > 0.48, 1, 0)
    
    print("y_pred_bool", y_pred_bool)
    print(np.unique(y, return_counts=True))

    print(classification_report(y_test, y_pred_bool))
    print(confusion_matrix(y_test, y_pred_bool))
    
timestep = 5
model(df, timestep=timestep, number_of_lstm_nodes=4056)

