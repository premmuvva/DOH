
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
print("test run count", flush=True)
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
        if (np.isnan(row).any()): 
            # print(row)
            continue
        X.append(row)
        label = df_y_np[i + time_step_size]
        y.append(label)
        
    return np.array(X), np.array(y)

df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])

def generate_dataset(input_file, output_file):

    global df
    data_df = pd.read_csv(input_file, index_col=[0,1], skipinitialspace=True, low_memory=False)

    i = 0
    
    for date, new_df in data_df.groupby(level=0):
        # if i == 4:
        #     break
        print(f"processsing file {date}", flush=True)
        if i % 50 == 0:
            print(f"Current saving df size: {len(df)}")
            df.to_csv(output_file, index=False)
        #     break
        i += 1;
        new_df = data_df.loc[date].T
        
        step_size = 20

        for ii in range(0, len(new_df), step_size):
            chunk = new_df.iloc[ii:ii + step_size]

            # Check if all rows in the chunk are NaN
            if chunk.isna().all(axis=1).all():
                new_df = new_df.iloc[:ii + step_size]
                break
            
                
            
        # print(new_df)
        # print("new_df", new_df)
        # add logic to add rows which have no 20 consecutive all nan rows
        df = pd.concat([df, new_df])
    
    df.to_csv(output_file, index=False)
    # print(df, flush=True)


# generate_dataset('output/merge_npy/benignV2.csv', "output/temp/benign_pre_timestep_dataset_1.csv") 

generate_dataset('output/merge_npy/maliciousv2_2_cp.csv', "output/temp/malicious_pre_timestep_dataset.csv") 



# print(df)

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
# model(df, timestep=timestep, number_of_lstm_nodes=4056)

