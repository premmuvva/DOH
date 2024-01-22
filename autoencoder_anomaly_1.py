
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

from keras.layers import Input, Dense
from keras.models import Model

np.set_printoptions(threshold=300)
print("test run count")
# print(random.randint(0,10000))

def Sequential_Input_LSTM(total_data_df, time_step_size, predict_next=True):
    yy = total_data_df['Label'].replace(to_replace="Benign", value="0").replace(to_replace="Malicious", value="1").astype('int64')
    XX = total_data_df.drop(['Label'], axis=1)

    df_x_np = XX.to_numpy()
    df_y_np = yy.to_numpy()

    X = []
    y = []

    for i in range(0, len(df_x_np) - time_step_size):
        if predict_next:
            row = [a for a in df_x_np[i:i + time_step_size]]
            next_row = [a for a in df_x_np[i + time_step_size: i + time_step_size + time_step_size]]

            if (np.isnan(row).any()) or (np.isnan(next_row).any()) or len(next_row) != timestep:
                continue

            # print("row", row)
            # print("next_row", next_row)
            X.append(np.array(row).reshape(20))
            y.append(np.array(next_row).reshape(20))
        else:
            row = [a for a in df_x_np[i:i + time_step_size]]
            if (np.isnan(row).all()):
                continue
            X.append(row)
            label = df_y_np[i + time_step_size]
            y.append(label)

    return np.array(X), np.array(y)


df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])
malicious_df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])

def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


from datetime import datetime
current_time = "_".join(str(datetime.strptime(str(datetime.now()), "%Y-%m-%d %H:%M:%S.%f")).split())
output_path = f"output/lstm_{current_time}"

print("Creating directory", output_path) 
os.makedirs(output_path)

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





# Function to create autoencoder model
def create_autoencoder(input_size, encoding_dim):
    input_layer = Input(shape=(input_size))
    encoded = Dense(encoding_dim, activation='relu')(input_layer)
    encoded_1 = Dense(encoding_dim, activation='relu')(encoded)
    encoded_2 = Dense(encoding_dim, activation='relu')(encoded_1)
    decoded = Dense(input_size, activation='relu')(encoded_2)
    autoencoder = Model(input_layer, decoded)
    
    autoencoder.compile(optimizer='adam', loss='mse')  # Use 'mse' for reconstruction loss
    return autoencoder


def model(data_df, timestep, input_size, encoding_dim):
    X, y = Sequential_Input_LSTM(data_df, timestep, predict_next=True)
    X[np.isnan(X)] = 0
    y[np.isnan(y)] = 0

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)

    # Create and train the autoencoder
    autoencoder = create_autoencoder(input_size, encoding_dim)
    
    print(dir(autoencoder))
    
    print(autoencoder.summary())
    autoencoder.fit(X_train, y_train, epochs=10, batch_size=64, verbose=2)
    

    # Use autoencoder for prediction
    y_pred = autoencoder.predict(X_test)
    
    print("X_test", X_test)
    
    print("y_test", y_test)

    print("y_pred", y_pred)
    
    print("y_pred 0 ", y_pred[0], y_pred[0][:4])
    
    print("y_pred 1 ", y_pred[0][:4])
    
    print("y_test 0 ", y_test[0])
    
    print("diff 0 ", y_test[0][:4] - y_pred[0][:4])
    
    benign_mse = []
    malicious_mse = []
    mal_X, mal_y = Sequential_Input_LSTM(malicious_df, timestep, predict_next=True)
    y_pred_mal = autoencoder.predict(mal_X, verbose=2)
    
    print("y_pred_mal", y_pred_mal)
    
    for i in range(len(y_pred)):
        mse = np.mean(np.square(y_test[i][:4] - y_pred[i][:4]))
        benign_mse.append(mse)
    # print("Mean Squared Error:", sorted(benign_mse)[0:20])
    
    benign_mse = sorted(benign_mse)
    percentage = 95
    index_cutoff = int(len(benign_mse) * (percentage / 100))
    benign_mse = benign_mse[:index_cutoff]
    
    
    for i in range(len(mal_y)):
        mse = np.mean(np.square(mal_y[i][:4] - y_pred_mal[i][:4]))
        malicious_mse.append(mse)
    
    malicious_mse = sorted(malicious_mse)
    # percentage = 95
    index_cutoff = int(len(malicious_mse) * (percentage / 100))
    malicious_mse = malicious_mse[:index_cutoff]
        
    xs, ys = zip(*sorted(zip(range(len(malicious_mse)), sorted(malicious_mse))))
    plt.plot(xs, ys)
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_malicious_encoder_label_sorted_{input_size}.png")
    plt.clf()
    
    xs, ys = zip(*sorted(zip(range(len(benign_mse)), sorted(benign_mse))))
    plt.plot(xs, ys)
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/encoder_benign_mse_label_sorted_{input_size}.png")
    plt.clf()
    
    xs, ys = zip(*sorted(zip(range(len(malicious_mse)), malicious_mse)))
    plt.plot(xs, ys, label='Malicious', color='orange')
    xs, ys = zip(*sorted(zip(range(len(malicious_mse), len(malicious_mse) + len(benign_mse)), sorted(benign_mse))))
    plt.plot(xs, ys, label='Benign', color='blue')
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_combined_{input_size}_nodes_{timestep}.png")
    plt.clf()

    # Calculate reconstruction loss
    mse = np.mean(np.square(X_test - y_pred))
    print("Mean Squared Error:", mse)

    benign_mse = np.array(benign_mse)
    malicious_mse = np.array(malicious_mse)
    
    # For anomaly detection, you can set a threshold for classifying high MSE as anomalies.
    threshold = 120000  # Adjust as needed
    benign_anomalies = np.where(benign_mse > threshold, 1, 0)
    malicious_anomalies = np.where(benign_mse > threshold, 1, 0)
    

    print("Benign Anomalies:", benign_anomalies)
    print("malicious_anomalies :", malicious_anomalies)
    print("len of malicious_anomalies :", len(malicious_anomalies))
    print("len of Benign anomolies :", len(benign_anomalies))
    print("Benign Anomalies count:", np.sum(0 == benign_anomalies))
    print("malicious_anomalies count :", np.sum(1 == malicious_anomalies))
    accuracy = (np.sum(0 == benign_anomalies) + np.sum(1 == malicious_anomalies)) / (len(malicious_anomalies) + len(benign_anomalies))
    print("Accuracy:", accuracy, y_test)
    return accuracy

# Anomaly detection for different encoding dimensions
all_accuracies_anomaly = []
for encoding_dim in [2048]:  # Adjust the encoding dimension as needed
    accuracies_anomaly = []
    for timestep in range(5, 6):
        accu = model(df, timestep, input_size=20, encoding_dim=encoding_dim)
        accuracies_anomaly.append(accu)
    all_accuracies_anomaly.append(accuracies_anomaly)
    plt.plot(range(1, 11), accuracies_anomaly, marker='o')
    plt.xlabel('Time Step')
    plt.ylabel('Accuracy')
    plt.savefig(f"{output_path}/anomaly_accuracy_10_epoch_dim_{encoding_dim}.png")
    plt.clf()