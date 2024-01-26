
# -*- coding: utf-8 -*-
import copy
import os
from keras.models import Sequential
from keras.layers import LSTM, Dense, Flatten, Reshape
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import random
from sklearn.metrics import confusion_matrix
import string
import matplotlib.pyplot as plt
from common_utils import Sequential_Input_LSTM1 as Sequential_Input_LSTM
from common_utils import save_dataset, fetch_dataset, save_model

from keras.layers import Input, Dense
from keras.models import Model

np.set_printoptions(threshold=300)
print("test run count")
# print(random.randint(0,10000))



df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])
malicious_df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])

def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


from datetime import datetime
current_time = "_".join(str(datetime.strptime(str(datetime.now()), "%Y-%m-%d %H:%M:%S.%f")).split())
output_path = f"output/autoencoder_anomaly_1_{current_time}"

print("Creating directory", output_path) 
os.makedirs(output_path)



df,  malicious_df = fetch_dataset() 


print(df)

from keras import backend as K

def custom_mse(y_true, y_pred):
    # Custom MSE implementation
    # print(y_true, y_pred)
    return K.mean(K.square(y_pred[:] - y_true[:]), axis=-1)


# Function to create autoencoder model
def create_autoencoder(input_size, timestep, encoding_dim):
    input_layer = Input(shape=(input_size, 4))
    lstm = LSTM(units=encoding_dim)(input_layer)
    # flattened = Flatten()(lstm)
    encoded = Dense(encoding_dim, activation='relu')(lstm)
    encoded_1 = Dense(1024, activation='relu')(encoded)
    encoded_2 = Dense(512, activation='relu')(encoded_1)
    encoded_2_1 = Dense(256, activation='relu')(encoded_2)
    encoded_2_2 = Dense(512, activation='relu')(encoded_2_1)
    encoded_3 = Dense(1024, activation='relu')(encoded_2_2)
    encoded_4 = Dense(encoding_dim, activation='relu')(encoded_3)
    decoded = Dense(input_size * 4, activation='linear')(encoded_4)
    # autoencoder = Model(input_layer, decoded)
    reshaped_output = Reshape((timestep, 4))(decoded)  # Reshape to (None, 5, 4)
    autoencoder = Model(input_layer, reshaped_output)
    
    autoencoder.compile(optimizer='adam', loss="mse")  # Use 'mse' for reconstruction loss
    return autoencoder


def model(data_df, timestep, input_size, encoding_dim):
    X, y = Sequential_Input_LSTM(data_df, timestep, predict_next=True)
    print(X.shape)
    X[np.isnan(X)] = 0
    y[np.isnan(y)] = 0
    
    # X = X.reshape(len(X), 20)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)
    print(X_train.shape)
    save_dataset(X_train, X_test, y_train, y_test, output_path, timestep)
    # Create and train the autoencoder
    autoencoder = create_autoencoder(input_size, timestep, encoding_dim)
    
    print(dir(autoencoder))
    
    print(autoencoder.summary())
    autoencoder.fit(X_train, y_train, epochs=10, batch_size=64, verbose=2)
    
    save_model(autoencoder, output_path, timestep)
    
    
    # Use autoencoder for prediction
    # y_pred = autoencoder.predict(X_test)
    
    # print("X_test", X_test)
    # print("y_test", y_test)
    # print("y_pred", y_pred)
    # print("y_pred 0 ", y_pred[0], y_pred[0][:4])
    # print("y_pred 1 ", y_pred[0][:4])
    # print("y_test 0 ", y_test[0])
    # print("diff 0 ", y_test[0][:4] - y_pred[0][:4])
    
    # benign_mse = []
    # malicious_mse = []
    # mal_X, mal_y = Sequential_Input_LSTM(malicious_df, timestep, predict_next=True)
    # y_pred_mal = autoencoder.predict(mal_X, verbose=2)
    
    # print("y_pred_mal", y_pred_mal)
    
    # for i in range(len(y_pred)):
    #     mse = np.mean(np.square(y_test[i][:4] - y_pred[i][:4]))
    #     benign_mse.append(mse)
    # # print("Mean Squared Error:", sorted(benign_mse)[0:20])
    
    # benign_mse = sorted(benign_mse)
    # percentage = 95
    # index_cutoff = int(len(benign_mse) * (percentage / 100))
    # benign_mse = benign_mse[:index_cutoff]
    
    
    # for i in range(len(y_pred)):
    #     mse = np.mean(np.square(mal_y[i][:4] - y_pred_mal[i][:4]))
    #     malicious_mse.append(mse)
    
    # malicious_mse = sorted(malicious_mse)
    # # percentage = 95
    # index_cutoff = int(len(malicious_mse) * (percentage / 100))
    # malicious_mse = malicious_mse[:index_cutoff]
        
    # xs, ys = zip(*sorted(zip(range(len(malicious_mse)), sorted(malicious_mse))))
    # plt.plot(xs, ys)
    # plt.xlabel('count')
    # plt.ylabel('mse')
    # plt.savefig(f"{output_path}/mse_malicious_encoder_label_sorted_{input_size}.png")
    # plt.clf()
    
    # xs, ys = zip(*sorted(zip(range(len(benign_mse)), sorted(benign_mse))))
    # plt.plot(xs, ys)
    # plt.xlabel('count')
    # plt.ylabel('mse')
    # plt.savefig(f"{output_path}/encoder_benign_mse_label_sorted_{input_size}.png")
    # plt.clf()
    
    # xs, ys = zip(*sorted(zip(range(len(malicious_mse)), malicious_mse)))
    # plt.plot(xs, ys, label='Malicious', color='orange')
    # xs, ys = zip(*sorted(zip(range(len(malicious_mse), len(malicious_mse) + len(benign_mse)), sorted(benign_mse))))
    # plt.plot(xs, ys, label='Benign', color='blue')
    # plt.xlabel('count')
    # plt.ylabel('mse')
    # plt.savefig(f"{output_path}/mse_combined_{input_size}_nodes_{timestep}.png")
    # plt.clf()

    # # Calculate reconstruction loss
    # mse = np.mean(np.square(X_test - y_pred))
    # print("Mean Squared Error:", mse)

    # benign_mse = np.array(benign_mse)
    # malicious_mse = np.array(malicious_mse)
    
    # # For anomaly detection, you can set a threshold for classifying high MSE as anomalies.
    # threshold = 120000  # Adjust as needed
    # benign_anomalies = np.where(benign_mse > threshold, 1, 0)
    # malicious_anomalies = np.where(benign_mse > threshold, 1, 0)
    

    # print("Benign Anomalies:", benign_anomalies)
    # print("malicious_anomalies :", malicious_anomalies)
    # print("len of malicious_anomalies :", len(malicious_anomalies))
    # print("len of Benign anomolies :", len(benign_anomalies))
    # print("Benign Anomalies count:", np.sum(0 == benign_anomalies))
    # print("malicious_anomalies count :", np.sum(1 == malicious_anomalies))
    # accuracy = (np.sum(0 == benign_anomalies) + np.sum(1 == malicious_anomalies)) / (len(malicious_anomalies) + len(benign_anomalies))
    # print("Accuracy:", accuracy, y_test)
    # return accuracy

# Anomaly detection for different encoding dimensions
all_accuracies_anomaly = []
for encoding_dim in [2048]:  # Adjust the encoding dimension as needed
    accuracies_anomaly = []
    for timestep in range(5, 6):
        accu = model(df, timestep, input_size=timestep, encoding_dim=encoding_dim)
    #     accuracies_anomaly.append(accu)
    # all_accuracies_anomaly.append(accuracies_anomaly)
    # plt.plot(range(1, 11), accuracies_anomaly, marker='o')
    # plt.xlabel('Time Step')
    # plt.ylabel('Accuracy')
    # plt.savefig(f"{output_path}/anomaly_accuracy_10_epoch_dim_{encoding_dim}.png")
    # plt.clf()