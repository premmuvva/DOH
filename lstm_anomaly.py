
# -*- coding: utf-8 -*-
import copy
import os
from keras.models import Sequential
from keras.layers import LSTM, Dense, Lambda, Flatten, Reshape
from keras.layers import Dropout, RepeatVector, TimeDistributed, Dense
import pandas as pd
from sklearn.metrics import roc_curve, auc
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
from common_utils import fetch_dataset
from keras import backend as K
import pickle

np.set_printoptions(threshold=30)
print("test run count")
# print(random.randint(0,10000))


# df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])
# malicious_df = pd.DataFrame(columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])


df, malicious_df = fetch_dataset() 


print(df)


def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


current_time = "_".join(str(datetime.strptime(str(datetime.now()), "%Y-%m-%d %H:%M:%S.%f")).split())
output_path = f"output/lstm_anomaly_{current_time}"

print("Creating directory", output_path) 
os.makedirs(output_path)

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
    
    print("X 0", X[0])
    print("y 0", y[0])
    
    size_limit = int(0.1 * len(X))
    X_train, X_test, y_train, y_test = train_test_split(X[:size_limit], y[:size_limit], test_size=0.20, random_state=42)
    
    np.save(f"{output_path}/X_train_{timestep}_timesteps.npy", X_train)
    np.save(f"{output_path}/X_test_{timestep}_timesteps.npy", X_test)
    np.save(f"{output_path}/y_train_{timestep}_timesteps.npy", y_train)
    np.save(f"{output_path}/y_test_{timestep}_timesteps.npy", y_test)
    
    # print("count unique values for y.")
    # print(np.unique(y_train, return_counts=True))
    # print(np.unique(y, return_counts=True))

    print(len(X_train))

    model = Sequential()
    model.add(LSTM(units=lstm_nodes, return_sequences=True, input_shape=(timestep, 4)))
    model.add(LSTM(units=lstm_nodes, return_sequences=False))
    model.add(Dense(units=16, activation='linear'))
    # model.add(Reshape((timestep, 4)))
    
    # model = Sequential()
    # model.add(Dense(units=number_of_lstm_nodes, activation='relu', input_shape=(4, timestep))) 
    # model.add(LSTM(units=lstm_nodes, return_sequences=False))
    model.add(Dropout(rate=0.2))
    model.add(Dense(units=4, activation='relu'))
    # model.add(Dropout(rate=0.2))
    # model.add(LSTM(units=number_of_lstm_nodes, return_sequences=True))
    # # model.add(Dropout(rate=0.2))
    # # model.add(LSTM(units=number_of_lstm_nodes, return_sequences=True, activation='relu'))
    # model.add(Dropout(rate=0.2))
    # model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    # model.add(Dropout(rate=0.2))
    # model.add(Dense(units=number_of_lstm_nodes, activation='relu'))
    # model.add(Dense(units=timestep, activation='linear'))
    
    # print(model.summary())
    
    model.compile(optimizer='adam', loss='mse')
    model.build(input_shape=(32, timestep, 4))
    
    print(model.summary())
    
    print("training lstm")
    training_history = model.fit(X, y, epochs=10, batch_size=64, verbose=2, validation_split=0.2)
    
    
    with open(f"{output_path}/training_history_pickle_{lstm_nodes}.pkl", 'wb') as file:
        pickle.dump(training_history.history, file)
    
    loss = training_history.history['loss']
    val_loss = training_history.history['val_loss']

    epochs = range(1, len(loss) + 1)

    # Plotting training and validation loss
    plt.plot(epochs, loss, 'bo', label='Training loss')
    plt.plot(epochs, val_loss, 'b', label='Validation loss')
    plt.title('Training and Validation Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Loss')
    plt.legend()
    plt.savefig(f"{output_path}/training_history_{lstm_nodes}.png")
    plt.clf()

    
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
    start = 0 #random.randint(0, len(X_test))
    end = len(y_test) #int(0.1*len(mal_y)) + start
    y_pred_mal = model.predict(mal_X[start:end], verbose=2)

    print("len y test", len(y_test))
    print("len mal y test", len(mal_y))


    y_pred_benign = model.predict(X_test, verbose=2)

    for i in range(len(y_pred_benign)):
        mse = np.mean(np.square(y_test[i] - y_pred_benign[i]))
        benign_mse.append(mse)
    print("Mean Squared Error:", sorted(benign_mse)[:20])

    for i in range(len(y_pred_mal)):
        mse = np.mean(np.square(mal_y[i] - y_pred_mal[i]))
        malicious_mse.append(mse)
            
    # Create labels for ROC curve
    y_true = np.concatenate([np.zeros(len(benign_mse)), np.ones(len(malicious_mse))])
    y_scores = np.concatenate([benign_mse, malicious_mse])

    print("y_true", y_true)
    print("y_scores", y_scores)

    # Calculate ROC curve
    fpr, tpr, thresholds = roc_curve(y_true, y_scores)

    print("thresholds", thresholds)
    print("fpr", fpr)
    print("tpr", tpr)
    # Check for NaN or infinite values in outputs
    print("NaN in fpr:", np.isnan(fpr).any())
    print("NaN in tpr:", np.isnan(tpr).any())

    roc_auc = auc(fpr, tpr)

    # Plot ROC curve
    plt.figure()
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'AUC = {roc_auc:.2f}')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend(loc='lower right')
    plt.savefig(f"{output_path}/roc_3_{number_of_lstm_nodes}_nodes_{timestep}_timestep.png")
    plt.clf()

    # Assuming you already have fpr, tpr, and thresholds from roc_curve
    J_values = tpr - fpr
    optimal_threshold_index = np.argmax(J_values)
    optimal_threshold = thresholds[optimal_threshold_index]

    print("Optimal Threshold:", optimal_threshold)

    threshold = optimal_threshold
    mal_anomalies = np.where(np.array(malicious_mse) > threshold, 1, 0)
    benign_anomalies = np.where(np.array(benign_mse) > threshold, 0, 1)
    accuracy = (np.sum(mal_anomalies) + np.sum(benign_anomalies)) / (len(mal_anomalies) + len(benign_anomalies))
    print("numerator", (np.sum(mal_anomalies) + np.sum(benign_anomalies)))
    print("denominator", (len(mal_anomalies) + len(benign_anomalies)))
    print("accuracy", accuracy)
    # benign_mse = sorted(benign_mse)
    # percentage = 90
    # index_cutoff = int(len(benign_mse) * (percentage / 100))
    # benign_mse = benign_mse[:index_cutoff]
    
    return accuracy
    
    xs, ys = zip(*sorted(zip(range(len(benign_mse)), benign_mse)))
    plt.plot(xs, ys)
    plt.xlabel('count')
    plt.ylabel('mse')
    plt.savefig(f"{output_path}/mse_benign_label_sorted_{lstm_nodes}.png")
    plt.clf()
    
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
    # threshold = 0.1  # Adjust as needed
    # anomalies = np.where(np.array(malicious_mse) > threshold, 1, 0)
    
    # print("y_pred_bool", anomalies)
    # print(np.unique(anomalies, return_counts=True))
    # print(np.unique(y, return_counts=True))

    # print(classification_report(y_test, anomalies))
    # print(confusion_matrix(y_test, anomalies))
    # accuracy = np.sum(y_test == anomalies) / len(y_test)
    # print(accuracy, y_test)
    return accuracy

# Anomaly detection for different LSTM nodes
all_accuracies_anomaly = []
for lstm_nodes in [256, 512, 1024, 2048]:
    accuracies_anomaly = []
    for timestep in range(1, 11):
        accu = model(df, timestep=timestep, number_of_lstm_nodes=lstm_nodes)
        accuracies_anomaly.append(accu)
    all_accuracies_anomaly.append(accuracies_anomaly)
    plt.plot(range(1, 1+len(accuracies_anomaly)), accuracies_anomaly, marker='o')
    plt.xlabel('Time Step')
    plt.ylabel('Accuracy')
    plt.savefig(f"{output_path}/anomaly_accuracy_10_epoch_nodes_{lstm_nodes}.png")
    plt.clf()