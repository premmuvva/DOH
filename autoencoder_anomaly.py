# Import tensorflow modules
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Lambda, Dense, LeakyReLU, BatchNormalization, Input
from tensorflow.keras import Sequential, callbacks, losses
from tensorflow.nn import softmax
import copy
import string
import pandas as pd
import os
import random
import numpy as np
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split


# Ignore errors about CUDA driver. We do not have GPUs :(

class Autoencoder(Model):
    def __init__(self, layer_output_sizes):
          super(Autoencoder, self).__init__()

          #self.layer_output_sizes = layer_output_sizes
          #workaround to above commented line that does not work for some reason
          #self.__dict__['layer_output_sizes'] = layer_output_sizes
          layer_output_sizes = copy.deepcopy(layer_output_sizes)

          # The Encoder
          self.encoder = None
          for level in layer_output_sizes[:-1]:
              if self.encoder is None:
                  self.encoder = Sequential(name='Encoder')
                  #self.encoder.add(InputLayer(input_shape=(int(level),)))
                  self.encoder.add(Dense(int(level), name='input_layer_encoder'))
              else:
                  self.encoder.add(Dense(int(level)))
                  self.encoder.add(BatchNormalization())
                  self.encoder.add(LeakyReLU())

          # The Embedding layer of the Encoder
          self.encoder.add(Dense(layer_output_sizes[-1]))

          # Reverse layer descriptions
          layer_output_sizes.reverse()

          # The Decoder
          self.decoder = None
          for level in layer_output_sizes[1:]:
              if self.decoder is None:
                  self.decoder = Sequential(name='Decoder')
                  #self.encoder.add(InputLayer(input_shape=(int(level),)))
                  self.decoder.add(Dense(int(level), name='input_layer_decoder'))
              else:
                  self.decoder.add(Dense(int(level)))
                  self.decoder.add(BatchNormalization())
                  self.decoder.add(LeakyReLU())

    def call(self, x):
      encoded = self.encoder(x)
      decoded = self.decoder(encoded)
      return decoded

    def model(self): #for visualization purposes only
        x = Input(shape=(16))
        return Model(inputs=[x], outputs=self.call(x))
    

np.set_printoptions(threshold=30)
print("test run count")
# print(random.randint(0,10000))

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

            if (np.isnan(row).any()) or (np.isnan(next_row).any()):
                continue

            X.append(np.array(row).reshape(20))
            y.append(next_row)
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


output_path = f"output/lstm_{generate_random_string(4)}"

print("Creating directory", output_path) 
os.makedirs(output_path)

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
    decoded = Dense(input_size, activation='relu')(encoded)
    autoencoder = Model(input_layer, decoded)
    
    autoencoder.compile(optimizer='adam', loss='mse')  # Use 'mse' for reconstruction loss
    return autoencoder


def model(data_df, input_size, encoding_dim):
    X, y = Sequential_Input_LSTM(data_df, timestep, predict_next=True)
    X[np.isnan(X)] = 0
    y[np.isnan(y)] = 0

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)

    # Create and train the autoencoder
    #  = create_autoencoder(input_size, encoding_dim)
    model_architecture = [20,14,4] # the 16 corresponds to the number of features in our dataset. 
    autoencoder = Autoencoder(model_architecture)
    autoencoder.build(input_shape=(None, input_size))
    autoencoder.compile(optimizer='adam', loss='mse')
    
    print(autoencoder.summary())

    autoencoder.fit(X_train, y_train, epochs=1, batch_size=64, verbose=2)

    # Use autoencoder for prediction
    X_pred = autoencoder.predict(X_test)
    
    print("X_pred", X_pred)

    # Calculate reconstruction loss
    mse = np.mean(np.square(X_test - X_pred))
    print("Mean Squared Error:", mse)

    # For anomaly detection, you can set a threshold for classifying high MSE as anomalies.
    threshold = 0.1  # Adjust as needed
    anomalies = np.where(mse > threshold, 1, 0)

    print("Anomalies:", anomalies)
    accuracy = np.sum(y_test == anomalies) / len(y_test)
    print("Accuracy:", accuracy, y_test)
    return accuracy


all_accuracies_anomaly = []
for encoding_dim in [256]:  # Adjust the encoding dimension as needed
    accuracies_anomaly = []
    for timestep in range(5, 6):
        accu = model(df, input_size=20, encoding_dim=encoding_dim)
        accuracies_anomaly.append(accu)
    all_accuracies_anomaly.append(accuracies_anomaly)
    plt.plot(range(1, 11), accuracies_anomaly, marker='o')
    plt.xlabel('Time Step')
    plt.ylabel('Accuracy')
    plt.savefig(f"{output_path}/anomaly_accuracy_10_epoch_dim_{encoding_dim}.png")
    plt.clf()

# ae.compile(optimizer='adam', loss='mse')

# ae.fit()