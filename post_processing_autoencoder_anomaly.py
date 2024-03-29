import numpy as np
from common_utils import Sequential_Input_LSTM1
import tensorflow.keras as keras
import pandas as pd
from sklearn.metrics import roc_curve, auc
import matplotlib.pyplot as plt

from keras import backend as K

def custom_mse(y_true, y_pred):
    return K.mean(K.square(y_pred[:4] - y_true[:4]), axis=-1)

# output_path = "output/anomaly_lstm_2024-01-25_02:47:38.635190"
output_path = "output/autoencoder_anomaly_1_2024-01-25_18:38:18.304764"
number_of_lstm_nodes = 1024
timestep = 5
random_string = ""

print(f"wokrin with {output_path}, {number_of_lstm_nodes}, {timestep}, {random_string}")

X_test = np.load(f"{output_path}/X_test_{timestep}_timesteps.npy")
y_test = np.load(f"{output_path}/X_test_{timestep}_timesteps.npy")

model_name = f"{output_path}/model_time_step_{timestep}_nodes_{number_of_lstm_nodes}{random_string}.h5"

model = keras.models.load_model(model_name, custom_objects={'custom_mse': custom_mse})
malicious_df = pd.read_csv("output/temp/maliciousv2_final_without_multi_index.csv", header=[0], low_memory=False)
malicious_df['Label'] = 1
malicious_df = malicious_df.drop(['RawTimestamp', 'src', 'dst'], axis=1)

benign_mse = []
malicious_mse = []
mal_X, mal_y = Sequential_Input_LSTM1(malicious_df, timestep, predict_next=True)
y_pred_mal = model.predict(mal_X[:len(y_test)], verbose=2)

y_pred_benign = model.predict(X_test, verbose=2)

for i in range(len(y_pred_benign)):
    mse = np.mean(np.square(y_test[i] - y_pred_benign[i][0]))
    benign_mse.append(mse)
print("Mean Squared Error:", sorted(benign_mse)[:20])

for i in range(len(y_pred_mal)):
    mse = np.mean(np.square(mal_y[i][:4] - y_pred_mal[i][:4]))
    malicious_mse.append(mse)
        
# Create labels for ROC curve
y_true = np.concatenate([np.zeros(len(benign_mse)), np.ones(len(malicious_mse))])
y_scores = np.concatenate([benign_mse, malicious_mse])

print("y_true", y_true)
print("y_scores", y_scores)

# Check for NaN or infinite values in inputs
print("NaN in y_true:", np.isnan(y_true).any())
print("NaN in y_scores:", np.isnan(y_scores).any())

# Calculate ROC curve
fpr, tpr, _ = roc_curve(y_true, y_scores)

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
plt.savefig(f"{output_path}/roc_{number_of_lstm_nodes}_nodes_{timestep}_timestep.png")