import numpy as np
import random
import pandas as pd

from sklearn.preprocessing import MinMaxScaler, StandardScaler


def Sequential_Input_LSTM_transpose(total_data_df, time_step_size, predict_next=False):
    min_max_scaler = MinMaxScaler()
    columns_to_normalize = ['Number of Packets', 'Direction', 'Size', 'Duration']

    total_data_df[columns_to_normalize] = min_max_scaler.fit_transform(total_data_df[columns_to_normalize])

    yy = total_data_df['Label'].replace(to_replace="Benign", value="0").replace(to_replace="Malicious", value="1").astype('int64')
    XX = total_data_df.drop(['Label'], axis=1)

    df_x_np = XX.to_numpy()
    df_y_np = yy.to_numpy()

    X = []
    y = []

    for i in range(0, len(df_x_np) - time_step_size):
        if predict_next:
            row = [a for a in df_x_np[i:i + time_step_size]]
            # next_row = [a for a in df_x_np[i + time_step_size: i + 2 * time_step_size]]
            next_row = [a for a in df_x_np[i + time_step_size]]

            if (np.isnan(row).any()) or (np.isnan(next_row).any()) :#or len(next_row) != time_step_size:
                continue

            X.append(np.array(row))
            y.append(np.array(next_row))
        else:
            row = [a for a in df_x_np[i:i + time_step_size]]
            if (np.isnan(row).all()):
                continue
            X.append(row)
            label = df_y_np[i + time_step_size]
            y.append(label)

    return np.array(X), np.array(y)

def Sequential_Input_LSTM1(total_data_df, time_step_size, predict_next=True):
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

            if (np.isnan(row).any()) or (np.isnan(next_row).any()) or len(next_row) != time_step_size:
                continue

            # print("row", row)
            # print("next_row", next_row)
            # X.append(np.array(row).reshape(20))
            # y.append(np.array(next_row).reshape(20))
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

def Sequential_Input_LSTM1_with_reshape(total_data_df, time_step_size, predict_next=True):
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

            if (np.isnan(row).any()) or (np.isnan(next_row).any()) or len(next_row) != time_step_size:
                continue

            # print("row", row)
            # print("next_row", next_row)
            X.append(np.array(row).reshape(20))
            y.append(np.array(next_row).reshape(20))
            # X.append(row)
            # y.append(next_row)
        else:
            row = [a for a in df_x_np[i:i + time_step_size]]
            if (np.isnan(row).all()):
                continue
            X.append(row)
            label = df_y_np[i + time_step_size]
            y.append(label)

    return np.array(X), np.array(y)

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
            next_row = [a for a in df_x_np[i + 1]]

            if (np.isnan(row).any()) or (np.isnan(next_row).any()):
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

def save_dataset(X_train, X_test, y_train, y_test, output_path, timestep):
    np.save(f"{output_path}/X_train_{timestep}_timesteps.npy", X_train)
    np.save(f"{output_path}/X_test_{timestep}_timesteps.npy", X_test)
    np.save(f"{output_path}/y_train_{timestep}_timesteps.npy", y_train)
    np.save(f"{output_path}/y_test_{timestep}_timesteps.npy", y_test)
    
def fetch_dataset():
    # global df, malicious_df
    print("benign dataset: output/merge_npy/benignV2_merge_withoutmultiindex_final.csv")
    benign_df = pd.read_csv("output/merge_npy/benignV2_merge_withoutmultiindex_final.csv", header=[0], low_memory=False)
    # benign_df = pd.read_csv("output/merge_npy/benignV2_cloudflare.csv", header=[0], low_memory=False)
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
    return df, malicious_df

def save_model(model, output_path, timestep, number_of_lstm_nodes=1024):
    model_name = f"model_time_step_{timestep}_nodes_{number_of_lstm_nodes}.h5"
    print("saving model as ", model_name)
    model.save(f'{output_path}/{model_name}')