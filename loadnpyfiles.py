import numpy as np
import pandas as pd

def load_npy(file_path):

    # Load the data from the .npy file
    loaded_data = np.load(file_path, allow_pickle=True)  # Set allow_pickle=True if the data contains objects

    columns = ['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']

    # Create a DataFrame from the loaded data
    df = pd.DataFrame(loaded_data, columns=columns)
    return df

# Now you have a DataFrame (df) with the data from the .npy file
print(load_npy('output/3/df6.npy'))