import os
import numpy as np

import pandas as pd



def merge_npy_files_in_directory(directory_path, output_path):
    # Get a list of all .npy files in the specified directory
    npy_files = [f for f in os.listdir(directory_path) if f.endswith('.npy')]
    print()
    if not npy_files:
        print("No .npy files found in the specified directory.")
        return
    merged_data = np.load(os.path.join(directory_path, npy_files[0]), allow_pickle=True)
    
    index = pd.MultiIndex.from_product([npy_files[:1],['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']])
    
    df = pd.DataFrame(merged_data, index=index)

    i = 0
    # Iterate over the remaining .npy files and concatenate their data
    for npy_file in npy_files[:]:
        data = np.load(os.path.join(directory_path, npy_file), allow_pickle=True)
        
        index = pd.MultiIndex.from_product([[npy_file],['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']])
        df2 = pd.DataFrame(data, index=index)
        df = pd.concat([df, df2], axis=0)
        if i%100 == 0:
            print(f"merging file : {npy_file} of length {len(df)}")
            df.to_csv(output_path, index=True)
            print("saving...")
        i+=1
        
    df.to_csv(output_path, index=True)
    print(f"Merged data saved to {output_path}.")

# Example usage:
# directory_path = 'output/npy/benign/'
directory_path = 'output/npy/malicious/'
# output_path = 'output/begign.csv'
output_path = 'output/malicious.csv'

merge_npy_files_in_directory(directory_path, output_path)


