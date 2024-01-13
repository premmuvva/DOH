import os
import numpy as np
import gc
import pandas as pd



def merge_npy_files_in_directory(directory_path, output_path, progress_file):
    # Get a list of all .npy files in the specified directory
    npy_files = [f for f in os.listdir(directory_path) if f.endswith('.npy')]
    print()
    if not npy_files:
        print("No .npy files found in the specified directory.")
        return
    
    if os.path.exists(progress_file):
        with open(progress_file, 'r') as file:
            last_processed_file = file.readline().strip()
    else:
        last_processed_file = None
        
    # Skip files until the last processed file is encountered
    if last_processed_file is not None:
        print("total", len(npy_files))
        # print("6000th file name", npy_files[10000])
        npy_files = npy_files[npy_files.index(last_processed_file):]
        print("to be complete", len(npy_files))
        # return

    if not npy_files:
        print("No .npy files found in the specified directory.", flush=True)
        return
    
    print(f"{len(npy_files)} to be processed", flush=True)
    coloumns= ['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']
    
    # Load the merged data from the progress file or start with the first file
    if last_processed_file is None or not os.path.exists(output_path):
        merged_data = np.load(os.path.join(directory_path, npy_files[0]), allow_pickle=True)
        # print(merged_data.T)
        df = pd.DataFrame(merged_data.T, columns=coloumns)
        # print(df)

    else:
        df = pd.read_csv(output_path, index_col=[0, 1], low_memory=False)
        # df = store.select('df')


    i = 0
    total_memory_usage = 0
    
    nan_df = pd.DataFrame(np.nan, index=range(20), columns=coloumns)
    # print("nan_df", nan_df)
    # Iterate over the remaining .npy files and concatenate their data
    for npy_file in npy_files[1:]:
        data = np.load(os.path.join(directory_path, npy_file), allow_pickle=True)
        print(f"processing {npy_file}, current df size: {total_memory_usage}", flush=True)
        
        df2 = pd.DataFrame(data.T, columns=coloumns)
        # print("df2", df2)
            
        df = pd.concat([df,nan_df, df2], axis=0, ignore_index=True)
        
        # print(df)
        memory_usage = df.memory_usage(deep=True).sum()
        # memory_usage += 1
        if total_memory_usage > memory_usage:
            print(f"memory usage decreased: {npy_files.index(npy_file)}: {npy_file}, where previous file is {npy_files[npy_files.index(npy_file) - 1]}", flush=True)
            return
        total_memory_usage = memory_usage
        del df2
        gc.collect()
        
        if i%100 == 0:
            print(f"merging file : {npy_file} of length {len(df)}")
            df.to_csv(output_path, index=False)
            # print("saving...")
            with open(progress_file, 'w') as file:
                file.write(npy_file)
        i+=1
        
    df.to_csv(output_path, index=False)
    print(f"Merged data saved to {output_path}.")


merge_npy_files_in_directory('output/npy/benignV2/', 'output/merge_npy/benignV2_final_without_multi_index.csv', 'output/merge_npy/benign_final_without_multi_index_progress.log')
# merge_npy_files_in_directory('output/npy/maliciousv2/', 'output/temp/maliciousv2_final_without_multi_index.csv', 'output/temp/maliciousv2_final_without_multi_index_progress.log')


