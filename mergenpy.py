import os
import numpy as np
import gc
import pandas as pd



def merge_npy_files_in_directory(directory_path, output_path, h5_file, progress_file):
    # Get a list of all .npy files in the specified directory
    npy_files = [f for f in os.listdir(directory_path) if f.endswith('.npy')]
    print()
    if not npy_files:
        print("No .npy files found in the specified directory.")
        return
    # merged_data = np.load(os.path.join(directory_path, npy_files[0]), allow_pickle=True)
    
    # index = pd.MultiIndex.from_product([npy_files[:1],['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']])
    
    # df = pd.DataFrame(merged_data, index=index)
    
    if os.path.exists(progress_file):
        with open(progress_file, 'r') as file:
            last_processed_file = file.readline().strip()
    else:
        last_processed_file = None
        
    # Skip files until the last processed file is encountered
    if last_processed_file is not None:
        npy_files = npy_files[npy_files.index(last_processed_file):]

    if not npy_files:
        print("No .npy files found in the specified directory.", flush=True)
        return
    
    print(f"{len(npy_files)} to be processed", flush=True)
    
    # store=pd.HDFStore(h5_file)
    
    # Load the merged data from the progress file or start with the first file
    if last_processed_file is None:
        merged_data = np.load(os.path.join(directory_path, npy_files[0]), allow_pickle=True)
        index = pd.MultiIndex.from_product([npy_files[:1],['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']])
        df = pd.DataFrame(merged_data, index=index)
    else:
        df = pd.read_csv(output_path, index_col=[0, 1])
        # df = store.select('df')


    i = 0
    total_memory_usage = 0
    # Iterate over the remaining .npy files and concatenate their data
    for npy_file in npy_files[1:]:
        data = np.load(os.path.join(directory_path, npy_file), allow_pickle=True)
        print(f"processing {npy_file}, current df size: {total_memory_usage}", flush=True)
        
        index = pd.MultiIndex.from_product([[npy_file],['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']])
        df2 = pd.DataFrame(data, index=index)
        # print(df2)
        # df2.to_csv(output_path, mode='a', index=True)
        # flat_data = df2.flatten()
        # print("flat_data", flat_data)
        # import time
        # time.sleep(10)
        # store.append('df', df2, data_columns=['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp'])
            
        df = pd.concat([df, df2], axis=0)
        memory_usage = df.memory_usage(deep=True).sum()
        # memory_usage += 1
        if total_memory_usage > memory_usage:
            print(f"memory usage decreased: {npy_files.index(npy_file)}: {npy_file}, where previous file is {npy_files[npy_files.index(npy_file) - 1]}")
            return
        total_memory_usage = memory_usage
        # print("memory_usage", memory_usage)
        # print("total_memory_usage", total_memory_usage)
        del df2
        gc.collect()
        
        if i%100 == 0:
            print(f"merging file : {npy_file} of length {len(df)}")
            df.to_csv(output_path, index=True)
            # print("saving...")
            with open(progress_file, 'w') as file:
                file.write(npy_file)
        i+=1
        
    # store.close()
    df.to_csv(output_path, index=True)
    print(f"Merged data saved to {output_path}.")


# merge_npy_files_in_directory('output/npy/benignV2/', 'output/merge_npy/benignV2.csv', 'output/merge_npy/benign_progress.log')
merge_npy_files_in_directory('output/npy/maliciousv2/', 'output/merge_npy/maliciousv2_3.csv', 'output/merge_npy/maliciousv2_3.h5', 'output/merge_npy/maliciousv2_progress_3.log')


