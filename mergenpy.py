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
            processed_files = file.read().splitlines()
    else:
        processed_files = []
        
    # # Skip files until the last processed file is encountered
    # if last_processed_file is not None:
    #     print("total", len(npy_files))
    #     # print("6000th file name", npy_files[10000])
    #     npy_files = npy_files[npy_files.index(last_processed_file):]
    #     print("to be complete", len(npy_files))
    #     # return
    
    if processed_files:
        npy_files = [file for file in npy_files if file not in processed_files]
    

    if not npy_files:
        print("No .npy files found in the specified directory.", flush=True)
        return
    
    print(f"{len(npy_files)} to be processed", flush=True)
    
    
    # Load the merged data from the progress file or start with the first file
    if not os.path.exists(output_path):
        merged_data = np.load(os.path.join(directory_path, npy_files[0]), allow_pickle=True)
        index = pd.MultiIndex.from_product([npy_files[:1],['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']])
        df = pd.DataFrame(merged_data, index=index)
    else:
        df = pd.read_csv(output_path, index_col=[0, 1], low_memory=False)
        # df = store.select('df')


    i = 0
    total_memory_usage = 0
    # Iterate over the remaining .npy files and concatenate their data
    for npy_file in npy_files[1:]:
        data = np.load(os.path.join(directory_path, npy_file), allow_pickle=True)
        print(f"processing {npy_file}, current df size: {total_memory_usage}", flush=True)
        
        index = pd.MultiIndex.from_product([[npy_file],['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']])
        df2 = pd.DataFrame(data, index=index)
            
        df = pd.concat([df, df2], axis=0)
        # memory_usage = df.memory_usage(deep=True).sum()
        # if total_memory_usage > memory_usage:
        #     print(f"memory usage decreased: {npy_files.index(npy_file)}: {npy_file}, where previous file is {npy_files[npy_files.index(npy_file) - 1]}")
        #     return
        # total_memory_usage = memory_usage
        del df2
        gc.collect()
        
        processed_files.append(npy_file)
        if i%100 == 0:
            # intermediate save to avoid loss of processed data.
            print(f"merging file : {npy_file} of length {len(df)}")
            df.to_csv(output_path, index=True)
            with open(progress_file, 'w') as file:
                file.write('\n'.join(processed_files))
        i+=1
        
    df.to_csv(output_path, index=True)
    print(f"Merged data saved to {output_path}.")


merge_npy_files_in_directory('output/npy/benignV2/cloudflare', 'output/merge_npy/benignV2_cloudflare.csv', 'output/merge_npy/benign_progress_cloudflare.log')
# merge_npy_files_in_directory('output/npy/maliciousv2/', 'output/merge_npy/maliciousv2_2_10000.csv', 'output/merge_npy/maliciousv2_progress_2_10000.log')


