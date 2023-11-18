import pandas as pd
from scapy.all import *

import os
import concurrent.futures
import traceback
import os
import numpy as np

def process_pcap(pcap_file, df):
    
    print("Processing pcap:", pcap_file)
    
    packets = rdpcap(pcap_file)
    if(len(packets) == 0):
        return df
    first_packet = packets[0]
    
    # timestamp = datetime.fromtimestamp(int(first_packet.time))
    df.loc[len(df)] = {
                'src': first_packet[IP].src,
                'dst': first_packet[IP].dst,
                # 'Timestamp': timestamp,
                'RawTimestamp': first_packet.time,
                'Direction': 1,
                'Number of Packets': 0,
                'Size': 0,
                'Duration': 0
            }
    
    current_dir = 1

    for packet in packets:
            
        # timestamp = datetime.fromtimestamp(int(packet.time))
        packet_size = len(packet)
        
        
        temp = df.loc[len(df) - 1]
        
        if((temp['src'] != packet[IP].src) or (temp['dst'] != packet[IP].dst)): 
            current_dir = 0 if current_dir == 1 else 1
            df.loc[len(df)] = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                # 'Timestamp': timestamp,
                'RawTimestamp': packet.time,
                'Direction': current_dir,
                'Number of Packets': 1,
                'Size': packet_size,
                'Duration': 0
            }
            
        else:
            df.loc[len(df) - 1] = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                # 'Timestamp': timestamp,
                'RawTimestamp': packet.time,
                'Direction': current_dir,
                'Number of Packets': temp['Number of Packets'] + 1,
                'Size': temp['Size'] + packet_size,
                'Duration': temp['Duration'] + (packet.time - temp['RawTimestamp']) * 1000
            }
    return df


columns = ['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']

df_ar = []

def process_pcap_wrapper(args):
    try: 
        file_path, i = args
        df = pd.DataFrame(columns=columns)
        process_pcap(file_path, df)
        df_ar.append(i)
        np.save('output/2/df'+str(i)+'.npy', df)
    except Exception as e:
        print("An error", file_path)
        print(traceback.format_exc())

def get_process_params(dir_path):
    i = 0
    file_list = []
    for root, dirs, files in os.walk(dir_path):
        for filename in files:
            if filename.endswith(".pcap"):
        # if os.path.isfile(os.path.join(dir_path, filename)): 
                file_list.append((os.path.join(root, filename), i))
                i+=1
    return file_list

def run_executor(dir_path):
    file_list = get_process_params(dir_path)
    df_ar = [i for i in range(len(file_list))]
    print("Total number of file to process:", len(file_list))
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:    
        executor.map(process_pcap_wrapper, file_list)

def process(input_dir, output_csv):
    globals()['df_ar'] = []
    run_executor(input_dir)
    print("final list of output dfs", len(df_ar))
    # final_df = pd.DataFrame(columns=columns)
    # for ddf in df_ar:
    #     final_df = pd.concat(df_ar, ignore_index=True)
    # final_df.to_csv(output_csv, index=False)



# process("/home/x286t435/thesis/time-series/dataset/Malicious", 'output/Malicious.csv')
process("/home/x286t435/thesis/time-series/dataset/Benign", 'output/Benign.csv')

# for root, dirs, files in os.walk("/Users/reddy/Documents/classes/thesis/"):
#     print("root", root)
#     print("dirs", dirs)
#     print("files", files)
    

# directory_path = "/Users/reddy/Documents/classes/thesis/MaliciousDoH-dns2tcp-Pcap-001_600/"

# for filename in os.listdir(directory_path):
#     file_path = os.path.join(directory_path, filename)
#     if os.path.isfile(file_path):
#         process_pcap(file_path, df)
        
# df.to_csv('malicious.csv', index=False)

# begnign_directory_path = "/Users/reddy/Documents/classes/thesis/AdGuard/"

# begnign_df = pd.DataFrame(columns=columns)
# for filename in os.listdir(begnign_directory_path)[:1]:
#     file_path = os.path.join(begnign_directory_path, filename)
#     if os.path.isfile(file_path):
#         process_pcap(file_path, begnign_df)
        
# begnign_df.to_csv('beign.csv', index=False)
