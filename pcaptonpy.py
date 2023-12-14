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
    print(packets)
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
        output_file_name = 'output/npy/benign/'+str(i)+'.npy'
        if os.path.exists(output_file_name):
            print("File exists skipping")
        df = pd.DataFrame(columns=columns)
        process_pcap(file_path, df)
        # print(df)
        # print("transpose", df.T)
        # df_ar.append(i)
        np.save(output_file_name, df.T)
        del df
    except Exception as e:
        print("An error", file_path)
        print(traceback.format_exc())


def get_process_params(dir_path):
    i = 0
    file_list = []
    for root, dirs, files in os.walk(dir_path):
        for filename in files:
            if filename.endswith(".pcap"):
                file_path = os.path.join(root, filename)
                file_size = os.path.getsize(file_path)
                file_list.append((file_path, file_size, i))
                i+=1
    
        # Sort the file list based on file size (ascending order)
    # sorted_file_list = sorted(file_list, key=lambda x: x[1])

    # Extract only the file names from the sorted list
    sorted_file_names = [(file[0], file[2]) for file in file_list]
    # print(sorted_file_names)
    return sorted_file_names

    # return file_list

def run_executor(dir_path):
    file_list = get_process_params(dir_path)
    df_ar = [i for i in range(len(file_list))]
    print("Total number of file to process:", len(file_list))
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:    
        executor.map(process_pcap_wrapper, file_list[:])
    # for i in file_list:
    #     process_pcap_wrapper(i)

def process(input_dir, output_csv):
    globals()['df_ar'] = []
    run_executor(input_dir)
    print("final list of output dfs", len(df_ar))


# process("/home/x286t435/thesis/time-series/dataset/Malicious", 'output/Malicious.csv')
process("/home/x286t435/thesis/time-series/dohv2/output/pcap_split/benign/", 'output/npy/Benign.npy')

