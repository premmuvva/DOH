import pandas as pd
from scapy.all import *

import os
import concurrent.futures
import traceback
import os
import numpy as np

from io import BytesIO

def process_pcap(pcap_file, df):
    
    print(f"processoing {pcap_file} ", os.path.isfile(pcap_file))
    
    packets = rdpcap(pcap_file)
    
    if(len(packets) == 0):
        return df
    first_packet = packets[0]
    
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
        packet_size = len(packet)
        temp = df.loc[len(df) - 1]
        
        if((temp['src'] != packet[IP].src) or (temp['dst'] != packet[IP].dst)): 
            current_dir = 0 if current_dir == 1 else 1
            df.loc[len(df)] = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
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
                'RawTimestamp': packet.time,
                'Direction': current_dir,
                'Number of Packets': temp['Number of Packets'] + 1,
                'Size': temp['Size'] + packet_size,
                'Duration': temp['Duration'] + (packet.time - temp['RawTimestamp']) * 1000
            }
    
    return df


columns = ['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']
cloud_flare_files = ["dump_00001_20200113152847", "dump_00002_20200113162614", "dump_00003_20200113182754", "dump_00004_20200113193921", "dump_00005_20200113205730"]

df_ar = []

def process_pcap_wrapper(args):
    try: 
        file_path, i, output_path = args
        output_file_name = output_path + str(i) + '.npy'
        if os.path.exists(output_file_name):
            print("File exists skipping", args)
            return
        df = pd.DataFrame(columns=columns)
        process_pcap(file_path, df)
        np.save(output_file_name, df.T)
        del df
    except Exception as e:
        print("An error", file_path)
        print(traceback.format_exc())


def get_process_params(dir_path, output_path):
    i = 0
    file_list = []
    for root, dirs, files in os.walk(dir_path):
        for filename in files:
            if filename.endswith(".pcap"):
                if any(filename.startswith(prefix) for prefix in cloud_flare_files):
                    file_path = os.path.join(root, filename)
                    file_size = os.path.getsize(file_path)
                    file_list.append((file_path, file_size, os.path.splitext(filename)[0]))
                    i+=1
                    if(i%100 == 0):
                        print(filename)
    
        # Sort the file list based on file size (ascending order)
    # sorted_file_list = sorted(file_list, key=lambda x: x[1])

    sorted_file_names = [(file[0], file[2], output_path) for file in file_list]

    return sorted_file_names
    

def run_executor(dir_path, output_path):
    file_list = get_process_params(dir_path, output_path)
    df_ar = [i for i in range(len(file_list))]
    print("Total number of file to process:", len(file_list))
    # print("file_list[1000]", file_list[20000])
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:    
        executor.map(process_pcap_wrapper, file_list[::-1])

def process(input_dir, output_path):
    globals()['df_ar'] = []
    run_executor(input_dir, output_path)
    print("final list of output dfs", len(df_ar))


# Don't forget / at the end

# process("/home/x286t435/thesis/time-series/dataset/Malicious", 'output/Malicious.csv')
# process("/home/x286t435/thesis/time-series/dohv2/output/pcap_split/benign/", 'output/npy/Benign.npy')
# process("output/pcap_split/maliciousv2/", 'output/npy/maliciousv2/')
process("output/pcap_split/benignV2/", 'output/npy/benignV2/cloudflare/')

