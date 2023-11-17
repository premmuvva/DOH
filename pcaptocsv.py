from get_csv_from_pcap import extract_network_features

# print(extract_network_features("/Users/reddy/Documents/classes/thesis/MaliciousDoH-dns2tcp-Pcap-001_600/dns2tcp_tunnel_1111_doh8_2020-04-01T23:05:38.598516.pcap"))

import pandas as pd
from scapy.all import *

import os

def process_pcap(pcap_file, df):
    
    print("Processing pcap:", pcap_file)
    
    packets = rdpcap(pcap_file)
    first_packet = packets[0]
    
    timestamp = datetime.fromtimestamp(int(first_packet.time))
    df.loc[len(df)] = {
                'src': first_packet[IP].src,
                'dst': first_packet[IP].dst,
                'Timestamp': timestamp,
                'RawTimestamp': first_packet.time,
                'Direction': 1,
                'Number of Packets': 0,
                'Size': 0,
                'Duration': 0
            }
    
    current_dir = 1

    for packet in packets:
            
        timestamp = datetime.fromtimestamp(int(packet.time))
        packet_size = len(packet)
        
        
        temp = df.loc[len(df) - 1]
        
        if((temp['src'] != packet[IP].src) or (temp['dst'] != packet[IP].dst)): 
            current_dir = 0 if current_dir == 1 else 1
            df.loc[len(df)] = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'Timestamp': timestamp,
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
                'Timestamp': timestamp,
                'RawTimestamp': packet.time,
                'Direction': current_dir,
                'Number of Packets': temp['Number of Packets'] + 1,
                'Size': temp['Size'] + packet_size,
                'Duration': temp['Duration'] + (packet.time - temp['RawTimestamp']) * 1000
            }
    return df


columns = ['src', 'dst', 'Number of Packets', 'Timestamp', 'Direction', 'Size', 'Duration', 'RawTimestamp']
df = pd.DataFrame(columns=columns)


print(df)


import os
import concurrent.futures

def process_pcap_wrapper(args):
    file_path, df = args
    process_pcap(file_path, df)
    return df

directory_path = "/Users/reddy/Documents/classes/thesis/MaliciousDoH-dns2tcp-Pcap-001_600/"



for filename in os.listdir(directory_path):
    if os.path.isfile(os.path.join(directory_path, filename)): 
        file_list.append(os.path.join(directory_path, filename), pd.DataFrame(columns=columns))

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(process_pcap_wrapper, file_list[:4])

df.to_csv('malicious.csv', index=False)


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
