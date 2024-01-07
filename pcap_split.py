import os
import sys
import pandas as pd
import concurrent.futures
import subprocess
import time

directory_path = sys.argv[1]

from pcaptonpy import process_pcap

columns = ['src', 'dst', 'Number of Packets', 'Direction', 'Size', 'Duration', 'RawTimestamp']
df = pd.DataFrame(columns=columns)

def process_pcap_wrapper(args):
    print(args)
    full_path, stream, df = args
    
    outputfile = os.path.splitext(os.path.basename(full_path))[0]
    
    print("exists?? ", os.path.isfile(full_path))
    
    output_file_path = f"{os.getcwd()}/output/pcap_split/malicious1/{outputfile}-{stream}.pcap"
    tshark_command = [
                        "~/tshark/usr/local/bin/tshark",
                        "-r", full_path,
                        "-w", output_file_path,
                        "-Y", f"\"tcp.stream=={stream} && tls.app_data\""
                    ]
                    # os.popen(tshark_command).close()
                    # Run the command using subprocess and wait for completion
    process = subprocess.run(tshark_command, shell=True)
    return_code = process.returncode
    print("tshark done", return_code)
    
    cwd = os.getcwd()
    print("before cwd", cwd)

    
    new_df = process_pcap(output_file_path, df)
    print(new_df)

for root, dirs, files in os.walk(directory_path):
        for filename in files:
            if filename.endswith(".pcap"):
                full_path = os.path.join(root, filename)
    
                # print(full_path)
                tshark_command = f"~/tshark/usr/local/bin/tshark -r {full_path} -T fields -e tcp.stream | sort -n | uniq"
                stream_output = os.popen(tshark_command).read()
                
                # print(stream_output)
                # print(stream_output)
                wrapper_input = [(full_path, i, df) for i in stream_output.split('\n')]
                # with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:    
                #     executor.map(process_pcap_wrapper, wrapper_input)
                
                for i in wrapper_input:
                    process_pcap_wrapper(i)
                
                time.sleep(100)
        
                # for stream in stream_output.split('\n')[:1]:
                #     # Your code for processing each stream goes here
                #     new_func(df, full_path, stream)
