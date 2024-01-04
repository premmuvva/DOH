import os
import sys

directory_path = sys.argv[1]

for file_path in os.listdir(directory_path):
    full_path = os.path.join(directory_path, file_path)
    
    print(full_path)

    if os.path.isfile(full_path) and file_path.endswith('.pcap'):
        tshark_command = f"~/tshark/usr/local/bin/tshark -r {full_path} -T fields -e tcp.stream | sort -n | uniq"
        stream_output = os.popen(tshark_command).read()
        
        print(stream_output)
        
        for stream in stream_output.split('\n'):
            # Your code for processing each stream goes here
            tshark_command = f"~/tshark/usr/local/bin/tshark -r {full_path} -Y 'tcp.stream=={stream} && tls.app_data' -V"
            stream_output = os.popen(tshark_command).read()
            print("tshark_command", stream_output)
