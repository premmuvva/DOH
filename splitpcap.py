import os
import subprocess
import random

def process_pcap_files(input_folder, output_folder, max_file_size=50):
    # Ensure the output folder exists
    os.makedirs(output_folder, exist_ok=True)

    # Loop through all pcap files in the input folder
    for root, dirs, files in os.walk(input_folder):
        for file_name in files:
            if file_name.endswith(".pcap"):
                # Extract file name without extension
                file_base_name = os.path.splitext(file_name)[0]

                input_file_path = os.path.join(root, file_name)
                output_file_path = os.path.join(output_folder, f"{file_base_name}_{random.randint(0,100000)}_")

                # Run the tcpdump command
                command = f"tcpdump -r {input_file_path} -w {output_file_path} -C {max_file_size}"
                subprocess.run(command, shell=True)
                
                
input_folder = "/home/x286t435/thesis/time-series/dataset/Benign/"
output_folder = "/home/x286t435/thesis/time-series/dataset/Benign1234/"
process_pcap_files(input_folder, output_folder)
