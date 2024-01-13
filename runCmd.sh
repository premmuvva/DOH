#!/bin/bash

#SBATCH --time=23:59:00
#SBATCH --mem-per-cpu=32G
#SBATCH --cpus-per-task=5
#SBATCH --output=output/logs/lstm/lstm_anomaly_2.log
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --gres=gpu:1


echo "Reached before python lines of file: $1 start"
date
module load TensorFlow/2.7.1-foss-2021b-CUDA-11.4.1 
source venv/bin/activate
echo "Reached before python lines of file: $1"
venv/bin/python $1
# ./pcap_split.sh /home/x286t435/thesis/time-series/dataset/Malicious/ output/pcap_split/maliciousv2
# ./pcap_split.sh /home/x286t435/thesis/time-series/dataset/Benign output/pcap_split/benignV2
echo "After python lines of file: $1"
date
# find "/home/x286t435/thesis/time-series/dataset/Malicious/" -type f -print0 
# output/logs/merge_npy_malicous_2_10000.log   
# output/logs/pre_dataset_malicious.log