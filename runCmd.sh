#!/bin/bash

#SBATCH --time=23:59:00
#SBATCH --mem=180G
#SBATCH --cpus-per-task=36
#SBATCH --output=output/logs/pcap_split_benign.log
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --gres=gpu:0


echo "Reached before python lines of file: $1"
module load TensorFlow/2.7.1-foss-2021b-CUDA-11.4.1 
source venv/bin/activate
echo "Reached before python lines of file: $1"
# venv/bin/python $1
# ./pcap_split.sh /home/x286t435/thesis/time-series/dataset/Malicious/
# ./pcap_split.sh /home/x286t435/thesis/time-series/dataset/Benign
echo "After python lines of file: $1"

# find "/home/x286t435/thesis/time-series/dataset/Malicious/" -type f -print0