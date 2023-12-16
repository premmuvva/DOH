#!/bin/bash

#SBATCH --time=23:30:00
#SBATCH --mem=128G
#SBATCH --cpus-per-task=16
#SBATCH --output=output/logs/lstm.log
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --gres=gpu:1


echo "Reached before python lines of file: $1"
module load TensorFlow/2.7.1-foss-2021b-CUDA-11.4.1 
source venv/bin/activate
echo "Reached before python lines of file: $1"
venv/bin/python $1
echo "After python lines of file: $1"