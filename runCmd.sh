#!/bin/bash

#SBATCH --time=23:30:00
#SBATCH --mem=16G
#SBATCH --cpus-per-task=8
#SBATCH --output=lstmoutput1.log
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --gres=gpu:0


echo "Reached before python lines of file: $1"
module load TensorFlow/2.7.1-foss-2021b-CUDA-11.4.1 
source venv/bin/activate
echo "Reached before python lines of file: $1"
venv/bin/python $1
echo "After python lines of file: $1"