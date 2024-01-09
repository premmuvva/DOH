#!/bin/bash

directory_path="output/npy/maliciousv2/"

for ((i = $1; i <= $2; i++)); do
    file_name="$i.npy"
    file_path="$directory_path/$file_name"

    if [ ! -e "$file_path" ]; then
        echo "Missing file: $file_name"
    fi
done
