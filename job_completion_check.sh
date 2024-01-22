#!/bin/bash

# Job ID to monitor
JOB_ID=$1

while true; do
    # Check job status
    JOB_STATUS=$(squeue -h -j $JOB_ID -o "%T")

    # If job is not running, print a command and exit
    if [ -z "$JOB_STATUS" ]; then
        echo "Job $JOB_ID has completed. Your command here."
        exit 0
    fi

    # Wait for 5 seconds before checking again
    sleep 5
done
