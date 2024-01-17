0. Create the following directories: 
```
output/logs
output/npy
output/pcap_split
output/final_dataset
```

1. Split the pcap file to different streams: 
```
./pcap_split.sh /home/x286t435/thesis/time-series/dataset/Malicious/

./pcap_split.sh /home/x286t435/thesis/time-series/dataset/Benign
```

2. Convert pcap to npy files:
```
venv/bin/python3 pcaptonpy.py 

or 

sbatch runCmd.sh pcaptonpy.py 
```
If the program stops you can rerun it to continue. 


3. Merge npy files:
```
sbatch runCmd.sh mergenpy_without_multi_index.py 

```


4. Run your model: lstmV2.py or anomaly_lstm.py
