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

3. Merge npy files:
```
sbatch runCmd.sh mergenpy.py 
```

b - 447mb
m - 747