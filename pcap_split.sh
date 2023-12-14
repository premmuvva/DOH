max_threads=5
current_threads=0

for stream in `~/tshark/usr/local/bin/tshark -r $1 -T fields -e tcp.stream | sort -n | uniq`
do
    echo $stream 
    outputfile=$(echo "$1" | awk -F'/' '{print $2}' | awk -F'.' '{print $1}')
    {
    ~/tshark/usr/local/bin/tshark -r $1 -w output/pcap_split/benign/$outputfile-$stream.pcap -Y "tcp.stream==$stream && tls.app_data"
    ((current_threads--))
    } &
    ((current_threads++))
    if [ "$current_threads" -ge "$max_threads" ]; then
        wait
        current_threads=0
    fi
done
