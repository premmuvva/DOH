for stream in `tshark -r $1 -T fields -e tcp.stream | sort -n | uniq`
do
    echo $stream 
    outputfile=$(echo "$1" | awk -F'/' '{print $2}' | awk -F'.' '{print $1}')
    tshark -r $1 -w pcap_split/$outputfile-$stream.pcap -Y "tcp.stream==$stream && tls.app_data"
done
