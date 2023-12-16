max_threads=5
current_threads=0

for file_path in "$1"/*
do
    echo $file_path
    if [ -f "$file_path" ] && [[ "$file_path" == *.pcap ]]; then
        for stream in `~/tshark/usr/local/bin/tshark -r $file_path -T fields -e tcp.stream | sort -n | uniq`
        do
            echo $stream 
            # outputfile=$(echo "$1" | awk -F'/' '{print $2}' | awk -F'.' '{print $1}')
            outputfile=$(basename "$file_path" | cut -f 1 -d '.')
            echo "Prem $outputfile $file_path"
            {
            ~/tshark/usr/local/bin/tshark -r $file_path -w output/pcap_split/malicious/$outputfile-$stream.pcap -Y "tcp.stream==$stream && tls.app_data"
            ((current_threads--))
            } &
            ((current_threads++))
            if [ "$current_threads" -ge "$max_threads" ]; then
                wait
                current_threads=0
            fi
        done
    fi
done