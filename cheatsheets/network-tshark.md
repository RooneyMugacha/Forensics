# Network Forensics Cheatsheet

```bash
tshark -r cap.pcap -q -z io,phs                       # protocol hierarchy
tshark -r cap.pcap -q -z conv,tcp                     # TCP conversations
tshark -r cap.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri
tshark -r cap.pcap -Y "dns" -T fields -e frame.time_epoch -e dns.qry.name
tshark -r cap.pcap --export-objects http,extracted/
tshark -r cap.pcap -q -z follow,tcp,ascii,0           # follow stream 0
tcpdump -i eth0 -w capture.pcap
```

## Useful Wireshark display filters
```
ip.addr == 10.0.0.5
tcp.port == 4444
dns.qry.name contains "example"
http.request.method == "POST"
frame contains "password"
```

## DNS exfiltration tips
- Look for long or high-entropy subdomains and unusual query volume to one domain
- Sort by `frame.time_epoch` before reassembling chunks
- Base32/base64 labels often lose padding; re-pad before decoding
