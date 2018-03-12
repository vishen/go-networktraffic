# Network traffic watcher
This will watch network traffic on a particular device and pair up any traffic with the command that is running it.

This uses `lsof`, `pcap` and `github.com/google/gopacket` to watch the network and attempt to sync up the network packet with a running command.

Very useful video / blog https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket

## Prerequisites
```
- pcap
- sudo access
```

### Linux
```
$ sudo apt-get install libpcap-dev
```

### Mac
```
$ brew install pcap
```

## Running
```
$ go build -o networktraffic .
$ sudo ./networktraffic
```

Example output
```
Pcap Version=libpcap version 1.7.4
2018/03/12 15:15:43 No addresses found for 'any'
2018/03/12 15:15:43 No addresses found for 'bluetooth0'
2018/03/12 15:15:43 No addresses found for 'nflog'
2018/03/12 15:15:43 No addresses found for 'nfqueue'
2018/03/12 15:15:43 No addresses found for 'usbmon1'
2018/03/12 15:15:43 No addresses found for 'usbmon2'
2018/03/12 15:15:43 Starting pcap for device 'wlp59s0'
2018/03/12 15:15:43 Starting pcap for device 'lo'
2018/03/12 15:15:43 Starting pcap for device 'docker0'
2018/03/12 15:15:43 Starting pcap for device 'br-f4ae56ed08f9'
device=wlp59s0 :: IPv6 IPv6HopByHop
device=lo :: IPv4 UDP - 127.0.0.1:53052 -> 127.0.1.1:53
device=wlp59s0 :: IPv4 TCP - 192.168.0.38:59128 -> 52.11.229.118:443 (chrome,2918 -> unknown) - seq=3969154339 ack=1271874429 ACK
device=lo :: IPv4 UDP - 127.0.0.1:53052 -> 127.0.1.1:53
device=lo :: IPv4 UDP - 127.0.1.1:53 -> 127.0.0.1:53052
device=wlp59s0 :: IPv4 TCP - 192.168.0.38:58810 -> 192.168.0.115:8009 (chrome,2918 -> unknown) - seq=2819370194 ack=585518410 PSH ACK
device=wlp59s0 :: IPv4 TCP - 52.11.229.118:443 -> 192.168.0.38:59128 (unknown -> chrome,2918) - seq=1271874429 ack=3969154340 ACK
device=wlp59s0 :: IPv4 TCP - 192.168.0.115:8009 -> 192.168.0.38:58810 (unknown -> chrome,2918) - seq=585518410 ack=2819370311 PSH ACK
device=wlp59s0 :: IPv4 TCP - 192.168.0.38:58810 -> 192.168.0.115:8009 (chrome,2918 -> unknown) - seq=2819370311 ack=585518529 ACK
device=wlp59s0 :: ARP IPv6HopByHop
device=wlp59s0 :: ARP IPv6HopByHop
```
