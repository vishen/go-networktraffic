# Network traffic watcher
This will watch network traffic on a particular device and pair up any traffic with the command that is running it.

This uses `lsof`, `pcap` and `github.com/google/gopacket` to watch the network and attempt to sync up the network packet with a running command.

Very useful video / blog https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket

## Prerequisites
```
- Mac OSX only (at the moment)
- brew install pcap
- sudo access
```

## Running
```
$ go build -o networktraffic .
$ sudo ./networktraffic
```

Example output
```
Pcap Version=libpcap version 1.8.1 -- Apple version 67.60.1
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:56783 -> (xx:xx:xx:xx:xx:xx) 151.101.60.133:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:56778 -> (xx:xx:xx:xx:xx:xx) 151.101.60.133:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:56776 -> (xx:xx:xx:xx:xx:xx) 151.101.60.133:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:56775 -> (xx:xx:xx:xx:xx:xx) 151.101.60.133:443
[334] Google Chrome: IPv4 UDP (xx:xx:xx:xx:xx:xx) 209.85.202.189:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:65383
[334] Google Chrome: IPv4 UDP (xx:xx:xx:xx:xx:xx) 192.168.0.2:65383 -> (xx:xx:xx:xx:xx:xx) 209.85.202.189:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 151.101.60.133:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:56785
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 151.101.60.133:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:56778
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 151.101.60.133:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:56775
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 151.101.60.133:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:56783
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 151.101.60.133:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:56776
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:56793 -> (xx:xx:xx:xx:xx:xx) 192.30.253.125:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.30.253.125:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:56793
[339] WhatsApp: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:55132 -> (xx:xx:xx:xx:xx:xx) 158.85.224.178:443
[339] WhatsApp: IPv4 TCP (xx:xx:xx:xx:xx:xx) 158.85.224.178:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:55132
[339] WhatsApp: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:55132 -> (xx:xx:xx:xx:xx:xx) 158.85.224.178:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:55123 -> (xx:xx:xx:xx:xx:xx) 192.168.0.115:8009
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.115:8009 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:55123
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:55123 -> (xx:xx:xx:xx:xx:xx) 192.168.0.115:8009
[18645] Spotify: IPv4 UDP (xx:xx:xx:xx:xx:xx) 192.168.0.2:54177 -> (xx:xx:xx:xx:xx:xx 239.255.255.250:1900
[18645] Spotify: IPv4 UDP (xx:xx:xx:xx:xx:xx) 192.168.0.115:46183 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:54177
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 169.54.204.231:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:55269
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:55269 -> (xx:xx:xx:xx:xx:xx) 169.54.204.231:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 192.168.0.2:55269 -> (xx:xx:xx:xx:xx:xx) 169.54.204.231:443
[334] Google Chrome: IPv4 TCP (xx:xx:xx:xx:xx:xx) 169.54.204.231:443 -> (xx:xx:xx:xx:xx:xx) 192.168.0.2:55269
```

## TODO:
```
- Add packet size?
- Add signal handler to then show stats on exiting?
- Don't error on DNS lookups, and maybe print it nicer
- Print ARP calls in a nicer way
- Attempt to inspect HTTP traffic?
```
