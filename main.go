package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

type Device struct {
	name string
	ips  []net.IP
}

type Packet struct {
	device Device

	// Process Information
	srcCommandName  string
	srcPid          string
	destCommandName string
	destPid         string

	// Ethernet layer
	srcMAC       net.HardwareAddr
	destMAC      net.HardwareAddr
	ethernetType layers.EthernetType

	// IP layer
	protocol layers.IPProtocol
	srcIP    net.IP
	destIP   net.IP

	// TCP / UDP layer
	srcPort  uint16
	destPort uint16
	// TCP Specific
	seq uint32
	ack uint32
	FIN bool // FIN - Closes a connection
	SYN bool // SYN - Initiates a connection
	RST bool // RST -Aborts a connection in response to an error
	ACK bool // ACK - Acknowledges received data
	PSH bool // PSH - Indicates that the data should be pushed immediately
	URG bool
	ECE bool
	CWR bool
	NS  bool
}

func (p Packet) prettyPrint() {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("device=%s :: %s %s", p.device.name, p.ethernetType, p.protocol))

	if p.srcIP != nil && p.destIP != nil {
		sb.WriteString(fmt.Sprintf(" - %s:%d -> %s:%d", p.srcIP, p.srcPort, p.destIP, p.destPort))
	}

	if p.srcPid != "" || p.destPid != "" {
		var src string
		if p.srcPid != "" {
			src = fmt.Sprintf("%s,%s", p.srcCommandName, p.srcPid)
		} else {
			src = "unknown"
		}

		var dest string
		if p.destPid != "" {
			dest = fmt.Sprintf("%s,%s", p.destCommandName, p.destPid)
		} else {
			dest = "unknown"
		}

		sb.WriteString(fmt.Sprintf(" (%s -> %s)", src, dest))
	}

	if p.protocol == layers.IPProtocolTCP {
		sb.WriteString(fmt.Sprintf(" - seq=%d ack=%d", p.seq, p.ack))
		if p.FIN {
			sb.WriteString(" FIN")
		}
		if p.SYN {
			sb.WriteString(" SYN")
		}
		if p.RST {
			sb.WriteString(" RST")
		}
		if p.PSH {
			sb.WriteString(" PSH")
		}
		if p.ACK {
			sb.WriteString(" ACK")
		}
	}

	fmt.Println(sb.String())

}

func NewPacket(packet gopacket.Packet, device Device) (*Packet, error) {

	p := &Packet{device: device}

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		e, _ := ethernetLayer.(*layers.Ethernet)
		p.srcMAC = e.SrcMAC
		p.destMAC = e.DstMAC
		p.ethernetType = e.EthernetType
	} else {
		return p, fmt.Errorf("Unable to parse ethernet layer")
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		p.protocol = ip.Protocol
		p.srcIP = ip.SrcIP
		p.destIP = ip.DstIP
	} else {
		return p, nil
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if tcpLayer == nil && udpLayer == nil {
		return nil, fmt.Errorf("Unable to parse TCP or UDP layer")
	}

	if tcpLayer != nil {
		t, _ := tcpLayer.(*layers.TCP)
		p.srcPort = uint16(t.SrcPort)
		p.destPort = uint16(t.DstPort)
		p.seq = t.Seq
		p.ack = t.Ack
		// Flags
		p.FIN = t.FIN
		p.SYN = t.SYN
		p.RST = t.RST
		p.PSH = t.PSH
		p.ACK = t.ACK
		p.URG = t.URG
		p.ECE = t.ECE
		p.CWR = t.CWR
		p.NS = t.NS
	} else {
		u, _ := udpLayer.(*layers.UDP)
		p.srcPort = uint16(u.SrcPort)
		p.destPort = uint16(u.DstPort)
	}

	// Attempt to get lsof of the port
	if p.protocol == layers.IPProtocolTCP || p.protocol == layers.IPProtocolUDP {

		for _, deviceIP := range device.ips {
			if deviceIP.Equal(p.srcIP) {
				processInfo, err := GetProcessFromLocalPort(p.srcPort)
				if err != nil {
					continue
				}
				p.srcCommandName = processInfo.commandName
				p.srcPid = processInfo.pid
			} else if deviceIP.Equal(p.destIP) {
				processInfo, err := GetProcessFromLocalPort(p.destPort)
				if err != nil {
					continue
				}
				p.destCommandName = processInfo.commandName
				p.destPid = processInfo.pid
			} else {
				continue
			}
		}
	}

	return p, nil

}

func main() {
	version := pcap.Version()
	fmt.Printf("Pcap Version=%s\n", version)

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var foundDevices []Device

	// Print device information
	for _, device := range devices {
		addresses := device.Addresses
		if len(addresses) == 0 {
			log.Printf("No addresses found for '%s'", device.Name)
			continue
		}

		d := Device{
			name: device.Name,
			ips:  make([]net.IP, len(addresses)),
		}

		for _, addr := range addresses {
			d.ips = append(d.ips, addr.IP)
		}

		foundDevices = append(foundDevices, d)
	}

	wg := sync.WaitGroup{}
	for _, device := range foundDevices {
		log.Printf("Starting pcap for device '%s'\n", device.name)
		wg.Add(1)
		go func(d Device) {
			// Open device
			handle, err = pcap.OpenLive(d.name, snapshot_len, promiscuous, timeout)
			if err != nil {
				log.Printf("error opening pcap handle for '%s': %v", d.name, err)
				wg.Done()
				return
			}
			defer handle.Close()

			// Use the handle as a packet source to process all packets
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				// printPacketInfo(packet)

				p, err := NewPacket(packet, d)
				if err != nil {
					fmt.Printf("Error creating new packet: %s\n", err)
					continue
				}
				p.prettyPrint()

			}
		}(device)
	}

	wg.Wait()
	fmt.Println("Finished")
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet

	// https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
