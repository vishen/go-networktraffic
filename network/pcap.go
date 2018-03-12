package network

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
	"github.com/vishen/go-networktraffic/process"
)

var (
	snapshotLen int32         = 1024
	promiscuous bool          = false
	timeout     time.Duration = 30 * time.Second
)

type FilterNetworkFunc func(Packet) bool

type Device struct {
	name string
	ips  []net.IP
}

type Packet struct {
	OriginalPacket gopacket.Packet
	Device         Device
	filterFunc     FilterNetworkFunc

	// Process Information
	SrcCommandName  string
	SrcPid          string
	DestCommandName string
	DestPid         string

	// Ethernet layer
	SrcMAC       net.HardwareAddr
	DestMAC      net.HardwareAddr
	EthernetType layers.EthernetType

	// IP layer
	Protocol layers.IPProtocol
	SrcIP    net.IP
	DestIP   net.IP

	// TCP / UDP layer
	SrcPort  uint16
	DestPort uint16
	// TCP Specific
	Seq uint32
	Ack uint32
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

func NewPacket(packet gopacket.Packet, device Device, filterFunc FilterNetworkFunc) (*Packet, error) {

	p := &Packet{Device: device, OriginalPacket: packet, filterFunc: filterFunc}

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		e, _ := ethernetLayer.(*layers.Ethernet)
		p.SrcMAC = e.SrcMAC
		p.DestMAC = e.DstMAC
		p.EthernetType = e.EthernetType
	} else {
		return p, fmt.Errorf("Unable to parse ethernet layer")
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		p.Protocol = ip.Protocol
		p.SrcIP = ip.SrcIP
		p.DestIP = ip.DstIP
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
		p.SrcPort = uint16(t.SrcPort)
		p.DestPort = uint16(t.DstPort)
		p.Seq = t.Seq
		p.Ack = t.Ack
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
		p.SrcPort = uint16(u.SrcPort)
		p.DestPort = uint16(u.DstPort)
	}

	// Attempt to get lsof of the port
	if p.Protocol == layers.IPProtocolTCP || p.Protocol == layers.IPProtocolUDP {

		for _, deviceIP := range device.ips {
			if deviceIP.Equal(p.SrcIP) {
				processInfo, err := process.GetProcessFromLocalPort(p.SrcPort)
				if err != nil {
					continue
				}
				p.SrcCommandName = processInfo.CommandName
				p.SrcPid = processInfo.PID
			} else if deviceIP.Equal(p.DestIP) {
				processInfo, err := process.GetProcessFromLocalPort(p.DestPort)
				if err != nil {
					continue
				}
				p.DestCommandName = processInfo.CommandName
				p.DestPid = processInfo.PID
			} else {
				continue
			}
		}
	}

	return p, nil
}

func (p Packet) prettyPrint() {

	if !p.filterFunc(p) {
		return
	}

	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("device=%s :: %s %s", p.Device.name, p.EthernetType, p.Protocol))

	if p.SrcIP != nil && p.DestIP != nil {
		sb.WriteString(fmt.Sprintf(" - %s:%d -> %s:%d", p.SrcIP, p.SrcPort, p.DestIP, p.DestPort))
	}

	if p.SrcPid != "" || p.DestPid != "" {
		var src string
		if p.SrcPid != "" {
			src = fmt.Sprintf("%s,%s", p.SrcCommandName, p.SrcPid)
		} else {
			src = "unknown"
		}

		var dest string
		if p.DestPid != "" {
			dest = fmt.Sprintf("%s,%s", p.DestCommandName, p.DestPid)
		} else {
			dest = "unknown"
		}

		sb.WriteString(fmt.Sprintf(" (%s -> %s)", src, dest))
	}

	if p.Protocol == layers.IPProtocolTCP {
		sb.WriteString(fmt.Sprintf(" - seq=%d ack=%d", p.Seq, p.Ack))
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

func (p Packet) printPacketInfo() {
	packet := p.OriginalPacket

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

func getAllDevices() []Device {
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

	return foundDevices
}

func StartListening(device string, filterFunc FilterNetworkFunc) {
	version := pcap.Version()
	fmt.Printf("Pcap Version=%s\n", version)

	foundDevices := getAllDevices()
	if device != "" {
		for i, d := range foundDevices {
			if d.name == device {
				foundDevices = []Device{foundDevices[i]}
				break
			}
		}
	}

	wg := sync.WaitGroup{}
	for _, device := range foundDevices {
		log.Printf("Starting pcap for device '%s'\n", device.name)
		wg.Add(1)
		go func(d Device) {
			// Open device
			handle, err := pcap.OpenLive(d.name, snapshotLen, promiscuous, timeout)
			if err != nil {
				log.Printf("error opening pcap handle for '%s': %v", d.name, err)
				wg.Done()
				return
			}
			defer handle.Close()

			// Use the handle as a packet source to process all packets
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				p, err := NewPacket(packet, d, filterFunc)
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
