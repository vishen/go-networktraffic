package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
tcpLayer: &{BaseLayer:{Contents:[194 47 1 187 190 39 45 175 0 0 0 0 176 2 255 255 122 131 0 0 2 4 5 180 1 3 3 5 1 1 8 10 27 19 115 77 0 0 0 0 4 2 0 0] Payload:[]} SrcPort:49711 DstPort:443(https) Seq:3190238639 Ack:0 DataOffset:11 FIN:false SYN:true RST:false PSH:false ACK:false URG:false ECE:false CWR:false NS:false Window:65535 Checksum:31363 Urgent:0 sPort:[194 47] dPort:[1 187] Options:[TCPOption(MSS:1460 0x05b4) TCPOption(NOP:) TCPOption(WindowScale: 0x05) TCPOption(NOP:) TCPOption(NOP:) TCPOption(Timestamps:454259533/0 0x1b13734d00000000) TCPOption(SACKPermitted:) TCPOption(EndList:) TCPOption(EndList:)] Padding:[] opts:[{OptionType:2 OptionLength:4 OptionData:[5 180]} {OptionType:1 OptionLength:1 OptionData:[]} {OptionType:3 OptionLength:3 OptionData:[5]} {OptionType:1 OptionLength:1 OptionData:[]}] tcpipchecksum:{pseudoheader:<nil>}}
*/

// get the local ip and port based on our destination ip
func localIPPort(dstip net.IP) (net.IP, int) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port
		}
	}
	log.Fatal("could not get local ip: " + err.Error())
	return nil, -1
}

func createTCPPacket() {

	/*ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			fmt.Printf("Waiting for connection\n")
			conn, err := ln.Accept()
			if err != nil {
				panic(err)
			}
			fmt.Println(conn.RemoteAddr())
			conn.Close()
		}

	}()*/

	dstIP := net.ParseIP("209.85.203.102")
	dstPort := 80

	srcIP := net.ParseIP("192.168.0.31")
	srcPort := 8000

	conn, err := net.DialIP("ip:tcp", nil, &net.IPAddr{IP: dstIP})
	if err != nil {
		log.Fatalf("Dial: %s\n", err)
	}

	// This time lets fill out some information
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     12345,
		SYN:     true,
		Window:  65535,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, options, tcpLayer); err != nil {
		log.Fatalf("Error serialising layer: %s\n", err)
	}

	//https://github.com/grahamking/latency/blob/master/latency.go#L227

	conn.Write(buffer.Bytes())
	fmt.Println("Wrote packet")

	buf := make([]byte, 1024)
	conn.Read(buf)
	fmt.Printf("%X\n", buf)

	done := make(chan bool, 1)
	<-done

}

func scanPort() {
	createTCPPacket()
}

func main() {
	scanPort()
}
