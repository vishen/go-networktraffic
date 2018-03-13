package main

import (
	"fmt"
	"log"
	"net"
)

func listenPacket() {

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	//conn, err := net.Listen("tcp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Listen Packet: %s\n", err)
	}
	defer conn.Close()

	p := ipv4.NewPacketConn(conn)
	if err := p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		log.Fatal(err)
	}

	for {
		log.Printf("Waiting for data...\n")
		buf := make([]byte, 4096)
		_, _addr, err := p.ReadFrom(buf)
		if err != nil {
			log.Fatalf("Error reading connection: %s\n", err)
		}

		fmt.Println(buf)
		fmt.Println(_addr)
		fmt.Printf("buf: %s\n", buf)
		fmt.Printf("addr: %v\n", _addr)

	}
}

func listen() {
i	ln, err := net.Listen("tcp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}


}

func main() {
	// listenPacket()
}
