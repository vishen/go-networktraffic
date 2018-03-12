package cmd

import (
	"fmt"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/vishen/go-networktraffic/network"
)

func runCommand(cmd *cobra.Command, args []string) {
	device := cmd.Flag("device").Value.String()
	command := cmd.Flag("command").Value.String()
	pid := cmd.Flag("pid").Value.String()
	trafficType := cmd.Flag("type").Value.String()

	switch trafficType {
	case "ALL", "TCP", "UDP", "ARP", "DNS":
		break
	default:
		fmt.Printf("unknown type '%s'\n", trafficType)
		os.Exit(1)
	}

	filterFunc := func(p network.Packet) bool {
		valid := true

		if pid != "" {
			valid = p.SrcPid == pid || p.DestPid == pid
		}

		if command != "" {
			valid = p.SrcCommandName == command || p.DestCommandName == command
		}

		switch trafficType {
		case "TCP":
			valid = p.Protocol == layers.IPProtocolTCP
		case "UDP":
			valid = p.Protocol == layers.IPProtocolUDP
		case "ARP":
			valid = p.EthernetType == layers.EthernetTypeARP
		case "DNS":
			valid = p.Protocol == layers.IPProtocolUDP && (p.SrcPort == 53 || p.DestPort == 53)
		}

		return valid
	}

	network.StartListening(device, filterFunc)
}

var NetworkTrafficCmd = &cobra.Command{
	Use:   "networktraffic",
	Short: "networktraffic: filter and watch incoming and outgoing network traffic",
	Run:   runCommand,
}

func init() {
	NetworkTrafficCmd.PersistentFlags().StringP("device", "d", "", "device name to use (can be found using ifconfig)")
	NetworkTrafficCmd.PersistentFlags().StringP("command", "c", "", "command name to filter network traffic for")
	NetworkTrafficCmd.PersistentFlags().StringP("pid", "p", "", "pid name to filter network traffic for")
	NetworkTrafficCmd.PersistentFlags().StringP("type", "t", "ALL", "type of traffic to watch: ALL, TCP, UDP, ARP or DNS")
}
