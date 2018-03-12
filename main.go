package main

import (
	"log"

	"github.com/vishen/go-networktraffic/cmd"
)

func main() {
	if err := cmd.NetworkTrafficCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
