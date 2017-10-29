package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const (
	cacheTimeout = time.Second * 15
)

var (
	processPortCache map[uint16]*Process
	lsofBin          string
)

type Process struct {
	pid         string
	commandName string
	fileName    string
	TST         string

	addedTime time.Time
}

func GetProcessFromLocalPort(port uint16) (*Process, error) {
	found, ok := processPortCache[port]
	if ok && time.Now().Before(found.addedTime.Add(cacheTimeout)) {
		return found, nil
	}

	p := &Process{}

	//TODO(vishen): Handle the case when that port doesn't exist
	// [IPv4] [UDP] (a0:99:9b:13:e1:5f) 192.168.0.31:60309 -> (ac:22:05:20:a0:d3) 192.168.0.1:53
	// 2017/10/29 21:43:52 Error executing lsof command: exit status 1
	d, err := exec.Command(lsofBin, "-i", fmt.Sprintf(":%d", port), "-FcnT").Output()
	if err != nil {
		return p, fmt.Errorf("Error executing lsof command: %s\n", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(d)), "\n") {
		switch line[0] {
		case 'p':
			p.pid = line[1:]
		case 'c':
			p.commandName = line[1:]
		case 'n':
			p.fileName = line[1:]
		case 'T':
			if line[:3] == "TST" {
				p.TST = line[4:]
			}
		}
	}

	p.addedTime = time.Now()
	processPortCache[port] = p

	return p, nil

}

func init() {
	processPortCache = make(map[uint16]*Process)

	var err error
	lsofBin, err = exec.LookPath("lsof")
	if err != nil {
		log.Fatalf("Error getting lsof bin path: %s\n", err)
	}
}
