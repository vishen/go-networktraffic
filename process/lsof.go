package process

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const (
	cacheTimeout = time.Second * 5
)

var (
	processPortCache map[uint16]*Process
	lsofBin          string
)

type Process struct {
	PID         string
	CommandName string
	Filename    string
	TST         string

	addedTime time.Time
}

func GetProcessFromLocalPort(port uint16) (*Process, error) {
	found, ok := processPortCache[port]
	if ok && time.Now().Before(found.addedTime.Add(cacheTimeout)) {
		return found, nil
	}

	p := &Process{}

	d, err := exec.Command(lsofBin, "-i", fmt.Sprintf(":%d", port), "-FcnT").Output()
	if err != nil {
		return p, fmt.Errorf("Error executing lsof command: %s\n", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(d)), "\n") {
		switch line[0] {
		case 'p':
			p.PID = line[1:]
		case 'c':
			p.CommandName = line[1:]
		case 'n':
			p.Filename = line[1:]
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
