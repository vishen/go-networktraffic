package main

import (
	"fmt"
	"os/exec"
)

func main() {

	pid := "24111"
	pid = "338"
	// pid = "753"
	//pid = "15660"
	//pid = "14654"

	/*
			State:
			       Marks a process that is idle (sleeping for longer than about 20 seconds).
		               R       Marks a runnable process.
		               S       Marks a process that is sleeping for less than about 20 seconds.
		               T       Marks a stopped process.
		               U       Marks a process in uninterruptible wait.
		               Z       Marks a dead process (a ``zombie'').

			 time       accumulated CPU time, user + system (alias cputime)
	*/

	psOutputFmt := "user,pid,ppid,%cpu,%mem,lstart,etime,jobc,pri,state,time"

	cmd := exec.Command("/bin/ps", "o", psOutputFmt, "-p", pid)

	data, err := cmd.Output()
	fmt.Println("Error: ", err)
	fmt.Printf("%s\n", data)

	cmd = exec.Command("/bin/ps", "o", "command", "-p", pid)

	data, err = cmd.Output()
	fmt.Println("Error: ", err)
	fmt.Printf("%s\n", data)
}
