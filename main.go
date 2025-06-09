package main

import (
	"fmt"
	"os"
	"time"
)

func cmd() {
	// current process id
	pid := os.Getpid()
	fmt.Println("Current process ID:", pid)

	outfile, err := os.Create(fmt.Sprintf("output_%d.log", pid))
	// outfile, err := os.CreateTemp("", "output_*.log")
	if err != nil {
		panic(err)
	}
	defer outfile.Close()

	errfile, err := os.Create(fmt.Sprintf("error_%d.log", pid))
	// errfile, err := os.CreateTemp("", "error_*.log")
	if err != nil {
		panic(err)
	}
	defer errfile.Close()

	p := &os.ProcAttr{
		Files: []*os.File{nil, outfile, errfile},
	}

	// start a duplicate of the current process
	name := os.Args[0]
	fmt.Println("Starting a new process...", os.Args)

	proc, err := os.StartProcess(name, []string{name, "start"}, p)
	if err != nil {
		panic(err)
	}

	fmt.Println("Started process with PID:", proc.Pid)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "start" {
		time.Sleep(2 * time.Second)
		fmt.Println("This is the child process.")
		return
	}

	fmt.Println("This is the parent process.")
	cmd()
	fmt.Println("Parent process finished.")
}
