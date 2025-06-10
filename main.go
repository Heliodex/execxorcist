package main

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const logsDir = "./logs"

func mainProcess(processData string) (err error) {
	outHash := hex.EncodeToString(sha3.SumSHAKE256([]byte(processData), 3)) // short hash for identification

	err = os.MkdirAll(logsDir, 0o755)
	if err != nil {
		return
	}

	// create file if it does not exist
	outfile, err := os.OpenFile(filepath.Join(logsDir, outHash+"_out"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer outfile.Close()

	errfile, err := os.OpenFile(filepath.Join(logsDir, outHash+"_err"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer outfile.Close()

	p := &os.ProcAttr{
		Files: []*os.File{nil, outfile, errfile},
	}

	// start a duplicate of the current process
	name := os.Args[0]
	fmt.Println("Forking current process...", name)

	proc, err := os.StartProcess(name, []string{name, "start", processData}, p)
	if err != nil {
		return
	}

	fmt.Println("Started process with PID:", proc.Pid)
	return
}

func subProcess() {
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "start" {
		fmt.Println("This is the subprocess.")
		subProcess()
		return
	}

	fmt.Println("This is the main process.")
	err := mainProcess("test")
	if err != nil {
		fmt.Println("Error starting main process:", err)
	}
}
