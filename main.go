package main

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var homeDir string

func init() {
	var err error
	if homeDir, err = os.UserHomeDir(); err != nil {
		fmt.Println("Error getting home directory:", err)
		os.Exit(1)
	}
}

func getLogsPath() string {
	logsPath := filepath.Join(homeDir, ".logs")
	if err := os.MkdirAll(logsPath, 0o755); err != nil {
		fmt.Println("Error creating logs directory:", err)
		os.Exit(1)
	}
	return logsPath
}

func getProcsPath() string {
	procsPath := filepath.Join(homeDir, ".procs")
	if err := os.MkdirAll(procsPath, 0o755); err != nil {
		fmt.Println("Error creating processes directory:", err)
		os.Exit(1)
	}
	return procsPath
}

func idHash(data []string) string {
	return hex.EncodeToString(sha3.SumSHAKE256([]byte(strings.Join(data, "")), 3)) // short hash for identification
}

func mainProc(processData []string) (err error) {
	logsPath := getLogsPath()
	outHash := idHash(processData)

	// create file if it does not exist
	const perms = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	outfile, err := os.OpenFile(filepath.Join(logsPath, outHash+"_out"), perms, 0o644)
	if err != nil {
		return
	}
	defer outfile.Close()

	errfile, err := os.OpenFile(filepath.Join(logsPath, outHash+"_err"), perms, 0o644)
	if err != nil {
		return
	}
	defer errfile.Close()

	// start a duplicate of the current process
	fmt.Println("Forking current process...")

	current := os.Args[0]
	args := append([]string{current, "sub"}, processData...)

	proc, err := os.StartProcess(current, args, &os.ProcAttr{
		Files: []*os.File{nil, outfile, errfile},
	})
	if err != nil {
		return
	}

	fmt.Println("Started process with PID:", proc.Pid)
	return
}

func subProc(processData []string) {
	procsPath := getProcsPath()
	outHash := idHash(processData)

	// start the process with the provided data

	// create process file
	procFilePath := filepath.Join(procsPath, outHash)
	procFile, err := os.Create(procFilePath)
	if err != nil {
		fmt.Println("Error creating process file:", err)
		os.Exit(1)
	}
	defer procFile.Close()
}

func listProcs() {
	procsPath := getProcsPath()
	files, err := os.ReadDir(procsPath)
	if err != nil {
		fmt.Println("Error reading processes directory:", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No processes found.")
		return
	}

	fmt.Println("Processes:")
	for _, file := range files {
		if file.IsDir() {
			continue // Skip directories
		}
		fmt.Println("-", file.Name())
	}
}

func main() {
	nargs := len(os.Args)
	if nargs > 1 {
		switch os.Args[1] {
		case "help":
			fmt.Println("WELCOME TO HELP")

		case "list":
			listProcs()

		case "sub": // run as subprocess
			if nargs < 3 {
				fmt.Println("No process data provided.")
				os.Exit(1)
			}

			subProc(os.Args[2:])

		default:
			fmt.Println("Unknown command", os.Args[1])
			os.Exit(1)
		}

		return
	}

	// main process

	if err := mainProc([]string{"blaargh"}); err != nil {
		fmt.Println("Error starting main process:", err)
	}
}
