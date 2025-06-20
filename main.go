package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var mainDir string

func init() {
	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		os.Exit(1)
	}

	mainDir = filepath.Join(homedir, ".xc")
}

// mainly for identification atm
func getHashPath() string {
	hashPath := filepath.Join(mainDir, "hash")
	if err := os.MkdirAll(hashPath, 0o755); err != nil {
		fmt.Println("Error creating hash directory:", err)
		os.Exit(1)
	}
	return hashPath
}

func getLogsPath() string {
	logsPath := filepath.Join(mainDir, "logs")
	if err := os.MkdirAll(logsPath, 0o755); err != nil {
		fmt.Println("Error creating logs directory:", err)
		os.Exit(1)
	}
	return logsPath
}

func getProcsPath() string {
	procsPath := filepath.Join(mainDir, "procs")
	if err := os.MkdirAll(procsPath, 0o755); err != nil {
		fmt.Println("Error creating processes directory:", err)
		os.Exit(1)
	}
	return procsPath
}

func idHash(data []string) string {
	return hex.EncodeToString(sha3.SumSHAKE256([]byte(strings.Join(data, " ")), 3)) // short hash for identification
}

type Process struct {
	hash, args string
	pid        int
	running    bool
}

func checkProc(hash, procsPath string) (exists bool) {
	_, err := os.Stat(filepath.Join(procsPath, hash))
	return err == nil
}

func openLogs(hash string) (outfile, errfile *os.File, close func(), err error) {
	const perms = os.O_CREATE | os.O_RDWR | os.O_APPEND
	logsPath := getLogsPath()

	outfile, err = os.OpenFile(filepath.Join(logsPath, hash+"_out"), perms, 0o644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open output file: %w", err)
	}

	errfile, err = os.OpenFile(filepath.Join(logsPath, hash+"_err"), perms, 0o644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open error file: %w", err)
	}

	return outfile, errfile, func() {
		outfile.Close()
		errfile.Close()
	}, nil
}

func writeLogs(file *os.File) (err error) {
	w := &bytes.Buffer{}
	file.Seek(0, 0) // Reset file pointer to the beginning

	if _, err = file.WriteTo(w); err != nil {
		return
	}

	// get last 15 lines
	lines := strings.Split(w.String(), "\n")
	lines = lines[max(len(lines)-15, 0):]

	for _, line := range lines {
		fmt.Println("    ", line)
	}

	return
}

func getArgs(hash string) (args string, err error) {
	argsFilePath := filepath.Join(getHashPath(), hash)
	argsData, err := os.ReadFile(argsFilePath)
	if err != nil {
		return
	}

	return string(argsData), nil
}

func getPid(hash string) (pid int, err error) {
	procFilePath := filepath.Join(getProcsPath(), hash)
	procData, err := os.ReadFile(procFilePath)
	if err != nil {
		return
	}

	fmt.Sscanf(string(procData), "%d", &pid)
	return
}

func kill(hash string) (err error) {
	procsPath := getProcsPath()
	if !checkProc(hash, procsPath) {
		return fmt.Errorf("process with hash %s does not exist", hash)
	}

	pid, err := getPid(hash)
	if err != nil {
		return fmt.Errorf("failed to get process ID: %w", err)
	}

	if pid == -1 {
		return fmt.Errorf("process with hash %s has already been killed", hash)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process with PID %d: %w", pid, err)
	}

	if err = proc.Kill(); err != nil {
		return fmt.Errorf("failed to kill process with PID %d: %w", pid, err)
	}

	fmt.Println("Successfully killed process with hash", hash, "and PID", pid)

	if err = os.WriteFile(filepath.Join(procsPath, hash), []byte("-1\n"), 0o644); err != nil {
		return fmt.Errorf("failed to update process file: %w", err)
	}
	return
}

func list() (err error) {
	procsPath := getProcsPath()
	files, err := os.ReadDir(procsPath)
	if err != nil {
		return fmt.Errorf("failed to read processes directory: %w", err)
	}

	if len(files) == 0 {
		fmt.Println("No processes running.")
		return
	}

	fmt.Println("Processes:")

	procs := make([]Process, len(files))

	for i, file := range files {
		if file.IsDir() {
			continue // Skip directories (they shouldn't be here anyway)
		}

		hash := file.Name()
		procs[i].hash = hash

		if procs[i].args, err = getArgs(hash); err != nil {
			fmt.Println("Error reading args file:", err)
		}

		if procs[i].pid, err = getPid(hash); err != nil {
			fmt.Println("Error reading process file:", err)
		}

		if procs[i].pid == -1 {
			procs[i].running = false
			continue
		}

		// check if process is running
		proc, err := os.FindProcess(procs[i].pid)
		if err != nil {
			continue
		}

		if err = proc.Signal(syscall.Signal(0)); err == nil {
			procs[i].running = true
			continue
		}

		if err.Error() != "os: process already finished" {
			procs[i].running = true
		}
	}

	for _, proc := range procs {
		var status string
		if proc.running {
			status = "running"
		} else {
			status = "stopped"
		}
		fmt.Printf("%s | PID %7d | %s | %s\n", proc.hash, proc.pid, status, proc.args)
	}
	return
}

func logs(hash string) (err error) {
	procsPath := getProcsPath()
	if !checkProc(hash, procsPath) {
		return fmt.Errorf("process with hash %s does not exist", hash)
	}

	outfile, errfile, closeFiles, err := openLogs(hash)
	if err != nil {
		return fmt.Errorf("failed to open log files: %w", err)
	}
	defer closeFiles()

	fmt.Println("Logs for process", hash)

	fmt.Println("Output logs:")
	if err = writeLogs(outfile); err != nil {
		return fmt.Errorf("failed to write output logs: %w", err)
	}

	fmt.Println("Error logs:")
	if err = writeLogs(errfile); err != nil {
		return fmt.Errorf("failed to write error logs: %w", err)
	}

	return
}

func remove(hash string) (err error) {
	procsPath := getProcsPath()
	if !checkProc(hash, procsPath) {
		return fmt.Errorf("process with hash %s does not exist", hash)
	}

	paths := []string{
		filepath.Join(procsPath, hash),
		filepath.Join(getHashPath(), hash),
		filepath.Join(getLogsPath(), hash+"_out"),
		filepath.Join(getLogsPath(), hash+"_err"),
	}

	for _, path := range paths {
		if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
	}

	fmt.Println("Successfully removed process with hash", hash)
	return
}

func run(args []string) (err error) {
	hashPath, procsPath := getHashPath(), getProcsPath()
	outHash := idHash(args)
	if checkProc(outHash, procsPath) {
		return fmt.Errorf("process with hash %s already exists or cannot be accessed", outHash)
	}

	outfile, errfile, closeFiles, err := openLogs(outHash)
	if err != nil {
		return fmt.Errorf("failed to open log files: %w", err)
	}
	defer closeFiles()

	fmt.Println("Starting process...")

	name := args[0]

	proc, err := os.StartProcess(
		name,
		args,
		&os.ProcAttr{Files: []*os.File{nil, outfile, errfile}})
	if err != nil {
		if err := os.Remove(outfile.Name()); err != nil {
			fmt.Println("Failed to remove output file:", err)
		}

		if err := os.Remove(errfile.Name()); err != nil {
			fmt.Println("Failed to remove error file:", err)
		}

		return fmt.Errorf("failed to start process: %w", err)
	}

	fmt.Println("Started process with hash", outHash, "and pid", proc.Pid)

	// Write process ID to a file
	procfile, err := os.Create(filepath.Join(procsPath, outHash))
	if err != nil {
		return fmt.Errorf("failed to create process file: %w", err)
	}
	defer procfile.Close()

	if _, err = procfile.WriteString(fmt.Sprintf("%d\n", proc.Pid)); err != nil {
		return fmt.Errorf("failed to write process data to file: %w", err)
	}

	// Write other data to hash file
	hashFile, err := os.Create(filepath.Join(hashPath, outHash))
	if err != nil {
		return fmt.Errorf("failed to create hash file: %w", err)
	}
	defer hashFile.Close()

	if _, err = hashFile.WriteString(strings.Join(args, " ")); err != nil {
		return fmt.Errorf("failed to write data to hash file: %w", err)
	}

	return
}

func main() {
	nargs := len(os.Args)
	if nargs < 2 {
		fmt.Println("No command provided.")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help":
		fmt.Println("WELCOME TO HELP")

	case "kill":
		if nargs < 3 {
			fmt.Println("Usage: kill <hash>")
			os.Exit(1)
		}

		if err := kill(os.Args[2]); err != nil {
			fmt.Println("Error killing process:", err)
			os.Exit(1)
		}

	case "list":
		if err := list(); err != nil {
			fmt.Println("Error listing processes:", err)
			os.Exit(1)
		}

	case "logs":
		if nargs < 3 {
			fmt.Println("Usage: logs <hash>")
			os.Exit(1)
		}

		if err := logs(os.Args[2]); err != nil {
			fmt.Println("Error retrieving logs:", err)
			os.Exit(1)
		}

	case "remove":
		if nargs < 3 {
			fmt.Println("Usage: remove <hash>")
			os.Exit(1)
		}

		if err := remove(os.Args[2]); err != nil {
			fmt.Println("Error removing process:", err)
			os.Exit(1)
		}

	case "run":
		if nargs < 3 {
			fmt.Println("Usage: run <program> [args...]")
			os.Exit(1)
		}

		if err := run(os.Args[2:]); err != nil {
			fmt.Println("Error starting main process:", err)
			os.Exit(1)
		}

	default:
		fmt.Println("Unknown command", os.Args[1])
		os.Exit(1)
	}
}
