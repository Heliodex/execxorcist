package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	return "#" + hex.EncodeToString(sha3.SumSHAKE256([]byte(strings.Join(data, " ")), 3)) // short hash for identification
}

func isHash(h string) (ok bool) {
	if len(h) != 7 || h[0] != '#' {
		return
	}

	// TODO: check for hex
	return true
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

type ProgramConfig struct {
	Name    string   `json:"name"`
	WorkDir string   `json:"workdir"`
	Args    []string `json:"args"`
}

func readConfig() (config []ProgramConfig, err error) {
	// read xc.json file in the current directory
	const configPath = "xc.json"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file %s does not exist", configPath)
	}

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	if err = json.Unmarshal(configFile, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %w", err)
	}
	return
}

func checkName(name string) *ProgramConfig {
	config, err := readConfig()
	if err != nil {
		fmt.Println("Error checking process name:", err)
		os.Exit(1)
	}

	for _, c := range config {
		if c.Name == name {
			return &c
		}
	}
	return nil
}

func killHash(hash string) error {
	procsPath := getProcsPath()
	if !checkProc(hash, procsPath) {
		return fmt.Errorf("process with hash %s does not exist", hash)
	}

	pid, err := getPid(hash)
	if err != nil {
		return fmt.Errorf("failed to get PID: %w", err)
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
	return nil
}

func killConf() error {
	config, err := readConfig()
	if err != nil {
		return fmt.Errorf("failed to read configuration: %w", err)
	}

	for _, c := range config {
		hash := idHash(c.Args)
		if err := killHash(hash); err != nil {
			fmt.Printf("failed to kill program %v: %v\n", hash, err)
		}
	}
	return nil
}

const alreadyFinished = "os: process already finished"

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

		if err.Error() != alreadyFinished {
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

func logsHash(hash string) error {
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
	return nil
}

func logsConf() error {
	config, err := readConfig()
	if err != nil {
		return fmt.Errorf("failed to read configuration: %w", err)
	}

	for _, c := range config {
		hash := idHash(c.Args)
		if err := logsHash(hash); err != nil {
			fmt.Printf("failed to retrieve logs for program %v: %v\n", hash, err)
		}
	}
	return nil
}

func removeHash(hash string) (err error) {
	procsPath := getProcsPath()
	if !checkProc(hash, procsPath) {
		return fmt.Errorf("process with hash %s does not exist", hash)
	}

	fmt.Println("Attempting to kill process with hash", hash)
	if err = killHash(hash); err != nil {
		fmt.Println("Error killing process:", err)
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

func removeConf() error {
	config, err := readConfig()
	if err != nil {
		return fmt.Errorf("failed to read configuration: %w", err)
	}

	for _, c := range config {
		hash := idHash(c.Args)
		if err := removeHash(hash); err != nil {
			fmt.Printf("failed to remove program %v: %v\n", hash, err)
		}
	}
	return nil
}

func run(args []string, workDir string) error {
	if len(args) == 0 {
		return errors.New("no command provided to run")
	}

	hashPath, procsPath := getHashPath(), getProcsPath()
	outHash := idHash(args)

	var restarting bool
	if checkProc(outHash, procsPath) {
		fmt.Printf("process with hash %s already exists, restarting\n", outHash)
		restarting = true
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
		&os.ProcAttr{
			Dir:   workDir,
			Files: []*os.File{nil, outfile, errfile},
		})
	if err != nil {
		if !restarting {
			if err := os.Remove(outfile.Name()); err != nil {
				fmt.Println("Failed to remove output file:", err)
			}

			if err := os.Remove(errfile.Name()); err != nil {
				fmt.Println("Failed to remove error file:", err)
			}
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

	if _, err = fmt.Fprintf(procfile, "%d\n", proc.Pid); err != nil {
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
	return nil
}

func runConf() error {
	config, err := readConfig()
	if err != nil {
		return fmt.Errorf("failed to read configuration: %w", err)
	}

	for _, c := range config {
		if err := run(c.Args, c.WorkDir); err != nil {
			fmt.Printf("failed to run command %v: %v\n", c.Args, err)
		}
	}
	return nil
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
			if err := killConf(); err != nil {
				fmt.Println("Error killing from configuration file:", err)
				os.Exit(1)
			}
		} else if arg := os.Args[2]; isHash(arg) {
			if err := killHash(arg); err != nil {
				fmt.Println("Error killing by hash:", err)
				os.Exit(1)
			}
		} else if c := checkName(arg); c != nil {
			if err := killHash(idHash(c.Args)); err != nil {
				fmt.Println("Error killing by name:", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Command ran with unknown identifier:", arg)
			os.Exit(1)
		}

	case "list":
		if err := list(); err != nil {
			fmt.Println("Error listing processes:", err)
			os.Exit(1)
		}

	case "logs":
		if nargs < 3 {
			if err := logsConf(); err != nil {
				fmt.Println("Error retrieving logs from configuration file:", err)
				os.Exit(1)
			}
		} else if arg := os.Args[2]; isHash(arg) {
			if err := logsHash(arg); err != nil {
				fmt.Println("Error retrieving logs by hash:", err)
				os.Exit(1)
			}
		} else if c := checkName(arg); c != nil {
			if err := logsHash(idHash(c.Args)); err != nil {
				fmt.Println("Error retrieving logs by name:", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Command ran with unknown identifier:", arg)
			os.Exit(1)
		}

	case "remove":
		if nargs < 3 {
			if err := removeConf(); err != nil {
				fmt.Println("Error removing from configuration file:", err)
				os.Exit(1)
			}
		} else if arg := os.Args[2]; isHash(arg) {
			if err := removeHash(arg); err != nil {
				fmt.Println("Error removing by hash:", err)
				os.Exit(1)
			}
		} else if c := checkName(arg); c != nil {
			if err := removeHash(idHash(c.Args)); err != nil {
				fmt.Println("Error removing by name:", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Command ran with unknown identifier:", arg)
			os.Exit(1)
		}

	case "run":
		if nargs < 3 {
			if err := runConf(); err != nil {
				fmt.Println("Error starting from configuration file:", err)
				os.Exit(1)
			}
		} else if arg := os.Args[2]; isHash(arg) {
			if err := run(os.Args[2:], ""); err != nil {
				fmt.Println("Error starting process:", err)
				os.Exit(1)
			}
		} else if c := checkName(arg); c != nil {
			if err := run(c.Args, c.WorkDir); err != nil {
				fmt.Println("Error starting by name:", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Command ran with unknown identifier:", arg)
			os.Exit(1)
		}

	default:
		fmt.Println("Unknown command", os.Args[1])
		os.Exit(1)
	}
}
