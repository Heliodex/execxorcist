package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}

	nnum, err := strconv.Atoi(os.Args[1])
	if err != nil {
		os.Exit(1)
	}

	// print upon kill with ctrl c
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		i := <-c
		fmt.Println("Process interrupted:", i)
		os.Exit(0)
	}()

	fmt.Println("Doing work for", nnum, "seconds...")
	time.Sleep(time.Duration(nnum) * time.Second)
	fmt.Println("Finished!")
}
