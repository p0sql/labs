package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Printf("Victime... PID: %d\n", os.Getpid())
	
	for {
		fmt.Printf("coucou PID: %d\n", os.Getpid())
		time.Sleep(10 * time.Second)
	}
}
