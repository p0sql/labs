package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func ReadToProcessMemory(s_pid string, s_size string) {
	var registers syscall.PtraceRegs
	pid, errno := strconv.Atoi(s_pid)
	if errno != nil {
		fmt.Printf("Failed to convert string to int\n")
		return
	}

	size, err := strconv.Atoi(s_size)
	if err != nil {
		fmt.Printf("Failed to convert string to int\n")
		return
	}

	err = syscall.PtraceAttach(pid) // S'attacher au processus avec la CAP_SYS_PTRACE

	fmt.Printf("[+] Attaching to process\n")

	if err != nil {
		fmt.Printf("[-] Failed to attach\n")
		return
	}

	//Attendre que le SE renvoie un signal au processus de se stopper sinon on pourrait lire les registres
	//avant que le processus ne soit complètement stoppé
	syscall.Wait4(pid, nil, 0, nil)

	fmt.Printf("[+] Reading process registers\n")

	err = syscall.PtraceGetRegs(pid, &registers) // Lecture des registres du processus

	if err != nil {
		fmt.Printf("[-] Cannot read registers\n")
	}

	fmt.Printf("[*] Base pointer : 0x%x\n", registers.Rbp)
	fmt.Printf("[*] Instruction pointer : 0x%x\n", registers.Rip)
	/*
		for i < (size / 8) {
			next_addr = registers.Rbp + uint64((i * 8))
			chunk := make([]byte, 8)
			_, err = syscall.PtracePeekData(pid, uintptr(next_addr), chunk)
			if err != nil {
				fmt.Printf("[-] Cannot read memory\n")
			}
			//fmt.Printf("chunk -> %s\n", string(chunk))
			data = append(data, string(chunk))
			i = i + 1
		}

		remaining_bytes := size % 8
		if remaining_bytes != 0 {
			next_addr = registers.Rbp + uint64((i * 8))
			//fmt.Printf("Next addr -> 0x%x\n", next_addr)
			chunk := make([]byte, 8)
			_, err = syscall.PtracePeekData(pid, uintptr(next_addr), chunk)
			if err != nil {
				fmt.Printf("Cannot read memory\n")
			}
			data = append(data, string(chunk))
		}

		//fmt.Println(total)
		//print(strings.Join(data, ""))
		//for i := 1; i < len(data); i++ {
		fmt.Printf("%s\n", data)*/

	chunk := make([]byte, size)
	chunk2 := make([]byte, size)

	_, err = syscall.PtracePeekData(pid, uintptr(registers.Rip), chunk)

	if err != nil {
		fmt.Printf("[-] Cannot read memory\n")
		return
	}

	_, err = syscall.PtracePeekData(pid, uintptr(registers.Rbp), chunk)

	fmt.Println(string(chunk))
	fmt.Println((string(chunk2)))

	fmt.Printf("[*] Detaching from process...\n")
	err = syscall.PtraceDetach(pid)
	if err != nil {
		fmt.Printf("[-] Cannot detach\n")
		return
	}
}


func main() {
	pid := os.Args[1]
	size := os.Args[2]
	ReadToProcessMemory(pid, size)
}