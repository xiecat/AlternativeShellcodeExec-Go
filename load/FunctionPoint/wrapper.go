package main

/*
#include <windows.h>

// C Wrapper function to call the shellcode
__declspec(dllexport) void WINAPI WrapperFunc(PVOID lpFlsData) {
	((void(*)())lpFlsData)();
}
*/
import "C"
import "unsafe"

// WrapperFunc is the exported function from the wrapper.c file
func WrapperFunc(lpFlsData uintptr) {
	C.WrapperFunc(C.PVOID(unsafe.Pointer(lpFlsData)))
}
