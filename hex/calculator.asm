.386
.model flat,stdcall
;https://yeanhoo.gitee.io/2020/07/14/%E6%B1%87%E7%BC%96%E8%AF%AD%E8%A8%80%E7%BC%96%E5%86%99shellcode%E5%AE%9E%E7%8E%B0%E5%BC%B9%E7%AA%97%E8%AE%A1%E7%AE%97%E5%99%A8/
; 代码区域
.code

main:
	push ebp
	mov ebp,esp
	sub esp,20h; 开辟栈空间
; 获取Kernel32基址
	assume fs:nothing
	mov eax,[fs:30h]; peb结构所在地址
	mov eax,[eax+0Ch]; Ldr
	mov eax,[eax+1Ch]; 指向ntdll
	mov eax,[eax]; 指向kernelbase
	mov eax,[eax]; 指向kernel32
	mov eax,[eax+08h]; BaseAddress
;遍历kernel32导出函数
	; 初始化栈空间用来保存变量
	mov DWORD PTR[ebp-04h],0; 用来存放导出函数“地址表”
	mov DWORD PTR[ebp-08h],0; 用来存放导出函数“名称表”
	mov DWORD PTR[ebp-0Ch],0; 用来存放导出函数“序号表”

	; 解析PE结构获取导出表结构实际地址
	mov ebx,DWORD PTR[eax + 3Ch]   ; NT头偏移地址
	lea ebx,DWORD PTR[ebx + eax]   ; NT头VA
	mov ebx,DWORD PTR[ebx + 78h]   ; 导出表结构VirtualAddress
	lea edx,DWORD PTR[ebx + eax]   ; 导出表结构实际地址

	; 获取导出函数地址表VA
	mov ebx,DWORD PTR[edx + 1Ch]   ; AddressOfFunctions 偏移
	lea ebx,DWORD PTR[ebx + eax]   ; AddressOfFunctions 实际地址
	mov DWORD PTR[ebp - 04h],ebx   ; 保存到局部变量

	; 获取导出函数名称表VA
	mov ebx,DWORD PTR[edx + 20h]   ; AddressOfNames 偏移
	lea ebx,DWORD PTR[ebx + eax]   ; AddressOfNames 实际地址
	mov DWORD PTR[ebp - 08h],ebx   ; 保存到局部变量

	; 获取导出函数序号表VA
	mov ebx,DWORD PTR[edx + 24h]   ; AddressOfNameOrdinals 偏移
	lea ebx,DWORD PTR[ebx + eax]   ; AddressOfNameOrdinals 实际地址
	mov DWORD PTR[ebp - 0Ch],ebx   ; 保存到局部变量

	; 开始遍历三张表,找到目标函数地址
	mov edi,DWORD PTR[edx + 18h]   ; NumberOfNames循环次数
	xor ecx,ecx		       ; 清空ecx,作为循环计数
	mov esi,DWORD PTR[ebp - 08h]   ; 暂存导出函数名称表 实际地址
_ExportName:
	mov ebx,DWORD PTR[esi + ecx * 4];函数名称 偏移地址
	lea ebx,DWORD PTR[ebx + eax]; 获取第n个导出函数的名称 实际地址

	; 判断函数名称
	mov ebx,[ebx]
	cmp ebx,456E6957h;判断是否WinE
	je _FindFunc

	;自增1,开始下一次遍历
	inc ecx;
	jmp _ExportName

_FindFunc:
	;找到目标函数，获取该函数地址VA
	mov ebx,DWORD PTR[ebp - 0Ch]    ; 序号表 实际地址
	xor edx,edx		        ; 注意序号表是2字节数组
	mov dx,WORD PTR[ebx + ecx * 2]  ; 获取对应序号表中保存的值
	mov ebx,DWORD PTR[ebp - 04h]    ; 地址表 实际地址
	mov ebx,DWORD PTR[ebx + edx * 4]; 地址表中，目标函数地址 偏移地址
	lea eax,DWORD PTR[ebx + eax]    ; 目标函数实际地址;
; 调用函数
	jmp _gotFunc
	g_str db "calc.exe"
	g_stop db 0
_gotFunc:	call $+5
	pop ebx;获取eip
	sub ebx,0Eh
	push 5h
	push ebx
	call eax
	; 恢复函数栈帧
	mov esp,ebp
	pop ebp
	ret
end main

end