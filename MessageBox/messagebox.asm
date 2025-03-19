.386 
.model flat, stdcall 
.stack 4096
assume fs:nothing


.code 
start:		
    push ebp
    mov ebp, esp
    sub esp, 100h 
	
	mov eax, [fs:30h]		    ; Pointer to PEB 
	mov eax, [eax + 0ch]		; Pointer to Ldr
	mov eax, [eax + 14h]		; Pointer to InMemoryOrderModuleList
	mov eax, [eax]				  ; this program's module
	mov eax, [eax]				  ; ntdll module
	mov eax, [eax]				 ; kernel32
	mov eax, [eax -8h + 18h]; kernelbase.DllBase
	mov [ebp-4h], eax; luu dllbase cua kernelbase vao stack
	push 0
	push "ss"
	push "erdd"
	push "Acor"
	push "PteG"		    
	mov [ebp - 28h], esp			
	mov ebx, eax ;luu dia chi kernelbase.dll vao ebx

	 ; get address of PE signature
	mov eax, [ebx + 3ch] ; 0x3c into the image - RVA of PE signature
	add eax, ebx ; address of PE signature

	 ; get address of Export Table
	mov eax, [eax + 78h] ; RVA of Export Table
	add eax, ebx ; address of Export Table = Export Table RVA + kernel32 base

	 ; get number of exported functions
	mov ecx, [eax + 14h] 
	mov [ebp - 18h], ecx ; store number of exported functions

	 ; get address of exported functions table
	mov ecx, [eax + 1ch] ; get RVA of exported functions table
	add ecx, ebx ; get address of exported functions table
	mov [ebp - 1ch], ecx ; store address of exported functions table

	 ; get address of name pointer table
	mov ecx, [eax + 20h] ; get RVA of Name Pointer Table
	add ecx, ebx ; get address of Name Pointer Table
	mov [ebp - 20h], ecx ; store address of Name Pointer Table

	 ; get address of functions ordinal table
	mov ecx, [eax + 24h] ; get RVA of functions ordinal table
	add ecx, ebx ; get address of functions ordinal table
	mov [ebp - 24h], ecx ; store address of functions ordinal table
 
	 ; loop through exported function name pointer table and find position of WinExec
	xor eax, eax
	xor ecx, ecx
 
	timGetProcAddress:
		mov esi, [ebp - 28h] ; esi = pointer to WinExec
		mov edi, [ebp - 20h] ; edi = pointer to exported function names table
		cld ; https://en.wikipedia.org/wiki/Direction_flag
		mov edi, [edi + eax*4] ; get RVA of the next function name in the exported function names table
		add edi, ebx ; get address of the next function name in the exported function names table

		mov cx, 8 ; tell the next-comparison instruction to compare first 8 bytes
		repe cmpsb ; check if esi == edi
 
		jz ok
		inc eax ; increase the counter
		cmp eax, [ebp - 18h] ; check if we have looped over all the exported function names
		jne timGetProcAddress 
 
	ok: 
		mov ecx, [ebp - 24h] ; ecx = ordinal table
		mov edx, [ebp - 1ch] ; edx = export address table

		; get address of WinExec ordinal
		mov ax, [ecx + eax * 2] ; get WinExec ordinal
		mov eax, [edx + eax * 4]; get RVA of WinExec function
		add eax, ebx ; get VA of WinExec



	mov [ebp-8h], eax; luu dia chi GetProcAddress
	push 0
    	push 'Ayra'
	push 'rbiL'
	push 'daoL'
    	push esp
	push [ebp-4h] ; kernelbase.DllBase
	call dword ptr [ebp-8h] ; call GetProcAddress, luu dia chi cua LoadLibrary vao eax
	mov [ebp-0ch], eax ;address LoadLibraryA
	
	push 0
	push "ll"
	push "d.23"
	push "resu"
	push esp
	call dword ptr [ebp-0ch] ; Call LoadLibraryA, luu dia chi cua user32.dll vao eax
	mov [ebp-10h], eax; address user32.dll
	
	push 0
	push "Axo"
	push "Bega"
	push "sseM"
	push esp
	push [ebp-10h]
	call dword ptr [ebp-8h]
	mov [ebp-14h], eax; dia chi cua MessageBoxA

	push 0
	push "!t"
	push "ahc "
	push "cuc "
	push "xobe"
	push "gass"
	push "em e"
	push "docl"
	push "lehs"
	mov eax, esp

	push 0
	push "!ed "
	push "ioh "
	push "yan "
	push "emag"
	mov ebx, esp

	push 0
	push eax
	push ebx
	push 0
	call dword ptr [ebp-14h]

	push 0
	push "sse"
	push "corP"
	push "tixE"
	push esp
	
	push [ebp-4h] ; kernelbase.DllBase
	call dword ptr [ebp-8h]
	push 0
	call eax ; ExitProcess
			
end start
