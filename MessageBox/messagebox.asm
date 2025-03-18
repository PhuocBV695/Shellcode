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
	add eax, 1315888 ; GetProcAddress
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
	push "aall"
	sub  word ptr [esp+2], "aa"
	push "d.23"
	push "resu"
	push esp
	call dword ptr [ebp-0ch] ; Call LoadLibraryA, luu dia chi cua user32.dll vao eax
	mov [ebp-10h], eax; address user32.dll
	
	push 0
	push "aAxo"
	sub  byte ptr [esp+3], "a"
	push "Bega"
	push "sseM"
	push esp
	push [ebp-10h]
	call dword ptr [ebp-8h]
	mov [ebp-14h], eax; dia chi cua MessageBoxA

	push 0
	push "aa!t"
	sub  word ptr [esp+2], "aa"
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
	push "asse"
	sub  word ptr [esp+3], "a"
	push "corP"
	push "tixE"
	push esp
	
	push [ebp-4h] ; kernelbase.DllBase
	call dword ptr [ebp-8h]
	push 0
	call eax ; ExitProcess
			
end start
