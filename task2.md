# Một số điều quan trọng cần chú ý  
Shellcode thực chất là opcodes được biên dịch từ mã nguồn chương trình để máy tính có thể thực thi được, tùy vào kiến trúc máy tính thì shellcode cũng khác nhau  
Ta có thể lấy trực tiếp opcodes từ hexeditor, các công cụ,... hoặc để trực quan hơn thì ta lấy trực tiếp từ IDA:  
  
![image](https://github.com/user-attachments/assets/a38e3448-4fa5-424d-932d-f363030afa97)  
  
Về cơ bản chương trình chạy từ shellcode khá đầy đủ chức năng giống một chương trình bình thường, tuy nhiên có một điều quan trọng là shellcode không thể gọi trực tiếp các WinApi như một chương trình bình thường được (như `GetStdHandle`, `WriteConsoleA`,...) hay gọi hoặc khai báo các biến/hằng bằng section `.data` được  
Để có thể sử dụng các biến, chuỗi, ... thì ta có thể push thẳng vào stack (chú ý kiểu LE/BE và kích thước của 1 ô trong stack):  
```assembly
  push 0
  push "!ed "
  push "ioh "
  push "yan "
  push "emag"
```
Về các funtions trong winapi, ta không thể invoke hay call ra trực tiếp, nhưng có 2 hàm quan trọng trong kernel32/kernelbase là `GetProcAddress` (tìm địa chỉ của hàm) và `LoadLibraryA` (có thể load thư viện và trả về địa chỉ của thư viện đó) có thể giải quyết được vấn đề này  
Và kernel32/kernelbase lại luôn luôn được load vào chương trình dù ta không chủ động import và có thể dễ dàng tìm địa chỉ mà không phải phụ thuộc vào các WinApi khác:  
  
![image](https://github.com/user-attachments/assets/c35d66e4-adef-4f49-a50d-134f54a0c27c)  
  
ta kiểm tra các thư viện được load vào chương trình trên bằng winDbg:  
  
![image](https://github.com/user-attachments/assets/c010e776-e1e1-475e-8feb-c7a233a81cfa)  

Các bước tìm base address của kernel32.dll/kernelbase.dll (ở đây là mình tìm kernelbase.dll)  
về cơ bản ta tìm kiếm theo mô hình sau:  
`TEB->PEB->Ldr->InMemoryOrderLoadList->currentProgram->ntdll->kernel32->kernelbase.BaseDll`  
Để trực quan hơn, ta debug bằng [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/):  
bắt đầu từ TEB:  
command: `dt _teb`  
![image](https://github.com/user-attachments/assets/dec57a80-471a-4273-bc58-8f1fc1895498)  
TEB hay thread information block chứa thông tin về một thread, offset 0x30 hay teb.baseaddress+0x30 trỏ đến PEB (chứa baseaddress của PEB)  
tiếp đến là PEB:  
`dt _peb`  
![image](https://github.com/user-attachments/assets/05a9b5f3-891f-487b-b391-7597d1bd557b)  
Ta thấy 2 trường hay gặp là `BeingDebugged` (cho biết chương trình có đang bị debug hay không) và `Ldr` ( trỏ đến `PEB_LDR_DATA`)  

PEB_LDR_DATA:  
`dt _PEB_LDR_DATA`  
![image](https://github.com/user-attachments/assets/e6aad492-5a75-48db-a4de-0b6faa44e44d)  
offset 0x14 trong PEB_LDR_DATA trỏ đến `InMemoryOrderModuleList` chứa thông tin về các module được load cùng với process đang chạy  
`InMemoryOrderModuleList` là một danh sách liên kết đôi, tức như ta đã biết, danh sách liên kết chứa data và con trỏ  
trong trường hợp này là:  
`InMemoryOrderLoadList->currentProgram->ntdll->kernel32->kernelbase.BaseDll`  
về cơ bản là mỗi node chứa 3 thành phần là data: base address, 1 con trỏ trỏ đến node trước đó và 1 con trỏ trỏ đến node tiếp theo  
Cứ thế ta lấy được Base address của kernelbase.dll:  
```assembly
	mov eax, [fs:30h]		    ; Pointer to PEB 
	mov eax, [eax + 0ch]		; Pointer to Ldr
	mov eax, [eax + 14h]		; Pointer to InMemoryOrderModuleList
	mov eax, [eax]				  ; this program's module
	mov eax, [eax]				  ; ntdll module
	mov eax, [eax]				 ; kernel32
	mov eax, [eax + 10h]; kernelbase.DllBase
```
dòng cuối phải là `mov eax, [eax + 10h]` vì `[eax+10h]` chứa data còn nếu chỉ là `[eax]` như trên thì chỉ chứa con trỏ trỏ đến node tiếp theo  
Về việc mình lấy kernelbase.dll thay vì kernel32.dll như mọi người thì do khi debug mình đã phát hiện ra một điều khá lạ và hay:  
![image](https://github.com/user-attachments/assets/408804fa-be79-430d-8391-d3053ec4de92)  
Như trong hình trên ta thấy rõ, hàm `LoadLibraryA` nó không thực sự nằm trong kernel32.dll mà là nằm trong kernelbase.dll  
mình có tìm hiểu thì nhận được thông tin đại khái như sau:  
![image](https://github.com/user-attachments/assets/6cfb69d4-7266-4ed8-879a-13869ed50630)  
  
khi tìm các hàm khác thì có 1 số hàm chứa bên trong cả 2 thư viện:  
![image](https://github.com/user-attachments/assets/c36ee549-3451-4544-9dc7-20ea910398f3)  
  
Mình đoán rằng kernel32 đã cũ, trong khi thời gian luôn xuất hiện thêm các dll mới, các functions mới, nếu không cập nhật các hàm `GetProcAddress`, `LoadLibraryA` thì sẽ không thể đáp ứng chức năng  
có [bài thảo luận](https://www.unknowncheats.me/forum/general-programming-and-reversing/220491-differences-kernel32-dll-kernelbase-dll.html) trên mạng nói về vấn đề này:  
  
![image](https://github.com/user-attachments/assets/4d9b466f-1317-4b01-883e-b333a5ba4ef7)  
  
Tuy nhiên sử dụng kernel32 hay kernelbase đều chạy được và không có sự khác biệt nên không quá quan trọng  
Thông tin thêm về sự khác biệt giữa 2 thư viện này khá hiếm, mình sẽ tìm hiểu kỹ hơn và bổ sung sau.  

# MessageBox  
Vì push bằng tay khá mất thời gian nên mình đã viết 1 file python để gen code asm  
```python
n=input("Nhap ky tu can push: ")
print(n)
n=n[::-1]
print("push 0")
c=(len(n)%4)
n="a"*((4-c)%4)+n
print(f'push "{n[(4-c)%4:4]}"')

for i in range(4,len(n),4):
    print(f'push "{n[i:i+4]}"')
print("push esp")
```
  
![image](https://github.com/user-attachments/assets/9fbfcc74-8087-479f-89de-9a7debc97370)  
