n=input("Nhap ky tu can push: ")
print(n)
n=n[::-1]
print("push 0")
if len(n)%4:
    c=(len(n)%4)
    n="a"*(4-c)+n
    print(f'push "{n[4-c:4]}"')
else:
    print(f'push "{n[:4]}"')

for i in range(4,len(n),4):
    print(f'push "{n[i:i+4]}"')
print("push esp")
