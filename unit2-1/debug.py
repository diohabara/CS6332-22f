#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, gdb, process

context.terminal = ["tmux", "splitw", "-v"]

shellcode = asm("")
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./1-shellcode-32"])
p = gdb.attach(
    io,
    """
    break main
    run
    """,
)
io.interactive()
