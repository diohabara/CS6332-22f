# Part-1: Aribrary write with format string vulnerability (20 pt)

## Problem Statement

This part will provide you with two binaries with format string vulnerability to overwrite GOT entries. Please write scripts to exploit those binaries and catch the flags. You will get full credit by inputting your flags and submitting solution scripts.

First run $fetch unit3 to check out the challenges. In the later part of the assignment, you will implement dynamic defense to guard the binaries against your attack.

## 0-aw-64 10

### Problem Statement1

```txt
overwrite got and run your function.
```

### Exploit1

```bash
./0-aw0-64.py
```

## 1-aw-64 10

### Problem Statement2

```txt
again ret2libc. let's call a function from libc to run a command.
the program took care of setreguid() for you.
```

### Exploit2

```bash
TXK220008@ctf-vm1:~/unit3/1-aw-64$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "13 printf@@GLIBC_2.2.5$"
   603: 0000000000055810   161 FUNC    GLOBAL DEFAULT   13 printf@@GLIBC_2.2.5
TXK220008@ctf-vm1:~/unit3/1-aw-64$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system@@GLIBC_2.2.5$"
  1351: 00000000000453a0    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```

diff `66672`

```bash
./1-aw-64.py
```
