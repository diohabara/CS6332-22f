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

Run the script.

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

Edit `catflag`

```bash
vim catflag
```

like this.

```sh
#!/bin/sh
cat flag
```

Create a symbolic link so that it will be called.

```bash
chmod +x catflag
ln -s catflag Writing
```

Run the script.

```bash
./1-aw-64.py
```
