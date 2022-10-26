# Part-1: Aribrary write with format string vulnerability (20 pt)

## Problem Statement

This part will provide you with two binaries with format string vulnerability to overwrite GOT entries. Please write scripts to exploit those binaries and catch the flags. You will get full credit by inputting your flags and submitting solution scripts.

First run $fetch unit3 to check out the challenges. In the later part of the assignment, you will implement dynamic defense to guard the binaries against your attack.

## 1-aw-64 10

### Problem Statement

again ret2libc. let's call a function from libc to run a command. the program took care of setreguid() for you.

### Exploit

## 2-fs-aw-64 10

### Problem Statement

now it is time to take a control over a variable somwehre in memory. craft your input to overwrite and pass the check.

### Exploit
