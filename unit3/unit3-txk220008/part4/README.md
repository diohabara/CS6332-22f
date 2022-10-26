# Part-4: Position Independent Executable (PIE) (30 pt)

## Problem Statement

In this assignment, we build the binary with -fpie option; therefore, you no longer be able to find the GOT address range for GOT by only referring to ELF headers. You need to calculate the address at runtime referring to the base address of the section. Due to ASLR, the loader will map the .text section can be loaded to a different address every time you execute the binary.

```
$ readelf --relocs fs-no-binary-pie-64

....
Relocation section '.rela.plt' at offset 0x8a8 contains 19 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000202018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 getenv@GLIBC_2.2.5 + 0
000000202020  000300000007 R_X86_64_JUMP_SLO 0000000000000000 putchar@GLIBC_2.2.5 + 0
000000202028  000500000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000202030  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fread@GLIBC_2.2.5 + 0
000000202038  000700000007 R_X86_64_JUMP_SLO 0000000000000000 write@GLIBC_2.2.5 + 0
000000202040  000800000007 R_X86_64_JUMP_SLO 0000000000000000 getpid@GLIBC_2.2.5 + 0
000000202048  000900000007 R_X86_64_JUMP_SLO 0000000000000000 fclose@GLIBC_2.2.5 + 0
000000202050  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 chdir@GLIBC_2.2.5 + 0
000000202058  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000202060  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000202068  000d00000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000202070  000e00000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000202078  001000000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
000000202080  001100000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
000000202088  001200000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000202090  001300000007 R_X86_64_JUMP_SLO 0000000000000000 open@GLIBC_2.2.5 + 0
000000202098  001400000007 R_X86_64_JUMP_SLO 0000000000000000 fopen@GLIBC_2.2.5 + 0
0000002020a0  001600000007 R_X86_64_JUMP_SLO 0000000000000000 getppid@GLIBC_2.2.5 + 0
```

In the part of the assignment, you need to work on two subparts.

1. Exploit AW binary built with -fPIE option (10 pt)
2. Modify / update your solution for Part-3 to handle PIE binary (20 pt)
