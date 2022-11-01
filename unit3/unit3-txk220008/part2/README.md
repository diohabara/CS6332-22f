# Part-2: Find relocatable entries using ELFIO library (20 pt)

## Problem Statement

````txt
To protect the Global Offet Table (GOT) from being overwritten by the attacker, you first need to identify the section and memory address range. In this part, you will extend ELFIO to get a list of GOT entries and their address (Relocation Offset). We expect you to implement readelf -reloc so that list of GOT entries and their address at runtime.

For a given binary, readelf -reloc will give you the following output.

```bash
$ readelf --relocs /tmp/fs-code-exec-64

....

Relocation section '.rela.plt' at offset 0x4e0 contains 11 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 putchar@GLIBC_2.2.5 + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000601040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000601048  000800000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
000000601050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 getegid@GLIBC_2.2.5 + 0
000000601058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
000000601060  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 open@GLIBC_2.2.5 + 0
000000601068  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
kjee@ctf-vm1.syssec.utdallas.edu:/home/kjee $
```

And we expect your implement should work as follows,

```bash
$ ./part2 /tmp/fs-code-exec-64

GOT range: 0x000000601018 ~ 000000601068
 
Offset          Symbol name      
---------------------------------
000000601018    putchar
000000601020    puts
000000601028    __stack_chk_fail
...
000000601068    exit
```

Please ELFIO tutorial code regarding how to use ELFIO and readelf.c source to confirm how to find relocs entries and get their addresses.
````

## Write-up

There is an API called [`get_entry()`](https://github.com/serge1/ELFIO/blob/main/elfio/elfio_relocation.hpp#L122), which sets a symbol's offset and name. Use this API while iterating over a section.

What we want is only symbols in `.rela.plt` section, so compare section's name using [`get_name()`](https://github.com/serge1/ELFIO/blob/b99697792573588574793408a30fdffaa1c81f43/elfio/elfio_section.hpp#L98) method.

Run it like this.

```bash
make
./part2 <elf_file>
```

E.g., you can apply the program to `aw0-64`, which we solved in the previous parts.

```bash
TXK220008@ctf-vm1:~/unit3/0-aw0-64$ ./part2 aw0-64
GOT range: 000000602018 ~ 000000602068

Offset          Symbol name
---------------------------------
000000602018    puts
000000602020    __stack_chk_fail
000000602028    printf
000000602030    read
000000602038    __libc_start_main
000000602040    fgets
000000602048    execve
000000602050    prctl
000000602058    __isoc99_sscanf
000000602060    getegid
000000602068    setregid
```

```bash
TXK220008@ctf-vm1:~/unit3/0-aw0-64$ readelf --relocs ./aw0-64

Relocation section '.rela.dyn' at offset 0x518 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601ff8  000800000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000602080  000d00000005 R_X86_64_COPY     0000000000602080 stdin@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x548 contains 11 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000602018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000602020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000602028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000602030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000602038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000602040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fgets@GLIBC_2.2.5 + 0
000000602048  000700000007 R_X86_64_JUMP_SLO 0000000000000000 execve@GLIBC_2.2.5 + 0
000000602050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
000000602058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 __isoc99_sscanf@GLIBC_2.7 + 0
000000602060  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 getegid@GLIBC_2.2.5 + 0
000000602068  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
```

The program shows as expected.
