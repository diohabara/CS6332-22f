# Part-3: Guarding GOT segment against AW attempt (40 pt)

## Problem Statement

In regular execution environment, without having PINTOOL layer in between, a process would first make a call to `_dl_runtime_resolve*()` from glibc to implement lazy loading. However, as you run your target process inside the PINTOOL context, PINTOOL framework implements its own custom loader using dynamic linking library to avoid conflict with its own library. It is obvious the PINTOOL framework and its target process both need basic libraries, including glibc and can’t be shared one another. Consider the call tracek (backtrace) from regular exuection and PINTOOL execution.

- Regular execution (capture by GDB)

```bash
 ► f 0   0x7ffff7deef11 _dl_runtime_resolve_xsavec+1
   f 1         0x400986 read_func+18
   f 2         0x400b08 input_func+14
   f 3         0x400b48 main+51
   f 4   0x7ffff7a2d840 __libc_start_main+240
```

- PINTOOL execution (capture by PIN_Backtrace())

```bash
0x7f3671e6eb47 : _dl_rtld_di_serinfo
0x7f3671e76f8a : _dl_find_dso_for_object
0x4009d4 : read_func
0x400b08 : input_func
0x400b48 : main
0x7f365e497840 : __libc_start_main
0x4007e9 : _start
```

You can consider `_dl_rtld_di_serinfo()` as a legitimate access to the GOT entry to be white-listed. Therefore any overwrite attempts outside the `_dl_rtld_di_serinfo()` function context we consider to be a suspicious event to raise the alarm and stop the execution of the process. To implement the solution, you must instrument memory write instructions and check their destinations at runtime. In case the memory address falls inside the range of GOT section, you need to trace back function call history and confirm the instruction is called from a legitimate function.

```txt
Your pintool should detect 0-aw0-64 and 1-aw-64 to its minimum while it can run regular program (e.g., /bin/*) with no complaints.
```

## Write-up

### Get GOT range

We can reuse the code in [part2](../part2/README.md).

```cpp
uint64_t lowAddr, highAddr;
std::vector<std::pair<Elf64_Addr, std::string>> getSectionPairs(elfio &reader, std::string section_name)
{
  std::vector<std::pair<Elf64_Addr, std::string>> sectionPairs;
  Elf_Half sec_num = reader.sections.size();
  for (int i = 0; i < sec_num; ++i)
  {
    section *psec = reader.sections[i];
    const relocation_section_accessor symbols(reader, psec);
    if (psec->get_name() == section_name)
    {
      for (unsigned int j = 0; j < symbols.get_entries_num(); ++j)
      {
        Elf64_Addr offset;
        Elf64_Addr symbolValue;
        std::string symbolName;
        unsigned type;
        Elf_Sxword addend;
        Elf_Sxword calcValue;
        symbols.get_entry(j, offset, symbolValue, symbolName, type, addend, calcValue);
        sectionPairs.push_back(std::make_pair(offset, symbolName));
      }
    }
  }
  return sectionPairs;
}

bool getGOTRange(char *elfname, UINT64 &lowAddr, UINT64 &highAddr)
{
  elfio reader;
  if (!reader.load(elfname))
  {
    std::cerr << "Can't find or process ELF file " << elfname << std::endl;
    return false;
  }
  std::string section_name = ".rela.plt";
  auto sectionPairs = getSectionPairs(reader, section_name);
  auto pairWithMinAddr = std::min_element(sectionPairs.begin(), sectionPairs.end(), [](const auto &a, const auto &b)
                                          { return a.first < b.first; });
  auto pairWithMaxAddr = std::max_element(sectionPairs.begin(), sectionPairs.end(), [](const auto &a, const auto &b)
                                          { return a.first < b.first; });
  lowAddr = pairWithMinAddr->first;
  highAddr = pairWithMaxAddr->first;
  return true;
}
```

### Traverse instructions

Let's look inside `Trace` that's called at `TRACE_AddInstrumentFunction(Trace, 0);`.

It check if the instruction is writing memory.

```cpp
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
  {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
    {
      if (!INS_IsMemoryWrite(ins))
      {
        continue;
      }
      UINT32 memOperands = INS_MemoryOperandCount(ins);
      for (UINT32 memOp = 0; memOp < memOperands; memOp++)
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)detectGotOverwritten, IARG_MEMORYWRITE_EA, IARG_CONST_CONTEXT, IARG_END);
      }
    }
  }
```

At the bottom, it is calling [`INS_InsertCall`](https://syssec.run/pin/group__INS__INSTRUMENTATION.html#gaea02f152d3515f4758b8f979a380da09) so that we can get some information.

### Get the instruction information using `PIN_Backtrace`

As [`INS_InsertCall`](https://syssec.run/pin/group__INS__INSTRUMENTATION.html#gaea02f152d3515f4758b8f979a380da09) accepts variable length arguments, I passed `IARG_MEMORYWRITE_EA` and `IARG_CONST_CONTEXT`.

`IARG_MEMORYWRITE_EA` will be used to check if the address is between GOT.

`IARG_CONST_CONTEXT` will be used to check if the function name is `_dl_rtld_di_serinfo`, which is the only legitimate function to overwrite GOT in this problem.

### Check memory range && Check if the instruction is `_dl_rtld_di_serinfo`

Check the memory. If it is at the outside of GOT, that's OK.

```c++
  auto isInsideGOT = (void *)lowAddr <= write_ea && write_ea <= (void *)highAddr;
  if (!isInsideGOT) {
    return;
  }
```

Check the instruction. If the instruction is legitimate, mark the flag.

```c++
  void *buf[128];
  PIN_LockClient();
  PIN_Backtrace(ctxt, buf, sizeof(buf) / sizeof(buf[0]));
  PIN_UnlockClient();
  auto isGotOverwrittenLegitimately = false;
  for (size_t i = 0; i < (size_t)sizeof(buf) / sizeof(buf[0]); ++i)
  {
    auto addrint = VoidStar2Addrint(buf[i]);
    auto function_name = RTN_FindNameByAddress(addrint);
    if (function_name == legitimateOverwriter)
    {
      isGotOverwrittenLegitimately = true;
    }
  }
```

### Insert an instruction to prevent from being run

Insert `PIN_ExitProcess(2)` and stop the program unless the program does not meet the requirements.

```c++
  if (!isGotOverwrittenLegitimately) {
    OutFile << "Suspicious attack detected at: " << VoidStar2Addrint(write_ea) << endl;
    PIN_ExitProcess(2);
  }
```

### Test

This is how to run the program.

```bash
make -e obj-intel64/part3.so
pin -t obj-intel64/part3.so -- <program_to_execute>
```

In the case of running exploit program:

```bash
./test_defense_0.py # for aw0-64
./test_defense_1.py # for aw-64
```

When you run `/bin/ls`, it successfully list its files.

```bash
TXK220008@ctf-vm1:~/unit3/0-aw0-64$ pin -t obj-intel64/part3.so -- /bin/ls
aw0-64    aw0-64.out  core         flag      obj-intel64  part2.cpp  part3.cpp  pin.log      readelf.c  run.sh  test_defense.py
aw0-64.c  aw0-64.txt  exploit1.py  Makefile  part2        part2.o    part3.out  pintool.log  README.md  t
```

Its logging file shows it successfully ends.

```txt
Range: 6414360 - 6415248
Fini: 0x61e018 0x61e390 

```

When you run with `aw0-64`, it cannot get the flag.

```bash
TXK220008@ctf-vm1:~/unit3/0-aw0-64$ ./test_defense.py 
[*] '/home/TXK220008/unit3/0-aw0-64/aw0-64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/usr/local/pin/pin': pid 9556
[*] target: 0x40088c
./test_defense.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil("bytes)?\n"))
b'This function will read your input for N bytes and then write them to an address A.\nHow many bytes do you want to write (N, in decimal, max 128 bytes)?\n'
./test_defense.py:22: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("6")
./test_defense.py:25: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil(")?\n"))
b'What is the address that you want to write (A, in hexadexmial, e.g., 0xffffde01)?\n'
./test_defense.py:26: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(hex(printf_got))
./test_defense.py:29: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil("bytes)\n"))
b'Please provide your input (MAX 6 bytes)\n'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ cat flag
[*] Process '/usr/local/pin/pin' stopped with exit code 2 (pid 9556)
[*] Got EOF while sending in interactive
Traceback (most recent call last):
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/process.py", line 746, in close
    fd.close()
BrokenPipeError: [Errno 32] Broken pipe
```

And the logging file shows that there was a suspicious attack.

```txt
Range: 6299672 - 6299752
Suspicious attack detected at: 6299688
```

When you run with `aw-64`, it cannot get the flag.

```bash
TXK220008@ctf-vm1:~/unit3/1-aw-64$ ./test_defense.py 
[*] '/home/TXK220008/unit3/1-aw-64/aw-64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/usr/local/pin/pin': pid 11023
[*] '/lib/x86_64-linux-gnu/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
./test_defense.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil("decimal)?\n"))
b'This function will read N bytes from address A and print them\nHow many bytes do you want to read (N, in decimal)?\n'
./test_defense.py:25: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(read_size)
./test_defense.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil("01)?\n"))
b'What is the address that you want to read (A, in hexadexmial, e.g., 0xffffde01)?\n'
./test_defense.py:28: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(hex(printf_got))
b'Reading 8 bytes from 0x602028\n'
[*] printf_real_addr: 0x7f1717793810
[*] target: 0x7f17177833a0
./test_defense.py:45: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil("bytes)?\n"))
b'This function will read your input for N bytes and then write them to an address A.\nHow many bytes do you want to write (N, in decimal, max 128 bytes)?\n'
./test_defense.py:46: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("16")
./test_defense.py:48: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil(")?\n"))
b'What is the address that you want to write (A, in hexadexmial, e.g., 0xffffde01)?\n'
./test_defense.py:49: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(hex(printf_got))
./test_defense.py:53: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil("bytes)"))
Traceback (most recent call last):
  File "./test_defense.py", line 53, in <module>
    print(p.recvuntil("bytes)"))
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/tube.py", line 333, in recvuntil
    res = self.recv(timeout=self.timeout)
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/tube.py", line 105, in recv
    return self._recv(numb, timeout) or b''
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/tube.py", line 183, in _recv
    if not self.buffer and not self._fillbuffer(timeout):
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/tube.py", line 154, in _fillbuffer
    data = self.recv_raw(self.buffer.get_fill_size())
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/process.py", line 686, in recv_raw
    raise EOFError
EOFError
[*] Process '/usr/local/pin/pin' stopped with exit code 2 (pid 11023)
```

And the logging file shows that there was a suspicious attack.

```txt
Range: 6299672 - 6299768
Suspicious attack detected at: 6299688
```
