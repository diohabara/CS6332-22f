# Part-0: Your first binary instrumentation (10 pt)

## Problem statement

```
Extend the inscount example and count the number of memory write instructions.
```

## How to run

- Run & Build

```bash
./run.sh
```

## write-up

Intel Pin has an API called `INS_MemoryOperandIsWritten` to check if an instruction is writing a memory. Use this and count the number.

The overall procedures are in [`inscount.cpp`](./inscount.cpp).
