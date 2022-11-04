# Part-0: Your first binary instrumentation (10 pt)

## Problem statement

```txt
Extend the inscount example and count the number of memory write instructions.
```

## How to run

- If you do not have a directory called `obj-intel64`, create it.

  ```bash
  mkdir obj-intel64
  ```

- Run and output the count

  ```bash
  make -e obj-intel64/inscount.so
  pin -t obj-intel64/inscount.so -- /bin/ls
  cat inscount.out
  ```

## write-up

Intel Pin has an API called `INS_MemoryOperandIsWritten` to check if an instruction writes a memory. Use this API to count the number of memory writes.

The overall procedures are in [`inscount.cpp`](./inscount.cpp).
