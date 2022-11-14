# Unit4

## Problem Statement

**NOTE:** You will connect to and use `ctf-vm1.utdallas.edu` for this assignment. You can either directly connect to the host from UTD network or `ssh <netid>@syssec.run -p 2201` from the public network.

In this homework you will implement a basic form of [binary translator] for Intel architecture that would instrument [single](isPrime.c) [argument](fib.c) [functions](fibp.c). The main focus is in three folds. We want to learn (1) basic principles of software-based virtualization and instrumentation techniques, (2) CISC instruction decoding and disassembly techniques Intel architecture (i386/AMD64), and (3) profiling and monitoring the guest code behavior by instrumenting [inline monitors] on-the-fly.

The unit provides [skeleton codes] to implement a minimal binary translator for Intel architecture. In summary, your implementation will (1) Intel instruction decoder decode instruction, (2) patch the branch (or control) instruction to switch into callout context, (3) profile program execution at runtime, and (4) apply an optimization.

Although the assignment is tested and verified for GCC compilers in ctf-vm1 (version 5.4 and 7.3), the other environmental factors may affect compilers to generate different machine instruction sequences, resulting in runtime failures. Please feel free to consult the instructor or TA regarding such issues.

### Preliminaries

Again, you will begin the lab by building and running the provided skeleton code. Then, you will incrementally extend it in the course of completing each part. Two recursive functions with no [side effects] ([Fibonacci](fib.c) and [isPrime](isprime.c)), written in plain C, are provided to test your binary translator. Fibonacci comes in with two different implementations, recursive [fib.c](fib.c) and iterative [fibp.c](fibp.c) versions.

Both functions have signatures that take a single integer argument, return an integer with no side effects. Inside the main driver code [lab4.c](lab.c), all functions are alias as `int64_t user_prog(void *)`. While all functions take a single argument, we need to support two different ways to pass the argument(s). [fib.c](fib.c) takes an integer argument and returns an integer value. [fibp.c](fibp.c) takes input in pointer type to support variable-length arguments. We use the `void*` type to indicate generic input types.

To test each function, first, copy the template code located in `/home/labs/unit4/lab4.zip` from your ctf-vm1 and run the following.

```bash
# Fibonacci functions.
$ make fib
$ ./lab4_fib

$ make fibp
$ ./lab4_fibp

$ make prime
$ ./lab4_prime
```

- [x] `./lab4_fib`
- [x] `./lab4_fibp`
- [x] `./lab4_prime`

### Submission guideline

This assignment will be due at 11:59 PM, Nov 18. To submit the assignment, you will extend the provided skeleton codes to implement a solution for each part. Please do not forget to write a README.md document to explain your code and
solution.

```txt
<netid>-lab04/
├── Lab4-1/
├── Lab4-2/
├── Lab4-3/
├── Lab4-4/
├── Lab4-5/
└── README.md
```

## Lab4-1: Patching binary to return (20 pt)

### Problem Statement 4-1

The first step will get you warmed up and comfortable with code patching. Look at the bottom of `main()`. Just before main calls `user_prog()`, it calls `StartProfiling()` which is your hook. It allows you to inspect and/or modify the target function, `user_prog()` in this case before it starts executing. Your objective is to use `StartProfiling()` to binary patch `user_prog()` to return immediately.  It gives you and opportunity to inspect and/or modify the target function, `user_prog()` in this case, before it starts  executing. Your objective in Part1 is to use StartProfiling to binary patch `user_prog()` to *immediately return*.

### Write-up 4-1

To return the function immediately, insert this function in `StartProfiling`. This function makes the first instruction the `ret` instruction, which results in an immediate return.

```c
void ReturnImmediately(void *func) { ((uint32_t *)func)[0] = 0xc3; }

void StartProfiling(void *func) { ReturnImmediately(func); }
```

## Lab4-2: Callout and return (20 pt)

### Problem Statement 4-2

In this step you should accomplish the same thing as Part0x01 but this time using [a callout][glue-IA32] that emulates function return. The trickiness is that they need to save all the registers (EAX, EBX ...) and condition registers (EFLAGS for Intel) because the code was not expecting a callout. The normal `gcc` calling conventions are not sufficient. Find the glue code in [ia32_callout.S][glue-IA32].

You should *patch* the first instruction on `user_prog()` with a callout. The callout should emulate the behavior of the function return behavior by returning not to the calling site of the callout (which is the normal behavior) but directly to the return PC on the stack.

### info

**[Hint]** You will patch *user_prog()* to call [glue code][glue-IA32]. What is the format for `call` instruction?

Try to add and run an aritrary code from the callout context by replacing *NOT_IMPLEMENTED()* inside *handleRetCallout()* with something else.

### Write-up 4-2

## Lab4-3: IA32 Instruction Decode (30 pt)

The goal of this step is to use *[StartProfiling()]* to decode a block of instructions. You need only to decode enough of each instruction to determine its length. By doing this you should be able to decode a block of instructions of arbitrary length. *[StartProfiling()]* should print the address, opcode, and length of instructions for *[user_prog()]* until it encounters `ret` (0xc9) instruction.

Due to the complexity of Intel ISA being CISC, the core challenge for the part is to get the right length for each instruction. On the other hand, it is simpler than ARM architecture as it has limited set of instructions which make control (branch) operations. To help you on this, we provide IA32 opcode map in *[ia32DecodeTable]*. Use it as you see fit. Or if you find any instruction not covered by the map, please feel free to update the table.

The following is the sample output.

```txt
input number: 10
addr 0x8049310, opcode: 55, len: 1, isCFlow: false
addr 0x8049311, opcode: 89, len: 2, isCFlow: false
addr 0x8049313, opcode: 57, len: 1, isCFlow: false
addr 0x8049314, opcode: 56, len: 1, isCFlow: false
addr 0x8049315, opcode: 53, len: 1, isCFlow: false
addr 0x8049316, opcode: 51, len: 1, isCFlow: false
addr 0x8049317, opcode: 8d, len: 3, isCFlow: false
addr 0x804931a, opcode: 89, len: 2, isCFlow: false
addr 0x804931c, opcode: 83, len: 3, isCFlow: false
addr 0x804931f, opcode: 77, len: 2, isCFlow: true
addr 0x8049321, opcode: 8b, len: 2, isCFlow: false
addr 0x8049323, opcode: ba, len: 5, isCFlow: false
addr 0x8049328, opcode: eb, len: 2, isCFlow: true
addr 0x804932a, opcode: 8b, len: 2, isCFlow: false
addr 0x804932c, opcode: 83, len: 3, isCFlow: false
addr 0x804932f, opcode: 50, len: 1, isCFlow: false
addr 0x8049330, opcode: e8, len: 5, isCFlow: true
addr 0x8049335, opcode: 83, len: 3, isCFlow: false
addr 0x8049338, opcode: 89, len: 2, isCFlow: false
addr 0x804933a, opcode: 89, len: 2, isCFlow: false
addr 0x804933c, opcode: 8b, len: 2, isCFlow: false
addr 0x804933e, opcode: 83, len: 3, isCFlow: false
addr 0x8049341, opcode: 50, len: 1, isCFlow: false
addr 0x8049342, opcode: e8, len: 5, isCFlow: true
addr 0x8049347, opcode: 83, len: 3, isCFlow: false
addr 0x804934a, opcode: 1, len: 2, isCFlow: false
addr 0x804934c, opcode: 11, len: 2, isCFlow: false
addr 0x804934e, opcode: 8d, len: 3, isCFlow: false
addr 0x8049351, opcode: 59, len: 1, isCFlow: false
addr 0x8049352, opcode: 5b, len: 1, isCFlow: false
addr 0x8049353, opcode: 5e, len: 1, isCFlow: false
addr 0x8049354, opcode: 5f, len: 1, isCFlow: false
addr 0x8049355, opcode: 5d, len: 1, isCFlow: false
addr 0x8049356, opcode: c3, len: 1, isCFlow: true
```

## Lab4-4: Control flow following and program profiling (50 pt)

You should now have the tools to identify the control (or branch) instructions and follow the control flow of IA32 architecture. With this, you will extend [lab4.c] to implement the same binary patching / unpatching operations you did for the previous lab. Again, decode the instructions to be executed until you hit a control flow instruction. Binary patch that instruction to call you instead of doing the control flow. You can then return to the code knowing that you will be called before execution passes that point. When your handler is called, unpatch the instruction, emulate its behavior, and binary patch the end of the following basic block. For each basic block you encounter, dump the instructions in that block in the same format as Lab3-3. You should stop this process when you hit the `StopProfiling()` function. Create a data structure to capture the start address of each basic block executed and the number of instructions. Run target program  (`user_prog()`) with different inputs and check the number of instructions (and basic blocks) executions.

## Lab4-5: Memoizer (30 pt)

As you have seen from the profiling result (Lab4-4), the runtime cost of the recursive program (fib.c) exponentially grows as the input increase. To improve the runtime performance, you will optimize the runtime performance by extending the binary patcher by reducing the number of overlapping computations. We will implement the [memoization] by keeping track of the input argument and return value pairs.

To implement, you need to extend both Call and Ret handlers to observe input and ret values and associate them. For each function call, you will first check the global cache area for the stored result from the previous runs. If found, you will immediately return the cached value, or you will proceed to run the function body.

**NOTE**: This assignment is for [fib.c] and [isPrime.c] not for [fibp.c].

## Resources

You may find this reference helpful for PC assembly language programming. You will need the [Intel IA32 manuals] for exact instruction formats and decoding rules. You can find them here:

- [Volume 1]
- [Volume 2]

[binary translator]:https://dl.acm.org/doi/10.1145/3321705.3329819
[skeleton codes]:https://files.syssec.org/lab4.zip
[side effects]:https://en.wikipedia.org/wiki/Side_effect_(computer_science)
[inline monitors]:https://files.syssec.org/0907-mm.pdf

[Intel IA32 manuals]:https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
[Volume 1]:https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf
[Volume 2]:https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf

[lab4.c]:lab4.c
[fibp.c]:fibp.c
[isPrime.c]:isPrime.c
[fib.c]:fib.c
[user_prog()]:lab4.c#L21
[StartProfiling()]:lab4.c#L84
[ia32DecodeTable]:ia32_disas.c
[memoization]:https://en.wikipedia.org/wiki/Memoization

[glue-IA32]:ia32_callout.S
