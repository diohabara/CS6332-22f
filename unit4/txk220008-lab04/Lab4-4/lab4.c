#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ia32_context.h"
#include "ia32_disas.h"
#include "macros.h"

/* addresses of asm callout glue code */

extern void *jccCallout;
extern void *jmpCallout;
extern void *callCallout;
extern void *retCallout;

extern uint32_t ia32DecodeTable[]; /* see below */

/* user-defined macros */
// ref: https://stackoverflow.com/a/3219471/10210870
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"
// for cache
#define CACHE_SIZE 1024

/* user-defined */
// cache for fib
uint32_t depth_to_value[CACHE_SIZE];
// depth of the call stack
int32_t depth = 0;
// {jne: 0x01, ja: 0x2, jle: 0x3}
uint8_t jcc_flag = 0x00000000;
// buffer to store the address for patching/unpatching
int8_t control_buffer[5];
// total number of basic blocks
uint32_t total_block_size = 0;
void *last_patched_address;
void *next_to_patch_address;
void ia32Decode(uint8_t *ptr, IA32Instr *instr);
void SaveInstructionsInBuffer(void);
void RestoreInstructionsFromBuffer(void);
void CallOffset(void *func, int32_t offset);
void PatchToPrintDecodedInstructions(void *func);

/* instrumentation target */

extern int user_prog(void *a);

void StartProfiling(void *func);

void StopProfiling(void);

void ia32Decode(uint8_t *ptr, IA32Instr *instr);

void *callTarget;

/*********************************************************************
 *
 *  callout handlers
 *
 *   These get called by asm glue routines.
 *
 *********************************************************************/

void handleJccCallout(SaveRegs regs) {
  total_block_size++;
  RestoreInstructionsFromBuffer();
  printf(ANSI_COLOR_GREEN "---JccCallout---\n" ANSI_COLOR_RESET);
  // ref: https://faydoc.tripod.com/cpu/ja.htm
  // jne: ZF=0
  // ja: CF=0 and ZF=0
  // jle: ZF=1 or SF<>OF
  void *nextInstr = next_to_patch_address;
  bool CF = regs.eflags & 1;
  bool ZF = regs.eflags >> 6 & 1;
  bool SF = regs.eflags >> 7 & 1;
  bool OF = regs.eflags >> 11 & 1;
  bool jneFlag = (ZF == 0);            // jump short if not equal (ZF=0)
  bool jaFlag = (CF == 0 && ZF == 0);  // jump short if above (CF=0 and ZF=0)
  bool jleFlag =
      (ZF == 1 || SF != OF);  // jump short if less or equal (ZF=1 or SF<>OF)
  if (jcc_flag == 0x1 && jneFlag) {
    nextInstr += control_buffer[1];
    jcc_flag = 0x0;
  }
  if (jcc_flag == 0x2 && jaFlag) {
    nextInstr += control_buffer[1];
    jcc_flag = 0x0;
  }
  if (jcc_flag == 0x3 && jleFlag) {
    nextInstr += control_buffer[1];
    jcc_flag = 0x0;
  }
  regs.pc = nextInstr;
  PatchToPrintDecodedInstructions(nextInstr);
}

void handleJmpCallout(SaveRegs regs) {
  total_block_size++;
  RestoreInstructionsFromBuffer();
  printf(ANSI_COLOR_YELLOW "---JmpCallout---\n" ANSI_COLOR_RESET);
  void *nextInstr = next_to_patch_address + control_buffer[1];
  regs.pc = nextInstr;
  PatchToPrintDecodedInstructions(nextInstr);
}

void handleCallCallout(SaveRegs regs) {
  total_block_size++;
  depth++;
  RestoreInstructionsFromBuffer();
  printf(ANSI_COLOR_BLUE "---CallCallout---\n" ANSI_COLOR_RESET);
  uint32_t offset;
  memcpy(&offset, control_buffer + 1, 4);
  callTarget = next_to_patch_address + offset;
  PatchToPrintDecodedInstructions(callTarget);
}

void handleRetCallout(SaveRegs regs) {
  total_block_size++;
  RestoreInstructionsFromBuffer();
  depth--;
  printf(ANSI_COLOR_MAGENTA "---RetCallout---\n" ANSI_COLOR_RESET);
  void *nextInstr = regs.retPC;
  if (nextInstr <= (void *)user_prog) {
    return;
  }
  PatchToPrintDecodedInstructions(nextInstr);
}

/*********************************************************************
 *
 *  ia32Decode
 *
 *   Decode an IA32 instruction.
 *
 *********************************************************************/

void ia32Decode(uint8_t *ptr, IA32Instr *instr) {
  // instruction layout
  // | prefix(1) | opcode(1-3) | ModR/M(1) | SIB(1) | displacement(1-4) |
  // immediate(1-4) |
  if (ptr == NULL || instr == NULL) {
    return;
  }
  uint8_t prefix = ptr[0];
  uint32_t prefixType = ia32DecodeTable[prefix];
  uint8_t decodedType = IA32_DECODE_TYPE(prefixType);
  instr->opcode = prefix;
  instr->isCFlow = prefixType & IA32_CFLOW;
  if (prefixType == 0 || prefixType & IA32_notimpl != 0 ||
      prefixType & IA32_PREFIX != 0) {
    instr->imm = 0;
    instr->len = 1;
    instr->modRM = 0;
    return;
  }
  uint8_t opcodeLength = 1;
  if (ptr[1] == 0x0f) {  // has 0x0f as an escape byte
    /** opcode layout
     * <op>
     * 0x0f <op>
     * 0x0f 0x38 <op>
     * 0x0f 0x3a <op>
     */
    if (ptr[2] == 0x38 || ptr[2] == 0x3a) {
      opcodeLength = 3;
      instr->opcode <<= 8;
      instr->opcode |= ptr[3];
    } else {
      opcodeLength = 2;
      instr->opcode <<= 8;
      instr->opcode |= ptr[2];
    }
  }
  bool hasModrm = prefixType & IA32_MODRM;
  bool hasSIB = false;
  uint8_t displacementLength = 0;
  if (hasModrm) {
    instr->modRM = ptr[opcodeLength];
    uint8_t mod = (instr->modRM >> 6) & 0b11;
    uint8_t reg = (instr->modRM >> 3) & 0b111;
    uint8_t rm = instr->modRM & 0b111;
    if (mod == 0b00) {
      if (rm == 0b100) {  // SIB needed
        hasSIB = true;
      } else if (rm == 0b101) {  // disp32 needed
        displacementLength = 4;
      }
    } else if (mod == 0b01) {  // disp8
      displacementLength = 1;
      if (rm == 0b100) {  // SIB needed
        hasSIB = true;
      }
    } else if (mod == 0b10) {  // disp32
      displacementLength = 4;
      if (rm == 0b100) {  // SIB needed
        hasSIB = true;
      }
    }
  }
  bool hasImm8 = prefixType & IA32_IMM8;
  bool hasImm32 = prefixType & IA32_IMM32;
  if (hasImm8) {
    instr->imm = ptr[opcodeLength + hasModrm + hasSIB + displacementLength];
    instr->len = opcodeLength + hasModrm + hasSIB + displacementLength + 1;
  } else if (hasImm32) {
    instr->imm = *(uint32_t *)(ptr + opcodeLength + hasModrm + hasSIB +
                               displacementLength);
    instr->len = opcodeLength + hasModrm + hasSIB + displacementLength + 4;
  } else {
    instr->imm = 0;
    instr->len = opcodeLength + hasModrm + hasSIB + displacementLength;
  }
}

/*********************************************************************
 *
 *  StartProfiling, StopProfiling
 *
 *   Profiling hooks. This is your place to inspect and modify the profiled
 *   function.
 *
 *********************************************************************/
void SaveInstructionsInBuffer() {
  memcpy(control_buffer, last_patched_address, 5);
}

void RestoreInstructionsFromBuffer() {
  memcpy(last_patched_address, control_buffer, 5);
}

void CallOffset(void *func, int32_t offset) {
  ((uint8_t *)func)[0] = 0xe8;
  memcpy((func + 1), &offset, 4);
}

void PatchToPrintDecodedInstructions(void *func) {
  IA32Instr instr = {false, 0, 0, 0, 0};
  void *currentAddress = func;
  while (true) {
    ia32Decode((uint8_t *)currentAddress, &instr);
    printf("addr %p, opcode: %x, len: %d, isCFlow: %s\n", currentAddress,
           instr.opcode, instr.len,
           instr.isCFlow ? ANSI_COLOR_GREEN "true" ANSI_COLOR_RESET
                         : ANSI_COLOR_RED "false" ANSI_COLOR_RESET);
    if (instr.isCFlow) {
      last_patched_address = currentAddress;
      next_to_patch_address = currentAddress + instr.len;
      SaveInstructionsInBuffer();
      void *callout;
      if (instr.opcode == 0x75 || instr.opcode == 0x77 ||
          instr.opcode == 0x7e) {    // jne/ja/jle
        if (instr.opcode == 0x75) {  // jne
          jcc_flag = 0x1;
        }
        if (instr.opcode == 0x77) {  // ja
          jcc_flag = 0x2;
        }
        if (instr.opcode == 0x7e) {  // jle
          jcc_flag = 0x3;
        }
        callout = &jccCallout;
      } else if (instr.opcode == 0xeb) {  // jmp
        callout = &jmpCallout;
      } else if (instr.opcode == 0xe8) {  // call
        callout = &callCallout;
      } else if (instr.opcode == 0xc3) {  // ret
        callout = &retCallout;
      }
      int32_t offset = (int32_t)callout - abs((int32_t)currentAddress + 5);
      CallOffset(currentAddress, offset);
      return;
    }
    currentAddress += instr.len;
  }
}

void StartProfiling(void *func) {
  printf(ANSI_COLOR_CYAN "---Profiling started---\n" ANSI_COLOR_RESET);
  memset(depth_to_value, 0, sizeof(depth_to_value));
  PatchToPrintDecodedInstructions(func);
}

void StopProfiling(void) {
  RestoreInstructionsFromBuffer();
  printf("total block size: %u\n", total_block_size);
  printf(ANSI_COLOR_CYAN "---Profiling stopped---\n" ANSI_COLOR_RESET);
}

int main(int argc, char *argv[]) {
  int value;
  char *end;

  char buf[16];

  if (argc != 1) {
    fprintf(stderr, "usage: %s\n", argv[0]);
    exit(1);
  }

#ifdef __FIB__
  printf("running fib()\n");
#endif

#ifdef __FIBP__
  printf("running fibp()\n");
#endif

#ifdef __PRIME__
  printf("running isPrime()\n");
#endif

  printf("input number: ");
  scanf("%15s", buf);

  value = strtol(buf, &end, 10);

  if (((errno == ERANGE) && ((value == LONG_MAX) || (value == LONG_MIN))) ||
      ((errno != 0) && (value == 0))) {
    perror("strtol");
    exit(1);
  }

  if (end == buf) {
    fprintf(stderr, "error: %s is not an integer\n", buf);
    exit(1);
  }

  if (*end != '\0') {
    fprintf(stderr, "error: junk at end of parameter: %s\n", end);
    exit(1);
  }

  StartProfiling(user_prog);

#if defined(__FIB__) || defined(__PRIME__)
  value = user_prog((void *)value);
#else
  value = user_prog(&value);
#endif

  StopProfiling();

  printf("%d\n", value);
  exit(0);
}
