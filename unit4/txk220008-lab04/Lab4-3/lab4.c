#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "ia32_context.h"
#include "ia32_disas.h"
#include "macros.h"

/* addresses of asm callout glue code */

extern void *jccCallout;
extern void *jmpCallout;
extern void *callCallout;
extern void *retCallout;

extern uint32_t ia32DecodeTable[]; /* see below */

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

void handleJccCallout(SaveRegs regs) { NOT_IMPLEMENTED(); }

void handleJmpCallout(SaveRegs regs) { NOT_IMPLEMENTED(); }

void handleCallCallout(SaveRegs regs) { NOT_IMPLEMENTED(); }

void handleRetCallout(SaveRegs regs) { printf("part2 done\n"); }

/*********************************************************************
 *
 *  ia32Decode
 *
 *   Decode an IA32 instruction.
 *
 *********************************************************************/

// TODO: part3
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
      } else {
      }
    } else if (mod == 0b01) {  // disp8
      displacementLength = 1;
      if (rm == 0b100) {  // SIB needed
        hasSIB = true;
      } else {
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

void ReturnImmediately(void *func) { ((uint32_t *)func)[0] = 0xc3; }

void ReturnImmediatelySafely(void *func) {
  uint32_t offset = (uint32_t)((void *)&retCallout - (func + 8));
  ((uint8_t *)func)[0] = 0x90;
  ((uint8_t *)func)[1] = 0x90;
  ((uint8_t *)func)[2] = 0x90;
  ((uint8_t *)func)[3] = 0xe8;
  ((uint32_t *)func)[1] = offset;
}

// TODO: part3
void PrintDecodedInstructions(void *func) {
  while (true) {
    IA32Instr instr;
    ia32Decode((uint8_t *)func, &instr);
    // addr 0x8049310, opcode: 55, len: 1, isCFlow: false
    printf("addr %p, opcode: %x, len: %d, isCFlow: %s\n", func, instr.opcode,
           instr.len, instr.isCFlow ? "true" : "false");
    if (instr.opcode == 0xc3) {  // stop if `ret` comes
      break;
    }
    func += instr.len;
  }
}

void StartProfiling(void *func) {
  // TODO: part3
  PrintDecodedInstructions(func);
}

void StopProfiling(void) {}

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
