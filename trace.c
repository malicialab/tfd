/* 
 *  generation of trace files v60
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"
#include <stdio.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>
#include <inttypes.h>
#include "DECAF_main.h"
#include "trace.h"
#include "operandinfo.h"
#include <xed-interface.h>

/* Map to convert register numbers */
int regmapping[] = { -1, -1, -1, -1, -1, -1, -1, -1,
  R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI,
  R_EAX, R_ECX, R_EDX, R_EBX, R_EAX, R_ECX, R_EDX, R_EBX,
  R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI,
  R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI
};

/* Map from XED register numbers to
    0) Christopher's register numbers
    1) Regnum
    2) Registry size in bytes
*/
int xed2chris_regmapping[][3] = {
/* XED_REG_INVALID */ {-1, -1, -1},
/* XED_REG_CR0 */ {-1, -1, -1},
/* XED_REG_CR1 */ {-1, -1, -1},
/* XED_REG_CR2 */ {-1, -1, -1},
/* XED_REG_CR3 */ {-1, -1, -1},
/* XED_REG_CR4 */ {-1, -1, -1},
/* XED_REG_CR5 */ {-1, -1, -1},
/* XED_REG_CR6 */ {-1, -1, -1},
/* XED_REG_CR7 */ {-1, -1, -1},
/* XED_REG_CR8 */ {-1, -1, -1},
/* XED_REG_CR9 */ {-1, -1, -1},
/* XED_REG_CR10 */ {-1, -1, -1},
/* XED_REG_CR11 */ {-1, -1, -1},
/* XED_REG_CR12 */ {-1, -1, -1},
/* XED_REG_CR13 */ {-1, -1, -1},
/* XED_REG_CR14 */ {-1, -1, -1},
/* XED_REG_CR15 */ {-1, -1, -1},
/* XED_REG_DR0 */ {-1, -1, -1},
/* XED_REG_DR1 */ {-1, -1, -1},
/* XED_REG_DR2 */ {-1, -1, -1},
/* XED_REG_DR3 */ {-1, -1, -1},
/* XED_REG_DR4 */ {-1, -1, -1},
/* XED_REG_DR5 */ {-1, -1, -1},
/* XED_REG_DR6 */ {-1, -1, -1},
/* XED_REG_DR7 */ {-1, -1, -1},
/* XED_REG_DR8 */ {-1, -1, -1},
/* XED_REG_DR9 */ {-1, -1, -1},
/* XED_REG_DR10 */ {-1, -1, -1},
/* XED_REG_DR11 */ {-1, -1, -1},
/* XED_REG_DR12 */ {-1, -1, -1},
/* XED_REG_DR13 */ {-1, -1, -1},
/* XED_REG_DR14 */ {-1, -1, -1},
/* XED_REG_DR15 */ {-1, -1, -1},
/* XED_REG_FLAGS */ {-1, -1, -1},
// Change this line to introduce eflags as an operand
/* XED_REG_EFLAGS */ {-1, -1, -1}, //{eflags_reg, R_EFLAGS},
/* XED_REG_RFLAGS */ {-1, -1, -1},
/* XED_REG_AX */ {ax_reg, R_EAX, 2},
/* XED_REG_CX */ {cx_reg, R_ECX, 2},
/* XED_REG_DX */ {dx_reg, R_EDX, 2},
/* XED_REG_BX */ {bx_reg, R_EBX, 2},
/* XED_REG_SP */ {sp_reg, R_ESP, 2},
/* XED_REG_BP */ {bp_reg, R_EBP, 2},
/* XED_REG_SI */ {si_reg, R_ESI, 2},
/* XED_REG_DI */ {di_reg, R_EDI, 2},
/* XED_REG_R8W */ {-1, -1, -1},
/* XED_REG_R9W */ {-1, -1, -1},
/* XED_REG_R10W */ {-1, -1, -1},
/* XED_REG_R11W */ {-1, -1, -1},
/* XED_REG_R12W */ {-1, -1, -1},
/* XED_REG_R13W */ {-1, -1, -1},
/* XED_REG_R14W */ {-1, -1, -1},
/* XED_REG_R15W */ {-1, -1, -1},
/* XED_REG_EAX */ {eax_reg, R_EAX, 4},
/* XED_REG_ECX */ {ecx_reg, R_ECX, 4},
/* XED_REG_EDX */ {edx_reg, R_EDX, 4},
/* XED_REG_EBX */ {ebx_reg, R_EBX, 4},
/* XED_REG_ESP */ {esp_reg, R_ESP, 4},
/* XED_REG_EBP */ {ebp_reg, R_EBP, 4},
/* XED_REG_ESI */ {esi_reg, R_ESI, 4},
/* XED_REG_EDI */ {edi_reg, R_EDI, 4},
/* XED_REG_R8D */ {-1, -1, -1},
/* XED_REG_R9D */ {-1, -1, -1},
/* XED_REG_R10D */ {-1, -1, -1},
/* XED_REG_R11D */ {-1, -1, -1},
/* XED_REG_R12D */ {-1, -1, -1},
/* XED_REG_R13D */ {-1, -1, -1},
/* XED_REG_R14D */ {-1, -1, -1},
/* XED_REG_R15D */ {-1, -1, -1},
/* XED_REG_RAX */ {-1, -1, -1},
/* XED_REG_RCX */ {-1, -1, -1},
/* XED_REG_RDX */ {-1, -1, -1},
/* XED_REG_RBX */ {-1, -1, -1},
/* XED_REG_RSP */ {-1, -1, -1},
/* XED_REG_RBP */ {-1, -1, -1},
/* XED_REG_RSI */ {-1, -1, -1},
/* XED_REG_RDI */ {-1, -1, -1},
/* XED_REG_R8 */ {-1, -1, -1},
/* XED_REG_R9 */ {-1, -1, -1},
/* XED_REG_R10 */ {-1, -1, -1},
/* XED_REG_R11 */ {-1, -1, -1},
/* XED_REG_R12 */ {-1, -1, -1},
/* XED_REG_R13 */ {-1, -1, -1},
/* XED_REG_R14 */ {-1, -1, -1},
/* XED_REG_R15 */ {-1, -1, -1},
/* XED_REG_AL */ {al_reg, R_EAX, 1},
/* XED_REG_CL */ {cl_reg, R_ECX, 1},
/* XED_REG_DL */ {dl_reg, R_EDX, 1},
/* XED_REG_BL */ {bl_reg, R_EBX, 1},
/* XED_REG_SPL */ {-1, -1, -1},
/* XED_REG_BPL */ {-1, -1, -1},
/* XED_REG_SIL */ {-1, -1, -1},
/* XED_REG_DIL */ {-1, -1, -1},
/* XED_REG_R8B */ {-1, -1, -1},
/* XED_REG_R9B */ {-1, -1, -1},
/* XED_REG_R10B */ {-1, -1, -1},
/* XED_REG_R11B */ {-1, -1, -1},
/* XED_REG_R12B */ {-1, -1, -1},
/* XED_REG_R13B */ {-1, -1, -1},
/* XED_REG_R14B */ {-1, -1, -1},
/* XED_REG_R15B */ {-1, -1, -1},
/* XED_REG_AH */ {ah_reg, R_EAX, 1},
/* XED_REG_CH */ {ch_reg, R_ECX, 1},
/* XED_REG_DH */ {dh_reg, R_EDX, 1},
/* XED_REG_BH */ {bh_reg, R_EBX, 1},
/* XED_REG_ERROR */ {-1, -1, -1},
/* XED_REG_RIP */ {-1, -1, -1},
/* XED_REG_EIP */ {-1, -1, -1},
/* XED_REG_IP */ {-1, -1, -1},
/* XED_REG_MMX0 */ {mmx0_reg, 0, 8},
/* XED_REG_MMX1 */ {mmx1_reg, 1, 8},
/* XED_REG_MMX2 */ {mmx2_reg, 2, 8},
/* XED_REG_MMX3 */ {mmx3_reg, 3, 8},
/* XED_REG_MMX4 */ {mmx4_reg, 4, 8},
/* XED_REG_MMX5 */ {mmx5_reg, 5, 8},
/* XED_REG_MMX6 */ {mmx6_reg, 6, 8},
/* XED_REG_MMX7 */ {mmx7_reg, 7, 8},
/* XED_REG_MXCSR */ {-1, -1, -1},
/* XED_REG_STACKPUSH */ {-1, -1, -1},
/* XED_REG_STACKPOP */ {-1, -1, -1},
/* XED_REG_GDTR */ {-1, -1, -1},
/* XED_REG_LDTR */ {-1, -1, -1},
/* XED_REG_IDTR */ {-1, -1, -1},
/* XED_REG_TR */ {-1, -1, -1},
/* XED_REG_TSC */ {-1, -1, -1},
/* XED_REG_TSCAUX */ {-1, -1, -1},
/* XED_REG_MSRS */ {-1, -1, -1},
/* XED_REG_X87CONTROL */ {fpu_control_reg, fpu_control_reg, 2},
/* XED_REG_X87STATUS */ {fpu_status_reg, fpu_status_reg, 2},
/* XED_REG_X87TOP */ {-1, -1, -1},
/* XED_REG_X87TAG */ {-1, -1, -1}, //{fpu_tag_reg, fpu_tag_reg, 2},
/* XED_REG_X87PUSH */ {-1, -1, -1},
/* XED_REG_X87POP */ {-1, -1, -1},
/* XED_REG_X87POP2 */ {-1, -1, -1},
/* XED_REG_CS */ {cs_reg, R_CS, 2},
/* XED_REG_DS */ {ds_reg, R_DS, 2},
/* XED_REG_ES */ {es_reg, R_ES, 2},
/* XED_REG_SS */ {ss_reg, R_SS, 2},
/* XED_REG_FS */ {fs_reg, R_FS, 2},
/* XED_REG_GS */ {gs_reg, R_GS, 2},
/* XED_REG_TMP0 */ {-1, -1, -1},
/* XED_REG_TMP1 */ {-1, -1, -1},
/* XED_REG_TMP2 */ {-1, -1, -1},
/* XED_REG_TMP3 */ {-1, -1, -1},
/* XED_REG_TMP4 */ {-1, -1, -1},
/* XED_REG_TMP5 */ {-1, -1, -1},
/* XED_REG_TMP6 */ {-1, -1, -1},
/* XED_REG_TMP7 */ {-1, -1, -1},
/* XED_REG_TMP8 */ {-1, -1, -1},
/* XED_REG_TMP9 */ {-1, -1, -1},
/* XED_REG_TMP10 */ {-1, -1, -1},
/* XED_REG_TMP11 */ {-1, -1, -1},
/* XED_REG_TMP12 */ {-1, -1, -1},
/* XED_REG_TMP13 */ {-1, -1, -1},
/* XED_REG_TMP14 */ {-1, -1, -1},
/* XED_REG_TMP15 */ {-1, -1, -1},
/* XED_REG_ST0 */ {fpu_st0_reg, 0, 10},
/* XED_REG_ST1 */ {fpu_st1_reg, 1, 10},
/* XED_REG_ST2 */ {fpu_st2_reg, 2, 10},
/* XED_REG_ST3 */ {fpu_st3_reg, 3, 10},
/* XED_REG_ST4 */ {fpu_st4_reg, 4, 10},
/* XED_REG_ST5 */ {fpu_st5_reg, 5, 10},
/* XED_REG_ST6 */ {fpu_st6_reg, 6, 10},
/* XED_REG_ST7 */ {fpu_st7_reg, 7, 10},
/* XED_REG_XMM0 */ {xmm0_reg, 0, 16},
/* XED_REG_XMM1 */ {xmm1_reg, 1, 16},
/* XED_REG_XMM2 */ {xmm2_reg, 2, 16},
/* XED_REG_XMM3 */ {xmm3_reg, 3, 16},
/* XED_REG_XMM4 */ {xmm4_reg, 4, 16},
/* XED_REG_XMM5 */ {xmm5_reg, 5, 16},
/* XED_REG_XMM6 */ {xmm6_reg, 6, 16},
/* XED_REG_XMM7 */ {xmm7_reg, 7, 16},
/* XED_REG_XMM8 */ {xmm8_reg, 8, 16},
/* XED_REG_XMM9 */ {xmm9_reg, 9, 16},
/* XED_REG_XMM10 */ {xmm10_reg, 10, 16},
/* XED_REG_XMM11 */ {xmm11_reg, 11, 16},
/* XED_REG_XMM12 */ {xmm12_reg, 12, 16},
/* XED_REG_XMM13 */ {xmm13_reg, 13, 16},
/* XED_REG_XMM14 */ {xmm14_reg, 14, 16},
/* XED_REG_XMM15 */ {xmm15_reg, 15, 16},
/* XED_REG_YMM0 */ {-1, -1, -1},
/* XED_REG_YMM1 */ {-1, -1, -1},
/* XED_REG_YMM2 */ {-1, -1, -1},
/* XED_REG_YMM3 */ {-1, -1, -1},
/* XED_REG_YMM4 */ {-1, -1, -1},
/* XED_REG_YMM5 */ {-1, -1, -1},
/* XED_REG_YMM6 */ {-1, -1, -1},
/* XED_REG_YMM7 */ {-1, -1, -1},
/* XED_REG_YMM8 */ {-1, -1, -1},
/* XED_REG_YMM9 */ {-1, -1, -1},
/* XED_REG_YMM10 */ {-1, -1, -1},
/* XED_REG_YMM11 */ {-1, -1, -1},
/* XED_REG_YMM12 */ {-1, -1, -1},
/* XED_REG_YMM13 */ {-1, -1, -1},
/* XED_REG_YMM14 */ {-1, -1, -1},
/* XED_REG_YMM15 */ {-1, -1, -1},
/* XED_REG_LAST */ {-1, -1, -1},
/* XED_REG_CR_FIRST */ {-1, -1, -1},
/* XED_REG_CR_LAST */ {-1, -1, -1},
/* XED_REG_DR_FIRST */ {-1, -1, -1},
/* XED_REG_DR_LAST */ {-1, -1, -1},
/* XED_REG_FLAGS_FIRST */ {-1, -1, -1},
/* XED_REG_FLAGS_LAST */ {-1, -1, -1},
/* XED_REG_GPR16_FIRST */ {-1, -1, -1},
/* XED_REG_GPR16_LAST */ {-1, -1, -1},
/* XED_REG_GPR32_FIRST */ {-1, -1, -1},
/* XED_REG_GPR32_LAST */ {-1, -1, -1},
/* XED_REG_GPR64_FIRST */ {-1, -1, -1},
/* XED_REG_GPR64_LAST */ {-1, -1, -1},
/* XED_REG_GPR8_FIRST */ {-1, -1, -1},
/* XED_REG_GPR8_LAST */ {-1, -1, -1},
/* XED_REG_GPR8H_FIRST */ {-1, -1, -1},
/* XED_REG_GPR8H_LAST */ {-1, -1, -1},
/* XED_REG_INVALID_FIRST */ {-1, -1, -1},
/* XED_REG_INVALID_LAST */ {-1, -1, -1},
/* XED_REG_IP_FIRST */ {-1, -1, -1},
/* XED_REG_IP_LAST */ {-1, -1, -1},
/* XED_REG_MMX_FIRST */ {-1, -1, -1},
/* XED_REG_MMX_LAST */ {-1, -1, -1},
/* XED_REG_MXCSR_FIRST */ {-1, -1, -1},
/* XED_REG_MXCSR_LAST */ {-1, -1, -1},
/* XED_REG_PSEUDO_FIRST */ {-1, -1, -1},
/* XED_REG_PSEUDO_LAST */ {-1, -1, -1},
/* XED_REG_SR_FIRST */ {-1, -1, -1},
/* XED_REG_SR_LAST */ {-1, -1, -1},
/* XED_REG_TMP_FIRST */ {-1, -1, -1},
/* XED_REG_TMP_LAST */ {-1, -1, -1},
/* XED_REG_X87_FIRST */ {-1, -1, -1},
/* XED_REG_X87_LAST */ {-1, -1, -1},
/* XED_REG_XMM_FIRST */ {-1, -1, -1},
/* XED_REG_XMM_LAST */ {-1, -1, -1},
/* XED_REG_YMM_FIRST */ {-1, -1, -1},
/* XED_REG_YMM_LAST */ {-1, -1, -1},
};

/* Buffer to store instructions */
char filebuf[FILEBUFSIZE];

/* Trace statistics */
struct trace_stats tstats = {0};

/* This flags we might want to put as part of the EntryHeader without 
 * writing to file */
int insn_already_written = 0;
int is_duplicated_insn = 0;

/* Variables to keep disassembler state */
static xed_state_t dstate;
static xed_decoded_inst_t xedd;

/* Variable to signal that only writing certain thread (ignore if -1) */
uint32_t tid_to_trace = -1;

/* Store eflags register index */
int eflags_idx = -1;

/* Store address of last instruction decoded */
uint32_t last_decoded_insn_address = 0;

/* Current trace */
FILE * curr_trace = NULL;

/* Function prototypes */
unsigned int write_operand(FILE *stream, OperandVal op);
void clear_trace_stats(void);



/* XED2 initialization */
void xed2_init(void) {
  xed_tables_init ();
  xed_state_zero (&dstate);

  xed_state_init(&dstate,
    XED_MACHINE_MODE_LEGACY_32,
    XED_ADDRESS_WIDTH_32b,
    XED_ADDRESS_WIDTH_32b);
}

/* Print the statistics variables */
void print_trace_stats(void) {
  monitor_printf(default_mon, "Number of instructions decoded: %" PRIu64 "\n",
    tstats.insn_counter_decoded);
  monitor_printf(default_mon, "Number of operands decoded: %" PRIu64 "\n",
    tstats.operand_counter);
  monitor_printf(default_mon, "Number of instructions written to trace: %" 
                  PRIu64 "\n", tstats.insn_counter_traced);
  monitor_printf(default_mon, 
                  "Number of tainted instructions written to trace: %" PRIu64 
                  "\n",
                  tstats.insn_counter_traced_tainted);
}

/* Clear trace statistics */
void clear_trace_stats(void) {
  memset(&tstats, 0, sizeof(struct trace_stats));
}

/* Return the offset of the operand. Zero except for AH,BH,CH,DH that is one */
FILE * open_trace(CPUState * env, const char * filename, ProcRecord * pr) {
  FILE * trace; 
 
  /* Check parameters */ 
  if (!env || !filename || !pr) {
    return NULL;
  }

  /* If previous trace did not close properly, close it now */
  if (curr_trace) {
    close_trace(curr_trace, NULL, 0);
  }

  /* Open trace file */
  trace = fopen(filename, "w");
  if (!trace)
    return NULL;

  /* Set trace buffer size */
  setvbuf(trace, filebuf, _IOFBF, FILEBUFSIZE);

  /* Write the trace header */
  TraceHeader th;
  th.magicnumber = MAGIC_NUMBER;
  th.version = VERSION_NUMBER;
  th.n_procs = 1;
  th.gdt_base = (&env->gdt)->base;
  th.idt_base = (&env->idt)->base;
  fwrite(&th, sizeof(th), 1, trace);

  /* Write process info */
  fwrite(pr, PROC_REC_FIXED_SIZE, 1, trace);

  /* Write module info */
  fwrite(pr->mod_arr, sizeof(ModuleRecord), pr->n_mods, trace);

  /* Force header to be written */
  fflush(trace);

  /* Set current trace */
  curr_trace = trace;

  return trace;
}

inline int getOperandOffset (OperandVal *op) {
  if ((op->type == TRegister) && ((op->addr.reg_addr >= ah_reg) && 
      (op->addr.reg_addr <= bh_reg)))
    return 1;

  return 0;
}

/* Return the content of the FPU tag word */
/*
static uint32_t get_fpu_tag_word(CPUState* env) {
  uint32_t fptag = 0;
  unsigned int i;
  //uint64_t float_significand = 0;
  //uint16_t float_exponent = 0;

  for (i=7; i>=0; i--) {
    fptag <<= 2;
    if (env->fptags[i]) {
      fptag |= 3;
    }
    else {
      cpu_get_fp80(&float_significand,&float_exponent, 
                    ((FPReg *)(&(env->fpregs)))[i].d);
      if (float_exponent == 0 && float_significand == 0) {
        // zero
        fptag |= 1;
      } 
      else if ((float_exponent == 0) || 
               (float_exponent == 0x7fff) ||
               ((float_significand & (1LL << 63)) == 0)
      )
      {
        // NaNs, infinity, denormal
        fptag |= 2;
      }
    }
  }
  return fptag;
}
*/

/* This is the central function
  Given a memory address, reads a bunch of memory bytes and
    calls the disassembler to obtain the information
  Then it stores the information into the eh EntryHeader
*/
void decode_address(CPUState* env, uint32_t address, EntryHeader *eh, 
                    uint32_t pid, uint32_t tid, int ignore_taint)
{
  unsigned char insn_buf[MAX_INSN_BYTES];
  unsigned int is_stackpush = 0, is_stackpop = 0, is_x87push = 0;
  unsigned int fp_idx = 0;
  unsigned int stackpushpop_acc = 0;
  unsigned int add_fpus = 0;
  //unsigned int add_fputags = 0;
  int i;
  int op_idx = -1;
  int regnum = 0;

  /* Read instruction from guest memory */
  DECAF_read_mem(env, address, MAX_INSN_BYTES, insn_buf);

  /* Disassemble instruction buffer */
  xed_decoded_inst_zero_set_mode(&xedd, &dstate);
  xed_error_enum_t xed_error =
    xed_decode(&xedd, XED_STATIC_CAST(const xed_uint8_t*,insn_buf), 
                MAX_INSN_BYTES);
  xed_bool_t okay = (xed_error == XED_ERROR_NONE);
  if (!okay) return;

  // Increase counters
  tstats.insn_counter_decoded++;

  /* Check if duplicated instruction, i.e., 
      same address as previous insn and not REP/REPNE 
     This prevents writing twice instructions with exceptions */
  if (address == last_decoded_insn_address) {
    const xed_operand_values_t *xopv = 
      xed_decoded_inst_operands_const(&xedd);
    is_duplicated_insn = (xed_operand_values_has_real_rep(xopv) == 0);
  }
  else {
    is_duplicated_insn = 0;
  }

  // Save address
  last_decoded_insn_address = address;

  /* Clear out Entry header 
     This should not be needed if everything is initialized
     So, commenting it out for performance reasons 
  */
  //memset(eh, 0, sizeof(EntryHeader));

  /* Copy the address and instruction size */
  eh->address = address;
  uint16_t inst_size = xed_decoded_inst_get_length(&xedd);
  eh->inst_size = (inst_size <= MAX_INSN_BYTES) ? inst_size : MAX_INSN_BYTES;

  /* Set process identifier */
  eh->pid = pid;

  /* Set thread identifier */
  eh->tid = tid;

  /* Copy instruction rawbytes */
  memcpy(eh->rawbytes, insn_buf, eh->inst_size);

  /* Get the number of XED operands */
  const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
  int xed_ops = xed_inst_noperands(xi);

  /* Initialize eflags index */
  eflags_idx = -1;

  /* Initialize remaining fields in EntryHeader */
  eh->num_operands = 0;
  eh->tp = TP_NONE; /* Gets updated at tracing_taint_propagate */
  eh->eflags = 0;   /* Gets updated at insn_end */
  eh->df = 0;       /* Gets updated at insn_end */
  eh->cc_op = *(&env->cc_op);

  /* Get the category of the instruction */
  xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);

  /* Iterate over the XED operands */
  for(i = 0; i < xed_ops; i++) {
    if(op_idx >= MAX_NUM_OPERANDS)
      break;
    //assert(op_idx < MAX_NUM_OPERANDS);

    /* Get operand */
    const xed_operand_t* op = xed_inst_operand(xi,i);
    xed_operand_enum_t op_name = xed_operand_name(op);

    switch(op_name) {
      /* Register */
      case XED_OPERAND_REG0:
      case XED_OPERAND_REG1:
      case XED_OPERAND_REG2:
      case XED_OPERAND_REG3:
      case XED_OPERAND_REG4:
      case XED_OPERAND_REG5:
      case XED_OPERAND_REG6:
      case XED_OPERAND_REG7:
      case XED_OPERAND_REG8:
      case XED_OPERAND_REG9:
      case XED_OPERAND_REG10:
      case XED_OPERAND_REG11:
      case XED_OPERAND_REG12:
      case XED_OPERAND_REG13:
      case XED_OPERAND_REG14:
      case XED_OPERAND_REG15: {
        xed_reg_enum_t xed_regid = xed_decoded_inst_get_reg(&xedd, op_name);
        regnum = xed2chris_regmapping[xed_regid][1];

        // Special handling for Push/Pop
        if (xed_regid == XED_REG_STACKPUSH) is_stackpush = 1;
        else if (xed_regid == XED_REG_STACKPOP) is_stackpop = 1;
        else if (xed_regid == XED_REG_X87PUSH) is_x87push = 1;

        if (-1 == regnum)
          break;
        else {
          op_idx++;
          eh->num_operands++;
          eh->operand[op_idx].addr.reg_addr = 
            xed2chris_regmapping[xed_regid][0];
          eh->operand[op_idx].length = 
            xed2chris_regmapping[xed_regid][2];
            //(uint8_t) xed_decoded_inst_operand_length (&xedd, i);
          eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
          switch (eh->operand[op_idx].addr.reg_addr) {
            /* 32-bit general purpose registers */
            case eax_reg:
            case ebx_reg:
            case ecx_reg:
            case edx_reg:
            case ebp_reg:
            case esp_reg:
            case esi_reg:
            case edi_reg:
              eh->operand[op_idx].type = TRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val32 = env->regs[regnum];
              break;
            /* 16-bit general purpose registers */
            case ax_reg:
            case bx_reg:
            case cx_reg:
            case dx_reg:
            case bp_reg:
            case sp_reg:
            case si_reg:
            case di_reg:
              eh->operand[op_idx].type = TRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val32 = env->regs[regnum];
              eh->operand[op_idx].value.val32 &= 0xFFFF;
              break;
            /* 8-bit general purpose registers */
            case al_reg:
            case bl_reg:
            case cl_reg:
            case dl_reg:
              eh->operand[op_idx].type = TRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val32 = env->regs[regnum];
              eh->operand[op_idx].value.val32 &= 0xFF;
              break;
            case ah_reg:
            case bh_reg:
            case ch_reg:
            case dh_reg:
              eh->operand[op_idx].type = TRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val32 = env->regs[regnum];
              eh->operand[op_idx].value.val32 = 
                (eh->operand[i].value.val32 & 0xFF00) >> 8;
              break;
            /* Segment registers */
            case cs_reg:
            case ds_reg:
            case es_reg:
            case ss_reg:
            case fs_reg:
            case gs_reg:
              eh->operand[op_idx].type = TRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val32 = 
                env->segs[regnum].selector;
              eh->operand[op_idx].value.val32 &= 0xFFFF;
              break;
            /* MMX registers */
            case mmx0_reg:
            case mmx1_reg:
            case mmx2_reg:
            case mmx3_reg:
            case mmx4_reg:
            case mmx5_reg:
            case mmx6_reg:
            case mmx7_reg:
              eh->operand[op_idx].type = TMMXRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val64 = 
                ((FPReg *)(&(env->fpregs)))[regnum].mmx.q;
              break;
            case xmm0_reg:
            case xmm1_reg:
            case xmm2_reg:
            case xmm3_reg:
            case xmm4_reg:
            case xmm5_reg:
            case xmm6_reg:
            case xmm7_reg:
            case xmm8_reg:
            case xmm9_reg:
            case xmm10_reg:
            case xmm12_reg:
            case xmm13_reg:
            case xmm14_reg:
            case xmm15_reg:
              eh->operand[op_idx].type = TXMMRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.xmm_val._q[0] = 
                ((XMMReg *)(&(env->xmm_regs)))[regnum]._q[0];
              eh->operand[op_idx].value.xmm_val._q[1] = 
                ((XMMReg *)(&(env->xmm_regs)))[regnum]._q[1];
              break;
            /* Float data registers */
            case fpu_st0_reg:
            case fpu_st1_reg:
            case fpu_st2_reg:
            case fpu_st3_reg:
            case fpu_st4_reg:
            case fpu_st5_reg:
            case fpu_st6_reg:
            case fpu_st7_reg:
              add_fpus = 1;
              //add_fputags = 1;
              fp_idx = (*(&env->fpstt) + regnum) & 7;
              eh->operand[op_idx].type = TFloatRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.float_val = 
                ((FPReg *)(&(env->fpregs)))[fp_idx].d;
              // Operand address encodes both stack and hardware indices
              eh->operand[op_idx].addr.reg_addr = regnum | (fp_idx << 4);
              break;
            /* Float control registers */
            case fpu_status_reg:
              /* 
                XED does not include the FPU status word as an operand 
                  if it is only read by the instruction.
                  So this case is only for instructions that write it, 
                  e.g., fucompp 
                We add it as operand, if needed, after processing the operands
              */
              add_fpus = 0;
              //add_fputags = 1;
              eh->operand[op_idx].type = TFloatControlRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val32 =
                ((uint32_t) *(&env->fpus) & 0xC7FF) |
                (((uint32_t) *(&env->fpstt) & 0x7) << 11);
              // The FPU status word is always read, so fix the access
              eh->operand[op_idx].access = XED_OPERAND_ACTION_RW;
              // The following should not be needed. Check if bug in XED
              eh->operand[op_idx].length = 2;
              break;
            case fpu_control_reg:
              add_fpus = 1;
              //add_fputags = 1;
              eh->operand[op_idx].type = TFloatControlRegister;
              eh->operand[op_idx].usage = unknown;
              eh->operand[op_idx].value.val32 = 
                (uint32_t) *(&env->fpuc);
              // The following should not be needed. Check if bug in XED
              eh->operand[op_idx].length = 2;
              break;
            /* EFLAGS register */
            case eflags_reg:
              eflags_idx = op_idx;
              eh->operand[op_idx].type = TRegister;
              eh->operand[op_idx].usage = eflags;
              eh->operand[op_idx].value.val32 = 0;
              break;
            /* Default case: ignore register */
            default:
              break;
          }
        }
        if (ignore_taint == 0) {
          set_operand_taint(env, &(eh->operand[op_idx]));
        }
        else {
          eh->operand[op_idx].tainted = 0;
        }
        break;
      }

      /* Immediate */
      case XED_OPERAND_IMM0: {
        op_idx++;
        eh->num_operands++;
        eh->operand[op_idx].type = TImmediate;
        eh->operand[op_idx].usage = unknown;
        eh->operand[op_idx].addr.reg_addr = 0;
        eh->operand[op_idx].tainted = 0;
        eh->operand[op_idx].length = 
          (uint8_t) xed_decoded_inst_operand_length (&xedd, i);
        eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
        //xed_uint_t width = xed_decoded_inst_get_immediate_width(&xedd);
        if (xed_decoded_inst_get_immediate_is_signed(&xedd)) {
          xed_int32_t signed_imm_val = 
            xed_decoded_inst_get_signed_immediate(&xedd);
          eh->operand[op_idx].value.val32 = (uint32_t) signed_imm_val;
        }
        else {
          xed_uint64_t unsigned_imm_val =
            xed_decoded_inst_get_unsigned_immediate(&xedd);
          eh->operand[op_idx].value.val32 = (uint32_t) unsigned_imm_val;
        }
        break;
      }

      /* Special immediate only used in ENTER instruction */
      case XED_OPERAND_IMM1: {
        op_idx++;
        eh->num_operands++;
        eh->operand[op_idx].type = TImmediate;
        eh->operand[op_idx].usage = unknown;
        eh->operand[op_idx].addr.reg_addr = 0;
        eh->operand[op_idx].tainted = 0;
        eh->operand[op_idx].length = 
          (uint8_t) xed_decoded_inst_operand_length (&xedd, i);
        eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
        xed_uint8_t unsigned_imm_val = 
          xed_decoded_inst_get_second_immediate(&xedd);
        eh->operand[op_idx].value.val32 = (uint32_t) unsigned_imm_val;
        break;
      }


      /* Memory */
      case XED_OPERAND_AGEN:
      case XED_OPERAND_MEM0:
      case XED_OPERAND_MEM1: {
        unsigned long base = 0;
        unsigned long index = 0;
        unsigned long scale = 1;
        unsigned long segbase = 0;
        unsigned short segsel = 0;
        unsigned long displacement = 0;
        unsigned int j;
        size_t remaining = 0;

        /* Set memory index */
        int mem_idx = 0;
        if (op_name == XED_OPERAND_MEM1) mem_idx = 1;

        unsigned int memlen = xed_decoded_inst_operand_length (&xedd, i);

        for (j = 0; j < memlen; j+=4) {
          /* Initialization */
          base = 0;
          index = 0;
          scale = 1;
          segbase = 0;
          segsel = 0;
          displacement = 0;
          remaining = memlen - j;

          op_idx++;
          if(op_idx >= MAX_NUM_OPERANDS)
            break;
          //assert(op_idx < MAX_NUM_OPERANDS);
          eh->num_operands++;
          eh->operand[op_idx].type = TMemLoc;
          eh->operand[op_idx].usage = unknown;
          eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
          eh->operand[op_idx].length = 
            remaining > 4 ? 4 : (uint8_t) remaining;

          // Get Segment register
          xed_reg_enum_t seg_regid = 
            xed_decoded_inst_get_seg_reg(&xedd,mem_idx);

          if (seg_regid != XED_REG_INVALID) {
            const xed_operand_values_t *xopv = 
              xed_decoded_inst_operands_const(&xedd);
            xed_bool_t default_segment = 
              xed_operand_values_using_default_segment (xopv,mem_idx);

            if (!default_segment) {
              eh->num_operands++;
              int segmentreg = xed2chris_regmapping[seg_regid][0] - 100;

              segbase = env->segs[segmentreg].base;
              segsel = env->segs[segmentreg].selector;

              eh->memregs[op_idx][0].type = TRegister;
              eh->memregs[op_idx][0].usage = memsegment;
              eh->memregs[op_idx][0].length = 2;
              eh->memregs[op_idx][0].addr.reg_addr = 
                xed2chris_regmapping[seg_regid][0];
              eh->memregs[op_idx][0].access = (uint8_t) XED_OPERAND_ACTION_R;
              eh->memregs[op_idx][0].value.val32 = segsel;
              if (ignore_taint == 0) {
                set_operand_taint(env, &(eh->memregs[op_idx][0]));
              }
              else {
                eh->memregs[op_idx][0].tainted = 0;
              }

              int dt;
              if (segsel & 0x4)       // ldt
                dt = (&env->ldt)->base;
              else                    //gdt
                dt = (&env->gdt)->base;
              segsel = segsel >> 3;

              unsigned long segent = dt + 8 * segsel;
              unsigned char segdes[8];
              uint32_t *segdes_ptr = (uint32_t *)segdes;
              DECAF_read_mem(env, segent, 8, segdes);

#if 0
              // debugging code to double check segbase value
              unsigned long segbasenew = segdes[2] + segdes[3] * 256 +
              segdes[4] * 256 * 256 + segdes[7] * 256 * 256 * 256;
              if (segbase != segbasenew) {
                monitor_printf(default_mon, 
                                "segbase unexpected: 0x%08lX v.s 0x%08lX\n",
                                segbase, segbasenew);
              }
#endif
              /* Segment descriptor is stored as a memory operand */
              eh->num_operands+=2;
              eh->memregs[op_idx][3].type = TMemLoc;
              eh->memregs[op_idx][3].usage = memsegent0;
              eh->memregs[op_idx][3].length = 4;
              eh->memregs[op_idx][3].addr.mem32_addr = segent;
              eh->memregs[op_idx][3].access = 
                (uint8_t) XED_OPERAND_ACTION_R;
              eh->memregs[op_idx][3].value.val32 = *segdes_ptr;
              eh->memregs[op_idx][3].tainted = 0;

              eh->memregs[op_idx][4].type = TMemLoc;
              eh->memregs[op_idx][4].usage = memsegent1;
              eh->memregs[op_idx][4].length = 4;
              eh->memregs[op_idx][4].addr.mem32_addr = segent + 4;
              eh->memregs[op_idx][4].access = 
                (uint8_t) XED_OPERAND_ACTION_R;
              eh->memregs[op_idx][4].value.val32 = *(uint32_t *) (segdes + 4);
              eh->memregs[op_idx][4].tainted = 0;
            }
            else {
              eh->memregs[op_idx][0].type = TNone;
              eh->memregs[op_idx][3].type = TNone;
              eh->memregs[op_idx][4].type = TNone;
            }
          }
          else {
            eh->memregs[op_idx][0].type = TNone;
            eh->memregs[op_idx][3].type = TNone;
            eh->memregs[op_idx][4].type = TNone;
          }

          // Get Base register
          xed_reg_enum_t base_regid = 
            xed_decoded_inst_get_base_reg(&xedd,mem_idx);
          if (base_regid != XED_REG_INVALID) {
            eh->num_operands++;
            int basereg = xed2chris_regmapping[base_regid][1];
            base = env->regs[basereg];
            eh->memregs[op_idx][1].type = TRegister;
            eh->memregs[op_idx][1].usage = membase;
            eh->memregs[op_idx][1].addr.reg_addr = 
              xed2chris_regmapping[base_regid][0];
            eh->memregs[op_idx][1].length =
              xed2chris_regmapping[base_regid][2];
            eh->memregs[op_idx][1].access = (uint8_t) XED_OPERAND_ACTION_R;
            eh->memregs[op_idx][1].value.val32 = base;
            if (ignore_taint == 0) {
              set_operand_taint(env, &(eh->memregs[op_idx][1]));
            }
            else {
              eh->memregs[op_idx][1].tainted = 0;
            }
          }
          else {
            eh->memregs[op_idx][1].type = TNone;
          }

          // Get Index register and Scale
          xed_reg_enum_t index_regid = 
            xed_decoded_inst_get_index_reg(&xedd,mem_idx);
          if (mem_idx == 0 && index_regid != XED_REG_INVALID) {
            eh->num_operands++;
            int indexreg = xed2chris_regmapping[index_regid][1];
            index = env->regs[indexreg];
            eh->memregs[op_idx][2].type = TRegister;
            eh->memregs[op_idx][2].usage = memindex;
            eh->memregs[op_idx][2].addr.reg_addr = 
              xed2chris_regmapping[index_regid][0];
            eh->memregs[op_idx][2].length = 
              xed2chris_regmapping[index_regid][2];
            eh->memregs[op_idx][2].access = (uint8_t) XED_OPERAND_ACTION_R;
            eh->memregs[op_idx][2].value.val32 = index;
            if (ignore_taint == 0) {
              set_operand_taint(env, &(eh->memregs[op_idx][2]));
            }
            else {
              eh->memregs[op_idx][2].tainted = 0;
            }

            // Get Scale (AKA width) (only have a scale if the index exists)
            if (xed_decoded_inst_get_scale(&xedd,i) != 0) {
              scale = 
                (unsigned long) xed_decoded_inst_get_scale(&xedd,mem_idx);
              eh->num_operands++;
              eh->memregs[op_idx][6].type = TImmediate;
              eh->memregs[op_idx][6].usage = memscale;
                eh->memregs[op_idx][6].addr.reg_addr = 0;
              eh->memregs[op_idx][6].length = 1;
              eh->memregs[op_idx][6].access = (uint8_t) XED_OPERAND_ACTION_R;
              eh->memregs[op_idx][6].value.val32 = scale;
              eh->memregs[op_idx][6].tainted = 0;
            }
          }
          else {
            eh->memregs[op_idx][2].type = TNone;
            eh->memregs[op_idx][6].type = TNone;
          }

          // Get displacement (AKA offset)
          displacement =
            (unsigned long) xed_decoded_inst_get_memory_displacement
            (&xedd,mem_idx);
          if (displacement > 0) {
            eh->num_operands++;
            eh->memregs[op_idx][5].type = TDisplacement;
            eh->memregs[op_idx][5].usage = memdisplacement;
            eh->memregs[op_idx][5].addr.reg_addr = 0;
            eh->memregs[op_idx][5].length = 
              xed_decoded_inst_get_memory_displacement_width(&xedd,mem_idx);
            eh->memregs[op_idx][5].access = (uint8_t) XED_OPERAND_ACTION_R;
            eh->memregs[op_idx][5].value.val32 = displacement;
            eh->memregs[op_idx][5].tainted = 0;
          }
          else {
            eh->memregs[op_idx][5].type = TNone;
          }

          // Fix displacement for:
          //   1) Any instruction that pushes into the stack, since ESP is 
          //        decremented before memory operand is written using ESP. 
          //        Affects: ENTER,PUSH,PUSHA,PUSHF,CALL
          if (is_stackpush) {
            stackpushpop_acc += eh->operand[op_idx].length;
            displacement = displacement - stackpushpop_acc -j;
          }
          //   2) Pop instructions where the 
          //      destination operand is a memory location that uses ESP 
          //        as base or index register. 
          //      The pop operations increments ESP and the written memory 
          //        location address needs to be adjusted.
          //      Affects: pop (%esp)
          else if ((category == XED_CATEGORY_POP) && (!is_stackpop)) {
            if ((eh->memregs[op_idx][1].addr.reg_addr == esp_reg) || 
                (eh->memregs[op_idx][2].addr.reg_addr == esp_reg)) 
            {
              displacement = displacement + eh->operand[op_idx].length;
            }
          }

          // Calculate memory address accessed
          eh->operand[op_idx].addr.mem32_addr =
            j + segbase + base + index * scale + displacement;

          // Special handling for LEA instructions
          eh->operand[op_idx].value.val32 = 0;
          if (op_name == XED_OPERAND_AGEN) {
            eh->operand[op_idx].type = TMemAddress;
            eh->operand[op_idx].length = 4;
          }
          else {
              DECAF_read_mem(env, 
                              eh->operand[op_idx].addr.mem32_addr,
                              (int)(eh->operand[op_idx].length), 
                              (uint8_t *)&(eh->operand[op_idx].value.val32));
          }

          // If needed, set operand taint
          if (ignore_taint == 0) {
            set_operand_taint(env, &(eh->operand[op_idx]));
          }
          else {
            eh->operand[op_idx].tainted = 0;
          }
        }
        break;
      }

      /* Jumps */
      case XED_OPERAND_PTR:  // pointer (always in conjunction with a IMM0)
      case XED_OPERAND_RELBR: { // branch displacements
        xed_uint_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
        /* Displacement is from instruction end */
        /* Adjust displacement with instruction size */
        disp = disp + eh->inst_size;
        op_idx++;
        eh->num_operands++;
        eh->operand[op_idx].type = TJump;
        eh->operand[op_idx].usage = unknown;
        eh->operand[op_idx].addr.reg_addr = 0;
        eh->operand[op_idx].length = 4;
        eh->operand[op_idx].access = (uint8_t) xed_operand_rw (op);
        eh->operand[op_idx].value.val32 = disp;
        eh->operand[op_idx].tainted = 0;
        break;
      }

      default:
        break;
    }
  }

  /* XED does not add the FPU status word as an operand if it is only read
      Thus, we add it ourselves if needed */
  if (add_fpus) {
    op_idx++;
    eh->num_operands++;
    eh->operand[op_idx].type = TFloatControlRegister;
    eh->operand[op_idx].usage = unknown;
    eh->operand[op_idx].addr.reg_addr = fpu_status_reg;
    eh->operand[op_idx].length = 2;
    eh->operand[op_idx].access = XED_OPERAND_ACTION_R;
    eh->operand[op_idx].value.val32 = 
      ((uint32_t) *(&env->fpus) & 0xC7FF) |
      (((uint32_t) *(&env->fpstt) & 0x7) << 11);
    eh->operand[op_idx].tainted = 0;
  }

  /* XED does not add the FPU tag word as an operand
      Thus, we add it ourselves if needed */
  /*
  if (add_fputags) {
    op_idx++;
      eh->num_operands++;
      eh->operand[op_idx].type = TFloatControlRegister;
      eh->operand[op_idx].usage = unknown;
      eh->operand[op_idx].addr.reg_addr = fpu_tag_reg;
      eh->operand[op_idx].length = 2;
      eh->operand[op_idx].access = XED_OPERAND_ACTION_RW;
      eh->operand[op_idx].value.val32 = get_fpu_tag_word();
      eh->operand[op_idx].tainted = 0;
    }
  */

  /* For instructions that push into the float stack, 
    need to adjust the hardware index for the destination float register */
  if (is_x87push) {
    for (i = 0; i <= op_idx; i++) {
      if (eh->operand[i].type == TFloatRegister) {
        fp_idx = eh->operand[i].addr.reg_addr >> 4;
        regnum = eh->operand[i].addr.reg_addr & 0xF;
        eh->operand[i].addr.reg_addr = regnum | (((fp_idx - 1) & 7) << 4);
        break;
      }
    } 
  }

  /* Increment the operand counter without including ESP */
  tstats.operand_counter += eh->num_operands;

  /* Make sure we mark the end of the list of valid operands */
  op_idx++;
  eh->operand[op_idx].type = TNone;
}

/* Output function
   Writes an operand structure to the given file
*/
unsigned int write_operand(FILE *stream, OperandVal op) {
  unsigned int i = 0;
  unsigned int num_elems_written = 0;
  uint64_t float_significand = 0;
  uint16_t float_exponent = 0;

  if (stream == NULL) return 0;

  /* Write fixed part of operand */
  num_elems_written += fwrite(&op, OPERAND_VAL_FIXED_SIZE, 1, stream);

  /* Write enums */
  uint8_t enums[2];
  enums[0] = (uint8_t) op.type;
  enums[1] = (uint8_t) op.usage;
  num_elems_written += fwrite(&enums, OPERAND_VAL_ENUMS_REAL_SIZE, 1, stream);

  /* Write address and value */
  switch(op.type) {
    /* We should not have a TNone operand here */
    case TNone:
      fprintf(stderr, "Found optype TNone inside write_operand\n");
      assert(0);
      break;

    /* Register (does not include MMX or Float registers): 
     *   Address is 1 byte
     *   Value is 4 bytes
     */
    case TRegister:
      num_elems_written += fwrite(&(op.addr.reg_addr), 1, 1, stream);
      num_elems_written += fwrite(&(op.value.val32), 4, 1, stream);
      break;

    /* Memory location: 
     *   Address is 4 bytes
     *   Value is 4 bytes
     */
    case TMemLoc:
      num_elems_written += fwrite(&(op.addr.mem32_addr), 4, 1, stream);
      num_elems_written += fwrite(&(op.value.val32), 4, 1, stream);
      break;

    /* Immediate: 
     *   No address
     *   Value is 4 bytes
     */
    case TImmediate:
    case TDisplacement:
      num_elems_written += fwrite(&(op.value.val32), 4, 1, stream);
      break;

    /* Jump: 
     *   No address
     *   Value is 4 bytes
     */
    case TJump:
      num_elems_written += fwrite(&(op.value.val32), 4, 1, stream);
      break;

    /* Float register: 
     *   Address is 1 byte
     *   Value is 10 bytes (2 bytes for exponent/sign, 8 bytes for significand)
     */
    case TFloatRegister:
      cpu_get_fp80(&float_significand,&float_exponent,op.value.float_val);
      num_elems_written += fwrite(&(op.addr.reg_addr), 1, 1, stream);
      num_elems_written += fwrite(&float_exponent, 2, 1, stream);
      num_elems_written += fwrite(&float_significand, 8, 1, stream);
      break;

    /* Memory address: 
     *   Address is 4 bytes
     *   Value is 4 bytes
     */
    case TMemAddress:
      num_elems_written += fwrite(&(op.addr.mem32_addr), 4, 1, stream);
      num_elems_written += fwrite(&(op.value.val32), 4, 1, stream);
      break;

    /* MMX Register: 
     *   Address is 1 byte
     *   Value is 8 bytes
     */
    case TMMXRegister:
      num_elems_written += fwrite(&(op.addr.reg_addr), 1, 1, stream);
      num_elems_written += fwrite(&(op.value.val64), 8, 1, stream);
      break;

    /* XMM Register: 
     *   Address is 1 byte
     *   Value is 16 bytes
     */
    case TXMMRegister:
      num_elems_written += fwrite(&(op.addr.reg_addr), 1, 1, stream);
      num_elems_written += fwrite(&(op.value.xmm_val._q[1]), 8, 1, stream);
      num_elems_written += fwrite(&(op.value.xmm_val._q[0]), 8, 1, stream);
      break;

    /* Float Control Register: 
     *   Address is 1 byte
     *   Value is 4 bytes
     */
    case TFloatControlRegister:
      num_elems_written += fwrite(&(op.addr.reg_addr), 1, 1, stream);
      num_elems_written += fwrite(&(op.value.val32), 4, 1, stream);
      break;

    default:
      fprintf(stderr, "Unknown optype inside write_operand\n");
      assert(0);
      break;

      return 0;
  }

  /* For each byte in the operand, check if tainted.
      If tainted, write taint record */
  assert(op.length <= MAX_OPERAND_LEN);
  for (i = 0; i < op.length; i++) {
    if (op.tainted & (1 << i)) {
      /* Write fixed part of taint_record */
      num_elems_written += 
        fwrite(&(op.records[i]), TAINT_RECORD_FIXED_SIZE, 1, stream);

      /* Write only the non-empty taint_byte_record */
      assert(op.records[i].numRecords <= MAX_NUM_TAINTBYTE_RECORDS);
      num_elems_written += fwrite(&(op.records[i].taintBytes), 
        sizeof(TaintByteRecord), op.records[i].numRecords, stream);
    }
  }

  return num_elems_written;
}

/* Output function
   Writes an EntryHeader to the given file
*/
unsigned int write_insn(CPUState* env, FILE *stream, EntryHeader *eh)
{
  unsigned int num_elems_written = 0;

  /* If no stream or no instruction, ignore write */
  if ((stream == NULL) || (eh == NULL)) return 0;

  /* If tid_to_trace is set, write only if we're in the thread tid */
  if (tid_to_trace != (uint32_t)(-1) && tid_to_trace != eh->tid) return 0;

  if (!is_duplicated_insn && (eh->inst_size > 0)) {
    /* Write fixed part of entry header */
    num_elems_written += fwrite(eh, ENTRY_HEADER_FIXED_SIZE, 1, stream);

    /* Write rawbytes */
    num_elems_written += fwrite(&(eh->rawbytes), eh->inst_size, 1, stream);

    /* Write remaining operands */
    int i = 0,j = 0;
    while ((eh->operand[i].type != TNone) && (i < MAX_NUM_OPERANDS)) {
      write_operand(stream, eh->operand[i]);

      /* For Memory operands, need to write memregs and segent's */
      if ((eh->operand[i].type == TMemLoc) ||
          (eh->operand[i].type == TMemAddress))
      {
        /* Write Memregs operands */
        for (j = 0; j < MAX_NUM_MEMREGS; j++) {
          if (eh->memregs[i][j].type != TNone) {
            write_operand(stream, eh->memregs[i][j]);
          }
        }
      }
      i++;
    }

    insn_already_written = 1;
    tstats.insn_counter_traced++;
  #ifdef TAINT_ENABLED
    if (insn_tainted) tstats.insn_counter_traced_tainted++;
  #endif
    /* Avoid flushing to improve performance */
    //fflush(stream);

  }

  return num_elems_written;
}

/* Write trailer and close trace */
int close_trace(FILE *stream, ProcRecord ** pr_arr, size_t num_procs) {
  uint32_t num_found_processes = 0;
  unsigned int i;
  uint32_t num_elems_written = 0;
  uint32_t trailer_begin = TRAILER_BEGIN;
  uint32_t trailer_end = TRAILER_END;
  uint32_t process_list_size = 0;

  // Clear statistics
  clear_trace_stats();

  // Clear current trace
  curr_trace = NULL;

  if (!stream)
    return -1;

  // If required, write process information
  if (pr_arr) {
    //monitor_printf(default_mon, "Dumping information for %u processes\n", 
    //    num_procs);

    // Write delimiter to trace
    fwrite(&trailer_begin, sizeof(trailer_begin), 1, stream);

    // Write each process to the trace
    for (i = 0; i < num_procs; i++) {
      // If process is not found, move on to next process
      if (pr_arr[i]->pid == -1) {
        continue;
      }
      else {
        num_found_processes++;
      }

      // Write Process
      num_elems_written += fwrite(pr_arr[i], PROC_REC_FIXED_SIZE, 1, stream);
      process_list_size += PROC_REC_FIXED_SIZE;

      //monitor_printf(default_mon, "  Dumping process: %s (%d) Nmods: %d\n", 
      //  proc.name, proc.pid, proc.n_mods);
      
      // Write Modules
      num_elems_written += fwrite(pr_arr[i]->mod_arr, sizeof(ModuleRecord), 
                                  pr_arr[i]->n_mods, stream);
      process_list_size += pr_arr[i]->n_mods * sizeof(ModuleRecord);
    }

    // Write size of trailer
    fwrite(&process_list_size, sizeof(process_list_size), 1, stream);

    // Write number of processes
    fwrite(&num_found_processes, sizeof(num_found_processes), 1, stream);

    // Write end of trailer marker
    fwrite(&trailer_end, sizeof(trailer_end), 1, stream);

    // Free the process array
    for (i = 0; i < num_procs; i++) {
      if (pr_arr[i])
        free(pr_arr[i]);
    }
    free(pr_arr);
    pr_arr = NULL;
  }

  // Close the trace file
  return fclose(stream);
}

