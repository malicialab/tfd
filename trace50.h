/* 
 *  generation of trace files v50
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

#ifndef _TRACE_H_
#define _TRACE_H_

#include <inttypes.h>
#undef INLINE
#include "DECAF_main.h"

/* Size of buffer to store instructions */
#define FILEBUFSIZE 104857600

/* Trace header values */
#define VERSION_NUMBER 50
#define MAGIC_NUMBER 0xFFFFFFFF

/* Taint origins */
#define TAINT_SOURCE_NIC_IN 0
#define TAINT_SOURCE_KEYBOARD_IN 1
#define TAINT_SOURCE_FILE_IN 2
#define TAINT_SOURCE_NETWORK_OUT 3
#define TAINT_SOURCE_API_TIME_IN 4
#define TAINT_SOURCE_API_FILE_IN 5
#define TAINT_SOURCE_API_REGISTRY_IN 6
#define TAINT_SOURCE_API_HOSTNAME_IN 7
#define TAINT_SOURCE_API_FILE_INFO_IN 8
#define TAINT_SOURCE_API_SOCK_INFO_IN 9
#define TAINT_SOURCE_API_STR_IN 10
#define TAINT_SOURCE_API_SYS_IN 11
#define TAINT_SOURCE_HOOKAPI 12
#define TAINT_SOURCE_MODULE 13

/* Starting origin for network connections */
#define TAINT_ORIGIN_START_TCP_NIC_IN 10000
#define TAINT_ORIGIN_START_UDP_NIC_IN 11000
#define TAINT_ORIGIN_MODULE           20000

/* Taint propagation definitions */
#define TP_NONE 0           // No taint propagation
#define TP_SRC 1            // Taint propagated from SRC to DST
#define TP_CJMP 2           // Cjmp using tainted EFLAG
#define TP_MEMREAD_INDEX 3  // Memory read with tainted index
#define TP_MEMWRITE_INDEX 4 // Memory write with tainted index
#define TP_REP_COUNTER 5    // Instruction with REP prefix and tainted counter
#define TP_SYSENTER 6       // Sysenter

/* Trace format definitions */
#define MAX_NUM_OPERANDS 30 // FNSAVE has a memory operand of 108 bytes
#define MAX_NUM_MEMREGS 5  /* Max number of memregs per memory operand */
#define MAX_NUM_TAINTBYTE_RECORDS 3
#define MAX_STRING_LEN 32
#define MAX_OPERAND_LEN 8 /* Max length of an operand in bytes */
#define MAX_INSN_BYTES 15 /* Maximum number of bytes in a x86 instruction */

/* Macro to access address and value of register operand */
#define REGOP_ADDR(op) ((op).addr)
#define REGOP_VAL(op) ((op).value)

/* Macro to access address and value of a memory operand */
#define MEMOP_ADDR(op) ((op).addr)
#define MEMOP_VAL(op) ((op).value)


#define REGNUM(regid) (regmapping[(regid) - 100])

/* Register identifers used in trace */
/* segment registers */
#define es_reg 100
#define cs_reg 101
#define ss_reg 102
#define ds_reg 103
#define fs_reg 104
#define gs_reg 105
/* 8-bit registers */
#define al_reg 116
#define cl_reg 117
#define dl_reg 118
#define bl_reg 119
#define ah_reg 120
#define ch_reg 121
#define dh_reg 122
#define bh_reg 123
/* 16-bit registers */
#define ax_reg 124
#define cx_reg 125
#define dx_reg 126
#define bx_reg 127
#define sp_reg 128
#define bp_reg 129
#define si_reg 130
#define di_reg 131
/* 32-bit registers */
#define eax_reg 132
#define ecx_reg 133
#define edx_reg 134
#define ebx_reg 135
#define esp_reg 136
#define ebp_reg 137
#define esi_reg 138
#define edi_reg 139
/* special registers */
#define eip_reg 140
#define cr3_reg 141
#define eflags_reg 145
/* MMX registers */
#define mmx0_reg 164
#define mmx1_reg 165
#define mmx2_reg 166
#define mmx3_reg 167
#define mmx4_reg 168
#define mmx5_reg 169
#define mmx6_reg 170
#define mmx7_reg 171
/* XMM registers */
#define xmm0_reg  172
#define xmm1_reg  173
#define xmm2_reg  174
#define xmm3_reg  175
#define xmm4_reg  176
#define xmm5_reg  177
#define xmm6_reg  178
#define xmm7_reg  179
#define xmm8_reg  180
#define xmm9_reg  181
#define xmm10_reg 182
#define xmm11_reg 183
#define xmm12_reg 184
#define xmm13_reg 185
#define xmm14_reg 186
#define xmm15_reg 187
/* float data registers */
#define fpu_st0_reg 188
#define fpu_st1_reg 189
#define fpu_st2_reg 190
#define fpu_st3_reg 191
#define fpu_st4_reg 192
#define fpu_st5_reg 193
#define fpu_st6_reg 194
#define fpu_st7_reg 195
/* float control registers */
#define fpu_control_reg 196
#define fpu_status_reg  197
#define fpu_tag_reg     198


enum OpType { TNone = 0, TRegister, TMemLoc, TImmediate, TJump, 
  TFloatRegister, TMemAddress, TMMXRegister, TXMMRegister, 
  TFloatControlRegister, TDisplacement };

enum OpUsage { unknown = 0, esp, counter, membase, memindex, memsegment,
  memsegent0, memsegent1 };


typedef struct _taint_byte_record {
  uint32_t source;              // Tainted data source (network,keyboard...)
  uint32_t origin;              // Identifies a network flow
  uint32_t offset;              // Offset in tainted data buffer (network)
} TaintByteRecord;

#define TAINT_RECORD_FIXED_SIZE 1

typedef struct _taint_record {
  uint8_t numRecords;          // How many TaintByteRecord currently used
  TaintByteRecord taintBytes[MAX_NUM_TAINTBYTE_RECORDS];
} taint_record_t;

#define OPERAND_VAL_FIXED_SIZE 12
#define OPERAND_VAL_ENUMS_REAL_SIZE 2

typedef struct _operand_val {
  uint8_t access; /* xed_operand_action_enum_t */
  uint8_t length;
  uint16_t tainted;
  uint32_t addr;
  uint32_t value;
  enum OpType type;
  enum OpUsage usage;
  taint_record_t records[MAX_OPERAND_LEN];
} OperandVal;

#define ENTRY_HEADER_FIXED_SIZE 24

/* Entry header description
  address:       Address where instruction is loaded in memory
  tid:           Thread identifier
  inst_size:     Number of bytes in x86 instruction
  num_operands:  Number of operands (includes all except ESP)
  tp:            Taint propagation value. See above.
  eflags:        Value of the EFLAGS register
  cc_op:         Determines operation performed by QEMU on CC_SRC,CC_DST.
                   ONLY REQUIRES 8-bit
  df:            Direction flag. Has to be -1 (x86_df=1) or 1 (x86_df = 0)
                    COULD BE DERIVED FROM eflags
  operand[]:     Operands accessed by instruction
  memregs[][idx]:   Operands used for indirect addressing
    idx == 0 -> Segment register
    idx == 1 -> Base register
    idx == 2 -> Index register
    idx == 3 -> Segent0
    idx == 4 -> Segent1
  rawybytes[]:   Rawbytes of the x86 instruction
*/
typedef struct _entry_header {
  uint32_t address;
  uint32_t tid;
  uint16_t inst_size;
  uint8_t num_operands;
  uint8_t tp;
  uint32_t eflags;
  uint32_t cc_op;
  uint32_t df;
  char rawbytes[MAX_INSN_BYTES];
  OperandVal operand[MAX_NUM_OPERANDS];
  OperandVal memregs[MAX_NUM_OPERANDS][MAX_NUM_MEMREGS];
} EntryHeader;

typedef struct _module_record {
  char name[MAX_STRING_LEN];
  uint32_t base;
  uint32_t size;
} ModuleRecord;

typedef struct _proc_record {
  char name[MAX_STRING_LEN];
  uint32_t pid;
  int n_mods;
  uint32_t ldt_base;
  ModuleRecord * mod_arr;
} ProcRecord;

#define PROC_REC_FIXED_SIZE MAX_STRING_LEN+12

typedef struct _trace_header {
  int magicnumber;
  int version;
  int n_procs;
  uint32_t gdt_base;
  uint32_t idt_base;
} TraceHeader;

/* Structure to hold trace statistics */
struct trace_stats {
  uint64_t insn_counter_decoded; // Instructions decoded
  uint64_t insn_counter_traced;  // Instructions written to trace
  uint64_t insn_counter_traced_tainted; // Tainted insn written to trace
  uint64_t operand_counter;      // Operands decoded
};

/* Exported variables */
extern int received_tainted_data;
extern int has_page_fault;
extern int insn_already_written;
extern int regmapping[];
extern long insn_counter_traced; // Instruction counter in trace
extern unsigned int tid_to_trace;
extern struct trace_stats tstats;

/* Exported Functions */
int get_regnum(OperandVal op);
int getOperandOffset (OperandVal *op);
// Open trace (best called just before writting first instruction)
FILE * open_trace(CPUState* env, const char * filename, ProcRecord * proc);
// Initialize disassembler
void xed2_init();
// Disassemble an instruction
void decode_address(CPUState* env, uint32_t address, EntryHeader *eh, 
                    uint32_t tid, int ignore_taint);
// Write insn to trace
unsigned int write_insn(CPUState* env, FILE *stream, EntryHeader *eh);
// Close trace
int close_trace(FILE *stream);
// Print trace statistics
void print_trace_stats();

#endif // _TRACE_H_

