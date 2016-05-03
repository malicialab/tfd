/* 
 *  generation of state files v40
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
 *  Copyright (C) 2009-2010 Zhenkai Liang <liangzk@comp.nus.edu.sg>
 *  Copyright (C) 2009-2010 Heng Yin <heyin@syr.edu>
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

#ifndef _STATE_H_
#define _STATE_H_

#include "DECAF_main.h"

/* The size of a memory page */
#define STATE_PAGE_SIZE 4096

/* The number of bytes covered by a taint block */
#define STATE_TAINT_BLOCK_SIZE 64

/* State header values */
#define STATE_VERSION_NUMBER 40
#define STATE_MAGIC_NUMBER 0xFFFEFFFE

/* Whether to save kernel memory in addition to user memory */
#define SAVE_KERNEL_MEM 0

/* Whether to save registers in addition to memory */
#define SAVE_REGISTERS 1

/* Whether to save taint information in addition to values */
#define SAVE_TAINT 1

/* Flag masks */
#define STATE_SAVE_REGISTERS_MASK 0x1
#define STATE_SAVE_KERNEL_MEM_MASK 0x2
#define STATE_SAVE_TAINT_MASK 0x4
#define STATE_VIRTUAL_ADDR_MASK 0x8
#define STATE_PROCESS_SNAPSHOT_MASK 0x10

/* Snapshot type mask */
#define STATE_SNAPSHOT_TYPE_PROCESS 0x1
#define STATE_SNAPSHOT_TYPE_SYSTEM 0x2

/* In the current state file format, the layout of the x86 registers
   we use is modeled after 32-bit Linux's user_regs_struct. It's not
   really ideal for our applications: for instance, it records the
   segment registers, but not the LDT/GDT or the segment descriptors.
   The question of what registers we want to save should be revisited
   the next time we revise the file format. -SMcC */

struct state_file_regs_struct
{
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint32_t ebp;
  uint32_t eax;
  uint32_t xds;
  uint32_t xes;
  uint32_t xfs;
  uint32_t xgs;
  uint32_t orig_eax;
  uint32_t eip;
  uint32_t xcs;
  uint32_t eflags;
  uint32_t esp;
  uint32_t xss;
};

/* State header description
  magicnumber:   The magic number used to identify a state file
  version:       The version of the state file
  word_size:     The word size for the architecture the state belongs to
  flags:         Flags that specified the options when state file was created
    0: register flag:     one if register structure included in state file
    1: kernel flag:       one if kernel memory included in state file
    2: taint flag:        one if taint information included in state file
    3: address flag:      one if addresses are virtual, zero if physical
    4: snapshotType flag: one if process snapshot, zero if system
*/
typedef struct _state_header {
  uint32_t magic_number;
  uint32_t version;
  uint16_t word_size;
  uint16_t flags;
} StateHeader;

/* A memory region, usually corresponds to a memory page */
typedef struct _region {
  uint32_t begin;
  uint32_t end;
} region_t;

/* A taint block */
typedef struct _taint_block {
  uint32_t begin;
  uint64_t taint_mask;
} taint_block_t;

/* Saves system state (dump of all system's physical memory)
   The state is captured at function call
   env can be NULL if there is no need to save registers
   Returns zero if successful, otherwise it failed
*/
int save_system_state(CPUState* env, const char *filename);

/* Saves process state for process identified by cr3 into filename
   The snapshot_type should be STATE_SNAPSHOT_TYPE_PROCESS or
     STATE_SNAPSHOT_TYPE_SYSTEM
   The state is captured at function call
   env can be NULL if there is no need to save registers
   Returns zero if successful, otherwise it failed
*/
int save_state_by_cr3(CPUState* env, uint32_t cr3, const char *filename, 
                      int snapshot_type);

/* Saves process state for process identified by pid into filename
   The snapshot_type should be STATE_SNAPSHOT_TYPE_PROCESS or
     STATE_SNAPSHOT_TYPE_SYSTEM
   The state is captured at function call
   env can be NULL if there is no need to save registers
   Returns zero if successful, otherwise it failed
*/
int save_state_by_pid(CPUState* env, uint32_t pid, const char *filename, 
                      int snapshot_type);

/* Saves process state for process identified by pid into filename
   The snapshot_type should be STATE_SNAPSHOT_TYPE_PROCESS or
     STATE_SNAPSHOT_TYPE_SYSTEM
   The state is captured the first time the process execution reaches addr
   env can be NULL if there is no need to save registers
   Returns zero if successful, otherwise it failed
*/
int save_state_at_addr(CPUState* env, uint32_t pid, uint32_t addr, 
                        const char *filename, int snapshot_type);

#endif // _STATE_H_
