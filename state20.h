/* 
 *  generation of state files v20
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

#ifndef _STATE20_H_
#define _STATE20_H_

#include "DECAF_main.h"
#include "DECAF_target.h"

/* Whether to save kernel memory in addition to user memory */
#define SAVE_KERNEL_MEM 0

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

/* Saves memory state for process identified by cr3 into filename
   The state is captured at function call
   env can be NULL if there is no need to save registers
   Returns zero if successful, otherwise it failed
*/
int save_state_by_cr3(CPUState* env, uint32_t cr3, const char *filename);

/* Saves memory state for process identified by pid into filename
   The state is captured at function call
   env can be NULL if there is no need to save registers
   Returns zero if successful, otherwise it failed
*/
int save_state_by_pid(CPUState* env, uint32_t pid, const char *filename);

/* Saves memory state for process identified by cr3 into filename
   The state is captured the first time the process execution reaches addr
   env can be NULL if there is no need to save registers
   Returns zero if successful, otherwise it failed
*/
int save_state_at_addr(CPUState* env, uint32_t pid, uint32_t addr, 
                        const char *filename);

#endif // _STATE20_H_
