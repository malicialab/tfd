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

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include "state20.h"
#include "bswap.h"
#include "shared/hookapi.h"
#include "shared/vmi_c_wrapper.h"

#define STATE_PAGE_SIZE 4096

/* Trace header values */
#define STATE_VERSION_NUMBER 20
#define STATE_MAGIC_NUMBER 0xFFFEFFFE

/* File to dump the state */
static FILE *statelog = 0;

/* CR3 of process for which memory will be dumped */
static uint32_t statecr3 = 0;

/* The memory dump will be taken when execution reaches this address */
static uint32_t stateaddr = 0;

/* Hook handle for taking the memory dump at a specific EIP value */
static uint32_t stateaddr_hook_handle = 0;

/* A region */
typedef struct {
  uint32_t begin;
  uint32_t end;
} map_t;

/* Save registers */
int save_registers(CPUState* env, struct state_file_regs_struct *regs)
{
  if (env) {
    regs->eax = env->regs[R_EAX];
    regs->ebx = env->regs[R_EBX];
    regs->ecx = env->regs[R_ECX];
    regs->edx = env->regs[R_EDX];
    regs->esi = env->regs[R_ESI];
    regs->edi = env->regs[R_EDI];
    regs->ebp = env->regs[R_EBP];
    regs->esp = env->regs[R_ESP];
    regs->eip = DECAF_getPC(env);
    regs->eflags = *(&env->eflags);
    regs->xcs = env->segs[R_CS].selector;
    regs->xds = env->segs[R_DS].selector;
    regs->xes = env->segs[R_ES].selector;
    regs->xfs = env->segs[R_FS].selector;
    regs->xgs = env->segs[R_GS].selector;
    regs->xss = env->segs[R_SS].selector;
    regs->orig_eax = 0;           //? Do we need to remember the call number
    return 1;
  }
  else {
    memset(regs, 0, sizeof(struct state_file_regs_struct));
    return 0;
  }
}

/* Save state (registers + memory pages) for process identified by statecr3 */
void save_state(void *opaque)
{
  CPUState *env = (CPUState *)opaque;
  struct state_file_regs_struct regs;

  /* remove address hook */
  if (stateaddr_hook_handle) {
    gva_t eip = DECAF_getPC(env);
    if (eip == stateaddr) {
      monitor_printf(default_mon, "Saving state at address: 0x%08x\n",
                      stateaddr);
      hookapi_remove_hook(stateaddr_hook_handle);
    }
  }

  /* fail if the there is no file handle */
  if (!statelog)
    return;

  monitor_printf(default_mon,"Saving state for CR3: 0x%08x\n", statecr3);

  /* Write header fields */
  uint32_t magic = STATE_MAGIC_NUMBER;
  uint32_t version = STATE_VERSION_NUMBER;
  fwrite(&magic, 4, 1, statelog);
  fwrite(&version, 4, 1, statelog);

  /* save registers 
   * v20 requires the registers to be in the state file */
  save_registers(env, &regs);
  fwrite(&regs, sizeof(regs), 1, statelog);

  /* Flush the metadata (header + registers) */
  fflush(statelog);

  /* save memories */
  //traverse_pages();
  uint32_t page_start_addr = 0;
  char buf[STATE_PAGE_SIZE];
  int err = 0;
  uint32_t stop_addr = 0xFFFFE000;

#if SAVE_KERNEL_MEM == 0
  // Avoid saving kernel memory if not requested
  stop_addr = VMI_guest_kernel_base - STATE_PAGE_SIZE; 
#endif

  for (page_start_addr = 0; page_start_addr <= stop_addr; 
       page_start_addr+= STATE_PAGE_SIZE)
  {
    //monitor_printf(default_mon, "Page_start: 0x%08x\n", page_start_addr);
    err = DECAF_read_mem_with_pgd(env, statecr3, page_start_addr,
                                    STATE_PAGE_SIZE, buf);
    if (!err) {
      map_t range;
      range.begin = page_start_addr;
      range.end = page_start_addr + STATE_PAGE_SIZE - 1;
      //monitor_printf(default_mon, "Writing page: 0x%08x -> 0x%08x\n", 
      //   range.begin, range.end);

      /* write range to file */
      fwrite(&range, sizeof(range), 1, statelog);

      /* write page to file */
      fwrite(buf, 1, STATE_PAGE_SIZE, statelog);
      //fflush(statelog);
    }
  }

  /* close state file */
  fclose(statelog);
  statelog = 0;

  return;
}

/* Save state for given process (identified by CR3) */
int save_state_by_cr3(CPUState* env, uint32_t cr3, const char *filename) {
  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_by_cr3");
    return 1;
  }

  statecr3 = cr3;
  save_state(env);

  return 0;
}

/* Save state for given process (identified by PID) */
int save_state_by_pid(CPUState* env, uint32_t pid, const char *filename) {
  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_by_pid");
    return 1;
  }

  statecr3 = VMI_find_cr3_by_pid_c(pid);
  if (0 == statecr3)
    return 1;

  save_state(env);

  return 0;
}

/* Save state for given process (identified by PID) 
 * when process execution reaches given address */
int save_state_at_addr(CPUState* env, uint32_t pid, uint32_t addr, 
                        const char *filename)
{
  statecr3 = VMI_find_cr3_by_pid_c(pid);
  if (0 == statecr3)
    return 1;

  stateaddr = addr;

  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_at_addr");
    return 1;
  }

  monitor_printf(default_mon,
    "Hooking save state address: 0x%08x CR3: 0x%08x\n", stateaddr, statecr3);
  stateaddr_hook_handle =
    hookapi_hook_function(0, stateaddr, statecr3, save_state, env, 
                          sizeof(CPUState*));

  return 0;
}

