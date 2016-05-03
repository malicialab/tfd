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

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "state.h"
#include "DECAF_main.h"
#include "DECAF_target.h"
#ifdef TRACE_VERSION_50
#include "trace50.h"
#else
#include "trace.h"
#endif
#include "bswap.h"
#include "shared/hookapi.h"
#include "shared/vmi_c_wrapper.h"

/* Maximum number of bytes that cpu_physical_memory_rw can read */
#define MAX_PHYS_MEMSIZE_READ 1024

#ifdef TAINT_ENABLED
#if SAVE_TAINT != 0
/* The number of taint blocks needed to cover a memory page */
static size_t num_taint_blocks_in_page = 
  STATE_PAGE_SIZE / STATE_TAINT_BLOCK_SIZE;
#endif // #if (SAVE_TAINT != 0)
#endif // #ifdef TAINT_ENABLED

/* Structure to store the save options */
typedef struct _save_state_options {
  uint32_t hook_handle;
  unsigned int snapshot_type;
  unsigned int use_virtual_addresses;
  FILE *statelog;
  uint32_t statecr3;
  uint32_t stateaddr;
  CPUState* env;
} SaveStateOptions;

/* Save options */
static SaveStateOptions save_state_options;

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
    return 0;
  }
}

/* Save state (registers + memory pages) for process identified by statecr3 */
void save_state(void *opaque)
{
  SaveStateOptions *options = (SaveStateOptions *)opaque;
  StateHeader header;
  int saved_registers = 0;
  struct state_file_regs_struct regs;
  uint32_t flags = 0;
  unsigned int use_virtual_addresses = options->use_virtual_addresses & 0x1;
  unsigned int process_snapshot = 
    options->snapshot_type & STATE_SNAPSHOT_TYPE_PROCESS;
  unsigned int system_snapshot = 
    options->snapshot_type & STATE_SNAPSHOT_TYPE_SYSTEM;

  /* remove address hook */
  if (options->hook_handle) {
    gva_t eip = DECAF_getPC(options->env);
    if (eip == options->stateaddr) {
      monitor_printf(default_mon, "Saving state at address: 0x%08x\n",
                      options->stateaddr);
      hookapi_remove_hook(options->hook_handle);
    }
  }

  /* Stop the VM */
  DECAF_stop_vm();

  /* fail if the there is no file handle */
  if (!options->statelog)
    goto fail;

  if (process_snapshot) {
    monitor_printf(default_mon,"Saving state for CR3: 0x%08x\n", 
                    options->statecr3);
  }
  else if (system_snapshot) {
    use_virtual_addresses = 0;
    monitor_printf(default_mon,"Saving system state\n"); 
  }
  else {
    monitor_printf(default_mon,"Unknown snapshot type\n");
    goto fail;
  }

  /* Save registers into structure if needed */
#if SAVE_REGISTERS != 0
  saved_registers = save_registers(options->env, &regs);
#endif

  /* Compute flags */
  flags |= saved_registers;
#ifdef TAINT_ENABLED
#if SAVE_TAINT != 0
  flags |= STATE_SAVE_TAINT_MASK;
#endif // #if SAVE_TAINT != 0
#endif // #ifdef TAINT_ENABLED
  if (!process_snapshot || (SAVE_KERNEL_MEM != 0)) {
    flags |= STATE_SAVE_KERNEL_MEM_MASK;
  }
  flags |= (use_virtual_addresses << 3);
  flags |= (process_snapshot << 4);

  /* Create state file header */
  header.magic_number = STATE_MAGIC_NUMBER;
  header.version = STATE_VERSION_NUMBER;
  header.word_size = TARGET_LONG_BITS;
  header.flags = flags;

  /* Write header to state file */
  fwrite(&header, sizeof(StateHeader), 1, options->statelog);

  /* Write register structure if needed */
  if (saved_registers == 1) {
    fwrite(&regs, sizeof(regs), 1, options->statelog);
  }

  /* Flush the metadata (header + registers) */
  fflush(options->statelog);

  /* save memory */
  //traverse_pages();
  uint32_t page_start_addr = 0, paddr = 0;
  unsigned char page_buf[STATE_PAGE_SIZE];
  int err = 0;
  uint32_t size, offset, l;
  target_phys_addr_t page_phys_addr;

  /* Select a stop address */
  uint32_t stop_addr;
  if (process_snapshot) {
#if SAVE_KERNEL_MEM == 0
    // Avoid saving kernel memory if not requested
    stop_addr = VMI_guest_kernel_base - STATE_PAGE_SIZE;
#else
    stop_addr = 0xFFFFE000;
#endif
  }
  else {
    // ram_size defined in sysemu.h
    stop_addr = ram_size - STATE_PAGE_SIZE;
  }

  //monitor_printf(default_mon, "Stop_addr: 0x%08x\n", stop_addr);

  for (page_start_addr = 0; page_start_addr <= stop_addr; 
       page_start_addr+= STATE_PAGE_SIZE)
  {

    if (process_snapshot) {
      //monitor_printf(default_mon, "Page_start: 0x%08x (virtual)\n", 
      //  page_start_addr);
      err = DECAF_read_mem_with_pgd(options->env, options->statecr3, 
                                    page_start_addr, STATE_PAGE_SIZE, 
                                    page_buf);
    }
    else {
      //monitor_printf(default_mon, "Page_start: 0x%08x (physical)\n", 
      //  page_start_addr);

      size = STATE_PAGE_SIZE;
      paddr = page_start_addr;
      offset = 0;
      while (size > 0) {
        l = MAX_PHYS_MEMSIZE_READ;
        if (l > size)
            l = size;
        //monitor_printf(default_mon, "Reading: 0x%08x (%d) -> 0x%08x\n", 
        //  paddr, l, page_buf + offset);
        cpu_physical_memory_rw(paddr, page_buf + offset, l, 0);
        paddr += l;
        size -= l;
        offset += l;
      }
      err = 0;
    }

    if (!err) {
      region_t range;

      /* Process snapshot and physical address */
      if (process_snapshot && !use_virtual_addresses) {
        page_phys_addr = DECAF_get_phys_addr_with_pgd(NULL, 
                                options->statecr3, page_start_addr);
        range.begin = page_phys_addr;
        range.end = page_phys_addr + STATE_PAGE_SIZE - 1;
      }
      /* System snapshot -> page_start_addr is physical address 
          or
         Process snaphsot with virtual addr -> page_start is virtual address */
      else {
        range.begin = page_start_addr;
        range.end = page_start_addr + STATE_PAGE_SIZE - 1;
      }

      //monitor_printf(default_mon, "Writing page: 0x%08x -> 0x%08x\n", 
      //   range.begin, range.end);

      /* write range to file */
      fwrite(&range, sizeof(range), 1, options->statelog);

      /* write page to file */
      fwrite(page_buf, 1, STATE_PAGE_SIZE, options->statelog);
      //fflush(options->statelog);

#ifdef TAINT_ENABLED
#if SAVE_TAINT != 0
      /* Write taint data for the page to file, by breaking in 
         taint blocks of size STATE_TAINT_BLOCK_SIZE */
      unsigned int i, j;
      uint32_t offset;
      taint_block_t tb;
      uint64_t taintmask, bitmask;
      size_t num_elems_written = 0;
      taint_record_t trecords[STATE_TAINT_BLOCK_SIZE];

      /* Get physical address for this page */
      if (process_snapshot) {
        page_phys_addr = DECAF_get_phys_addr_with_pgd(NULL, options->statecr3, 
                                                      page_start_addr);
        //monitor_printf(default_mon, "PhysAddr: 0x%08x\n", page_phys_addr);
      }
      else {
        page_phys_addr = page_start_addr;
      }

      /* write taint blocks to file */
      if(page_phys_addr != -1) {
        for (i = 0; i < num_taint_blocks_in_page; i++) {
          offset = STATE_TAINT_BLOCK_SIZE * i;
          taintmask = 
            taintcheck_memory_check(page_phys_addr + offset, 
              STATE_TAINT_BLOCK_SIZE, (void *)trecords);
          /* Write the taint block */
          tb.begin = page_start_addr + offset;
          tb.taint_mask = taintmask;
          fwrite(&tb, sizeof(taint_block_t), 1, options->statelog);
          if (taintmask != 0) {
            //monitor_printf(default_mon, "Found taint block @ 0x%08x\n", 
            //                tb.begin);
            /* Write the taint data */
            for (j = 0; j < STATE_TAINT_BLOCK_SIZE; j++) {
              bitmask = 1LLU << j;
              if (taintmask & bitmask) {
                /* Write fixed part of taint_record */
                assert(trecords[j].numRecords > 0 && 
                  trecords[j].numRecords <= MAX_NUM_TAINTBYTE_RECORDS);
                num_elems_written +=
                  fwrite(&(trecords[j].numRecords), TAINT_RECORD_FIXED_SIZE, 
                    1, options->statelog);

                /* Write only the non-empty taint_byte_record */
                num_elems_written += 
                  fwrite(&(trecords[j].taintBytes), sizeof(TaintByteRecord), 
                    trecords[j].numRecords, options->statelog);
              }
            }
          }
        }
      }
#endif // #if (SAVE_TAINT != 0)
#endif // #ifdef TAINT_ENABLED
    }
  }

  /* close state file */
  fclose(options->statelog);

  /* Clear options */
  memset(options, 0, sizeof(SaveStateOptions));

  /* Restart the VM */
  DECAF_start_vm();

  return;

fail:
  DECAF_start_vm();
  return;
}

/* Save state for given process (identified by CR3) */
int save_system_state(CPUState* env, const char *filename) {
  FILE *statelog;

  /* Open snapshot file */
  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_by_cr3");
    return 1;
  }

  /* Set options */
  save_state_options.hook_handle = 0;
  save_state_options.snapshot_type = 0;
  save_state_options.use_virtual_addresses = 0;
  save_state_options.statelog = statelog;
  save_state_options.statecr3 = 0;
  save_state_options.stateaddr = 0;
  save_state_options.env = env;

  /* Save snapshot */
  save_state(&save_state_options);

  return 0;
}


/* Save state for given process (identified by CR3) */
int save_state_by_cr3(CPUState* env, uint32_t cr3, const char *filename, 
                      int snapshot_type) 
{
  FILE *statelog;

  /* Open snapshot file */
  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_by_cr3");
    return 1;
  }

  /* Set options */
  save_state_options.hook_handle = 0;
  save_state_options.snapshot_type = snapshot_type;
  save_state_options.use_virtual_addresses = 1;
  save_state_options.statelog = statelog;
  save_state_options.statecr3 = cr3;
  save_state_options.stateaddr = 0;
  save_state_options.env = env;

  /* Save snapshot */
  save_state(&save_state_options);

  return 0;
}

/* Save state for given process (identified by PID) */
int save_state_by_pid(CPUState* env, uint32_t pid, const char *filename, 
                      int snapshot_type) 
{
  FILE *statelog;
  uint32_t statecr3;

  /* Find CR3 */
  statecr3 = VMI_find_cr3_by_pid_c(pid);
  if (0 == statecr3)
    return 1;

  /* Open snapshot file */
  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_by_pid");
    return 1;
  }

  /* Set options */
  save_state_options.hook_handle = 0;
  save_state_options.snapshot_type = snapshot_type;
  save_state_options.use_virtual_addresses = 1;
  save_state_options.statelog = statelog;
  save_state_options.statecr3 = statecr3;
  save_state_options.stateaddr = 0;
  save_state_options.env = env;

  /* Save snapshot */
  save_state(&save_state_options);

  return 0;
}

/* Save state for given process (identified by PID) 
 * when process execution reaches given address */
int save_state_at_addr(CPUState* env, uint32_t pid, uint32_t addr, 
                        const char *filename, int snapshot_type)
{
  uint32_t statecr3;
  FILE *statelog;

  /* Find CR3 */
  statecr3 = VMI_find_cr3_by_pid_c(pid);
  if (0 == statecr3)
    return 1;

  /* Open snapshot file */
  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_at_addr");
    return 1;
  }

  /* Set options */
  save_state_options.snapshot_type = snapshot_type;
  save_state_options.use_virtual_addresses = 1;
  save_state_options.statelog = statelog;
  save_state_options.statecr3 = statecr3;
  save_state_options.stateaddr = addr;
  save_state_options.env = env;

  /* Hook address */
  monitor_printf(default_mon,
    "Hooking save state address: 0x%08x CR3: 0x%08x\n", addr, statecr3);
  save_state_options.hook_handle =
    hookapi_hook_function(0, addr, statecr3, save_state, 
      &save_state_options, sizeof(SaveStateOptions));

  return 0;
}

