/* 
 *  helper functions for hooks
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
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
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#ifdef TAINT_ENABLED
#include "shared/tainting/taintcheck_opt.h"
#include "shared/tainting/tainting.h"
#endif // #ifdef TAINT_ENABLED
#include "hook_helpers.h"
#ifdef TRACE_VERSION_50
#include "trace50.h"
#else
#include "trace.h"
#endif
#include "tfd.h"
#include "shared/function_map.h"
#include "shared/hookapi.h"
#include "shared/vmi_c_wrapper.h"

#if 0
#ifdef TAINT_ENABLED
/* Taint a memory region. Caller is in charge of freeing param */
int taint_mem(uint32_t vaddr, uint32_t size, void *param)
{
  TaintByteRecord *hook_rec = param;
  //fprintf(stderr,"tainting: 0x%x, size=%d, type=%d, origin=%d, offset=%d\n",
  //    vaddr, size, hook_rec->source, hook_rec->origin, hook_rec->offset);

  uint32_t paddr = 0, vaddr2=0;
  taint_record_t records[64];
  uint32_t i, j, len, offset;
  uint32_t trOffset = hook_rec->offset;

  for(i=0; i<size; i+=len) {
    vaddr2 = vaddr;
    paddr = DECAF_get_phys_addr(NULL, (vaddr+i)&TARGET_PAGE_MASK);
    offset = (vaddr+i)&(TARGET_PAGE_SIZE-1);
    paddr += offset;
    len = 
      (TARGET_PAGE_SIZE - offset > size-i) ? size-i : TARGET_PAGE_SIZE-offset;
    
    /* while loop is because we can only taint 64 bytes at a time */
    int rem_size = len;
    while (rem_size > 0) {
      int this_size = rem_size <= 64 ? rem_size : 64;
      
      unsigned char vals[64];
      assert(!read_mem(vaddr2, this_size, vals));
    
      for (j = 0; j < this_size; j++) {
        memset (&records[j],0,sizeof(taint_record_t));
        records[j].numRecords = 1;
        records[j].taintBytes[0].source = hook_rec->source;
        records[j].taintBytes[0].origin = hook_rec->origin;
        records[j].taintBytes[0].offset = trOffset;
        trOffset++;
      } /* end for */

      /* actually do taint */
      taintcheck_taint_memory(paddr, this_size, 
        (this_size<64)? (1ULL<<size)-1: (uint64_t)(-1), 
        (uint8_t*)records);
      //fprintf(stderr,"  paddr=%08x vaddr2=%08x this_size=%d \n", 
      //  paddr, vaddr2, this_size);

      /* prepare for next loop iteration */
      rem_size -= this_size;
      vaddr2 += this_size;
      paddr += this_size;
    } /* end while */
  }

  // free (param);
  return 0;
}


int taint_reg(int reg_id, void *param)
{
  TaintByteRecord *hook_rec = param;
  
  /* we do not taint EIP currently --Heng Yin */
  if(reg_id == eip_reg) return -1;

  taint_record_t records[MAX_OPERAND_LEN];
  //memset (&records,0,sizeof(records));

  uint32_t base_id=0, reg_offset=0, size=0;
  reg_index_from_id(reg_id, &base_id, &reg_offset, &size);
  int i;
  for (i = 0; i < size; ++i) {
    records[i].numRecords = 1;
    records[i].taintBytes[0].source = TAINT_SOURCE_HOOKAPI; //hook_rec->source
    records[i].taintBytes[0].origin = hook_rec->origin;
    records[i].taintBytes[0].offset = hook_rec->offset + i;
  }
  
  taintcheck_taint_register(base_id, reg_offset, size, (1<<size)-1, 
    (uint8_t*)records);
  return 0;
}


uint64_t get_mem_taint(uint32_t vaddr, uint32_t size, uint8_t *rec) //size<=64
{
  //return taintcheck_check_virtmem(NULL, vaddr, size, rec);
  return taintcheck_check_virtmem(vaddr, size);
}

/* recover the taint information 
 * size <= 64
 */
void set_mem_taint(uint32_t vaddr, uint32_t size, uint64_t taint, 
                    uint8_t *records)
{
  taintcheck_taint_virtmem(NULL, vaddr, size, taint, records);
}


void clean_mem_taint(uint32_t vaddr, int size)
{
  taintcheck_taint_virtmem(NULL, vaddr, size, 0, NULL);
}

#endif // #ifdef TAINT_ENABLED
#endif

void get_procname(char *buf, uint32_t *pid)
{
  VMI_find_process_by_cr3_c(cpu_single_env->cr[3], buf, MAX_STRING_LEN, pid);
}


int write_log(const char *const name, const char *const fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char hookname[128]= "";
  
  if ((strncmp(name,"tracenetlog",11) == 0) && (tracenetlog)) {
    vfprintf(tracenetlog, fmt, ap);   
  }
  else if (strncmp(name,"tracehooklog",12) == 0) {
    if (!tracehooklog) {
      snprintf(hookname, 128, "%s.hooklog", tracename_p); 
      tracehooklog = fopen(hookname, "w");
      if (0 == tracehooklog) {
        perror("write_log");
        return -1;
      }
      vfprintf(tracehooklog, fmt, ap);
    }
    else {
     vfprintf(tracehooklog, fmt, ap);
    }
  }
  else {
    vfprintf(stderr, fmt, ap);
  }
  va_end(ap);

  return 0;
}

int get_function_name (uint32_t eip, char *mod_name_ptr, char *fun_name_ptr)
{
  int error = funcmap_get_name_c(eip, tracecr3, mod_name_ptr, fun_name_ptr);
  if (error != 0) {
    strncpy(mod_name_ptr,"unknown",512);
    strncpy(fun_name_ptr,"unknown",512);
  }
  else {
    mod_name_ptr[511] = '\0';
    fun_name_ptr[511] = '\0';
  }
  return error;
}

