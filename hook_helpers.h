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

#ifndef _HOOK_HELPERS_H_
#define _HOOK_HELPERS_H_

#include <inttypes.h>
#include <stdio.h>
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "hookapi.h"


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

static inline int read_mem(uint32_t vaddr, int length, unsigned char *buf)
{
  return (DECAF_read_mem(cpu_single_env, vaddr, length, buf) < 0);
}

static inline int write_mem(uint32_t vaddr, int length, unsigned char *buf)
{
  return (DECAF_write_mem(cpu_single_env, vaddr, length, buf) < 0);
}

/* Return the module and function name corresponding to the given instruction
Returns 0 if the EIP corresponds to the entry point of a known function, 
-1 otherwise.
    If the return value is 0 the module and function name are copied into the 
    mod_name_ptr and fun_name_ptr, otherwise those buffers contain "unknown".
    The function assumes that the query is for the process being traced
    NOTE: make sure that the buffers pointed by mod_name_ptr, fun_name_ptr 
    have at least 512 bytes 
*/ 
extern int get_function_name (uint32_t eip, char *mod_name_ptr, char *fun_name_ptr);
extern void get_procname(char *buf, uint32_t *pid);
extern int write_log(const char *const name, const char *const fmt, ...);
#if 0
#ifdef TAINT_ENABLED
//extern int taint_mem(uint32_t vaddr, uint32_t size, void *param);
extern int taint_reg(int reg_id, void *param);
extern uint64_t get_mem_taint(uint32_t vaddr, uint32_t size, uint8_t *records);
extern void clean_mem_taint(uint32_t vaddr, int size);
#endif // #ifdef TAINT_ENABLED
#endif

#ifdef __cplusplus
};
#endif // __cplusplus

#endif // _HOOK_HELPERS_H_
