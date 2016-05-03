/* 
 *  hooks helper functions
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

#ifndef _GROUP_HOOK_HELPER_H_
#define _GROUP_HOOK_HELPER_H_

#include "config.h"
#undef INLINE
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "shared/hookapi.h"
#include "shared/vmi_c_wrapper.h"
#include "hook_helpers.h"
#include "tfd.h"
#include "hook_plugin_loader.h"

#if TAINT_ENABLED
#define TAINT_RECORD_ONLY
#include "../trace.h" //for taint_record_t
#undef TAINT_RECORD_ONLY
#include "../skiptaint.h"
#endif // #if TAINT_ENABLED

/* 
** hook table types (used for generically hooking a list of functions 
*/
typedef void (*fcn_hook_t)(void *);

typedef struct {
  char *module;
  char *name;
  fcn_hook_t fcn;
  int do_hook;
} hook_t;


typedef struct {
  uint32_t hook_handle;
} retaddr_t;

void initialize_plugin(hook_t *hooks,int num_funs);
uint32_t get_retaddr();
uint32_t get_arg(int argnum);
void print_buffer(uint8_t * start, uint32_t len);
int get_string(uint32_t address, char *str, int max_size);
int get_unicode_string(uint32_t address, char *str, int str_max_size);
int get_bin_string(const char *str, int str_len, char *out, int out_size);

#if TAINT_ENABLED
uint64_t get_reg_taint(int reg_id);
int clean_taint_reg(int reg_id);
int is_arg_tainted(int argnum);
int is_str_tainted(uint32_t vaddr, int *len);
int get_string_taint(uint32_t address, uint32_t taintinfo[][2], int size);
void print_string_taint(FILE *fd,  uint32_t taintinfo[][2], int size,
  unsigned int bytes_per_line);
#endif // #if TAINT_ENABLED


#endif // #ifndef _GROUP_HOOK_HELPER_H_
