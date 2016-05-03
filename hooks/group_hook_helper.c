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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "group_hook_helper.h"


/* Common functionality to initialize plugin */
void initialize_plugin(hook_t *hooks,int num_funs) {
  /* Set functions that need to be hooked */
  int i;
  for (i = 0; i < num_funs; i++) {
    if (should_hook(hooks[i].module, hooks[i].name))
      hooks[i].do_hook = 1;
  }

  //WRITE ("plugin", "ENABLED:\n");

  /* Hook functions that should be hooked */
  for (i = 0; i < num_funs; i++) {
    if (0 != hooks[i].do_hook) {
      //WRITE ("plugin", "\tHooking %s::%s\n",
      //  hooks[i].module, hooks[i].name);
      hookapi_hook_function_byname(hooks[i].module, hooks[i].name,
        0, tracecr3, hooks[i].fcn, 0, 0);
    }
  }

  //WRITE ("plugin", "DISABLED:\n");

  /* Print which functions were not hooked
  for (i = 0; i < local_num_funs; i++) {
    if (0 == hooks[i].do_hook) {
      WRITE ("plugin", "\tNOT Hooking %s::%s\n",
        hooks[i].module, hooks[i].name);
    }
  }
  */
}

/* Read the return address from the stack */
uint32_t get_retaddr() {
  uint32_t retaddr = 0;
  int read_err = 0;

  // TODO: Should CPU State be non-NULL?
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            4, (unsigned char*)&retaddr);
  if (read_err)
    return 0;
  else
    return retaddr;
}

/* Print the buffer */
void print_buffer(uint8_t * start, uint32_t len) {
  char c = 0;
  uint8_t *ptr;

  uint8_t *strbuf = (uint8_t *)malloc (len * sizeof(uint8_t));
  if (strbuf == NULL) return;
  read_mem(start, len, strbuf);

  for (ptr = start; ptr < start + len; ptr++) {
    c = *ptr;
    if(isprint(c))
      write_log("stderr","\\%02X'%c'", c, c);
    else
      write_log("stderr","\\%02X", c);
  }
  write_log("stderr","\n");

  if (strbuf) free(strbuf);
}

/* Read a string from memory */
int get_string(uint32_t address, char *str, int str_max_size)
{
  int read_err = 0;
  unsigned int i = 0;
  while (i < str_max_size) {
    read_err = read_mem(address+i, 1, (unsigned char*)(str+i));
    if (read_err) {
      fprintf(stderr,"Got error when reading memory: 0x%x\n",address+i);
      str[i] = '\0';
    }
    if (str[i] == '\0') break;
    i++;
  }

  str[str_max_size-1] = '\0';
  return i;
}

// Read a Unicode string from memory
// Halfs maximum size if memory error found
int get_unicode_string(uint32_t address, char *str, int str_max_size)
{
  int read_err = 0;
  unsigned int i = 0;
  while (i < str_max_size) {
    read_err = read_mem(address+i, 2, (unsigned char*)(str+i));
    if (read_err) {
      str[i] = '\0';
      str[i+1] = '\0';
    }
    if (str[i] == '\0') break;
    i+=2;
  }

  str[str_max_size-1] = '\0';
  str[str_max_size-2] = '\0';
  return i;
}

/* Read argument from stack (assumes arguments are 4-byte long) */
uint32_t get_arg(int argnum)
{
  uint32_t arg;
  int read_err = 0;

  read_err = read_mem(cpu_single_env->regs[R_ESP]+4*argnum, 
                      4, (unsigned char*)&arg);
  if (read_err) return -1;

  return arg;
}

int get_bin_string(const char *str, int str_len, char *out, int out_size)
{
  int i = 0, num_chars = 0;
  char *curr_pos = out;
  char *end_buf = out + out_size - 3;

  if (str_len == 0) {
    sprintf(curr_pos,"00");
    out[2] = '\0';
    return 1;
  }

  for (i = 0; i < str_len; i++) {
    if (curr_pos >= end_buf) break;
    num_chars = sprintf(curr_pos,"%02x",(unsigned char)str[i]);
    curr_pos+=num_chars;
  }
  *curr_pos = '\0';
  return (curr_pos - out);
}


#if TAINT_ENABLED 
/* Returns the taint mask of a register */
uint64_t get_reg_taint(int reg_id) {
  uint32_t regnum=0, reg_offset=0, size=0;

  reg_index_from_id(reg_id, &regnum, &reg_offset, &size);
  return taintcheck_register_check(regnum, reg_offset, size, NULL);
}

/* Cleans the taint information of a register */
int clean_taint_reg(int reg_id) {
  uint32_t regnum=0, reg_offset=0, size=0;

  /* we do not taint EIP currently --Heng Yin */
  if(reg_id == eip_reg) return -1;

  reg_index_from_id(reg_id, &regnum, &reg_offset, &size);
  taintcheck_taint_register(regnum, reg_offset, size, 0, NULL);

  return 0;
}

/* Check if argument is tainted (assumes argument is 4-byte long)
    Returns 1 for tainted, 0 for not tainted */
int is_arg_tainted(int argnum)
{
  uint64_t taint;

  taint_record_t tr[4];
  memset((void *)tr,0,4*sizeof(taint_record_t));

  taint = get_mem_taint (cpu_single_env->regs[R_ESP]+4*argnum, 
                          4, (uint8_t *)&tr);

  if(taint)
    return 1;
  else
    return 0;
}

/*
 * check if the content of a buffer is tainted
 * vaddr: virtual address of the buffer
 * len: the buffer length, if *len=0, we treat the buffer as string and return
 * the actual length.
 * returns:
 *  0 - concrete buffer
 *  1 - tainted buffer (any of the bytes is tainted)
 */
int is_str_tainted(uint32_t vaddr, int *len)
{
  uint64_t taint;
  uint32_t ptr;
  int res = 0;
  unsigned char temp;
  int read_error = 0;

  uint32_t size = (uint32_t)*len;
  if (size != 0) {
  taint = get_mem_taint(vaddr, size, NULL);
  if (taint)
    return 1;
  else
    return 0;
  }

  /*
   * read buffer until either:
   * (1) if *len == 0, NULL character is found, or undetermined symbol is found
   * (2) if *len != 0, i>=*len
   */
  for (ptr = vaddr; ; ptr++) {
    read_error = read_mem(ptr, 1, &temp);
    if (read_error || (temp == 0))
      break;
    taint = get_mem_taint(ptr, 1, NULL);
    if (taint) {
      res = 1;
    }
    size++;
  }
  *len = size;

  return res;
}

/* Check if string is tainted
     Returns number of tainted bytes in string */
int get_string_taint(uint32_t address, uint32_t taintinfo[][2], int size)
{
  uint64_t taint;
  int taint_ctr = 0;

  taint_record_t tr;

  int i;
  // Special case for empty string. Check null terminator taint
  if (0 == size) {
    taint = get_mem_taint (address, 1, (uint8_t *)&tr);
    if (taint) {
      taintinfo[0][0] = tr.taintBytes[0].origin;
      taintinfo[0][1] = tr.taintBytes[0].offset;
      return 1;
    }
    else {
      taintinfo[0][0] = 0;
      taintinfo[0][1] = 0xffffffff;
      return 0;
    }
  }
  // Normal case
  for (i = 0; i<size; i++) {
    taint = get_mem_taint (address+i, 1, (uint8_t *)&tr);
    if (taint) {
      taint_ctr++;
      taintinfo[i][0] = tr.taintBytes[0].origin;
      taintinfo[i][1] = tr.taintBytes[0].offset;
    }
    else {
      taintinfo[i][0] = 0;
      taintinfo[i][1] = 0xffffffff;
    }
  }

  return taint_ctr;
}

void print_string_taint(FILE *fd,  uint32_t taintinfo[][2], int size, 
  unsigned int bytes_per_line)
{
  int i;
  for (i = 0; i < size; i++) {
    if (i % bytes_per_line == 0) {
      fprintf(fd,"%3d-%3d: ", i, i+bytes_per_line-1);
    }
    if ((taintinfo[i][0] == 0) && (taintinfo[i][1] == 0xffffffff)) {
      fprintf(fd,"(,) ");
    }
    else {
      fprintf(fd,"(%u,%u) ", taintinfo[i][0], taintinfo[i][1]);
    }
    if ((i+1) % bytes_per_line == 0) {
      fprintf(fd,"\n");
    }
  }
  if ((i+1) % bytes_per_line != 0) {
    fprintf(fd,"\n");
  }
  fflush(fd);
}

#endif //TAINT_ENABLED

