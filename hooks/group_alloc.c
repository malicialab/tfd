/* 
 *  hooks for memory allocation and deallocation
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

/*
 * TODO: Add 
 *    kernel32.dll::VirtualAllocEx, kernel32.dll::VirtualFreeEx
 *    msvcr100.dll::_recalloc, msvcr100_clr0400.dll::_recalloc
 *    msvcr80.dll::_aligned_malloc, msvcr80.dll::_aligned_offset_malloc
*/

#include <stdio.h>
#include <string.h>
#include "skiptaint.h"
#include "group_hook_helper.h"
#include "group_alloc.h"

#define LOCAL_DEBUG 1
#define WRITE if (LOCAL_DEBUG) write_log

hook_t hooks[] =
{
  /* Heap allocation */
  {"cygwin1.dll", "_malloc", malloc_call, 0},
  {"cygwin1.dll", "_calloc", calloc_call, 0},
  {"cygwin1.dll", "_realloc", realloc_call, 0},
  {"cygwin1.dll", "_free", free_call, 0},
  {"msvcrt.dll", "malloc", malloc_call, 0},
  {"msvcrt.dll", "_malloc_crt", malloc_call, 0},
  {"msvcrt.dll", "??2@YAPAXI@Z", malloc_call, 0},
  {"msvcrt.dll", "calloc", calloc_call, 0},
  {"msvcrt.dll", "_calloc_crt", calloc_call, 0},
  {"msvcrt.dll", "realloc", realloc_call, 0},
  {"msvcrt.dll", "_realloc_crt", realloc_call, 0},
  {"msvcrt.dll", "free", free_call, 0},
  {"msvcrt.dll", "??3@YAXPAX@Z", free_call, 0},
  {"MSVCR71.DLL", "malloc", malloc_call, 0},
  {"MSVCR71.DLL", "_malloc_crt", malloc_call, 0},
  {"MSVCR71.DLL", "??2@YAPAXI@Z", malloc_call, 0},
  {"MSVCR71.DLL", "calloc", calloc_call, 0},
  {"MSVCR71.DLL", "_calloc_crt", calloc_call, 0},
  {"MSVCR71.DLL", "realloc", realloc_call, 0},
  {"MSVCR71.DLL", "_realloc_crt", realloc_call, 0},
  {"MSVCR71.DLL", "free", free_call, 0},
  {"MSVCR71.DLL", "??3@YAXPAX@Z", free_call, 0},
  {"msvcr80.dll", "malloc", malloc_call, 0},
  {"msvcr80.dll", "_malloc_crt", malloc_call, 0},
  {"msvcr80.dll", "??2@YAPAXI@Z", malloc_call, 0},
  {"msvcr80.dll", "calloc", calloc_call, 0},
  {"msvcr80.dll", "_calloc_crt", calloc_call, 0},
  {"msvcr80.dll", "realloc", realloc_call, 0},
  {"msvcr80.dll", "_realloc_crt", realloc_call, 0},
  {"msvcr80.dll", "free", free_call, 0},
  {"msvcr80.dll", "??3@YAXPAX@Z", free_call, 0},
  {"msvcr100.dll", "malloc", malloc_call, 0},
  {"msvcr100.dll", "_malloc_crt", malloc_call, 0},
  {"msvcr100.dll", "??2@YAPAXI@Z", malloc_call, 0},
  {"msvcr100.dll", "calloc", calloc_call, 0},
  {"msvcr100.dll", "_calloc_crt", calloc_call, 0},
  {"msvcr100.dll", "realloc", realloc_call, 0},
  {"msvcr100.dll", "_realloc_crt", realloc_call, 0},
  {"msvcr100.dll", "free", free_call, 0},
  {"msvcr100.dll", "??3@YAXPAX@Z", free_call, 0},
  {"ntdll.dll", "RtlCreateHeap", rtl_create_heap_call, 0},
  {"ntdll.dll", "RtlAllocateHeap", rtl_allocate_heap_call, 0},
  {"ntdll.dll", "RtlFreeHeap", rtl_free_heap_call, 0},
  {"ntdll.dll", "RtlReAllocateHeap", rtl_reallocate_heap_call, 0},
  {"ntdll.dll", "ZwAllocateVirtualMemory", zw_allocate_virtual_memory_call, 0},
  {"ole32.dll", "CoTaskMemAlloc", malloc_call, 0},
  {"ole32.dll", "CoTaskMemFree", free_call, 0},
  {"ole32.dll", "CoTaskMemRealloc", realloc_call, 0},
  //{"kernel32.dll", "HeapCreate", heap_create_call, 0},
  {"kernel32.dll", "VirtualAlloc", virtual_alloc_call, 0},
  {"kernel32.dll", "VirtualFree", virtual_free_call, 0},
  {"kernel32.dll", "LocalAlloc", local_alloc_call, 0},
  {"kernel32.dll", "LocalReAlloc", local_realloc_call, 0},
  {"kernel32.dll", "LocalFree", local_free_call, 0},
  {"kernel32.dll", "GlobalAlloc", local_alloc_call, 0},
  {"kernel32.dll", "GlobalReAlloc", local_realloc_call, 0},
  {"kernel32.dll", "GlobalFree", local_free_call, 0},

  /* Map Views */
  {"ntdll.dll", "ZwMapViewOfSection", zw_map_view_of_section_call, 0},
  {"ntdll.dll", "ZwUnmapViewOfSection", zw_unmap_view_of_section_call, 0},

  /* Firefox custom allocators */
  // {"mozalloc.dll", "moz_malloc", malloc_call, 0},
  // {"mozalloc.dll", "moz_xmalloc", malloc_call, 0},
  // {"mozalloc.dll", "moz_calloc", calloc_call, 0},
  // {"mozalloc.dll", "moz_xcalloc", calloc_call, 0},
  // {"mozalloc.dll", "moz_realloc", realloc_call, 0},
  // {"mozalloc.dll", "moz_xrealloc", realloc_call, 0},
  // {"mozalloc.dll", "moz_free", free_call, 0},
  // {"mozalloc.dll", "moz_xfree", free_call, 0},
  // {"mozalloc.dll", "moz_memalign", memalign_call, 0},
  // {"mozalloc.dll", "moz_posix_memalign", posix_memalign_call, 0},
  // {"mozalloc.dll", "moz_xposix_memalign", posix_memalign_call, 0},
  // {"mozcrt19.dll", "malloc", malloc_call, 0},
  // {"mozcrt19.dll", "_malloc_crt", malloc_call, 0},
  // {"mozcrt19.dll", "??2@YAPAXI@Z", malloc_call, 0},
  // {"mozcrt19.dll", "calloc", calloc_call, 0},
  // {"mozcrt19.dll", "_calloc_crt", calloc_call, 0},
  // {"mozcrt19.dll", "realloc", realloc_call, 0},
  // {"mozcrt19.dll", "_realloc_crt", realloc_call, 0},
  // {"mozcrt19.dll", "free", free_call, 0},
  // {"mozcrt19.dll", "??3@YAXPAX@Z", free_call, 0},
  // {"mozcrt19.dll", "_V@YAXPAX@Z", free_call, 0},
  // {"mozcrt19.dll", "memalign", memalign_call, 0},
  // {"mozcrt19.dll", "posix_memalign", posix_memalign_call, 0},
  // {"xul.dll", "NS_Alloc", malloc_call, 0},
  // {"xul.dll", "NS_Alloc_P", malloc_call, 0},
  // {"xul.dll", "NS_Realloc", realloc_call, 0},
  // {"xul.dll", "NS_Realloc_P", realloc_call, 0},
  // {"xul.dll", "NS_Free", free_call, 0},
  // {"xul.dll", "NS_Free_P", free_call, 0},
  // {"nspr4.dll", "PR_Malloc", malloc_call, 0},
  // {"nspr4.dll", "PR_Calloc", calloc_call, 0},
  // {"nspr4.dll", "PR_Realloc", realloc_call, 0},
  // {"nspr4.dll", "PR_Free", free_call, 0},
  // {"mozsqlite3.dll", "sqlite3_malloc", malloc_call, 0},
  // {"mozsqlite3.dll", "sqlite3_realloc", realloc_call, 0},
  // {"mozsqlite3.dll", "sqlite3_free", free_call, 0},
  // More Firefox internal hooks in internal_init_plugin

  /* Safari custom allocators */
  //{"CoreFoundation.dll", "CFAllocatorAllocate", 
  //   cf_allocator_allocate_call, 0},
  //{"CoreFoundation.dll", "CFAllocatorReallocate", 
  //   cf_allocator_reallocate_call, 0},
  //{"CoreFoundation.dll", "CFAllocatorDeallocate", 
  //   cf_allocator_deallocate_call, 0},
  //{"WebKit.dll", "?fastZeroedMalloc@WTF@@YAPAXI@Z", malloc_call, 0},
  //{"WebKit.dll", "?fastCalloc@WTF@@YAPAXII@Z", calloc_call, 0},
  //{"JavaScriptCore.dll", "?fastMalloc@WTF@@YAPAXI@Z", malloc_call, 0},
  //{"JavaScriptCore.dll", "?fastZeroedMalloc@WTF@@YAPAXI@Z", malloc_call, 0},
  //{"JavaScriptCore.dll", "?fastCalloc@WTF@@YAPAXII@Z", calloc_call, 0},
  //{"JavaScriptCore.dll", "?fastRealloc@WTF@@YAPAXPAXI@Z", realloc_call, 0},
  //{"JavaScriptCore.dll", "?fastFree@WTF@@YAXPAX@Z", free_call, 0},
  //{"WebKit.dll", "?fastMalloc@WTF@@YAPAXI@Z", malloc_call, 0},
  //{"WebKit.dll", "?fastZeroedMalloc@WTF@@YAPAXI@Z", malloc_call, 0},
  //{"WebKit.dll", "?fastCalloc@WTF@@YAPAXII@Z", calloc_call, 0},
  //{"WebKit.dll", "?fastFree@WTF@@YAXPAX@Z", free_call, 0},


  /* Pigdin custom allocators */
  //{"libglib-2.0-0.dll", "g_malloc", malloc_call, 0},
  //{"libglib-2.0-0.dll", "g_malloc0", malloc_call, 0},
  //{"libglib-2.0-0.dll", "g_realloc", realloc_call, 0},
  //{"libglib-2.0-0.dll", "g_free", free_call, 0},
  //{"libglib-2.0-0.dll", "g_slice_alloc", malloc_call, 0},
  //{"libglib-2.0-0.dll", "g_slice_alloc0", malloc_call, 0},
  //{"libglib-2.0-0.dll", "g_slice_free1", g_slice_free1_call, 0},
  //{"libglib-2.0-0.dll", "g_slice_free_chain_with_offset",
  //    g_slice_free_chain_with_offset_call, 0},

};

int local_num_funs = (sizeof(hooks)/sizeof(hook_t));

void open_alloc_file() {
  char alloc_filename[128];
  snprintf(alloc_filename, 128, "%s.alloc", tracename_p);
  fprintf(stderr,"Opening file %s\n", alloc_filename);
  alloclog = fopen(alloc_filename, "w");
}

void internal_init_plugin()
{
  initialize_plugin(hooks,local_num_funs);

  /* Firefox custom allocators (internal) */
  // mozsqlite3.dll::sqlite3DbMallocRaw
  //hookapi_hook_function(0, 0x00285f30, sqlite3_db_alloc_call, NULL, 0);
  // mozsqlite3.dll::sqlite3DbRealloc
  //hookapi_hook_function(0, 0x002bd9e0, sqlite3_db_realloc_call, NULL, 0);
  // mozsqlite3.dll::sqlite3DbFree
  //hookapi_hook_function(0, 0x002a9920, sqlite3_db_free_call, NULL, 0);
  // mozsqlite3.dll::sqlite3MemMalloc
  //hookapi_hook_function(0, 0x002d8260, malloc_call, NULL, 0);
  // mozsqlite3.dll::sqlite3MemRealloc
  //hookapi_hook_function(0, 0x002d6e00, realloc_call, NULL, 0);
  // mozsqlite3.dll::sqlite3MemFree
  //hookapi_hook_function(0, 0x002d7a90, free_call, NULL, 0);
  //"mozcrt19.dll::huge_malloc",
  //"mozcrt19.dll::huge_palloc",
  //"mozcrt19.dll::huge_ralloc",
  //"mozcrt19.dll::huge_dalloc",
  //"mozcrt19.dll::chunk_alloc_mmap",
  //"mozcrt19.dll::chunk_dealloc_mmap",
  //"mozcrt19.dll::chunk_alloc",
  //"mozcrt19.dll::chunk_dealloc",

}

/************************* HEAP ALLOCATION **********************/

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t size;
} malloc_t;

void malloc_call(void *opaque)
{
  uint32_t stack[2];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], sizeof(stack), 
                    stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  malloc_t *s = malloc(sizeof(malloc_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->size = stack[1];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], malloc_ret, (void*)s,
                    sizeof(malloc_t));

  inc_st(current_tid);

  return;
}

void malloc_ret(void *opaque)
{
  malloc_t *s = (malloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Check if parameters tainted */
  int sizeT = 0;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, 
      "%08lld %08ld %04u %s::%s ALLOC 0x%08x %d %d 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, eax, s->size, sizeT, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

void calloc_call(void *opaque)
{
  uint32_t stack[3];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  malloc_t *s = malloc(sizeof(malloc_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->size = stack[1] * stack[2];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], calloc_ret, (void*)s,
                    sizeof(malloc_t));

  inc_st(current_tid);

  return;
}

void calloc_ret(void *opaque)
{
  malloc_t *s = (malloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];


  /* Check if parameters tainted */
  int sizeT = 0;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, 
      "%08lld %08ld %04u %s::%s CALLOC 0x%08x %d %d 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, eax, s->size, sizeT, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t boundary;
  uint32_t size;
} memalign_t;


void memalign_call(void *opaque)
{
  uint32_t stack[3];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  memalign_t *s = malloc(sizeof(memalign_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->boundary = stack[1];
  s->size = stack[2];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], memalign_ret, (void*)s,
                    sizeof(malloc_t));

  inc_st(current_tid);

  return;
}

void memalign_ret(void *opaque)
{
  memalign_t *s = (memalign_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get start address of allocated buffer from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s ALLOC 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, eax, s->size, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t ppMemPtr;
  uint32_t alignment;
  uint32_t size;
} posix_memalign_t;


void posix_memalign_call(void *opaque)
{
  uint32_t stack[4];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  posix_memalign_t *s = malloc(sizeof(posix_memalign_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->ppMemPtr = stack[1];
  s->alignment = stack[2];
  s->size = stack[3];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], posix_memalign_ret, (void*)s,
                    sizeof(malloc_t));

  inc_st(current_tid);

  return;
}

void posix_memalign_ret(void *opaque)
{
  uint32_t read_err;
  posix_memalign_t *s = (posix_memalign_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation results from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];
  if (eax != 0) goto finish;

  /* Read start address of allocated buffer */
  uint32_t addr;
  read_err = read_mem(s->ppMemPtr, sizeof(uint32_t),
                (unsigned char*)&addr);
  if (read_err) goto finish;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  //uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    /* NOTE: The allocation site actually encodes s->ppMemPtr */
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s ALLOC 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, addr, s->size, s->ppMemPtr);
  }

finish:
  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}



typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t bufPtr;
} free_t;

void free_call(void *opaque)
{
  uint32_t stack[2];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  free_t *s = malloc(sizeof(free_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->bufPtr = stack[1];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], free_ret, (void*)s,
                    sizeof(free_t));

  inc_st(current_tid);

  return;
}

void free_ret(void *opaque)
{
  free_t *s = (free_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE 0x%08x 0x%08x\n", 
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, s->bufPtr, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}


typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t bufPtr;
  uint32_t bufSize;
} realloc_t;

void realloc_call(void *opaque)
{
  uint32_t stack[3];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  realloc_t *s = malloc(sizeof(realloc_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->bufPtr = stack[1];
  s->bufSize = stack[2];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], realloc_ret, (void*)s,
                    sizeof(realloc_t));

  inc_st(current_tid);

  return;
}


void realloc_ret(void *opaque)
{
  realloc_t *s = (realloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    int sizeT = 0;
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE-R 0x%08x 0x%08x\n", 
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, s->bufPtr, eip);
    /* If new size is zero, realloc behaves as free, so do not print alloc */
    if (s->bufSize > 0) {
      fprintf(alloclog, 
        "%08lld %08ld %04u %s::%s ALLOC-R 0x%08x %d %d 0x0 0 0x0 0 0x%08x\n",
        s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
        fun_name, eax, s->bufSize, sizeT, eip);
    }
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t options;
  uint32_t initialSize;
  uint32_t maximumSize;
} heap_create_t;

void heap_create_call(void *opaque)
{
  uint32_t stack[4]; // Assume parameters are 4-byte long

  /*
    HANDLE WINAPI HeapCreate(
      __in  DWORD flOptions,
      __in  SIZE_T dwInitialSize,
      __in  SIZE_T dwMaximumSize
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  heap_create_t *s = malloc(sizeof(heap_create_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->options = stack[1];
  s->initialSize = stack[2];
  s->maximumSize = stack[3];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], heap_create_ret,
                    (void*)s, sizeof(heap_create_t));

  inc_st(current_tid);

  return;
}

void heap_create_ret(void *opaque)
{
  heap_create_t *s = (heap_create_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get heap handle from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Round up commit size */
  uint32_t num_pages = s->initialSize / 4096;
  uint32_t remains = s->initialSize % 4096;
  uint32_t size = remains > 0 ? (num_pages + 1) * 4096 : s->initialSize;

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s NEWHEAP 0x%08x %d 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name,
      fun_name, eax, size, s->options, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}


typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t flags;
  uint32_t heapBase;
  uint32_t reserveSize;
  uint32_t commitSize;
  uint32_t lock;
  uint32_t parameters;
} rtl_create_heap_t;

void rtl_create_heap_call(void *opaque)
{
  uint32_t stack[7]; // Assume parameters are 4-byte long

  /*
    PVOID RtlCreateHeap(
      __in      ULONG Flags,
      __in_opt  PVOID HeapBase,
      __in_opt  SIZE_T ReserveSize,
      __in_opt  SIZE_T CommitSize,
      __in_opt  PVOID Lock,
      __in_opt  PRTL_HEAP_PARAMETERS Parameters
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  rtl_create_heap_t *s = malloc(sizeof(rtl_create_heap_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->flags = stack[1];
  s->heapBase = stack[2];
  s->reserveSize = stack[3];
  s->commitSize = stack[4];
  s->lock = stack[5];
  s->parameters = stack[6];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], rtl_create_heap_ret,
                    (void*)s, sizeof(rtl_create_heap_t));

  // Do not increment the counter, as we want to hook the internal allocation
  //inc_st(current_tid);

  return;
}

void rtl_create_heap_ret(void *opaque)
{
  rtl_create_heap_t *s = (rtl_create_heap_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get heap handle from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* The _HEAP structure reserves 1664 bytes */
  uint32_t size = 1664;

  /* Round up commit size */
  uint32_t num_pages = s->commitSize / 4096;
  uint32_t remains = s->commitSize % 4096;
  uint32_t committedSize = 
    remains > 0 ? (num_pages + 1) * 4096 : s->commitSize;

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s NEWHEAP 0x%08x %d 0x%08x %d 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name,
      fun_name, eax, size, s->flags, committedSize, eip);
  }

  // We did not increase the counter, so do not decrease it
  //reset_st(s->entry_tid);

  if (s) free(s);

  return;
}


typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t size;
  uint32_t heapHandle;
  uint32_t flags;
} rtl_allocate_heap_t;


void rtl_allocate_heap_call(void *opaque)
{
  uint32_t stack[4]; // Assume parameters are 4-byte long

  /*
    PVOID  RtlAllocateHeap(IN PVOID HeapHandle,IN ULONG Flags,
      IN SIZE_T Size);
   */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  rtl_allocate_heap_t *s = malloc(sizeof(rtl_allocate_heap_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->size = stack[3];
  s->heapHandle = stack[1];
  s->flags = stack[2];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], rtl_allocate_heap_ret,
                    (void*)s, sizeof(rtl_allocate_heap_t));

  inc_st(current_tid);

  return;
}

void rtl_allocate_heap_ret(void *opaque)
{
  rtl_allocate_heap_t *s = (rtl_allocate_heap_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Check if parameters tainted */
  int sizeT = 0, handleT = 0, flagsT = 0;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, 
      "%08lld %08ld %04u %s::%s ALLOC 0x%08x %d %d "
      "0x%08x %d 0x%08x %d 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, eax, s->size, sizeT, s->heapHandle, handleT, s->flags, 
      flagsT, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}


void rtl_free_heap_call(void *opaque)
{
  uint32_t stack[4]; // Assume parameters are 4-byte long

  /*
    BOOLEAN  RtlFreeHeap(IN PVOID HeapHandle,IN ULONG Flags,
      IN PVOID HeapBase);
   */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  free_t *s = malloc(sizeof(free_t));
  if (s == NULL) return;
  s->insn_ctr = 
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->bufPtr = stack[3];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], rtl_free_heap_ret, (void*)s,
                    sizeof(free_t));

  inc_st(current_tid);

  return;
}

void rtl_free_heap_ret(void *opaque)
{
  free_t *s = (free_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE 0x%08x 0x%08x\n", 
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, s->bufPtr, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}



typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t size;
  uint32_t heapHandle;
  uint32_t flags;
  uint32_t old_buf_start;
} rtl_reallocate_heap_t;


void rtl_reallocate_heap_call(void *opaque)
{
  uint32_t stack[5]; // Assume parameters are 4-byte long

  /*
    PVOID RtlReAllocateHeap(HANDLE heap,ULONG flags,
      PVOID ptr,SIZE_T size);
   */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  rtl_reallocate_heap_t *s = malloc(sizeof(rtl_reallocate_heap_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->size = stack[4];
  s->heapHandle = stack[1];
  s->flags = stack[2];
  s->old_buf_start = stack[3];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], rtl_reallocate_heap_ret,
                    (void*)s, sizeof(rtl_reallocate_heap_t));

  inc_st(current_tid);

  return;
}

void rtl_reallocate_heap_ret(void *opaque)
{
  rtl_reallocate_heap_t *s = (rtl_reallocate_heap_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Check if parameters tainted */
  int sizeT = 0, handleT = 0, flagsT = 0;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE-R 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, s->old_buf_start, eip);
    fprintf(alloclog, 
      "%08lld %08ld %04u %s::%s ALLOC-R 0x%08x %d %d "
      "0x%08x %d 0x%08x %d 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, eax, s->size, sizeT, s->heapHandle, handleT, s->flags, 
      flagsT, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t processHandle;
  uint32_t baseAddressPtr;
  uint32_t zeroBits;
  uint32_t regionSizePtr;
  uint32_t allocationType;
  uint32_t protect;
} zw_allocate_virtual_memory_t;


void zw_allocate_virtual_memory_call(void *opaque)
{
  uint32_t stack[7]; // Assume parameters are 4-byte long

  /*
    NTSTATUS ZwAllocateVirtualMemory(
      __in     HANDLE ProcessHandle,
      __inout  PVOID *BaseAddress,
      __in     ULONG_PTR ZeroBits,
      __inout  PSIZE_T RegionSize,
      __in     ULONG AllocationType,
      __in     ULONG Protect
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* If not committing memory, ignore */
  if (!(stack[5] & 0x1000)) return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  zw_allocate_virtual_memory_t *s = 
    malloc(sizeof(zw_allocate_virtual_memory_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->processHandle = stack[1];
  s->baseAddressPtr = stack[2];
  s->zeroBits = stack[3];
  s->regionSizePtr = stack[4];
  s->allocationType = stack[5];
  s->protect = stack[6];

  // Hook the return address
  s->hook_handle = 
      hookapi_hook_return(stack[0], zw_allocate_virtual_memory_ret,
                          (void*)s, sizeof(zw_allocate_virtual_memory_t));

  inc_st(current_tid);

  return;
}

void zw_allocate_virtual_memory_ret(void *opaque)
{
  int read_err = 0;
  zw_allocate_virtual_memory_t *s = (zw_allocate_virtual_memory_t *)opaque;
  uint32_t baseAddr = 0, regionSize = 0;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get status from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* If unsuccessful, skip processing */
  if (eax != 0) goto finish;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  //uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Read base address for allocation */
  read_err = read_mem(s->baseAddressPtr, sizeof(uint32_t),
                (unsigned char*)&baseAddr);
  if (read_err) goto finish;

  /* Read the allocation size */
  read_err = read_mem(s->regionSizePtr, sizeof(uint32_t),
                (unsigned char*)&regionSize);
  if (read_err) goto finish;

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    /* NOTE: The allocation site actually encodes s->baseAddressPtr */
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s ALLOC 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, baseAddr, regionSize, s->baseAddressPtr);
  }

finish:
  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}


typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t sectionHandle;
  uint32_t processHandle;
  uint32_t baseAddressPtr;
  uint32_t zeroBits;
  uint32_t commitSize;
  uint32_t sectionOffsetPtr;
  uint32_t viewSizePtr;
  uint32_t inheritDisposition;
  uint32_t allocationType;
  uint32_t win32Protect;
} zw_map_view_of_section_t;


void zw_map_view_of_section_call(void *opaque)
{
  uint32_t stack[11]; // Assume parameters are 4-byte long

  /*
    NTSTATUS ZwMapViewOfSection(
      __in     HANDLE SectionHandle,
      __in     HANDLE ProcessHandle,
      __inout  PVOID *BaseAddress,
      __in     ULONG_PTR ZeroBits,
      __in     SIZE_T CommitSize,
      __inout  PLARGE_INTEGER SectionOffset,
      __inout  PSIZE_T ViewSize,
      __in     SECTION_INHERIT InheritDisposition,
      __in     ULONG AllocationType,
      __in     ULONG Win32Protect
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  zw_map_view_of_section_t *s = malloc(sizeof(zw_map_view_of_section_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->sectionHandle = stack[1];
  s->processHandle = stack[2];
  s->baseAddressPtr = stack[3];
  s->zeroBits = stack[4];
  s->commitSize = stack[5];
  s->sectionOffsetPtr = stack[6];
  s->viewSizePtr = stack[7];
  s->inheritDisposition = stack[8];
  s->allocationType = stack[9];
  s->win32Protect = stack[10];

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], zw_map_view_of_section_ret,
                    (void*)s, sizeof(zw_map_view_of_section_t));

  inc_st(current_tid);

  return;
}

void zw_map_view_of_section_ret(void *opaque)
{
  int read_err = 0;
  zw_map_view_of_section_t *s = (zw_map_view_of_section_t *)opaque;
  uint32_t baseAddr = 0, viewSize = 0;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get status from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* If unsuccessful, skip processing */
  if (eax != 0) goto finish;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  //uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Read base address for view */
  read_err = read_mem(s->baseAddressPtr, sizeof(uint32_t), 
                (unsigned char*)&baseAddr);
  if (read_err) goto finish;

  /* Read the view size */
  read_err = read_mem(s->viewSizePtr, sizeof(uint32_t), 
                (unsigned char*)&viewSize);
  if (read_err) goto finish;

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    /* NOTE: The allocation site actually encodes s->baseAddressPtr */
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s MAP 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, baseAddr, viewSize, s->baseAddressPtr);
  }

finish:
  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t processHandle;
  uint32_t baseAddressPtr;
} zw_unmap_view_of_section_t;


void zw_unmap_view_of_section_call(void *opaque)
{
  uint32_t stack[3]; // Assume parameters are 4-byte long

  /*
    NTSTATUS ZwUnmapViewOfSection(
      __in      HANDLE ProcessHandle,
      __in_opt  PVOID BaseAddress
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  zw_unmap_view_of_section_t *s = malloc(sizeof(zw_unmap_view_of_section_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->processHandle = stack[1];
  s->baseAddressPtr = stack[2];

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], zw_unmap_view_of_section_ret,
                    (void*)s, sizeof(zw_unmap_view_of_section_t));

  inc_st(current_tid);

  return;
}

void zw_unmap_view_of_section_ret(void *opaque)
{
  zw_unmap_view_of_section_t *s = (zw_unmap_view_of_section_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get status from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* If unsuccessful, skip processing */
  if (eax != 0) goto finish;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s UNMAP 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, s->baseAddressPtr, eip);
  }

finish:
  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t regAddr;
  uint32_t regSize;
  uint32_t flAllocationType;
  uint32_t flProtect;
} virtual_alloc_t;


void virtual_alloc_call(void *opaque)
{
  uint32_t stack[5]; // Assume parameters are 4-byte long

  /*
    LPVOID WINAPI VirtualAlloc(
      __in_opt  LPVOID lpAddress,
      __in      SIZE_T dwSize,
      __in      DWORD flAllocationType,
      __in      DWORD flProtect
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Read the parameters */
  virtual_alloc_t *s = malloc(sizeof(virtual_alloc_t));
  if (s == NULL) return;

  /* If the commit flag is not set, then ignore */
  if (!(stack[3] & 0x1000)) return;

  /* Store the parameters */
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->regAddr = stack[1];
  s->regSize = stack[2];
  s->flAllocationType = stack[3];
  s->flProtect = stack[4];

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], virtual_alloc_ret,
                    (void*)s, sizeof(virtual_alloc_t));

  inc_st(current_tid);

  return;
}

void virtual_alloc_ret(void *opaque)
{
  virtual_alloc_t *s = (virtual_alloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Read allocation address */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s VALLOC 0x%08x %d 0x%08x 0x%x 0x%x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, eax, s->regSize, s->regAddr, s->flAllocationType, 
      s->flProtect, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t regAddr;
  uint32_t regSize;
  uint32_t freeType;
} virtual_free_t;

void virtual_free_call(void *opaque)
{
  uint32_t stack[4]; // Assume parameters are 4-byte long

  /*
    BOOL WINAPI VirtualFree(
      __in  LPVOID lpAddress,
      __in  SIZE_T dwSize,
      __in  DWORD dwFreeType
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  virtual_free_t *s = malloc(sizeof(virtual_free_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->regAddr = stack[1];
  s->regSize = stack[2];
  s->freeType = stack[3];

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], virtual_free_ret,
                    (void*)s, sizeof(virtual_free_t));

  inc_st(current_tid);

  return;
}

void virtual_free_ret(void *opaque)
{
  virtual_free_t *s = (virtual_free_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get result */
  uint32_t eax = cpu_single_env->regs[R_EAX];
  if (eax == 0) goto finish;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, 
      "%08lld %08ld %04u %s::%s VFREE 0x%08x %d 0x%x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, s->regAddr, s->regSize, s->freeType, eip);
  }

finish:
  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t flags;
  uint32_t size;
} local_alloc_t;

void local_alloc_call(void *opaque)
{
  uint32_t stack[3]; // Assume parameters are 4-byte long

  /*
    HLOCAL WINAPI LocalAlloc(
      __in  UINT uFlags,
      __in  SIZE_T uBytes
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* If memory movable, then ignore */
  if (stack[1] & 0x0002) return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  local_alloc_t *s = malloc(sizeof(local_alloc_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->flags = stack[1];
  s->size = stack[2];

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], local_alloc_ret,
                    (void*)s, sizeof(local_alloc_t));

  inc_st(current_tid);

  return;
}

void local_alloc_ret(void *opaque)
{
  local_alloc_t *s = (local_alloc_t *)opaque;
  char type_str[7] = "ALLOC";

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Read allocation address */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Select ALLOC or CALLOC */
  if (s->flags & 0x0040) {
    strcpy(type_str,"CALLOC");
  }

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s %s 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
      fun_name, type_str, eax, s->size, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t handle;
  uint32_t size;
  uint32_t flags;
} local_realloc_t;

void local_realloc_call(void *opaque)
{
  uint32_t stack[4]; // Assume parameters are 4-byte long

  /*
    HLOCAL WINAPI LocalReAlloc(
      __in  HLOCAL hMem,
      __in  SIZE_T uBytes,
      __in  UINT uFlags
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  local_realloc_t *s = malloc(sizeof(local_realloc_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->handle = stack[1];
  s->size = stack[2];
  s->flags = stack[3];

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], local_realloc_ret,
                    (void*)s, sizeof(local_realloc_t));

  inc_st(current_tid);

  return;
}

void local_realloc_ret(void *opaque)
{
  local_realloc_t *s = (local_realloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Read result */
  uint32_t eax = cpu_single_env->regs[R_EAX];
  if (eax == 0) goto finish;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE-R 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, s->handle, eip);
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s ALLOC-R 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, eax, s->size, eip);
  }

finish:
  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t handle;
} local_free_t;

void local_free_call(void *opaque)
{
  uint32_t stack[2]; // Assume parameters are 4-byte long

  /*
    HLOCAL WINAPI LocalFree(
      __in  HLOCAL hMem
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  local_free_t *s = malloc(sizeof(local_free_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->handle = stack[1];

  // Hook the return address
  s->hook_handle = hookapi_hook_return(stack[0], local_free_ret,
                    (void*)s, sizeof(local_free_t));

  inc_st(current_tid);

  return;
}

void local_free_ret(void *opaque)
{
  local_free_t *s = (local_free_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get result */
  uint32_t eax = cpu_single_env->regs[R_EAX];
  if (eax != 0) goto finish;

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, s->handle, eip);
  }

finish:
  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t allocator;
  uint32_t size;
  uint32_t hint;
} cf_allocator_allocate_t;


void cf_allocator_allocate_call(void *opaque)
{
  uint32_t stack[4]; // Assume parameters are 4-byte long

  /*
    void * CFAllocatorAllocate (
       CFAllocatorRef allocator,
       CFIndex size,
       CFOptionFlags hint
    );
   */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  cf_allocator_allocate_t *s = malloc(sizeof(cf_allocator_allocate_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->allocator = stack[1];
  s->size = stack[2];
  s->hint = stack[3];

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], cf_allocator_allocate_ret,
                    (void*)s, sizeof(cf_allocator_allocate_t));

  inc_st(current_tid);

  return;
}

void cf_allocator_allocate_ret(void *opaque)
{
  cf_allocator_allocate_t *s = (cf_allocator_allocate_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get result */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s ALLOC 0x%08x %d 0 0x%08x 0 0x%08x 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, eax, s->size, s->allocator, s->hint, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t allocator;
  uint32_t bufPtr;
} cf_allocator_deallocate_t;

void cf_allocator_deallocate_call(void *opaque)
{
  uint32_t stack[3]; // Assume parameters are 4-byte long

  /*
    void CFAllocatorDeallocate (
       CFAllocatorRef allocator,
       void *ptr
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  cf_allocator_deallocate_t *s = malloc(sizeof(cf_allocator_deallocate_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->allocator = stack[1];
  s->bufPtr = stack[2];

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], cf_allocator_deallocate_ret, 
                    (void*)s, sizeof(cf_allocator_deallocate_t));

  inc_st(current_tid);

  return;
}

void cf_allocator_deallocate_ret(void *opaque)
{
  cf_allocator_deallocate_t *s = (cf_allocator_deallocate_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    // Currently not printing allocator
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      mod_name, fun_name, s->bufPtr, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t allocator;
  uint32_t bufPtr;
  uint32_t newSize;
  uint32_t hint;
} cf_allocator_reallocate_t;


void cf_allocator_reallocate_call(void *opaque)
{
  uint32_t stack[5]; // Assume parameters are 4-byte long

  /*
    void * CFAllocatorReallocate (
       CFAllocatorRef allocator,
       void *ptr,
       CFIndex newsize,
       CFOptionFlags hint
    );
  */

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  cf_allocator_reallocate_t *s = malloc(sizeof(cf_allocator_reallocate_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->entry_eip = eip;
  s->entry_tid = current_tid;
  s->allocator = stack[1];
  s->bufPtr = stack[2];
  s->newSize = stack[3];
  s->hint = stack[4];

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], cf_allocator_reallocate_ret,
                    (void*)s, sizeof(cf_allocator_reallocate_t));

  inc_st(current_tid);

  return;
}

void cf_allocator_reallocate_ret(void *opaque)
{
  cf_allocator_reallocate_t *s = (cf_allocator_reallocate_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    /* If the pointer is zero, it does not free */
    if (s->bufPtr != 0) {
      fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE-R 0x%08x 0x%08x\n",
        s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
        fun_name, s->bufPtr, eip);
    }
    /* If new size is zero, realloc behaves as free, so do not print alloc */
    if (s->newSize > 0) {
      fprintf(alloclog,
        "%08lld %08ld %04u %s::%s ALLOC-R 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
        s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name, 
        fun_name, eax, s->newSize, eip);
    }
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t db;
  uint32_t size;
} sqlite3_db_alloc_t;

void sqlite3_db_alloc_call(void *opaque)
{
  uint32_t stack[3];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  sqlite3_db_alloc_t *s = malloc(sizeof(sqlite3_db_alloc_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->db = stack[1];
  s->size = stack[2];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = 
      hookapi_hook_return(stack[0], sqlite3_db_alloc_ret, (void*)s,
                          sizeof(sqlite3_db_alloc_t));

  inc_st(current_tid);

  return;
}

void sqlite3_db_alloc_ret(void *opaque)
{
  sqlite3_db_alloc_t *s = (sqlite3_db_alloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  //char mod_name[512];
  //char fun_name[512];
  //get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog,
      "%08lld %08ld %04u %s::%s ALLOC 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      "mozsqlite3.dll", "sqlite3DbAllocRaw",
      eax, s->size, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t db;
  uint32_t bufPtr;
} sqlite3_db_free_t;

void sqlite3_db_free_call(void *opaque)
{
  uint32_t stack[3];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  sqlite3_db_free_t *s = malloc(sizeof(sqlite3_db_free_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->db = stack[1];
  s->bufPtr = stack[2];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], sqlite3_db_free_ret, (void*)s,
                    sizeof(sqlite3_db_free_t));

  inc_st(current_tid);

  return;
}

void sqlite3_db_free_ret(void *opaque)
{
  sqlite3_db_free_t *s = (sqlite3_db_free_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get module and function names */
  //char mod_name[512];
  //char fun_name[512];
  //get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      "mozsqlite3", "sqlite3DbFree",
      s->bufPtr, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t db;
  uint32_t bufPtr;
  uint32_t bufSize;
} sqlite3_db_realloc_t;

void sqlite3_db_realloc_call(void *opaque)
{
  uint32_t stack[4];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  sqlite3_db_realloc_t *s = malloc(sizeof(sqlite3_db_realloc_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->db = stack[1];
  s->bufPtr = stack[2];
  s->bufSize = stack[3];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], sqlite3_db_realloc_ret, 
                    (void*)s, sizeof(sqlite3_db_realloc_t));

  inc_st(current_tid);

  return;
}

void sqlite3_db_realloc_ret(void *opaque)
{
  sqlite3_db_realloc_t *s = (sqlite3_db_realloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get allocation start address from EAX */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Get module and function names */
  //char mod_name[512];
  //char fun_name[512];
  //get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE-R 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, 
      "mozsqlite3.dll", "sqlite3DbRealloc",
      s->bufPtr, eip);
    /* If new size is zero, realloc behaves as free, so do not print alloc */
    if (s->bufSize > 0) {
      fprintf(alloclog,
        "%08lld %08ld %04u %s::%s ALLOC-R 0x%08x %d 0 0x0 0 0x0 0 0x%08x\n",
        s->insn_ctr, tstats.insn_counter_traced, s->entry_tid,
        "mozsqlite3.dll", "sqlite3DbRealloc",
        eax, s->bufSize, eip);
    }
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t blockSize;
  uint32_t bufPtr;
} g_slice_free1_t;

void g_slice_free1_call(void *opaque)
{
  uint32_t stack[3];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  g_slice_free1_t *s = malloc(sizeof(g_slice_free1_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->blockSize = stack[1];
  s->bufPtr = stack[2];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Hook the return address */
  s->hook_handle = hookapi_hook_return(stack[0], g_slice_free1_ret, (void*)s,
                    sizeof(g_slice_free1_t));

  inc_st(current_tid);

  return;
}

void g_slice_free1_ret(void *opaque)
{
  g_slice_free1_t *s = (g_slice_free1_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE 0x%08x 0x%08x\n",
      s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name,
      fun_name, s->bufPtr, eip);
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

typedef struct {
  long long insn_ctr;
  uint32_t hook_handle;
  uint32_t entry_eip;
  uint32_t entry_tid;
  uint32_t blockSize;
  uint32_t memChain;
  uint32_t nextOffset;
  uint32_t numBlocks;
  uint32_t blocks[64];
} g_slice_free_chain_with_offset_t;

void g_slice_free_chain_with_offset_call(void *opaque)
{
  uint32_t stack[4];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  if (get_st(current_tid))
    return;

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /* Read function entry point */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Store the parameters */
  g_slice_free_chain_with_offset_t *s = 
    malloc(sizeof(g_slice_free_chain_with_offset_t));
  if (s == NULL) return;
  s->insn_ctr =
    tstats.insn_counter_traced > 0 ? tstats.insn_counter_traced + 1 : 0;
  s->blockSize = stack[1];
  s->memChain = stack[2];
  s->nextOffset = stack[3];
  s->entry_eip = eip;
  s->entry_tid = current_tid;

  /* Iterate over the chain of blocks */
  int read_err = 0;
  uint32_t blockAddr = stack[2];
  uint32_t numBlocks = 0;
  s->blocks[numBlocks++] = blockAddr;
  while ((blockAddr != 0) && (numBlocks < 64)) {
    read_err =  read_mem(blockAddr+stack[3], sizeof(blockAddr), 
                  (unsigned char*)&blockAddr);
    if (read_err) return;
    s->blocks[numBlocks] = blockAddr;
    numBlocks++;
  }
  s->numBlocks = numBlocks;

  /* Hook the return address */
  s->hook_handle = 
    hookapi_hook_return(stack[0], g_slice_free_chain_with_offset_ret, (void*)s,
                    sizeof(g_slice_free_chain_with_offset_t));

  inc_st(current_tid);

  return;
}

void g_slice_free_chain_with_offset_ret(void *opaque)
{
  unsigned int i;
  g_slice_free_chain_with_offset_t *s = 
    (g_slice_free_chain_with_offset_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check that this is the same thread as entry point */
  //assert(current_tid == s->entry_tid);

  /* Get module and function names */
  char mod_name[512];
  char fun_name[512];
  get_function_name(s->entry_eip,(char *)&mod_name,(char *)&fun_name);

  /* Get return address */
  uint32_t eip = DECAF_getPC(cpu_single_env);

  /* Print to file the parameter information */
  if (!alloclog) {
    open_alloc_file();
  }
  if (alloclog) {
    for (i = 0; i < s-> numBlocks; i++) {
      fprintf(alloclog, "%08lld %08ld %04u %s::%s FREE 0x%08x 0x%08x\n",
        s->insn_ctr, tstats.insn_counter_traced, s->entry_tid, mod_name,
        fun_name, s->blocks[i], eip);
    }
  }

  reset_st(s->entry_tid);

  if (s) free(s);

  return;
}

