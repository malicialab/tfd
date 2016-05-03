/* 
 *  hooks for process creating functions
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
#include <string.h>
#include "skiptaint.h"
#include "group_hook_helper.h"
#include "trackproc.h"
#include "group_process.h"
#include "fpu/softfloat.h"

#define LOCAL_DEBUG 1
#define WRITE if (LOCAL_DEBUG) write_log


hook_t hooks[] =
{
  /* Process tracking */
  {"ntdll.dll", "NtCreateProcess", NtCreateProcess_call, 0},
  {"ntdll.dll", "NtCreateProcessEx", NtCreateProcess_call, 0},
  {"ntdll.dll", "NtQueryInformationProcess", 
    NtQueryInformationProcess_call, 0},
  //{"kernel32.dll", "CloseHandle", CloseHandle_call, 0},
};

int local_num_funs = (sizeof(hooks)/sizeof(hook_t));


void internal_init_plugin()
{
  //WRITE ("plugin", "Hooking system functions\n");
  initialize_plugin(hooks,local_num_funs);

}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t handle_ptr;
  uint32_t access_mask;
  uint32_t object_attributes_ptr;
  uint32_t parent_handle;
  uint32_t inherit_object_table_flag;
  uint32_t section_handle;
  uint32_t debug_port;
  uint32_t exception_port;
} createprocess_t;


void NtCreateProcess_ret(void *opaque)
{
  /* Remove return hook */
  createprocess_t *s = (createprocess_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Read error code returned in EAX */
  if (cpu_single_env->regs[R_EAX] != 0) {
    // if the return value is not STATUS_SUCCESS
    goto FINISH;
  }

  /* Get current process PID */
  uint32_t curr_proc_pid = trackproc_get_current_pid();

  /* Read handle for new process */
  uint32_t ulProcHandle;
  DECAF_read_mem(NULL, s->handle_ptr, 4, &ulProcHandle);
  //WRITE("stderr",
  //      "NtCreateProcess_ret. Process Handle: %d (Parent PID: %d)\n",
  //      ulProcHandle, curr_proc_pid);

  /* Add handle for new process to process tracking */
  trackproc_add_new_handle(ulProcHandle, curr_proc_pid);

FINISH:
  if (s) free(s);

  return;
}

void NtCreateProcess_call(void *opaque)
{
  uint32_t stack[9];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Get current process PID */
  uint32_t curr_proc_pid = trackproc_get_current_pid();

  //WRITE("stderr", "NtCreateProcess_call...PID: %d\n", curr_proc_pid);

  /* Check if we are tracking the current process */
  if ((trackproc_is_running() == 0) || 
      (trackproc_find_pid(curr_proc_pid) == -1)) {
    return;
  }

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /*
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    typedef struct _OBJECT_ATTRIBUTES {
        ULONG Length;
        HANDLE RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;
        PVOID SecurityQualityOfService;
    } OBJECT_ATTRIBUTES;
    typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
  */

  /* Store parameters */
  createprocess_t *s = malloc(sizeof(createprocess_t));
  if (s == NULL) return;
  s->eip = DECAF_getPC(cpu_single_env);
  s->handle_ptr = stack[1];
  s->access_mask = stack[2];
  s->object_attributes_ptr = stack[3];
  s->parent_handle = stack[4];
  s->inherit_object_table_flag = stack[5];
  s->section_handle = stack[6];
  s->debug_port = stack[7];
  s->exception_port = stack[8];

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], NtCreateProcess_ret, s,
    sizeof(createprocess_t));

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t handle;
  uint32_t proc_info_class;
  uint32_t proc_info_ptr;
  uint32_t proc_info_len;
  uint32_t ret_len;
} ntqueryinformationprocess_t;

void NtQueryInformationProcess_ret(void *opaque)
{
  /* Remove return hook */
  ntqueryinformationprocess_t *s = (ntqueryinformationprocess_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Read error code returned in EAX */
  if (cpu_single_env->regs[R_EAX] != 0) {
    // if the return value is not STATUS_SUCCESS
    goto FINISH;
  }

  int read_err;
  uint32_t aruiBuf[20];

  /* Check that the buffer is not longer than supported */
  if (s->proc_info_len > sizeof(aruiBuf)) {
    goto FINISH;
  }

  /* Read process basic information */
  read_err = 
    DECAF_read_mem(NULL, s->proc_info_ptr, s->proc_info_len, aruiBuf);
  if (read_err) goto FINISH;
  uint32_t uiPID = aruiBuf[4];
  //uint32_t uiPPEB = aruiBuf[1];

  /* Set process PID for process handle */
  trackproc_set_pid(s->handle, uiPID);

  //WRITE("stderr", "NtQueryInformationProcess_ret. "
  //  "Handle: %d, PID: %d PebBase: %p\n", 
  //  s->handle, uiPID, uiPPEB);

FINISH:
  if (s) free(s);

  return;
}

void NtQueryInformationProcess_call(void *opaque)
{
  uint32_t stack[6];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Get current process PID */
  uint32_t curr_proc_pid = trackproc_get_current_pid();

  /* Check if we are tracking the current process */
  if ((trackproc_is_running() == 0) || 
      (trackproc_find_pid(curr_proc_pid) == -1)) {
    return;
  }

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /*
    NTSTATUS WINAPI NtQueryInformationProcess(
      __in       HANDLE ProcessHandle,
      __in       PROCESSINFOCLASS ProcessInformationClass,
      __out      PVOID ProcessInformation,
      __in       ULONG ProcessInformationLength,
      __out_opt  PULONG ReturnLength
    );
  */

  /* This is not the process handle that we are tracking. */
  if (trackproc_find_handle(stack[1]) == -1) {
    return;
  }

  /* For now, we don't get any information when the type is not "BASIC" */
  if (stack[2] != 0) {
    return;
  }

  /* Store parameters */
  ntqueryinformationprocess_t *s = 
    malloc(sizeof(ntqueryinformationprocess_t));
  if (s == NULL) return;
  s->eip = DECAF_getPC(cpu_single_env);
  s->handle = stack[1];
  s->proc_info_class = stack[2];
  s->proc_info_ptr = stack[3];
  s->proc_info_len = stack[4];
  s->ret_len = stack[5];

  //WRITE("stderr", "NtQueryInformationProcess_call. "
  //      "Current PID: %d, Process Handle: 0x%x, Info Type: %d, "
  //      "ProcessInfo: %p (%d)\n",
  //      curr_proc_pid, stack[1], stack[2], stack[3], stack[4]);

  /* Hook return of call */
  s->hook_handle = 
    hookapi_hook_return(stack[0], NtQueryInformationProcess_ret, s, 
                        sizeof(ntqueryinformationprocess_t));

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t handle;
} closehandle_t;


void CloseHandle_ret(void *opaque)
{
  /* Remove return hook */
  closehandle_t *s = (closehandle_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Read error code returned in EAX */
  if (cpu_single_env->regs[R_EAX] == 0) {
    // if the return value is not STATUS_SUCCESS
    goto FINISH;
  }

FINISH:
  if (s) free(s);

  return;
}

void CloseHandle_call(void *opaque)
{
  uint32_t stack[2];

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Get current process PID */
  uint32_t curr_proc_pid = trackproc_get_current_pid();

  /* Check if current process is the one traced or one of its children */
  if ((trackproc_is_running() == 0) || 
      (trackproc_find_pid(curr_proc_pid) == -1)) {
    return;
  }

  /* Read stack starting at ESP */
  if(DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                    sizeof(stack), stack) == -1)
    return;

  /*
    BOOL WINAPI CloseHandle(
      __in  HANDLE hObject
    );
  */

  /* Store parameters */
  closehandle_t *s = malloc(sizeof(closehandle_t));
  if (s == NULL) return;
  s->eip = DECAF_getPC(cpu_single_env);
  s->handle = stack[1];

  //WRITE("stderr", "NtCloseHandle...PID: %u Handle: %u\n", 
  //  curr_proc_pid, stack[1]);

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], CloseHandle_ret, s,
    sizeof(closehandle_t));

  return;
}

