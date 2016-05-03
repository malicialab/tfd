/* 
 *  error detection functionality
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

#include "config.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "DECAF_main.h"
#include "tfd.h"
#include "errdet.h"
#include "hook_helpers.h"
#include "sysemu.h"
#include "shared/vmi_c_wrapper.h"

// Windows exception codes
#define NTSTATUS uint32_t
#define STATUS_ACCESS_VIOLATION          ((NTSTATUS)0xC0000005)    // winnt
#define STATUS_DATATYPE_MISALIGNMENT     ((NTSTATUS)0x80000002)    // winnt
#define STATUS_BREAKPOINT                ((NTSTATUS)0x80000003)    // winnt
#define STATUS_SINGLE_STEP               ((NTSTATUS)0x80000004)    // winnt
#define STATUS_ARRAY_BOUNDS_EXCEEDED     ((NTSTATUS)0xC000008C)    // winnt
#define STATUS_FLOAT_DENORMAL_OPERAND    ((NTSTATUS)0xC000008D)    // winnt
#define STATUS_FLOAT_DIVIDE_BY_ZERO      ((NTSTATUS)0xC000008E)    // winnt
#define STATUS_FLOAT_INEXACT_RESULT      ((NTSTATUS)0xC000008F)    // winnt
#define STATUS_FLOAT_INVALID_OPERATION   ((NTSTATUS)0xC0000090)    // winnt
#define STATUS_FLOAT_OVERFLOW            ((NTSTATUS)0xC0000091)    // winnt
#define STATUS_FLOAT_STACK_CHECK         ((NTSTATUS)0xC0000092)    // winnt
#define STATUS_FLOAT_UNDERFLOW           ((NTSTATUS)0xC0000093)    // winnt
#define STATUS_INTEGER_DIVIDE_BY_ZERO    ((NTSTATUS)0xC0000094)    // winnt
#define STATUS_INTEGER_OVERFLOW          ((NTSTATUS)0xC0000095)    // winnt
#define STATUS_PRIVILEGED_INSTRUCTION    ((NTSTATUS)0xC0000096)    // winnt
#define STATUS_IN_PAGE_ERROR             ((NTSTATUS)0xC0000006)    // winnt
#define STATUS_ILLEGAL_INSTRUCTION       ((NTSTATUS)0xC000001D)    // winnt
#define STATUS_NONCONTINUABLE_EXCEPTION  ((NTSTATUS)0xC0000025)    // winnt
#define STATUS_STACK_OVERFLOW            ((NTSTATUS)0xC00000FD)    // winnt
#define STATUS_INVALID_DISPOSITION       ((NTSTATUS)0xC0000026)    // winnt
#define STATUS_GUARD_PAGE_VIOLATION      ((NTSTATUS)0x80000001)    // winnt
#define STATUS_INVALID_HANDLE            ((NTSTATUS)0xC0000008)    // winnt
#define STATUS_POSSIBLE_DEADLOCK         ((NTSTATUS)0xC0000194)

// Linux signals
#define LIN_SIGHUP 1 //Hangup (POSIX)
#define LIN_SIGINT 2 //Terminal interrupt (ANSI)
#define LIN_SIGQUIT 3 //Terminal quit (POSIX)
#define LIN_SIGILL 4 //Illegal instruction (ANSI)
#define LIN_SIGTRAP 5 //Trace trap (POSIX)
#define LIN_SIGIOT 6 //IOT Trap (4.2 BSD)
#define LIN_SIGBUS 7 //BUS error (4.2 BSD)
#define LIN_SIGFPE 8 //Floating point exception (ANSI)
#define LIN_SIGKILL 9 //Kill(can't be caught or ignored) (POSIX)
#define LIN_SIGUSR1 10 //User defined signal 1 (POSIX)
#define LIN_SIGSEGV 11 //Invalid memory segment access (ANSI)
#define LIN_SIGUSR2 12 //User defined signal 2 (POSIX)
#define LIN_SIGPIPE 13 //Write on a pipe with no reader, Broken pipe (POSIX)
#define LIN_SIGALRM 14 //Alarm clock (POSIX)
#define LIN_SIGTERM 15 //Termination (ANSI)
#define LIN_SIGSTKFLT 16 //Stack fault
#define LIN_SIGCHLD 17 //Child process has stopped or exited, changed (POSIX)
#define LIN_SIGCONT 18 //Continue executing, if stopped (POSIX)
#define LIN_SIGSTOP 19 //Stop executing(can't be caught or ignored) (POSIX)
#define LIN_SIGTSTP 20 //Terminal stop signal (POSIX)
#define LIN_SIGTTIN 21 //Background process trying to read, from TTY (POSIX)
#define LIN_SIGTTOU 22 //Background process trying to write, to TTY (POSIX)
#define LIN_SIGURG 23 //Urgent condition on socket (4.2 BSD)
#define LIN_SIGXCPU 24 //CPU limit exceeded (4.2 BSD)
#define LIN_SIGXFSZ 25 //File size limit exceeded (4.2 //BSD)
#define LIN_SIGVTALRM 26 //Virtual alarm clock (4.2 //BSD)
#define LIN_SIGPROF 27 //Profiling alarm clock (4.2 //BSD)
#define LIN_SIGWINCH 28 //Window size change (4.3 //BSD, Sun)
#define LIN_SIGIO 29 //I/O now possible (4.2 //BSD)
#define LIN_SIGPWR 30 //Power failure restart (System V)


typedef enum _ActionType { 
  ACTION_NONE = 0, 
  ACTION_TERM, 
  ACTION_STOP, 
  ACTION_TRACING_STOP 
} ActionType;

/* Actions for each detection condition */
static ActionType detect_action_taintedeip = ACTION_NONE;
static ActionType detect_action_exception = ACTION_NONE;
static ActionType detect_action_nullptr = ACTION_NONE;
static ActionType detect_action_processexit = ACTION_NONE;

/* Hook handle for exception detection */
static uintptr_t exception_hook_handle = 0;

/* Launch the given action */
void launch_action(ActionType action, int exitcode)
{
  switch (action) {
    case ACTION_NONE:
      break;
    case ACTION_TERM:
      tracing_clean_exit(exitcode);
      break;
    case ACTION_STOP:
      DECAF_stop_vm();
      break;
    case ACTION_TRACING_STOP:
      if (tracepid)
        tracing_stop();
      break;
    }
}

int action_str(ActionType action, char *action_str) {
  switch (action) {
    case ACTION_NONE:
      strncpy(action_str, "none", 5);
      break;
    case ACTION_TERM:
      strncpy(action_str, "term", 5);
      break;
    case ACTION_STOP:
      strncpy(action_str, "stop", 5);
      break;
    case ACTION_TRACING_STOP:
      strncpy(action_str, "tracestop", 10);
      break;
    default:
      strncpy(action_str, "unknown", 10);
      return -1;
  }
  return 0;
}

char *exception_str(int is_windows, uint32_t exception_code) {
  char *name;
  if (is_windows) {
    switch (exception_code) {
      case STATUS_ACCESS_VIOLATION:
        name = strdup("STATUS_ACCESS_VIOLATION");
        break;
      case STATUS_DATATYPE_MISALIGNMENT:
        name = strdup("STATUS_DATATYPE_MISALIGNMENT");
        break;
      case STATUS_BREAKPOINT:
        name = strdup("STATUS_BREAKPOINT");
        break;
      case STATUS_SINGLE_STEP:
        name = strdup("STATUS_SINGLE_STEP");
        break;
      case STATUS_ARRAY_BOUNDS_EXCEEDED:
        name = strdup("STATUS_ARRAY_BOUNDS_EXCEEDED");
        break;
      case STATUS_FLOAT_DENORMAL_OPERAND:
        name = strdup("STATUS_FLOAT_DENORMAL_OPERAND");
        break;
      case STATUS_FLOAT_DIVIDE_BY_ZERO:
        name = strdup("STATUS_FLOAT_DIVIDE_BY_ZERO");
        break;
      case STATUS_FLOAT_INEXACT_RESULT:
        name = strdup("STATUS_FLOAT_INEXACT_RESULT");
        break;
      case STATUS_FLOAT_INVALID_OPERATION:
        name = strdup("STATUS_FLOAT_INVALID_OPERATION");
        break;
      case STATUS_FLOAT_OVERFLOW:
        name = strdup("STATUS_FLOAT_OVERFLOW");
        break;
      case STATUS_FLOAT_STACK_CHECK:
        name = strdup("STATUS_FLOAT_STACK_CHECK");
        break;
      case STATUS_FLOAT_UNDERFLOW:
        name = strdup("STATUS_FLOAT_UNDERFLOW");
        break;
      case STATUS_INTEGER_DIVIDE_BY_ZERO:
        name = strdup("STATUS_INTEGER_DIVIDE_BY_ZERO");
        break;
      case STATUS_INTEGER_OVERFLOW:
        name = strdup("STATUS_INTEGER_OVERFLOW");
        break;
      case STATUS_PRIVILEGED_INSTRUCTION:
        name = strdup("STATUS_PRIVILEGED_INSTRUCTION");
        break;
      case STATUS_IN_PAGE_ERROR:
        name = strdup("STATUS_IN_PAGE_ERROR");
        break;
      case STATUS_ILLEGAL_INSTRUCTION:
        name = strdup("STATUS_ILLEGAL_INSTRUCTION");
        break;
      case STATUS_NONCONTINUABLE_EXCEPTION:
        name = strdup("STATUS_NONCONTINUABLE_EXCEPTION");
        break;
      case STATUS_STACK_OVERFLOW:
        name = strdup("STATUS_STACK_OVERFLOW");
        break;
      case STATUS_INVALID_DISPOSITION:
        name = strdup("STATUS_INVALID_DISPOSITION");
        break;
      case STATUS_GUARD_PAGE_VIOLATION:
        name = strdup("STATUS_GUARD_PAGE_VIOLATION");
        break;
      case STATUS_INVALID_HANDLE:
        name = strdup("STATUS_INVALID_HANDLE");
        break;
      case STATUS_POSSIBLE_DEADLOCK:
        name = strdup("STATUS_POSSIBLE_DEADLOCK");
        break;
      default:
        name = strdup("WINDOWS_UNKNOWN");
        break;
    }
  }
  else {
    switch (exception_code) {
      case LIN_SIGHUP:
        name = strdup("LIN_SIGHUP");
        break;
      case LIN_SIGINT:
        name = strdup("LIN_SIGINT");
        break;
      case LIN_SIGQUIT:
        name = strdup("LIN_SIGQUIT");
        break;
      case LIN_SIGILL:
        name = strdup("LIN_SIGILL");
        break;
      case LIN_SIGTRAP:
        name = strdup("LIN_SIGTRAP");
        break;
      case LIN_SIGIOT:
        name = strdup("LIN_SIGIOT");
        break;
      case LIN_SIGBUS:
        name = strdup("LIN_SIGBUS");
        break;
      case LIN_SIGFPE:
        name = strdup("LIN_SIGFPE");
        break;
      case LIN_SIGKILL:
        name = strdup("LIN_SIGKILL");
        break;
      case LIN_SIGUSR1:
        name = strdup("LIN_SIGUSR1");
        break;
      case LIN_SIGSEGV:
        name = strdup("LIN_SIGSEGV");
        break;
      case LIN_SIGUSR2:
        name = strdup("LIN_SIGUSR2");
        break;
      case LIN_SIGPIPE:
        name = strdup("LIN_SIGPIPE");
        break;
      case LIN_SIGALRM:
        name = strdup("LIN_SIGALRM");
        break;
      case LIN_SIGTERM:
        name = strdup("LIN_SIGTERM");
        break;
      case LIN_SIGSTKFLT:
        name = strdup("LIN_SIGSTKFLT");
        break;
      case LIN_SIGCHLD:
        name = strdup("LIN_SIGCHLD");
        break;
      case LIN_SIGCONT:
        name = strdup("LIN_SIGCONT");
        break;
      case LIN_SIGSTOP:
        name = strdup("LIN_SIGSTOP");
        break;
      case LIN_SIGTSTP:
        name = strdup("LIN_SIGTSTP");
        break;
      case LIN_SIGTTIN:
        name = strdup("LIN_SIGTTIN");
        break;
      case LIN_SIGTTOU:
        name = strdup("LIN_SIGTTOU");
        break;
      case LIN_SIGURG:
        name = strdup("LIN_SIGURG");
        break;
      case LIN_SIGXCPU:
        name = strdup("LIN_SIGXCPU");
        break;
      case LIN_SIGXFSZ:
        name = strdup("LIN_SIGXFSZ");
        break;
      case LIN_SIGVTALRM:
        name = strdup("LIN_SIGVTALRM");
        break;
      case LIN_SIGPROF:
        name = strdup("LIN_SIGPROF");
        break;
      case LIN_SIGWINCH:
        name = strdup("LIN_SIGWINCH");
        break;
      case LIN_SIGIO:
        name = strdup("LIN_SIGIO");
        break;
      case LIN_SIGPWR:
        name = strdup("LIN_SIGPWR");
        break;
      default:
        name = strdup("LINUX_UNKNOWN");
        break;
    }
  }
  return name;
}

ActionType string_to_action(const char *act)
{
  if (strcmp(act, "terminate")==0) {
    return ACTION_TERM;
  } 
  else if (strcmp(act, "stopvm")==0) {
    return ACTION_STOP;
  } 
  else if (strcmp(act, "stoptracing")==0) {
    return ACTION_TRACING_STOP;
  } 
  else {
    return ACTION_NONE;
  } 
}

static void exception_detection(void *opaque) {
  if (detect_action_exception == ACTION_NONE)
    return;

  /* Verify that this exception is one of critical exceptions */
  /* Should use VMI functionality to determine if Linux */
  if (0xC0000000 == VMI_guest_kernel_base) { // linux
    uint32_t eax = cpu_single_env->regs[R_EAX];
    uint32_t cr3 = cpu_single_env->cr[3];
    if (eax != LIN_SIGILL &&
        eax != LIN_SIGTRAP &&
        eax != LIN_SIGBUS &&
        eax != LIN_SIGFPE &&
        eax != LIN_SIGSEGV) return;
    monitor_printf(default_mon, 
                    "ntdll.dll::KiUserExceptionDispatcher raised by insn 0x%x."
                    " User exception detected.\n", eh.address);

    char *name = exception_str(0, eax);      
    monitor_printf(default_mon, "force_sig_info raised by insn 0x%x. "
                "User exception %s (0x%x) detected. "
                "cr3:0x%08x, tracecr3:0x%08x\n", 
                eh.address, name, eax, cr3, tracecr3);
    free(name);
  }
  else{ //windows
    uint32_t buf[3], exctRec[5];
    uint32_t esp = cpu_single_env->regs[R_ESP];
    int read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
    if (read_err == 0) {
        int err = read_mem(buf[0], sizeof(exctRec), (unsigned char*)exctRec);
        if (err == 0) {
            if (exctRec[0] != STATUS_ACCESS_VIOLATION && 
                exctRec[0] != STATUS_ARRAY_BOUNDS_EXCEEDED &&
                exctRec[0] != STATUS_FLOAT_DIVIDE_BY_ZERO &&
                exctRec[0] != STATUS_INTEGER_DIVIDE_BY_ZERO &&
                exctRec[0] != STATUS_ILLEGAL_INSTRUCTION &&
                exctRec[0] != STATUS_STACK_OVERFLOW &&
                exctRec[0] != STATUS_IN_PAGE_ERROR)
                return; // not a critical exception
        }
    }
    char *name = exception_str(1, exctRec[0]);      
    monitor_printf(default_mon, 
                  "ntdll.dll::KiUserExceptionDispatcher raised by insn 0x%x. "
                  "User exception %s (0x%x) detected.\n", 
                  eh.address, name, exctRec[0]);
    free(name);
  }
  // force this instruction to be written
  write_insn(cpu_single_env, tracelog,&eh);
  launch_action(detect_action_exception, EXIT_DETECT_EXCEPTION);
  return;
}

int enable_exception_detection()
{
  /* Should use VMI functionality to determine if Linux */
  if (0xC0000000 == VMI_guest_kernel_base) { // linux
/*
    if (force_sig_info_hook == 0x0) {
      monitor_printf(default_mon, "In errdet.c: "
                  "force_sig_info is 0x0, exit hooking.");
      return -1;
    }
    else{
      exception_hook_handle = 
        hookapi_hook_function(1, force_sig_info_hook, 0, 
                              exception_detection, NULL, 0);
      monitor_printf(default_mon, 
                    "In errdet.c: hooking force_sig_info@0x%08x.\n",
                    force_sig_info_hook);
      return 0;
    }
*/
    return -1;
  }
  else{ //windows
    exception_hook_handle = 
      hookapi_hook_function_byname("ntdll.dll", "KiUserExceptionDispatcher",
                                    0, 0, exception_detection, 0, 0);
    return 0;
  }
}

void disable_exception_detection() {
  if (exception_hook_handle != 0)
    hookapi_remove_hook(exception_hook_handle);
  exception_hook_handle = 0;
}

void set_detect_action_internal(const char* condition_str, 
                                const char* action_str)
{
  // Get action
  ActionType action = string_to_action(action_str);

  // Set action for given condition
  if (strcmp(condition_str, "taintedeip") == 0) {
#ifdef TAINT_ENABLED
    detect_action_taintedeip = action;
    monitor_printf(default_mon, 
                  "Set detect action for tainted EIP to %s.\n", action_str);
#else
    detect_action_taintedeip = ACTION_NONE;
    if (action != ACTION_NONE) {
      monitor_printf(default_mon, 
          "No taint support. Ignoring detection action for tainted EIP.\n");
    }
    else {
      monitor_printf(default_mon, 
                    "Set detect action for tainted EIP to %s.\n", action_str);
    }
#endif // #ifdef TAINT_ENABLED
  }
  else if (strcmp(condition_str, "nullptr") == 0) {
    detect_action_nullptr = action;
    monitor_printf(default_mon, 
                    "Set detect action for null pointer dereference to %s.\n",
                    action_str);
  }
  else if (strcmp(condition_str, "exception") == 0) {
    detect_action_exception = action;
    if (action != ACTION_NONE) {
      enable_exception_detection();
    }
    else {
      disable_exception_detection();
    }
    monitor_printf(default_mon, 
                    "Set detect action for user exception to %s.\n", 
                    action_str);
  }
  else if (strcmp(condition_str, "processexit") == 0) {
    detect_action_processexit = action;
    monitor_printf(default_mon, 
                    "Set detect action for process exit event to %s.\n", 
                    action_str);
  }
  else if (strcmp(condition_str, "all") == 0) {
    detect_action_taintedeip = action;
    detect_action_nullptr = action;
    detect_action_exception = action;
    detect_action_processexit = action;
    monitor_printf(default_mon, "Set detect action for all to %s.\n",
                    action_str);
  }
  else {
    monitor_printf(default_mon, "Unknown detection type.\n");
  }
}

void set_detect_action(Monitor *mon, const QDict *qdict)
{
  set_detect_action_internal(
    qdict_get_str(qdict, "condition"),
    qdict_get_str(qdict, "action"));
}

void procexit_detection(VMI_Callback_Params* params)
{
  if (params == NULL)
  {
    return;
  }

  int pid = params->rp.pid;

  /* If it is not the process being traced, ignore */
  if (tracepid != pid)
    return;

  monitor_printf(default_mon, "Process %d exited.\n", pid);

  /* Process being traced exited, stop tracing */
  tracing_stop();

  /* If no extra detection condition is set, return */
  if (detect_action_processexit == ACTION_NONE)
    return;

  /* Otherwise launch action */
  launch_action(detect_action_processexit, EXIT_DETECT_PROCESSEXIT);
}

void nullptr_detection(u_int32_t address)
{
  if (detect_action_nullptr == ACTION_NONE)
    return;

  monitor_printf(default_mon, "Null pointer dereference at 0x%08x\n", address);
  // force this instruction to be written
  write_insn(cpu_single_env, tracelog,&eh);

  launch_action(detect_action_nullptr, EXIT_DETECT_NULLPTR);
}

void taintedeip_detection(uint8_t *record)
{
  if (detect_action_taintedeip == ACTION_NONE)
    return;

  uint32_t pid;
  char name[32];
  CPUState* env = cpu_single_env;
  gva_t eip = DECAF_getPC(env);

  /* we ignore kernel-mode tainted eips to reduce false positives*/
  //if (DECAF_is_in_kernel())
  //  return ;

  VMI_find_process_by_cr3_c(env->cr[3], name,32, &pid);

  monitor_printf(default_mon, "Tainted EIP 0x%08x in process %d (%s)\n",
                  eip, pid, name);

  // We will miss the instruction triggering vulnerability condition
  // if we log at the end of instruction
  write_insn(env, tracelog,&eh);

  static int eip_tainted_flag = 0;

  struct timeval eiptime;

  if (0 == eip_tainted_flag) {
    eip_tainted_flag = 1;
    if (gettimeofday(&eiptime, 0) == 0) {
      monitor_printf(default_mon, "Time of tainted EIP detection: %ld.%ld\n", 
                  eiptime.tv_sec, eiptime.tv_usec);
    }
  }

  launch_action(detect_action_taintedeip, EXIT_DETECT_TAINTEIP);
}

