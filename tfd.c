/* 
 *  main plugin functions
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
 *  Copyright (C) 2009-2010 Zhenkai Liang <liangzk@comp.nus.edu.sg>
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
#include <sys/user.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "tfd.h"
#include "slirp/slirp.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "conf.h"
#include "skiptaint.h"
#include "conditions.h"
#include "readwrite.h"
#include "network.h"
#include "errdet.h"
#ifdef STATE_VERSION_20
#include "state20.h"
#else
#include "state.h"
#endif
#include "trackproc.h"
#include "shared/function_map.h"
#include "shared/vmi_c_wrapper.h"
// No Sleuthkit for now
// #include "libfstools.h"
/* plugin loading */
#include "hookapi.h"
#include "function_map.h"
#include "hook_plugin_loader.h"
#include "hook_helpers.h"
#ifdef TAINT_ENABLED
#include "shared/tainting/taintcheck_opt.h"
#include "shared/tainting/tainting.h"
#endif

/* Plugin interface */
static plugin_interface_t tracing_interface;

/* Entry header */
EntryHeader eh;

/* PID and CR3 of process being traced */
uint32_t tracepid = 0;
uint32_t tracecr3 = 0;

/* File handles */
FILE *tracelog = NULL;
FILE *tracenetlog = NULL;
FILE *tracehooklog = NULL;
FILE *alloclog = NULL;

/* Filename for functions file */
char functionsname[128]= "";

/* Filename for trace file */
char tracename[128]= "";
char *tracename_p = tracename;

/* Trace file path */
static char tracefile[256];

/* Start usage */
struct rusage startUsage;

/* DECAF callback handles */
static uintptr_t block_begin_cb_handle;
static uintptr_t insn_begin_cb_handle;
static uintptr_t insn_end_cb_handle;
static uintptr_t nic_rec_cb_handle;
static uintptr_t nic_send_cb_handle;
static uintptr_t keystroke_cb_handle;
static DECAF_Handle removeproc_handle;
static DECAF_Handle loadmainmodule_handle;

/* Skip decoding insn (if != 0, decode_address will not be called) */
int skip_decode_address = 0;

/* Skip writing instruction (if != 0, write_insn will not be called) */
int skip_trace_write = 0;

/* Whether we are tracing child process (if !=0, we are tracing child) */
unsigned int tracing_child = 0;

/* Whether the current instruction is tainted (if !=0 it is tainted) */
uint32_t insn_tainted=0;

/* Flag to indicate that next keystroke in callback needs to be tainted */
#ifdef TAINT_ENABLED
static int taint_key_enabled = 0;
#endif

/* Current thread id */
uint32_t current_tid = 0;

#if 0 
// No Sleuthkit for now
typedef struct {
  FS_INFO *fs;
  IMG_INFO *img;
  void *bs;
} disk_info_t;

// Now each disk_info array is broken out by BlockInterfaceType
#define MAX_DISKS 5
static disk_info_t disk_info[IF_COUNT][MAX_DISKS];
#endif

/* Forward declarations of functions used below */
void tracing_block_begin(DECAF_Callback_Params* params);
void tracing_insn_begin(DECAF_Callback_Params* params);
void tracing_insn_end(DECAF_Callback_Params* params);
static int tracing_init(void);
static void tracing_cleanup(void);
// Internal versions of monitor commands that do not require QDict
static void do_load_hooks_internal(const char *hooks_dirname, 
                                    const char *plugins_filename);
static void do_tracing_internal(uint32_t pid, const char *filename);
static void do_tracing_by_name_internal(
  const char *progname, const char *filename);


int tracing_start(uint32_t pid, const char *filename)
{
  /* Copy trace filename to global variable */
  strncpy(tracename, filename, 128);

  /* Set name for functions file */
  snprintf(functionsname, 128, "%s.functions", filename);

  // NOTE: we delay trace opening until first instruction

  /* Initialize netlog file */
  if (tracenetlog)
    fclose(tracenetlog);
  char netname[128];
  snprintf(netname, 128, "%s.netlog", filename);
  tracenetlog = fopen(netname, "w");
  if (NULL == tracenetlog) {
    perror("tracing_start");
    tracepid = 0;
    tracecr3 = 0;
    return -1;
  }
  else {
    fprintf(tracenetlog, "Flow       Off  Data\n");
    fflush(tracenetlog);
  }

  /* Set PID and CR3 of the process to be traced */
  tracecr3 = VMI_find_cr3_by_pid_c(pid);
  if (0 == tracecr3) {
    monitor_printf(default_mon, 
                  "CR3 for PID %d not found. Tracing all processes!\n",pid);
    tracepid = -1;
  }
  else {
    tracepid = pid;
  }
  monitor_printf(default_mon, "PID: %d CR3: 0x%08x\n", tracepid, tracecr3);

  /* Initialize disassembler */
  xed2_init();

  /* Clear skip taint flags */
  init_st();

  /* Initialize hooks only for this process */
  decaf_plugin->monitored_cr3 = tracecr3;

  /* Get system start usage */
  if (getrusage(RUSAGE_SELF, &startUsage) != 0)
    monitor_printf (default_mon, "Could not get start usage\n");

  // If tracing child, load process tracking hooks
  if (tracing_child) {
    trackproc_start(pid);
    load_hooks_in_plugin(&tracecr3, "group_process.so", hook_dirname);
  }

  /* Register block and instruction callbacks */
  block_begin_cb_handle =
    DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, tracing_block_begin, NULL);

  insn_begin_cb_handle =
    DECAF_register_callback(DECAF_INSN_BEGIN_CB,
                            tracing_insn_begin, &should_monitor);
  insn_end_cb_handle =
    DECAF_register_callback(DECAF_INSN_END_CB,
                        tracing_insn_end, &should_monitor);

  return 0;
}

void tracing_stop()
{
  /* If not tracing return */
  if (tracepid == 0)
    return;

  monitor_printf(default_mon, "Stop tracing process %d\n", tracepid);
  print_trace_stats();

  /* Get system stop usage */
  struct rusage stopUsage;
  if (getrusage(RUSAGE_SELF, &stopUsage) == 0) {
    double startUT = (double)startUsage.ru_utime.tv_sec +
                    (double)startUsage.ru_utime.tv_usec / 1e6;
    double startST = (double)startUsage.ru_stime.tv_sec +
                    (double)startUsage.ru_stime.tv_usec / 1e6;
    double stopUT = (double)stopUsage.ru_utime.tv_sec +
                    (double)stopUsage.ru_utime.tv_usec / 1e6;
    double stopST = (double)stopUsage.ru_stime.tv_sec +
                    (double)stopUsage.ru_stime.tv_usec / 1e6;

    double userProcessTime = (stopUT - startUT);
    double systemProcessTime = (stopST - startST);
    double processTime =  userProcessTime + systemProcessTime;

    monitor_printf (default_mon, "Processing time: %g U: %g S: %g\n",
      processTime, userProcessTime, systemProcessTime);
  }
  else {
    monitor_printf(default_mon, "Could not get usage\n");
  }


  // Close trace, reading the needed process information
  if (tracelog) {
#ifdef TRACE_VERSION_50
    close_trace(tracelog);
#else
    ProcRecord ** proc_arr = NULL;
    size_t num_procs = 0;
    proc_arr = trackproc_get_tracked_processes_info(cpu_single_env, tracepid, 
                                                    &num_procs);
    close_trace(tracelog, proc_arr, num_procs);
#endif
    tracelog = NULL;
  }

  // Reset globals
  tracepid = 0;

  // Close Net log
  if (tracenetlog) {
    fclose(tracenetlog);
    tracenetlog = 0;
  }

  // Close hook log
  if (tracehooklog) {
    fclose(tracehooklog);
    tracehooklog = 0;
  }

  // Close allocation log
  if (alloclog) {
    fclose(alloclog);
    alloclog = 0;
  }

  // Clear received_data flag
  received_tainted_data = 0;

// Print file with all functions offsets
#if PRINT_FUNCTION_MAP
  //map_to_file(functionsname);
#endif

  if (conf_save_state_at_trace_stop) {
    char statename[128];
    snprintf(statename, 128, "%s.state", tracename);

#ifdef STATE_VERSION_20
    int err = 
      save_state_by_cr3(cpu_single_env, tracecr3, statename);
#else
    int err = 
      save_state_by_cr3(cpu_single_env, tracecr3, statename, 
                        conf_save_state_at_trace_stop);
#endif // #ifdef STATE_VERSION_20

    if (err) {
      monitor_printf(default_mon, "Could not save state");
    }
  }

  /* Clear tracing child */
  if (tracing_child) {
    tracing_child = 0;
    skip_trace_write = 0;
    trackproc_stop();
  }

  /* Unregister block and instruction callbacks */
  if (block_begin_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb_handle);
    block_begin_cb_handle = DECAF_NULL_HANDLE;
  }
  if (insn_begin_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, insn_begin_cb_handle);
    insn_begin_cb_handle = DECAF_NULL_HANDLE;
  }
  if (insn_end_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_END_CB, insn_end_cb_handle);
    insn_end_cb_handle = DECAF_NULL_HANDLE;
  }

}


void tracing_block_begin(DECAF_Callback_Params* params)
{
  char current_proc[512] = "";
  CPUState* env = NULL;

  if (!params)
    return;

  env = params->bb.env;

  /* Get thread id (needs to be done before checking hooks) */
  // TODO: Are hooks checked before or after invoking block begin handler?
  current_tid = VMI_get_current_tid_c(env);

  // Let DECAF now that we want to hook the instructions in this block
  should_monitor = 
    (decaf_plugin->monitored_cr3 == env->cr[3]) && 
    (!DECAF_is_in_kernel(env) || tracing_kernel());

  /* If not right context, return */
  if  (!should_monitor)
    return;

  /* No need to check if we are tracing, otherwise block_begin unregistered */
  //if ((tracepid == 0) && (!procname_is_set()))
  //  return;

  /* If tracing module, check if we are in traced module */
  if (modname_is_set()) {
    // Get current module name
    tmodinfo_t *mi = (tmodinfo_t *) malloc(sizeof(tmodinfo_t));
    gva_t eip = DECAF_getPC(env);
    VMI_locate_module_c(eip, env->cr[3], current_proc, mi);

    // Check if right module
    if (mi && (modname_match(mi->name))) {
      tracing_start_condition = 1;
      modname_clear();
    }
  }

  return;
}

#ifdef TAINT_ENABLED
static void tracing_send_keystroke(DECAF_Callback_Params *params)
{
  /* If not tracing, return */
  if  (tracepid == 0)
    return;

  /* If we do not need to taint the key, return */
  if(!taint_key_enabled)
    return;

  /* Taint the key */
  uint32_t *taint_mark=params->ks.taint_mark;
  *taint_mark=taint_key_enabled;

  /* Disable flag so that next keystroke is not tainted */
  taint_key_enabled=0;

  /* Print keystroke */
  int keycode=params->ks.keycode;
  printf("Tainted keystroke %d \n ", keycode);
}

void do_taint_sendkey(Monitor *mon, const QDict *qdict)
{
  if(qdict_haskey(qdict, "key")) 
  {
    // Register keystroke callback if not registered
    if (!keystroke_cb_handle) {
      keystroke_cb_handle = DECAF_register_callback(DECAF_KEYSTROKE_CB,
        tracing_send_keystroke, &taint_key_enabled);
    }

    // Set taint flag to tell callback to taint the key
    taint_key_enabled=1;

    // Send the key
    do_send_key(qdict_get_str(qdict, "key"));
  }
  else {
    monitor_printf(mon, "taint_sendkey command is malformed\n");
  }
}
#endif //TAINT_ENABLED

static void stoptracing()
{
  monitor_printf(default_mon, "Received Signal: STOP\n");
  tracing_stop();
}

void tracing_clean_exit(int exitcode) {
  tracing_cleanup();
  exit(exitcode);
}

static void killqemu()
{
  monitor_printf(default_mon, "Received Signal: KILL\n");
  tracing_cleanup();
  exit(EXIT_KILL_SIGNAL);
}

int insn_access_user_mem(EntryHeader * eh) {
  unsigned int op_idx;

  for (op_idx = 0; op_idx < eh->num_operands; op_idx++) {
    // Check if instruction accesses user memory
    if ((eh->operand[op_idx].type == TMemLoc) &&
#ifdef TRACE_VERSION_50
        (eh->operand[op_idx].addr < VMI_guest_kernel_base)
#else
        (eh->operand[op_idx].addr.mem32_addr < VMI_guest_kernel_base)
#endif
      )
    {
      return 1;
    }
  }
  return 0;
}

static void do_load_hooks_internal (const char *hooks_dirname, 
    const char *plugins_filename)
{
  if (strcmp(plugins_filename, "") != 0)
    strncpy(hook_plugins_filename, plugins_filename, 256);
  if (strcmp(hooks_dirname, "") != 0)
    strncpy(hook_dirname, hooks_dirname, 256);

  load_hook_plugins(&(decaf_plugin->monitored_cr3),
    hook_plugins_filename,
    hook_dirname,
    ini);
}

void do_load_hooks(Monitor *mon, const QDict *qdict)
{
  do_load_hooks_internal(qdict_get_str(qdict, "hooks_dirname"), 
      qdict_get_str(qdict, "plugins_filepath"));
}

void do_unload_hooks(Monitor *mon, const QDict *qdict)
{
  unload_hook_plugins();
}

void do_load_config(Monitor *mon, const QDict *qdict)
{
  int err = 0;
  const char *config_filepath = 
    qdict_get_str(qdict, "configuration_filepath");

  // Parse configuration file
  err = check_ini(config_filepath);
  if (err) {
    monitor_printf (mon, "Could not find INI file: %s\nTry again.\n", 
      config_filepath);
  }
}


void do_tracing_stop(Monitor *mon)
{
  tracing_stop();
}


static void do_tracing_internal(uint32_t pid, const char *filename)
{
  /* if pid = 0, stop trace */
  if (0 == pid)
    tracing_stop();
  else {
    int retval = tracing_start(pid, filename);
    if (retval < 0)
      monitor_printf(default_mon, "Unable to open log file '%s'\n", filename);
  }

  /* Print configuration variables */
  //print_conf_vars(); 
}

void do_tracing(Monitor *mon, const QDict *qdict)
{
  uint32_t pid = qdict_get_int(qdict, "pid");
  const char *filename = qdict_get_str(qdict, "filepath");

  do_tracing_internal(pid, filename);
}

static void do_tracing_by_name_internal(const char *progname, 
                                        const char *filename)
{
  /* If process already running, start tracing */
  uint32_t pid = VMI_find_pid_by_name_c((char  *)progname);
  uint32_t minus_one = (uint32_t)(-1);
  if (pid != minus_one) {
    do_tracing_internal(pid,filename);
  }
  else {
    /* Otherwise, start monitoring for process start */
    procname_set(progname); 
    strncpy(tracefile, filename, 256);
    monitor_printf (default_mon, "Waiting for process %s to start\n", 
                    progname);
  }

  /* Print configuration variables */
  //print_conf_vars(); 
}

void do_tracing_by_name(Monitor *mon, const QDict *qdict)
{
  do_tracing_by_name_internal(qdict_get_str(qdict, "name"),
    qdict_get_str(qdict, "filepath"));
}

void do_tracing_child(Monitor *mon, const QDict *qdict)
{
  const char *progname = qdict_get_str(qdict, "name");
  const char *filename = qdict_get_str(qdict, "filepath");

  /* Set flag for tracing children */
  tracing_child = 1;

  /* Do not write anything to the trace until child starts */
  skip_trace_write = 1;

  /* Trace process by name */
  do_tracing_by_name_internal(progname, filename);
}

void do_save_state(Monitor *mon, const QDict *qdict)
{
  int err;

  if (!(qdict_haskey(qdict, "pid") &&
    qdict_haskey(qdict, "address") &&
    qdict_haskey(qdict, "filepath")) )
  {
#ifdef STATE_VERSION_20
    err = save_state_at_addr(NULL, qdict_get_int(qdict, "pid"),
                              qdict_get_int(qdict, "address"),
                              qdict_get_str(qdict, "filepath"));
#else
    err = save_state_at_addr(NULL, qdict_get_int(qdict, "pid"), 
                              qdict_get_int(qdict, "address"), 
                              qdict_get_str(qdict, "filepath"), 
                              STATE_SNAPSHOT_TYPE_PROCESS);
#endif // #ifdef STATE_VERSION_20

    if (err) {
      monitor_printf(mon, "Invalid pid or unable to open log file '%s'\n", 
        qdict_get_str(qdict, "filename"));
    }
  }
  else {
    monitor_printf(mon, "save_state command is malformed\n");
  }
}

void tracing_insn_begin(DECAF_Callback_Params* params)
{
  CPUState* env = NULL;

  /* If no parameters, return */
  if (!params)
    return;

  env = params->ib.env;

  /* If tracing start condition not satisified, return */
  if (!tracing_start_condition)
    return;

  /* If not tracing, return */
  // This should not be needed, as if not tracing insn_begin unregistered
  // if (tracepid == 0)
  //   return;

  /* If not tracing kernel and kernel instruction , return */
  // This should not be needed, as should_monitor captures this condition
  //if ( DECAF_is_in_kernel() && !tracing_kernel() )
  //  return;

  /* Get thread id */
  current_tid = VMI_get_current_tid_c(env);

  // Flag to be set if the instruction is written
  insn_already_written = 0;

  /* Disassemble the instruction */
  insn_tainted=0;
  if (skip_decode_address == 0) {
    gva_t eip = DECAF_getPC(env);

#ifdef TRACE_VERSION_50
    decode_address(env, eip, &eh, current_tid, get_st(current_tid));
#else
    uint32_t curr_pid;
    if (tracepid != -1) {
      curr_pid = tracepid;
    }
    else {
      curr_pid = VMI_find_pid_by_cr3_c(env->cr[3]);
    }

    decode_address(env, eip, &eh, curr_pid, current_tid, get_st(current_tid));
#endif
  }

}

void tracing_insn_end(DECAF_Callback_Params* params)
{
  CPUState* env = NULL;

  /* If no parameters, return */
  if (!params)
    return;

  env = params->ie.env;

  /* If not decoding, return */
  if (skip_decode_address)
    return;

  /* If tracing start condition not satisified, return */
  if (!tracing_start_condition)
    return ;

  /* If not tracing, return */
  // This should not be needed, as if not tracing insn_end unregistered
  // if (tracepid == 0)
  //   return;

  /* If not tracing kernel and kernel instruction, return */
  // This should not be needed, as should_monitor captures this condition
  //if ( DECAF_is_in_kernel() && !tracing_kernel() )
  //  return;

  /* If partially tracing kernel but did not access user memory, return */
  if (DECAF_is_in_kernel(env)) {
      if (tracing_kernel_partial() && (!insn_access_user_mem(&eh)))
        return;
#ifdef TAINT_ENABLED
      if (tracing_kernel_tainted() && (!insn_tainted))
        return;
#endif
  }

  /* Update the eflags */
  eh.eflags = *(&env->eflags);
#ifndef TRACE_VERSION_50
  if (eflags_idx != -1) {
    eh.operand[eflags_idx].value.val32 = *(&env->eflags);
  }
#endif
  eh.df = (*(&env->df) == 1)? 0x1 : 0xff;

  /* Clear eh.tp if inside a function hook */
  if (get_st(current_tid) > 0) eh.tp = TP_NONE;
  else {
    /* Update eh.tp if rep instruction */
    if ((eh.operand[2].usage == counter) && (eh.operand[2].tainted != 0))
      eh.tp = TP_REP_COUNTER;

    /* Updated eh.tp if sysenter */
    else if ((eh.rawbytes[0] == 0x0f) && (eh.rawbytes[1] == 0x34))
      eh.tp = TP_SYSENTER;
  }

  /* Split written operands if requested */
  if (conf_write_ops_at_insn_end) {
    update_written_operands (env, &eh);
  }

  /* If not writing to trace, or instruction already written, return */
  if (skip_trace_write || (insn_already_written == 1)) 
    return;

  /* Check if we need to write the disassembled instruction to the trace */
  int insn_to_be_written = 0;
  if (tracing_tainted_only()) {
#ifdef TAINT_ENABLED
    if (insn_tainted)
      insn_to_be_written = 1;
#endif      
  }
  else {
    if (conf_trace_only_after_first_taint) {
      if (received_tainted_data == 1) {
        insn_to_be_written = 1;
      }
    }
    else {
      insn_to_be_written = 1;
    }
  }

  if (insn_to_be_written) {
    /* If trace not yet open, open it */
    if (!tracelog) {
      ProcRecord * pr = trackproc_get_process_info(env, env->cr[3]);
      tracelog = open_trace(env, tracename, pr);
      if (NULL == tracelog) {
        perror("Could not open trace");
        tracing_stop();
        return;
      }
      /* Free process information */
      if (pr->mod_arr)
        free(pr->mod_arr);
      if (pr)
        free(pr);
      pr = NULL;
    }
    /* Write instruction to trace */
    write_insn(env, tracelog,&eh);
  }

  /* If first trace instruction, save state if requested */
  if ((tstats.insn_counter_traced == 1) && conf_save_state_at_trace_start) {
    char prestatename[128];
    snprintf(prestatename, 128, "%s.pre", tracename);

#ifdef STATE_VERSION_20
    int err = 
      save_state_by_cr3(env, tracecr3, prestatename);
#else
    int err = 
      save_state_by_cr3(env, tracecr3, prestatename, 
                        conf_save_state_at_trace_start);
#endif // #ifdef STATE_VERSION_20

    if (err) {
      monitor_printf(default_mon, "Could not save state");
    }
  }

  /* Record the thread ID of the first instruction in the trace, if needed */
  if (tracing_single_thread_only()) {
    if (tid_to_trace == -1 && insn_already_written == 1) {
      // If tid_to_trace is not -1, we record trace only the given thread id.
      tid_to_trace = current_tid;
    }
  }

}

/* Param format
    <pid>:<traceFilename>:<pidToSignal>:<processName>
*/
void tracing_after_loadvm(const char*param)
{
  char buf[256];
  strncpy(buf, param, sizeof(buf) - 1);
  buf[255] = '\0';
  int pid_to_signal = 0;

  char *pid_str = strtok(buf, ":");
  if (!pid_str)
    return;

  char *trace_filename = strtok(0, ":");
  if (!trace_filename)
    return;

  char *pid_to_signal_str = strtok(0, ":");

  char *process_name = strtok(0, ":");

  char *end = pid_str;
  int pid = (int) strtol (pid_str, &end, 10);
  if (end == pid_str) {
    pid = -1;
  }

  /* If no PID or Process_name, return */
  if ((process_name == NULL) && (pid == -1)) {
    monitor_printf(default_mon, "PARAM: %s\n", param);
    monitor_printf(default_mon, "START: %p END: %p\n", pid_str, end);
    monitor_printf(default_mon, "No PID or Process_name provided\n");
    return;
  }

  if (pid_to_signal_str) {
    end = pid_to_signal_str;
    pid_to_signal = (int) strtol (pid_to_signal_str, &end, 10);
    if (end == pid_to_signal_str) {
      pid_to_signal = 0;
    }
  }

  monitor_printf (default_mon, 
                  "PID: %d PID2SIGNAL: %d PROCESS_NAME: %s\n",
                  pid, pid_to_signal, process_name);

#ifdef TAINT_ENABLED
  /* Taint the network */
  do_taint_nic_internal(1);

  /* Filter traffic (read from ini configuration file) */
  print_nic_filter();

#endif // #ifdef TAINT_ENABLED  

  /* Load hooks */
  do_load_hooks_internal("","");

  /* Start trace */
  if (process_name == NULL)
    do_tracing_internal(pid, trace_filename);
  else
    do_tracing_by_name_internal(process_name,trace_filename);

  /* Send signal to notify that trace is ready */
  //if (pid_to_signal != 0) kill(pid_to_signal,SIGUSR1);
  int pipe_fd = open("/tmp/tfd.pipe",O_WRONLY);
  size_t num_written = write(pipe_fd,"OK",2);
  if (num_written != 2) {
    monitor_printf (default_mon, "Error writing to /tmp/tfd.pipe\n");
  }
  close(pipe_fd);

}

void set_trace_writing(Monitor *mon, const QDict *qdict)
{
  if (qdict_haskey(qdict, "on")) {
    monitor_printf(mon, "Write to trace is on.\n");
    skip_trace_write = 0;
    skip_decode_address = 0;
  } 
  else if (qdict_haskey(qdict, "off")) {
    monitor_printf(mon, "Write to trace is off.\n");
    skip_trace_write = 1;
    skip_decode_address = 1;
  } 
  else {
    monitor_printf(mon, "The option must be 'on' or 'off'.\n");
  }
}

static void tracing_proc_start(VMI_Callback_Params * params)
{
  /* If tracingbyname, check if this is the process to trace. 
      If so, start the trace */
  if (procname_is_set()) {
    if (procname_match(params->cp.name)) {
      uint32_t pid = params->cp.pid;

      // Start tracing
      do_tracing_internal(pid, tracefile);
      monitor_printf(default_mon, "Tracing %s\n", procname_get());

      // No need to keep monitoring process name
      procname_clear();
    }
  }

  /* If tracing child and first child 
       then trace child instead of parent and enable logging */
  if (tracing_child && trackproc_found_child()) {
    uint32_t curr_pid = params->cp.pid;
    if ((trackproc_find_pid(curr_pid) != -1) &&
        (curr_pid != trackproc_get_root_pid()))
    {
      uint32_t child_cr3 = VMI_find_cr3_by_pid_c(curr_pid);

      if (0 == child_cr3) {
        monitor_printf(default_mon, 
                        "CR3 for child process %d not found\n",curr_pid);
      }
      else {
        decaf_plugin->monitored_cr3 = child_cr3;
        tracepid = curr_pid;
        tracecr3 = child_cr3;
        monitor_printf(default_mon, 
                        "Now tracing child process. PID: %d CR3: 0x%08x\n",
                        curr_pid, child_cr3);
        skip_trace_write = 0;
        tracing_child = 0;
      }
    }
  }
}

static int tracing_init(void)
{
  // Setup signal handler to stop tracing
  signal(SIGUSR1, stoptracing);

  // SIGUSR2 is used by QEMU

  // Setup signal handler to exit emulator
  signal(SIGTERM, killqemu);

  // Clear trace start condition buffers
  procname_clear(); 
  modname_clear(); 

  // No Sleuthkit for now
  // bzero(disk_info, sizeof(disk_info_t) * IF_COUNT * MAX_DISKS);
  // qemu_pread = (qemu_pread_t)DECAF_bdrv_pread;

  // Parse configuration file
  int err = check_ini(ini_main_default_filename);
  if (err) {
    monitor_printf (default_mon, "Could not find INI file: %s\n"
                 "Use the command 'load_config <filename> to provide it.\n", 
                 ini_main_default_filename);
  }

  return 0;
}

static void tracing_cleanup(void)
{
  /* If tracing is on, stop it */
  tracing_stop();

  /* Remove VMI handles */
  if (removeproc_handle != DECAF_NULL_HANDLE) {
    VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
    removeproc_handle = DECAF_NULL_HANDLE;
  }
  if (loadmainmodule_handle != DECAF_NULL_HANDLE) {
    VMI_unregister_callback(VMI_CREATEPROC_CB, loadmainmodule_handle);
    loadmainmodule_handle = DECAF_NULL_HANDLE;
  }

  /* Remove DECAF callback handles */
  DECAF_stop_vm();
  if (block_begin_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb_handle);
    block_begin_cb_handle = DECAF_NULL_HANDLE;
  }
  if (insn_begin_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, insn_begin_cb_handle);
    insn_begin_cb_handle = DECAF_NULL_HANDLE;
  }
  if (insn_end_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_INSN_END_CB, insn_end_cb_handle);
    insn_end_cb_handle = DECAF_NULL_HANDLE;
  }
  if (nic_rec_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_NIC_REC_CB, nic_rec_cb_handle);
    nic_rec_cb_handle = DECAF_NULL_HANDLE;
  }
  if (nic_send_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_NIC_SEND_CB, nic_send_cb_handle);
    nic_send_cb_handle = DECAF_NULL_HANDLE;
  }
  if (keystroke_cb_handle != DECAF_NULL_HANDLE) {
    DECAF_unregister_callback(DECAF_KEYSTROKE_CB, keystroke_cb_handle);
    keystroke_cb_handle = DECAF_NULL_HANDLE;
  }
  DECAF_start_vm();

  /* Cleanup Sleuthkit */
  // No Sleuthkit for now
  // tracing_bdrv_cleanup();

  /* Unload hooks */
  unload_hook_plugins();

}

/* Monitor commands */
static mon_cmd_t tracing_term_cmds[] = {
#include "plugin_cmds.h"
  {NULL, NULL, },
};
static mon_cmd_t tracing_info_cmds[] = {
  {NULL, NULL, },
};

/* Plugin initialization */
plugin_interface_t * init_plugin()
{
  /* Select string comparison function */
  /* NOTE: this should be handle by VMI module if needed */
  if (0x80000000 == VMI_guest_kernel_base)
    comparestring = strcasecmp;
  else
    comparestring = strcmp;


  /* Set interface fields */
  tracing_interface.plugin_cleanup = tracing_cleanup;
  tracing_interface.mon_cmds = tracing_term_cmds;
  tracing_interface.info_cmds = tracing_info_cmds;
  tracing_interface.after_loadvm = tracing_after_loadvm;

  /* Register callbacks */
  DECAF_stop_vm();

  nic_rec_cb_handle=
    DECAF_register_callback(DECAF_NIC_REC_CB, tracing_nic_recv, NULL);

  nic_send_cb_handle=
    DECAF_register_callback(DECAF_NIC_SEND_CB, tracing_nic_send, NULL);

  DECAF_start_vm();

  // Insn begin and end callback are registered when tracing starts
  block_begin_cb_handle = DECAF_NULL_HANDLE;
  insn_begin_cb_handle = DECAF_NULL_HANDLE;
  insn_end_cb_handle = DECAF_NULL_HANDLE;

  // Keystroke handler will be registered later if needed
  keystroke_cb_handle = DECAF_NULL_HANDLE;

  removeproc_handle = 
    VMI_register_callback(VMI_REMOVEPROC_CB, procexit_detection, NULL);

  loadmainmodule_handle = 
    VMI_register_callback(VMI_CREATEPROC_CB, tracing_proc_start, NULL);

  /* Initialize tracing */
  tracing_init();

  /* Return plugin interace */
  return &tracing_interface;
}

