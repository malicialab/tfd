/* 
 *  parse configuration options from INI file
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
#include <assert.h>
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "conf.h"
#include "tfd.h"
#include "conditions.h"
#include "network.h"
#include "errdet.h"

/* Default configuration flags */
int conf_trace_only_after_first_taint = 1;
int conf_write_ops_at_insn_end = 0;
int conf_save_state_at_trace_start = 0;
int conf_save_state_at_trace_stop = 0;

/* Environment variables */
static int conf_ignore_dns = 0;
static int conf_tainted_only = 0;
static int conf_single_thread_only = 0;
static int conf_tracing_kernel_all = 0;
static int conf_tracing_kernel_tainted = 0;
static int conf_tracing_kernel_partial = 0;
static int conf_detect_memory_exception = 0;
static int conf_detect_null_pointer = 0;
static int conf_detect_process_exit = 0;
static int conf_detect_tainted_eip = 0;

/* Default hook files */
char hook_dirname[256] = DECAF_HOME "/shared/hooks/hook_plugins";
char hook_plugins_filename[256] = PLUGIN_PATH "/ini/hook_plugin.ini";

/* Default configuration file */
char ini_main_default_filename[256] = PLUGIN_PATH "/ini/main.ini";


void set_ignore_dns(Monitor *mon, const QDict *qdict)
{
  if (qdict_get_int(qdict, "state")) {
    conf_ignore_dns = 1;
    monitor_printf(default_mon, "Ignore DNS flag on.\n");
  }
  else {
    conf_ignore_dns = 0;
    monitor_printf(default_mon, "Ignore DNS flag off.\n");
  }
}

inline int tracing_ignore_dns()
{
    return conf_ignore_dns;
}

void set_tainted_only(Monitor *mon, const QDict *qdict)
{
  if (qdict_get_int(qdict, "state")) {
    conf_tainted_only = 1;
    monitor_printf(default_mon, "Taint-only flag on.\n");
  }
  else {
    conf_tainted_only = 0;
    monitor_printf(default_mon, "Taint-only flag off.\n");
  }
}

inline int tracing_tainted_only()
{
    return conf_tainted_only;
}

void set_single_thread_only(Monitor *mon, const QDict *qdict)
{
  if (qdict_get_int(qdict, "state")) {
    conf_single_thread_only = 1;
    monitor_printf(default_mon, "Single-thread-only flag on.\n");
  }
  else {
    conf_single_thread_only = 0;
    monitor_printf(default_mon, "Single-thread-only flag off.\n");
  }
}

inline int tracing_single_thread_only()
{
    return conf_single_thread_only;
}

void set_kernel_all(Monitor *mon, const QDict *qdict)
{
  if (qdict_get_int(qdict, "state")) {
    conf_tracing_kernel_all = 1;
    monitor_printf(default_mon, "Kernel-all flag on.\n");
  }
  else {
    conf_tracing_kernel_all = 0;
    monitor_printf(default_mon, "Kernel-all flag off.\n");
  }
}

inline int tracing_kernel_all()
{
    return conf_tracing_kernel_all;
}

void set_kernel_tainted(Monitor *mon, const QDict *qdict)
{
  if (qdict_get_int(qdict, "state")) {
    conf_tracing_kernel_tainted = 1;
    monitor_printf(default_mon, "Kernel-tainted flag on.\n");
  }
  else {
    conf_tracing_kernel_tainted = 0;
    monitor_printf(default_mon, "Kernel-tainted flag off.\n");
  }
}

inline int tracing_kernel_tainted()
{
    return conf_tracing_kernel_tainted;
}

void set_kernel_partial(Monitor *mon, const QDict *qdict)
{
  if (qdict_get_int(qdict, "state")) {
    conf_tracing_kernel_partial = 1;
    monitor_printf(default_mon, "Kernel-partial flag on.\n");
  }
  else {
    conf_tracing_kernel_partial = 0;
    monitor_printf(default_mon, "Kernel-partial flag off.\n");
  }
}

inline int tracing_kernel_partial()
{
    return conf_tracing_kernel_partial;
}

inline int tracing_kernel()
{
    return conf_tracing_kernel_all || conf_tracing_kernel_partial ||
        conf_tracing_kernel_tainted;
}

/* Print configuration variables */
void print_conf_vars()
{
  monitor_printf(
    default_mon,
    "TRACE_AFTER_FIRST_TAINT: %d\n"
      "WRITE_OPS_AT_INSN_END: %d\nSAVE_STATE_AT_TRACE_START: %d\n"
      "SAVE_STATE_AT_TRACE_STOP: %d\nIGNOREDNS: %d\nTAINTED_ONLY: %d\n"
      "SINGLE_THREAD_ONLY: %d\nTRACING_KERNEL_ALL: %d\n"
      "TRACING_KERNEL_TAINTED: %d\nTRACING_KERNEL_PARTIAL: %d\n"
      "DETECT_MEMORY_EXCEPTION: %d\nDETECT_NULL_POINTER: %d\n"
      "DETECT_PROCESS_EXIT: %d\nDETECT_TAINTED_EIP: %d\n",
    conf_trace_only_after_first_taint,
    conf_write_ops_at_insn_end,
    conf_save_state_at_trace_start,
    conf_save_state_at_trace_stop,
    conf_ignore_dns, 
    conf_tainted_only,
    conf_single_thread_only,
    conf_tracing_kernel_all,
    conf_tracing_kernel_tainted,
    conf_tracing_kernel_partial,
    conf_detect_memory_exception,
    conf_detect_null_pointer,
    conf_detect_process_exit,
    conf_detect_tainted_eip
  );
}

/* Parse network filter configuration */
void check_filter_conf(struct cnfnode *cn_root) {
#ifdef TAINT_ENABLED
  struct cnfresult *cnf_res;

  /* Transport */
  cnf_res = cnf_find_entry(cn_root, "network/filter_transport");
  if (cnf_res) {
    update_nic_filter("proto",cnf_res->cnfnode->value);
  }
  /* Source port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_sport");
  if (cnf_res) {
    update_nic_filter("sport",cnf_res->cnfnode->value);
  }
  /* Destination port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_dport");
  if (cnf_res) {
    update_nic_filter("dport",cnf_res->cnfnode->value);
  }
  /* Source addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_saddr");
  if (cnf_res) {
    update_nic_filter("src",cnf_res->cnfnode->value);
  }
  /* Destination addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_daddr");
  if (cnf_res) {
    update_nic_filter("dst",cnf_res->cnfnode->value);
  }
#endif // #ifdef TAINT_ENABLED 
  
}

/* Parse save_state configuration */
void set_save_state(struct cnfnode *cn_root, char *entry, int* flag) {
  struct cnfresult *cnf_res;

  cnf_res = cnf_find_entry(cn_root, entry);
  if (cnf_res) {
    if (strcmp(cnf_res->cnfnode->value,"") == 0) {
      // monitor_printf(default_mon, "Empty %s. Ignoring\n", entry);
      return;
    }
    else if (strcasecmp(cnf_res->cnfnode->value, "process") == 0) {
      *flag = 1;
      monitor_printf(default_mon, "%s set to process snapshot.\n", entry);
    }
    else if (strcasecmp(cnf_res->cnfnode->value, "system") == 0) {
      *flag = 2;
      monitor_printf(default_mon, "%s set to system snapshot.\n", entry);
    }
    else {
      monitor_printf(default_mon, 
                    "%s has incorrect value. Try <process|system>.\n",entry);
    }
  }
}

/* Parse boolean from configuration file */
static void set_bool_from_ini(struct cnfnode *cn_root, char *entry,int* flag) {
  struct cnfresult *cnf_res;

  cnf_res = cnf_find_entry(cn_root, entry);
  if (cnf_res) {
    if (strcasecmp(cnf_res->cnfnode->value, "yes") == 0) {
      *flag = 1;
      monitor_printf(default_mon, "%s is enabled.\n",entry);
    }
    else if (strcasecmp(cnf_res->cnfnode->value, "no") == 0) {
      *flag = 0;
      monitor_printf(default_mon, "%s is disabled.\n",entry);
    }
    else {
      monitor_printf(default_mon, "%s has incorrect value. Try <yes|no>.\n", 
                      entry);
    }
  }

}

/* Parse configuration file 
 * Returns zero if succeeds, -1 if it could not find the file */
int check_ini(const char *path_ini)
{
  struct cnfnode *cn_root;
  struct cnfmodule *mod_ini;
  struct cnfresult *cnf_res;

  register_ini(NULL);
  mod_ini = find_cnfmodule("ini");
  cn_root = cnfmodule_parse_file(mod_ini, path_ini);

  if (cn_root == NULL) {
    return -1;
  }

  /* Parse configuration flags */
  set_bool_from_ini(cn_root, "general/trace_only_after_first_taint",
    &conf_trace_only_after_first_taint);
  set_bool_from_ini(cn_root, "general/write_ops_at_insn_end",
    &conf_write_ops_at_insn_end);
  set_save_state(cn_root, "general/save_state_at_trace_start",
    &conf_save_state_at_trace_start);
  set_save_state(cn_root, "general/save_state_at_trace_stop",
    &conf_save_state_at_trace_stop);
  set_bool_from_ini(cn_root, "tracing/tracing_tainted_only",
    &conf_tainted_only);
  set_bool_from_ini(cn_root, "tracing/tracing_single_thread_only",
    &conf_single_thread_only);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel",
    &conf_tracing_kernel_all);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel_tainted",
    &conf_tracing_kernel_tainted);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel_partial",
    &conf_tracing_kernel_partial);

  /* Parse network configuration */
  set_bool_from_ini(cn_root, "network/ignore_dns",
    &conf_ignore_dns);
  check_filter_conf(cn_root);
#ifdef TAINT_ENABLED  
  print_nic_filter();
#endif  

  /* Set error detection action: memory exception */
  cnf_res = cnf_find_entry(cn_root, "detect/detect_memory_exception");
  if (cnf_res)
    set_detect_action_internal("exception", cnf_res->cnfnode->value);

  /* Set error detection action: null pointer dereference */
  cnf_res = cnf_find_entry(cn_root, "detect/detect_null_pointer");
  if (cnf_res)
    set_detect_action_internal("nullptr", cnf_res->cnfnode->value);

  /* Set error detection action: process exit */
  cnf_res = cnf_find_entry(cn_root, "detect/detect_process_exit");
  if (cnf_res)
    set_detect_action_internal("processexit", cnf_res->cnfnode->value);

  /* Set error detection action: tainted eip */
  cnf_res = cnf_find_entry(cn_root, "detect/detect_tainted_eip");
  if (cnf_res)
    set_detect_action_internal("taintedeip", cnf_res->cnfnode->value);

  /* Find hook configuration file */
  cnf_res = cnf_find_entry(cn_root, "function hooks/plugin_ini");
  if (cnf_res)
    strncpy(hook_plugins_filename, cnf_res->cnfnode->value, 255);
  hook_plugins_filename[255] = '\0';
  monitor_printf(default_mon, "Loading plugin options from: %s\n", 
                  hook_plugins_filename);

  /* Find hooks directory */
  cnf_res = cnf_find_entry(cn_root, "function hooks/plugin_directory");
  if (cnf_res) {
    strncpy(hook_dirname, cnf_res->cnfnode->value, 255);
    hook_dirname[255] = '\0';
  }
  monitor_printf(default_mon, "Loading plugins from: %s\n", hook_dirname);

  /* Free XML configuration tree */
  destroy_cnftree(cn_root);

  return 0;
}

