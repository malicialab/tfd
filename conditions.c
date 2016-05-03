/* 
 *  conditions to start a trace
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
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "conditions.h"
#include "DECAF_main.h"
#include "hookapi.h"
#include "conf.h"

// Whether the start condition is met
int tracing_start_condition = 1;

/* Start tracing on different conditions */
static uint32_t tc_start_counter = 0;
static uint32_t tc_start_at = 0;
static uint32_t tc_stop_counter = 0;
static uint32_t tc_stop_at = 0;
static uint32_t tc_stop_address = 0;
static uint32_t tc_stop_hook_handle = 0;
static uint32_t cond_func_address;
static uint32_t cond_func_hook_handle = 0;


void tc_modname(Monitor *mon, const QDict *qdict)
{
  modname_set(qdict_get_str(qdict, "modulename"));
  tracing_start_condition = 0;
}

void tc_address_hook(void *opaque)
{
  if (decaf_plugin->monitored_cr3 == cpu_single_env->cr[3]) {
    tracing_start_condition = 1;
    /* remove the hook */
    hookapi_remove_hook(cond_func_hook_handle);
   }

   return;
}

void tc_address(Monitor *mon, const QDict *qdict)
{
  int address = qdict_get_int(qdict, "codeaddress");

  /* Check if there is a conflict with conf_trace_only_after_first_taint */
  if (conf_trace_only_after_first_taint) {
    monitor_printf(default_mon, "tc_address_start conflicts with "
      "conf_trace_only_after_first_taint\n"
      "Disabling conf_trace_only_after_first_taint\n");
    conf_trace_only_after_first_taint = 0;
  }
  /* add a hook at address */
  tracing_start_condition = 0;
  cond_func_hook_handle = hookapi_hook_function(0, address, 0, tc_address_hook,
                              NULL, 0);
  cond_func_address = address;
}

void tc_address_start_hook(void *opaque)
{
  monitor_printf(default_mon, "tc_address_start_hook(*) called\n");
  if ((tracing_kernel_all() ||
    (decaf_plugin->monitored_cr3 == cpu_single_env->cr[3])) &&
    (tc_start_counter++ == tc_start_at))
  {
    tracing_start_condition = 1;
    tc_stop_counter = 0; // reset the tc_stop_counter at the execution saving
    /* remove the hook */
    hookapi_remove_hook(cond_func_hook_handle);
  }

  return;
}

void tc_address_start(Monitor *mon, const QDict *qdict)
{
  uint32_t address, at_counter;
  address = qdict_get_int(qdict, "codeaddress");
  at_counter = qdict_get_int(qdict, "timehit");

  /* Check if there is a conflict with conf_trace_only_after_first_taint */
  if (conf_trace_only_after_first_taint) {
    monitor_printf(mon, "tc_address_start conflicts with "
      "conf_trace_only_after_first_taint\n"
      "Disabling conf_trace_only_after_first_taint\n");
    conf_trace_only_after_first_taint = 0;
  }
  /* add a hook at address */
  tracing_start_condition = 0;
  tc_start_counter = 0;
  tc_start_at = at_counter;
  cond_func_hook_handle = hookapi_hook_function(0, address, 0,
                            tc_address_start_hook, NULL, 0);
  cond_func_address = address;
}

void tc_address_stop_hook(void *opaque)
{
  monitor_printf(default_mon, "tc_address_stop_hook(*) called\n");
  if ((tracing_kernel_all() ||
    (decaf_plugin->monitored_cr3 == cpu_single_env->cr[3])) &&
    (tc_stop_counter++ == tc_stop_at))
  {
    tracing_start_condition = 0;
    /* Properly call tracing_stop to stop tracing and
       perform other related operations (such as saving
       the state file) */
    tracing_stop();
    /* remove the hook */
    hookapi_remove_hook(tc_stop_hook_handle);
  }

  return;
}

void tc_address_stop(Monitor *mon, const QDict *qdict) 
{
  uint32_t address, at_counter;
  address = qdict_get_int(qdict, "codeaddress");
  at_counter = qdict_get_int(qdict, "timehit");

  /* add a hook at address */
  tc_stop_counter = 0;
  tc_stop_at = at_counter;
  tc_stop_hook_handle = hookapi_hook_function(0, address, 0,
                          tc_address_stop_hook, NULL, 0);
  tc_stop_address = address;
}

