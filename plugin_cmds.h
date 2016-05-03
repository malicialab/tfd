/* 
 *  plugin monitor commands 
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

/* Load a configuration file */
{ 
  .name = "load_config", 
  .args_type = "configuration_filepath:F", 
  .mhandler.cmd = do_load_config,
  .params = "configuration_filepath", 
  .help = "load configuration info from given file"
},

/* Commands related to traces */
{ 
  .name = "trace",
  .args_type = "pid:i,filepath:F", 
  .mhandler.cmd = do_tracing,
  .params = "pid filepath",
  .help = "save the execution trace of a process into the specified file"
},
{ 
  .name = "tracebyname",
  .args_type = "name:s,filepath:F", 
  .mhandler.cmd = do_tracing_by_name,
  .params = "name filepath",
  .help = "save the execution trace of a process into the specified file"
},
{ 
  .name = "trace_child", 
  .args_type = "name:s,filepath:F",
  .mhandler.cmd = do_tracing_child,
  .params = "name filepath",
  .help = "save the execution trace of the first child of given process into the specified file"
},
{
  .name = "trace_stop", 
  .args_type = "", 
  .mhandler.info = do_tracing_stop,
  .params = "", 
  .help = "stop tracing current process(es)"
},
{ 
  .name = "trace_writing", 
  .args_type = "on|off:s", 
  .mhandler.cmd = set_trace_writing,
  .params = "<on|off>",
  .help = "turn on/off writing to the execution trace"
},

/* Commands to start trace at different conditions */
{ 
  .name = "tc_modname", 
  .args_type = "modulename:s", 
  .mhandler.cmd = tc_modname,
  .params = "modulename", 
  .help = "start saving execution trace upon entering the specified module"
},
{ 
  .name = "tc_address", 
  .args_type = "codeaddress:i", 
  .mhandler.cmd = tc_address,
  .params = "codeaddress", 
  .help = "start saving execution trace upon reaching the specified virtual address"
},
{
  .name = "tc_address_start", 
  .args_type = "codeaddress:i,timehit:i", 
  .mhandler.cmd = tc_address_start,
  .params = "codeaddress timehit", 
  .help = "start saving execution trace upon reaching the specified virtual address for the (timehit+1)th times since the call of this tc_address_start command"
},
{ 
  .name = "tc_address_stop", 
  .args_type = "codeaddress:i,timehit:i", 
  .mhandler.cmd = tc_address_stop,
  .params = "codeaddress timehit", 
  .help = "stop saving execution trace upon reaching the specified virtual address for the (timehit+1)th times since the storing of execution trace"
},

/* Commands to determine what to include in trace */
{
  .name = "filter_kernel_all", 
  .args_type = "state:i", 
  .mhandler.cmd = set_kernel_all,
  .params = "state", 
  .help = "set flag to trace all kernel instructions in addition to user instructions"
},
{ 
  .name = "filter_kernel_partial", 
  .args_type = "state:i", 
  .mhandler.cmd = set_kernel_partial,
  .params = "state", 
  .help = "set flag to trace kernel instructions that modify user space memory"
},
{
  .name = "filter_single_thread_only",
  .args_type = "state:i",
  .mhandler.cmd = set_single_thread_only,
  .params = "state",
  .help = "set flag to trace only instructions from the same thread as the first instruction"
},

/* Record process state */
{
  .name = "save_state", 
  .args_type = "pid:i,address:i,filepath:s", 
  .mhandler.cmd = do_save_state,
  .params = "pid address filepath",
  .help = "save the state (register and memory) of a process when its execution hits the specified address (address needs to be the first address in a basic block)"
},

/* Load hooks */
{
  .name = "load_hooks", 
  .args_type = "hooks_dirname:F,plugins_filepath:F", 
  .mhandler.cmd = do_load_hooks,
  .params = "hooks_dirname  plugins_filepath",
  .help = "load hooks from given hook directory and plugins file"
},

/* Unload hooks */
{
  .name = "unload_hooks",
  .args_type = "",
  .mhandler.cmd = do_unload_hooks,
  .params = "",
  .help = "unload hooks"
},

/* Detect error conditions */
{ 
  .name = "detect", 
  .args_type = "condition:s,action:s", 
  .mhandler.cmd = set_detect_action,
  .params = "condition action",
  .help = "Set given action to error detection condition. Valid conditions: " DETECT_VALID_DETECTIONS_STR "Valid actions: " DETECT_VALID_ACTIONS_STR 
},


/************************** Taint-related commands ************************/
#ifdef TAINT_ENABLED
// Taint network
{
  .name = "taint_nic",
  .args_type = "state:i",
  .mhandler.cmd = do_taint_nic,
  .params = "state",
  .help = "set the network input to be tainted or not"
},
{
  .name = "taint_nic_filter",
  .args_type = "type:s,value:s",
  .mhandler.cmd = (void (*)())update_nic_filter,
  .params = "<clear|proto|sport|dport|src|dst> value",
  .help = "Update filter for tainting NIC"
},
{
  .name = "ignore_dns",
  .args_type = "state:i",
  .mhandler.cmd = set_ignore_dns,
  .params = "state",
  .help = "set flag to ignore received DNS packets"
},
{
  .name = "filter_tainted_only",
  .args_type = "state:i",
  .mhandler.cmd = set_tainted_only,
  .params = "state",
  .help = "set flag to trace only tainted instructions"
},
{
  .name = "filter_kernel_tainted",
  .args_type = "state:i",
  .mhandler.cmd = set_kernel_tainted,
  .params = "state",
  .help = "set flag to trace tainted kernel instructions in addition to user instructions"
},
// Taint keystroke
{
  .name = "taint_sendkey",
  .args_type = "key:s",
  .mhandler.cmd = do_taint_sendkey,
  .params = "key",
  .help = "send a tainted key to the guest system"
},
#endif // #ifdef TAINT_ENABLED

