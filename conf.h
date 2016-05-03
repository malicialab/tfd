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

#ifndef _CONF_H_
#define _CONF_H_
#include "tfd.h"
/* llconf */
#include <llconf/modules.h>
#include <llconf/ini.h>
#include <llconf/nodes.h>
#include <llconf/entry.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* External Variables */
extern int conf_trace_only_after_first_taint;
extern int conf_write_ops_at_insn_end;
extern int conf_save_state_at_trace_start;
extern int conf_save_state_at_trace_stop;
extern int tracing_table_lookup;
extern char hook_dirname[256];
extern char hook_plugins_filename[256];
extern char ini_main_default_filename[256];


/* Functions */
int check_ini(const char *path_ini);
void print_conf_vars(void);

void set_ignore_dns(Monitor *mon, const QDict *qdict);
int tracing_ignore_dns(void);

void set_tainted_only(Monitor *mon, const QDict *qdict);
int tracing_tainted_only(void);

void set_single_thread_only(Monitor *mon, const QDict *qdict);
int tracing_single_thread_only(void);

void set_kernel_all(Monitor *mon, const QDict *qdict);
int tracing_kernel_all(void);

void set_kernel_tainted(Monitor *mon, const QDict *qdict);
int tracing_kernel_tainted(void);

void set_kernel_partial(Monitor *mon, const QDict *qdict);
int tracing_kernel_partial(void);

int  tracing_kernel(void);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif // _CONF_H_

