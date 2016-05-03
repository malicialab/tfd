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

#ifndef _CONDITIONS_H_
#define _CONDITIONS_H_

#include <inttypes.h>
#include "DECAF_main.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

char cond_procname[64];
char cond_modulename[64];
int (*comparestring)(const char *, const char*);

/* External Variables */
extern int tracing_start_condition;

/* Functions */

static inline void procname_clear()
{
  cond_procname[0] = 0;
}

static inline char *procname_get()
{
  return cond_procname;
}

static inline void procname_set(const char *name)
{
  strncpy(cond_procname, name, sizeof(cond_procname));
}

static inline int procname_match(const char *name)
{
  return (strcmp(cond_procname, name) == 0);
}

static inline int procname_is_set()
{
  return (cond_procname[0] != 0);
}

static inline void modname_clear()
{
  cond_modulename[0] = 0;
}

static inline char *modname_get()
{
  return cond_modulename;
}

static inline void modname_set(const char *name)
{
  strncpy(cond_modulename, name, sizeof(cond_modulename));
}

static inline int modname_match(const char *name)
{
  return (comparestring(cond_modulename, name) == 0);
}

static inline int modname_is_set()
{
  return (cond_modulename[0] != 0);
}

extern void tc_modname(Monitor *mon, const QDict *qdict);
extern void tc_address(Monitor *mon, const QDict *qdict);
extern void tc_address_start(Monitor *mon, const QDict *qdict);
extern void tc_address_stop(Monitor *mon, const QDict *qdict);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _CONDITIONS_H_

