/* 
 *  main plugin function
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

#ifndef _TFD_H_
#define _TFD_H_

#include <stdio.h>
#include <inttypes.h>
#include <sys/user.h>
#ifdef TRACE_VERSION_50
#include "trace50.h"
#else
#include "trace.h"
#endif

/* Some configuration options that we don't foresee people to change 
 * Thus, they are not part of the ini configuration file */
#define PRINT_FUNCTION_MAP 1


/* Exit codes */
#define EXIT_ERROR -1
#define EXIT_NORMAL 1
#define EXIT_KILL_SIGNAL 13
#define EXIT_KILL_MSG 13
#define EXIT_DETECT_TAINTEIP 21
#define EXIT_DETECT_EXCEPTION 22
#define EXIT_DETECT_NULLPTR 23
#define EXIT_DETECT_PROCESSEXIT 24

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* External Variables */
extern FILE *tracelog;        // Trace file handle
extern FILE *tracenetlog;     // Network file handle
extern FILE *tracehooklog;    // Hook file handle
extern FILE *alloclog;        // Allocation log handle
extern uint32_t tracepid;     // PID of traced process
extern uint32_t tracecr3;     // CR3 of traced process
extern EntryHeader eh;        // Current instruction information
extern uint32_t current_tid;  // Current thread id
extern char *tracename_p;     // Trace filename
extern uint32_t insn_tainted; // Whether current instruction is tainted
extern int skip_decode_address; // If non-zero, instruction decoding is skipped
extern int skip_trace_write;  // If non-zero, instructions not written to trace


/* Functions */
int tracing_start(uint32_t pid, const char *filename); // Start tracing
void tracing_stop(void); // Stop tracing
void tracing_clean_exit(int exitcode); // Cleanly exit emulator

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _TFD_H_
