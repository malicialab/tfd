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

#ifndef _ERRDET_H_
#define _ERRDET_H_

#include "shared/DECAF_main.h"
#include "vmi_callback.h"

/* Error detection
 * TFD has some support for detecting errors in programs
 * The function enable_detection takes as input a mask in which each bit 
 *   represents a different technique being used to detect errors.
 * The following techniques are defined:
 *   1) DETECT_COND_TAINTEIP
 *     Instruction counter (EIP) is tainted
 *     Usually gives too many false positives
 *   2) DETECT_COND_EXCEPTION
 *     Invalid memory access exception (Windows only)
 *   3) DETECT_COND_NULLPTR 
 *     Program is dereferencing a null pointer
 *   4) DETECT_COND_PROCESSEXIT 
 *     Process being traced exits
 *     Useful with programs that should not exit like network servers
 *
 * The default action for all detection methods is to stop the trace and
 *   exit the emulator with a return value specific to the condition met
 *
 * Multiple techniques can be used simultaneously by constructing a mask 
 *   that AND's different macros 
 *
 * There is also to macros to activate or deactivate all techniques:
 *   DETECT_COND_NONE, DETECT_COND_ALL
 *
 */
#define DETECT_COND_TAINTEIP 1U  // Instruction counter (EIP) is tainted
#define DETECT_COND_EXCEPTION 2U // Invalid memory access exception (Windows)
#define DETECT_COND_NULLPTR 4U   // Program is dereferencing a null pointer
#define DETECT_COND_PROCESSEXIT 8U  // Process being traced exits
                                    // (servers that should not exit)

/* Detect condition shortcuts */
#define DETECT_COND_NONE 0U
#define DETECT_COND_ALL ~0U

/* String macros for valid detections and actions */
#define DETECT_VALID_DETECTIONS_STR "exception, nullptr, processexit, taintedeip, all"
#define DETECT_VALID_ACTIONS_STR "none, stoptracing, stopvm, terminate"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* Functions */
extern void set_detect_action(Monitor *mon, const QDict *qdict);
extern void set_detect_action_internal(const char* condition_str, 
                                        const char* action_str);
extern void tainteip_detection(uint8_t *record);
extern void procexit_detection(VMI_Callback_Params* params);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _ERRDET_H_

