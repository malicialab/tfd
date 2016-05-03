/* 
 *  functionality to skip nested hooks
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

#ifndef _SKIP_TAINT_H_
#define _SKIP_TAINT_H_

#include <stdio.h>
#include <inttypes.h>
#include "shared/vmi_c_wrapper.h"

#define MAX_NUMBER_OF_THREADS 16

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* If the skip_taint value is !=0 for a thread,
    the taint still propagates, but the operands for instructions from 
    that thread will have empty taint records in the execution trace 
    (i.e., the taint is tracked but not shown) */

/* Removes all threads from the skip taint array */
extern void init_st(void);

/* Clears the skip taint value for the given thread */
extern void reset_st(uint32_t tid);

/* Clears the skip taint value for the current thread */
extern void reset_cst(void);

/* Get the skip taint value for the given thread
   If [tid] is -1 then it checks for the current thread 
   If [tid] is unknown, it returns 0 */
extern int get_st(uint32_t tid);

/* Get the skip taint for the current thread
   If current thread is unknown, it returns 0 */
extern int get_cst(void);

/* Increment the skip taint value for the given thread
   Returns the skip taint value after incrementing it
   If [tid] is -1 then it increments it for the current thread 
   If [tid] is unknown, it adds an entry for this thread to the table */
extern int inc_st(uint32_t tid);

/* Increment the skip taint value for the current thread
   Returns the skip taint value after incrementing it
   If the current thread is unknown, it adds an entry for it to the table */
extern int inc_cst(void);

/* Decrement the skip taint value for the given thread
   Returns the skip taint value after decrementing it
   If [tid] is -1 then it decrements it for the current thread
   If [tid] is unknown, it adds an entry for this thread to the table */
extern int dec_st(uint32_t tid);

/* Decrement the skip taint value for the current thread
   Returns the skip taint value after decrementing it
   If the current thread is unknown, it adds an entry for it to the table */
extern int dec_cst(void);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif // _SKIP_TAINT_H_

