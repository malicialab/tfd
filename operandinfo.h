/* 
 *  functionality to update instruction operands
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

#ifndef _OPERANDINFO_H_
#define _OPERANDINFO_H_
#ifdef TRACE_VERSION_50
#include "trace50.h"
#else
#include "trace.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void set_operand_taint(CPUState* env, OperandVal *op);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _OPERANDINFO_H_
