/* 
 *  functionality to split operands into read and written
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

#ifndef _READWRITE_H_
#define _READWRITE_H_
#ifdef TRACE_VERSION_50
#include "trace50.h"
#else
#include "trace.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void update_written_operands (CPUState* env, EntryHeader *eh);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _READWRITE_H_

