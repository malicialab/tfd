/* 
 *  hooks for networking functions
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

#ifndef _GROUP_PROC_H_
#define _GROUP_PROC_H_

void NtCreateProcess_call(void *opaque);
void NtCreateProcess_ret(void *opaque);
void NtQueryInformationProcess_call(void *opaque);
void NtQueryInformationProcess_ret(void *opaque);
void CloseHandle_call(void *opaque);
void CloseHandle_ret(void *opaque);

#endif // #ifndef _GROUP_PROC_H_

