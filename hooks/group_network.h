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

#ifndef _GROUP_NETWORK_H_
#define _GROUP_NETWORK_H_

void send_call(void *opaque);
void send_ret(void *opaque);
void sendto_call(void *opaque);
void sendto_ret(void *opaque);
void wsasend_call(void *opaque);
void wsasend_ret(void *opaque);
void wsasenddisconnect_call(void *opaque);
void wsasenddisconnect_ret(void *opaque);
void transmitfile_call(void *opaque);
void transmitfile_ret(void *opaque);
void bind_call(void *opaque);
void bind_ret(void *opaque);
void connect_call(void *opaque);
void connect_ret(void *opaque);
void getsockname_call(void *opaque);
void getsockname_ret(void *opaque);
void recv_call(void *opaque);
void recv_ret(void *opaque);
void recvfrom_call(void *opaque);
void recvfrom_ret(void *opaque);
void InternetOpenA_call(void *opaque);
void InternetOpenA_ret(void *opaque);
void InternetOpenUrlA_call(void *opaque);
void InternetOpenUrlA_ret(void *opaque);
void InternetReadFile_call(void *opaque);
void InternetReadFile_ret(void *opaque);
void socket_call(void *opaque);
void socket_ret(void *opaque);

#endif // #ifndef _GROUP_NETWORK_H_

