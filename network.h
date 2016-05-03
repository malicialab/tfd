/* 
 *  network filter
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

#ifndef _NETWORK_H_
#define _NETWORK_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* Functions */
void do_taint_nic(Monitor *mon, const QDict *qdict);
void do_taint_nic_internal(int state);
void print_nic_filter (void);
int update_nic_filter (const char *filter_str, const char *value_str);
void tracing_nic_recv(DECAF_Callback_Params* params);
void tracing_nic_send(DECAF_Callback_Params* params);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _NETWORK_H_

