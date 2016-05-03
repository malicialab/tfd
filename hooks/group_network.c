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

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "group_hook_helper.h"
#include "group_network.h"
#include "tfd.h"


#define LOCAL_DEBUG 1
#define WRITE if (LOCAL_DEBUG) write_log

#define RECV_BYTES_ORIGIN 1100
#define RECV_DATA_ORIGIN 1101
#define RECVFROM_BYTES_ORIGIN 1102
#define RECVFROM_DATA_ORIGIN 1103
#define RECVFROM_ADDR_ORIGIN 1104
#define GETSOCKNAME_ORIGIN 1105
#define INTERNETREADFILE_BYTES_ORIGIN 1106
#define INTERNETREADFILE_DATA_ORIGIN 1107

/* Whether we want to stop the trace after sending */
#define STOP_TRACE_AFTER_SEND 0

/* Whether we want to stop the trace after connecting */
#define STOP_TRACE_AFTER_CONNECT 0

/* Whether we want to stop the trace after opening a connection */
#define STOP_TRACE_AFTER_OPEN 0

/* Whether we want to start the trace after opening a connection */
#define START_TRACE_AFTER_OPEN 0


hook_t hooks[] =
{
  /* send */
  {"ws2_32.dll", "send", send_call, 0},
  {"ws2_32.dll", "sendto", sendto_call, 0},
  {"ws2_32.dll", "WSASend", wsasend_call, 0},
  {"ws2_32.dll", "WSASendTo", wsasend_call, 0},
  {"ws2_32.dll", "WSASendDisconnect", wsasenddisconnect_call, 0},
  //{"?.dll", "WSASendMsg", wsasendmsg_call, 0},
  {"wsock32.dll", "send", send_call, 0},
  {"wsock32.dll", "sendto", sendto_call, 0},
  {"wsock32.dll", "TransmitFile", transmitfile_call, 0},
  //{"?.dll", "TransmitPackets", transmitpackets_call, 0},

  /* recv */
  {"ws2_32.dll", "recv", recv_call, 0},
  {"ws2_32.dll", "recvfrom", recvfrom_call, 0},

  /* bind */
  {"ws2_32.dll", "bind", bind_call, 0},
  {"wsock32.dll", "bind", bind_call, 0},

  /* connect */
  {"ws2_32.dll", "connect", connect_call, 0},
  {"wsock32.dll", "connect", connect_call, 0},

  /* getsockname */
  {"ws2_32.dll", "getsockname", getsockname_call, 0},
  {"wsock32.dll", "getsockname", getsockname_call, 0},

  /* socket */
  {"ws2_32.dll", "socket", socket_call, 0},
  {"wsock32.dll", "socket", socket_call, 0},

  /* InternetOpen */
  {"wininet.dll", "InternetOpenA", InternetOpenA_call, 0},

  /* InternetOpenUrl */
  {"wininet.dll", "InternetOpenUrlA", InternetOpenUrlA_call, 0},

  /* InternetReadFile */
  {"wininet.dll", "InternetReadFile", InternetReadFile_call, 0},
};

int local_num_funs = (sizeof(hooks)/sizeof(hook_t));


void internal_init_plugin()
{
  //skip_trace_write = 1;
  initialize_plugin(hooks,local_num_funs);
}


void log_data(uint32_t eip, uint32_t fd, int num_addr, uint32_t addr[],
  int len[],int num_elems)
{
  int read_err = 0;
  int i = 0;
  int j = 0;
  unsigned char data[512];
  char mod_name[512];
  char fun_name[512];

  //memset ((void *)data, 0, 512);

  //WRITE("tracenetlog", "Sent data using function @ EIP: %08x\n", eip);
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);
  WRITE("tracenetlog", "Sent data using function %s::%s\n",
      mod_name, fun_name,eip);
  WRITE("tracenetlog", "\tInstruction #: %d\n", tstats.insn_counter_traced);
  WRITE("tracenetlog", "\tFD: %d\n", fd);
  WRITE("tracenetlog", "\tNum_Addr: %d\n", num_addr);

  for (i = 0; i < num_addr; i++) {
    WRITE("tracenetlog", "\tADDR: %08x LEN: %d\n", addr[i], len[i]);


    /* Read the network data buffer */
    int len2 = 0;
    if (len[i] > 512) len2 = 512; else len2 = len[i];
    read_err = read_mem(addr[i], len2, data);
    if (read_err) {
      WRITE ("tracenetlog", "\tCould not read memory\n");
      return;
    }

#ifdef TAINT_ENABLED
    /* Read the taint */
    uint32_t buf_taint_arr[1024][2];
    int buf_taint = get_string_taint(addr[i], buf_taint_arr, len2);
    if (buf_taint) {
      print_string_taint(tracenetlog, buf_taint_arr, len2, 8);
    }
#endif // #ifdef TAINT_ENABLED

    /* Print the network data */
    WRITE ("tracenetlog", "\tDATA: 0x");
    for (j = 0; j < len2; j++) {
      WRITE ("tracenetlog","%02x", data[j]);
    }
    WRITE ("tracenetlog","\n");
  }
}

void send_call(void *opaque)
{
  uint32_t eip, fd;
  int len[5];
  uint32_t addr[5];
  uint32_t stack[7]; // All parameters are 4-byte long
  int num_addr = 0;
  int read_err = 0;

    /* If not tracing yet, return */
    if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /* Clear buffers */
  //memset ((void *)len, 0, sizeof(len));
  //memset ((void *)addr, 0, sizeof(addr));


  /*
    BUF INDEX -> PARAMETER
    send
    0 -> return address
    1 -> socket id
    2 -> buffer pointer
    3 -> length
    4 -> flags

  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);

  num_addr = 1;
  fd = stack[1];
  len[0] = stack[3] * 1;
  addr[0] = stack[2];


  log_data(eip,fd,num_addr,addr,len,5);

#if STOP_TRACE_AFTER_SEND != 0
  tracing_stop();
#endif

  return;
}

void sendto_call(void *opaque)
{
  uint32_t eip, fd;
  int len[5];
  uint32_t addr[5];
  uint32_t stack[7]; // All parameters are 4-byte long
  int num_addr = 0;
  int read_err = 0;
  char addrStr[INET_ADDRSTRLEN];
  struct sockaddr_in addrData;
  uint32_t address_buf;
  uint32_t address_len;

    /* If not tracing yet, return */
    if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /* Clear buffers */
  //memset ((void *)len, 0, sizeof(len));
  //memset ((void *)addr, 0, sizeof(addr));


  /*
    BUF INDEX -> PARAMETER
    sendto
    0 -> return address
    1 -> socket id
    2 -> buffer pointer
    3 -> length
    4 -> flags
    5 -> to
    6 -> tolen

  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);

  num_addr = 1;
  fd = stack[1];
  len[0] = stack[3] * 1;
  addr[0] = stack[2];


  log_data(eip,fd,num_addr,addr,len,5);

  /* Read the address structure */
  address_buf = stack[5];
  address_len = stack[6];
  WRITE("tracenetlog","Address @ 0x%lx (%d bytes)\n", address_buf,
    address_len);
  read_err = read_mem(address_buf, address_len, (unsigned char*)&addrData);
  if (!read_err) {
    /* Print the address structure */
    WRITE ("tracenetlog","\tFamily: %d\n",addrData.sin_family);
    WRITE ("tracenetlog","\tPort: %u\n",ntohs(addrData.sin_port));
    inet_ntop(AF_INET, &addrData.sin_addr, addrStr, sizeof(addrStr));
    WRITE ("tracenetlog","\tAddress: %s\n",addrStr);

#ifdef TAINT_ENABLED
    /* Check if address and port are tainted */
    taint_record_t record[6];
    uint64_t taint = get_mem_taint(address_buf+2, 6, (uint8_t *)&record);
    if(taint) {
      WRITE("tracenetlog","\tTaint: %08Lx\n", taint);
      /* Additionally print all taint records if desired
      int i = 0, j = 0;
      for (i = 0; i < 6; i++) {
        WRITE("plugin","Rec %d NumRec: %u TP: %u\n\t",
          i, record[i].numRecords,record[i].taintPropag);
        for (j = 0; j < record[i].numRecords; j++) {
          WRITE("plugin","(%u,%u,%u) ",
            record[i].taintBytes[j].source, record[i].taintBytes[j].origin,
            record[i].taintBytes[j].offset);
        }
        WRITE("plugin","\n");
      }
      */
    }
    else {
      WRITE("tracenetlog","\tNot tainted\n");
    }
#endif // #ifdef TAINT_ENABLED
  }
  else {
    WRITE("tracenetlog","\tCould not read address structure\n");
  }

#if STOP_TRACE_AFTER_SEND != 0
  tracing_stop();
#endif

  return;
}

void wsasend_call(void *opaque)
{
  uint32_t eip, fd;
  int len[5];
  uint32_t addr[5];
  uint32_t stack[7]; // All parameters are 4-byte long
  int i = 0;
  int num_addr = 0;
  int read_err = 0;
  int tmp_len = 0;
  int tmp_addr = 0;
  uint32_t addData[10];

    /* If not tracing yet, return */
    if (tracepid == 0) return;


  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /* Clear buffers */
  //memset ((void *)len, 0, sizeof(len));
  //memset ((void *)addr, 0, sizeof(addr));
  //memset ((void *)addData, 0, sizeof(addData));


  /*
    BUF INDEX -> PARAMETER
    WSASend, WSASendTo
    0 -> return address
    1 -> socket id
    2 -> pointer to array of WSABUF structures
    3 -> number of WSABUF structures
    4 -> OUT
    5 -> flags
    6 -> to (WSASendTo) / IGNORE (WSASend)
    7 -> tolen (WSASendTo) / IGNORE (WSASend)
    8 -> IGNORE (WSASendTo)
    9 -> IGNORE (WSASendTo)

  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);


  /* Need to extract real address and length from WSABuf structs */
  fd = stack[1];
  num_addr = stack[3] * 1;
  tmp_len = num_addr*2;
  tmp_addr = stack[2];
  memset (addData, 0, 40);
  if (tmp_len > 40) tmp_len = 40;
  read_err = read_mem(tmp_addr, tmp_len*4, (uint8_t *) addData);
  if (!read_err) {
    for (i = 0; i < num_addr; i++) {
      len[i] = addData[i*2] * 1;
      addr[i] = addData[i*2+1];
    }
  }
  else {
    num_addr = 1;
    len[0] = -1;
    addr[0] = -1;
  }


  /* Print the complete buffer
  term_printf ("BUF: \n");
  for (i = 0; i < num_params + 1; i++) {
    term_printf ("\t%02d: 0x%08x\n", i, stack[i]);
  }
  */

  log_data(eip,fd,num_addr,addr,len,5);

#if STOP_TRACE_AFTER_SEND != 0
  tracing_stop();
#endif

  return;
}

void transmitfile_call(void *opaque)
{
  uint32_t eip, fd;
  int len[5];
  uint32_t addr[5];
  uint32_t stack[7]; // All parameters are 4-byte long
  int num_addr = 0;
  int read_err = 0;

    /* If not tracing yet, return */
    if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /* Clear buffers */
  //memset ((void *)len, 0, sizeof(len));
  //memset ((void *)addr, 0, sizeof(addr));


  /*
    BUF INDEX -> PARAMETER
    TransmitFile
    0 -> return address
    1 -> socket id
    2 -> file id
    3 -> number of bytes in the file to transmit (zero = all file)
    4 -> size in bytes of each block of data sent in each send operation
    5 -> IGNORE
    6 -> pointer to array of WSABUF structures
    7 -> flags

  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);

  num_addr = 1;
  fd = stack[1];
  len[0] = stack[3] * 1;
  addr[0] = -1; // file


  /* Print the complete buffer
  term_printf ("BUF: \n");
  for (i = 0; i < num_params + 1; i++) {
    term_printf ("\t%02d: 0x%08x\n", i, stack[i]);
  }
  */

  log_data(eip,fd,num_addr,addr,len,5);

#if STOP_TRACE_AFTER_SEND != 0
  tracing_stop();
#endif

  return;
}

void wsasenddisconnect_call(void *opaque)
{
  uint32_t eip, fd;
  int len[5];
  uint32_t addr[5];
  uint32_t stack[7]; // All parameters are 4-byte long
  int num_addr = 0;
  int read_err = 0;
  int tmp_len = 0;
  int tmp_addr = 0;
  uint32_t addData[10];

    /* If not tracing yet, return */
    if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /* Clear buffers */
  //memset ((void *)len, 0, sizeof(len));
  //memset ((void *)addr, 0, sizeof(addr));
  //memset ((void *)addData, 0, sizeof(addData));

  /*
    BUF INDEX -> PARAMETER
    send, sendto
    WSASendDisconnect
    0 -> return address
    1 -> socket id
    2 -> pointer to WSABUF structure

  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);

  num_addr = 1;
  fd = stack[1];
  /* Need to extract real address and length from WSABuf struct */
  tmp_len = num_addr*2;
  tmp_addr = stack[1];
  memset (addData, 0, 40);
  if (tmp_len > 40) tmp_len = 40;
  read_err = read_mem(tmp_addr, tmp_len*4, (uint8_t *) addData);
  if (!read_err) {
      len[0] = addData[0] * 1;
      addr[0] = addData[1];
  }
  else {
    len[0] = -1;
    addr[0] = -1;
  }


  /* Print the complete buffer
  term_printf ("BUF: \n");
  for (i = 0; i < num_params + 1; i++) {
    term_printf ("\t%02d: 0x%08x\n", i, stack[i]);
  }
  */

  log_data(eip,fd,num_addr,addr,len,5);

#if STOP_TRACE_AFTER_SEND != 0
  tracing_stop();
#endif

  return;
}

void bind_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[7]; // All parameters are 4-byte long
  uint32_t sock_fd;
  uint32_t buf_start;
  uint32_t address_len;
  struct sockaddr_in addrData;
  int read_err = 0;
  char addrStr[INET_ADDRSTRLEN];

    /* If not tracing yet, return */
    if (tracepid == 0) return;


  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
    BUF INDEX -> PARAMETER
    bind, sendto
    int bind(SOCKET s,const struct sockaddr* name,int namelen);
    0 -> return address
    1 -> IN socket descriptor
    2 -> IN Address to assign to the socket from the sockaddr structure.
    3 -> IN Length of the value in the name parameter, in bytes

  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog","Binding socket using function %s::%s\n",
      mod_name, fun_name,eip);

  /* Read the address structure */
  sock_fd = stack[1];
  buf_start = stack[2];
  address_len = stack[3];
  WRITE("tracenetlog","\tFD: %u Buf_start: 0x%08x Len: %u\n",
    sock_fd, buf_start, address_len);
  read_err = read_mem(buf_start, address_len, (unsigned char*)&addrData);
  if (!read_err) {
    /* Print the address structure */
    WRITE ("tracenetlog","\tFamily: %d\n",addrData.sin_family);
    WRITE ("tracenetlog","\tPort: %u\n",ntohs(addrData.sin_port));
    inet_ntop(AF_INET, &addrData.sin_addr, addrStr, sizeof(addrStr));
    WRITE ("tracenetlog","\tAddress: %s\n",addrStr);

#ifdef TAINT_ENABLED
    /* Check if address and port are tainted */
    taint_record_t record[6];
    uint64_t taint = get_mem_taint(buf_start+2, 6, (uint8_t *)&record);
    if(taint) {
      WRITE("tracenetlog","\tTaint: %08Lx\n", taint);
      /* Additionally print all taint records if desired
      int i = 0, j = 0;
      for (i = 0; i < 6; i++) {
        WRITE("plugin","Rec %d NumRec: %u TP: %u\n\t",
          i, record[i].numRecords,record[i].taintPropag);
        for (j = 0; j < record[i].numRecords; j++) {
          WRITE("plugin","(%u,%u,%u) ",
            record[i].taintBytes[j].source, record[i].taintBytes[j].origin,
            record[i].taintBytes[j].offset);
        }
        WRITE("plugin","\n");
      }
      */
    }
    else {
      WRITE("tracenetlog","\tNot tainted\n");
    }
#endif // #ifdef TAINT_ENABLED

  }
  else {
    WRITE("tracenetlog","\tCould not read address structure\n");
  }

  return;
}

void connect_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[7]; // All parameters are 4-byte long
  uint32_t sock_fd;
  uint32_t buf_start;
  uint32_t address_len;
  struct sockaddr_in addrData;
  int read_err = 0;
  char addrStr[INET_ADDRSTRLEN];

    /* If not tracing yet, return */
    if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
    BUF INDEX -> PARAMETER
    connect
    int connect(SOCKET s,const struct sockaddr* name,int namelen);
    0 -> return address
    1 -> IN socket descriptor
    2 -> IN Address structure with address to connect to
    3 -> IN Length of address structure, in bytes
  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog", "Connecting using function %s::%s\n",
      mod_name, fun_name,eip);
  //WRITE("tracenetlog","Connecting using function at EIP: 0x%08x\n",eip);

  /* Read the address structure */
  sock_fd = stack[1];
  buf_start = stack[2];
  address_len = stack[3];
  WRITE("tracenetlog","\tFD: %u Buf_start: 0x%08x Len: %u\n",
    sock_fd, buf_start, address_len);
  read_err = read_mem(buf_start, address_len, (unsigned char*)&addrData);
  if (!read_err) {
    /* Print the address structure */
    WRITE ("tracenetlog","\tFamily: %d\n",addrData.sin_family);
    WRITE ("tracenetlog","\tPort: %u\n",ntohs(addrData.sin_port));
    inet_ntop(AF_INET, &addrData.sin_addr, addrStr, sizeof(addrStr));
    WRITE ("tracenetlog","\tAddress: %s\n",addrStr);

#ifdef TAINT_ENABLED
    /* Check if address and port are tainted */
    taint_record_t record[6];
    uint64_t taint = get_mem_taint(buf_start+2, 6, (uint8_t *)&record);
    if(taint) {
      WRITE("tracenetlog","\tTaint: %08Lx\n", taint);
      /* Additionally print all taint records if desired
      int i = 0, j = 0;
      for (i = 0; i < 6; i++) {
        WRITE("plugin","Rec %d NumRec: %u TP: %u\n\t",
          i, record[i].numRecords,record[i].taintPropag);
        for (j = 0; j < record[i].numRecords; j++) {
          WRITE("plugin","(%u,%u,%u) ",
            record[i].taintBytes[j].source, record[i].taintBytes[j].origin,
            record[i].taintBytes[j].offset);
        }
        WRITE("plugin","\n");
      }
      */
    }
    else {
      WRITE("tracenetlog","\tNot tainted\n");
    }
#endif // #ifdef TAINT_ENABLED
  }
  else {
    WRITE("tracenetlog","\tCould not read address structure\n");
  }

#if STOP_TRACE_AFTER_CONNECT != 0
  tracing_stop();
#endif

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t sd;
  uint32_t bufStart;
  uint32_t bufMaxLen;
  uint32_t bufLenPtr;
} getsockname_t;

void getsockname_call(void *opaque)
{
  uint32_t esp;
  uint32_t eip;
  uint32_t stack[7]; // All parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Read stack starting at ESP */
  esp = cpu_single_env->regs[R_ESP];
  read_err = DECAF_read_mem(NULL, esp, sizeof(stack), stack);
  if (read_err) return;

  /*
      BUF INDEX -> PARAMETER
      ws2_32.dll getsockname
      int getsockname(SOCKET s,struct sockaddr* name,int* namelen);
      0 -> return address
      1 -> IN socket descriptor
      2 -> OUT Address structure with socket information
      3 -> IN-OUT On call, size of the name buffer, in bytes.
        On return, size in bytes of the name parameter
  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  //WRITE("tracenetlog","Getting socket info using function at EIP: 0x%08x\n"
  //  "\tFD: %u BufStart: 0x%08x BufMaxLen: %d\n",eip,
  //    stack[1], stack[2], (int)stack[3]);
  WRITE("tracenetlog","Getting socket info using function %s::%s\n"
    "\tFD: %u BufStart: 0x%08x BufMaxLen: %d\n",
    mod_name, fun_name,stack[1],stack[2],(int)stack[3]);

  /* Store values needed by return hook */
  getsockname_t *s = malloc(sizeof(getsockname_t));
  if (s == NULL) return;
  s->eip = DECAF_getPC(cpu_single_env);
  s->sd = stack[1];
  s->bufStart = stack[2];
  s->bufMaxLen = stack[3];
  s->bufLenPtr = esp+12;

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], getsockname_ret, s,
    sizeof(getsockname_t));

  return;
}

void getsockname_ret(void *opaque)
{
  static int call_no = 0;
  static int offset  = 0;
  int read_err = 0;
  uint32_t bufRealLen = 0;
  getsockname_t *s = (getsockname_t *)opaque;
  struct sockaddr_in addrData;
  char addrStr[INET_ADDRSTRLEN];

  /* Remove return hook */
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> status */
  uint32_t eax = cpu_single_env->regs[R_EAX];
  if (eax != 0) return;

  /* Read size of address structure */
  read_err = read_mem(s->bufLenPtr, 4, (unsigned char*)&bufRealLen);
  if (!read_err) {
    WRITE ("tracenetlog","\tNumBytesWritten: %u\n",bufRealLen);
  }
  else {
    WRITE ("tracenetlog","\tCould not get number of bytes written\n");
    return;
  }

  /* Read the address structure */
  read_err = read_mem(s->bufStart, 16, (unsigned char*)&addrData);
  if (read_err) return;

  /* Print the address structure */
  inet_ntop(AF_INET, &addrData.sin_addr, addrStr, sizeof(addrStr));
  WRITE ("tracenetlog","\tFamily: %d Port: %u Address: %s\n",
   addrData.sin_family,ntohs(addrData.sin_port),addrStr);

#ifdef TAINT_ENABLED
  /* Taint address structure */
  if (bufRealLen > 0) {
    hook_taint_record_t tr;
    tr.source = TAINT_SOURCE_API_SOCK_INFO_IN;
    tr.origin = GETSOCKNAME_ORIGIN;
    tr.offset = offset;

    taint_mem(s->bufStart+2, 6, (void *)&tr);
  }
#endif //#ifdef TAINT_ENABLED

  offset += 6;
  ++call_no;

  if (s) free(s);

  return;
}

/*************************************************************************/

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t sd;
  uint32_t bufStart;
  uint32_t bufMaxLen;
  uint32_t flags;
} recv_t;

void recv_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[5]; // All parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
     int recv( IN SOCKET s, OUT char *buf, IN int len, IN int flags );

      0 -> return address
      1 -> IN The descriptor that identifies a connected socket
      2 -> OUT Pointer to the buffer to receive the incoming data
      3 -> IN Length, in bytes, of the buffer pointed to by buf
      4 -> IN Flags
  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog","Received data using function %s::%s\n",
    mod_name, fun_name);

  /* Store values needed by return hook */
  recv_t *s = malloc(sizeof(recv_t));
  if (s == NULL) return;
  s->eip = DECAF_getPC(cpu_single_env);
  s->sd = stack[1];
  s->bufStart = stack[2];
  s->bufMaxLen = stack[3];
  s->flags = stack[4];

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], recv_ret, s,
    sizeof(recv_t));

  return;
}

void recv_ret(void *opaque)
{
  static int call_no = 0;
  int read_err = 0;
  unsigned char data[1024];

  /* Remove return hook */
  recv_t *s = (recv_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> number of bytes received */
  uint32_t eax = cpu_single_env->regs[R_EAX];
  if (eax == 0xffffffff) return;

  /* Read the network data buffer */
  int len = (eax < 1024) ? eax : 1024;
  read_err = read_mem(s->bufStart, len, data);
  if (read_err) return;

  /* Log function info */
  WRITE("tracenetlog",
    "\tInstruction #: %d\n"
    "\tBytes received: %u FD:%u\n"
    "\tBufStart: 0x%08x BufMaxLen: %u\n"
    "\tFlags: 0x%x\n",
    tstats.insn_counter_traced, eax, s->sd, s->bufStart, 
    s->bufMaxLen, s->flags);

  /* Print the network data */
  WRITE ("tracenetlog", "\tDATA: 0x");
  unsigned int j;
  for (j = 0; j < len; j++) {
    WRITE ("tracenetlog","%02x", data[j]);
  }
  WRITE ("tracenetlog","\n");

#ifdef TAINT_ENABLED
  static int offset_bytes  = 0;
  static int offset_data  = 0;
  /* Taint the number of bytes received */
  hook_taint_record_t tr;
  tr.source = TAINT_SOURCE_API_SOCK_INFO_IN;
  tr.origin = RECV_BYTES_ORIGIN;
  tr.offset = offset_bytes;
  taint_reg(eax_reg, (void *)&tr);

  /* Taint the data received */
/*
  if (len > 0) {
    hook_taint_record_t tr2;
    tr2.source = TAINT_SOURCE_API_SOCK_INFO_IN;
    tr2.origin = RECV_DATA_ORIGIN;
    tr2.offset = offset_data;
    taint_mem(s->bufStart, eax, (void *)&tr2);
  }
*/

  offset_bytes += 4;
  offset_data += eax;
#endif // #ifdef TAINT_ENABLED
  ++call_no;

  if (s) free(s);

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t sd;
  uint32_t bufStart;
  uint32_t bufMaxLen;
  uint32_t flags;
  uint32_t from_ptr;
  uint32_t from_len;
} recvfrom_t;

void recvfrom_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[7]; // All parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
    int recvfrom( IN SOCKET s, OUT char *buf, IN int len, IN int flags,
      OUT struct sockaddr *from, IN-OUT int *fromlen);

      0 -> return address
      1 -> IN Descriptor identifying a bound socket
      2 -> OUT Pointer to the buffer to receive the incoming data
      3 -> IN Length, in bytes, of the buffer pointed to by buf
      4 -> IN Flags
      5 -> OUT An optional pointer to a buffer in a sockaddr structure
        that will hold the source address upon return
      6-> An optional pointer to the size, in bytes,
        of the buffer pointed to by the from parameter.
  */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog","Received data using function %s::%s\n",
    mod_name, fun_name);

  /* Store values needed by return hook */
  recvfrom_t *s = malloc(sizeof(recvfrom_t));
  if (s == NULL) return;
  s->eip = DECAF_getPC(cpu_single_env);
  s->sd = stack[1];
  s->bufStart = stack[2];
  s->bufMaxLen = stack[3];
  s->flags = stack[4];
  s->from_ptr = stack[5];
  s->from_len = stack[6];

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], recvfrom_ret, s,
    sizeof(recvfrom_t));

  return;
}

void recvfrom_ret(void *opaque)
{
  static int call_no = 0;
  //static int offset_addr  = 0;
  int read_err = 0;
  unsigned char data[1024];
  char addrStr[INET_ADDRSTRLEN];
  struct sockaddr_in addrData;
  int addrLen = 0;

  /* Remove return hook */
  recvfrom_t *s = (recvfrom_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> number of bytes received */
  uint32_t eax = cpu_single_env->regs[R_EAX];
  if (eax == 0xffffffff) return;

  /* Read the network data buffer */
  int len = (eax < 1024) ? eax : 1024;
  read_err = read_mem(s->bufStart, len, data);
  if (read_err) return;

  /* Log function info */
  WRITE("tracenetlog",
    "\tInstruction #: %d\n"
    "\tBytes received: %u FD:%u\n"
    "\tBufStart: 0x%08x BufMaxLen: %u\n"
    "\tFlags: 0x%x\n",
    tstats.insn_counter_traced, eax, s->sd, s->bufStart, 
    s->bufMaxLen, s->flags);

  /* Read the address structure */
  if (s->from_ptr != 0) {
    read_err = read_mem(s->from_len, 4, (unsigned char*)&addrLen);
    if (read_err) return;
    read_err = read_mem(s->from_ptr, addrLen, (unsigned char*)&addrData);
    if (read_err) return;
  }

  /* Print the address structure */
  inet_ntop(AF_INET, &addrData.sin_addr, addrStr, sizeof(addrStr));
  WRITE ("tracenetlog", "\tFamily: %d Port: %u Address: %s\n",
    addrData.sin_family,ntohs(addrData.sin_port),addrStr);

  /* Print the network data */
  WRITE ("tracenetlog", "\tDATA: 0x");
  unsigned int j;
  for (j = 0; j < len; j++) {
    WRITE ("tracenetlog","%02x", data[j]);
  }
  WRITE ("tracenetlog","\n");

#ifdef TAINT_ENABLED
  static int offset_bytes  = 0;
  static int offset_data  = 0;
  /* Taint the number of bytes received */
  hook_taint_record_t tr;
  tr.source = TAINT_SOURCE_API_SOCK_INFO_IN;
  tr.origin = RECVFROM_BYTES_ORIGIN;
  tr.offset = offset_bytes;
  taint_reg(eax_reg, (void *)&tr);

  /* Taint the data received */
/*
  if (len > 0) {
    hook_taint_record_t tr2;
    tr2.source = TAINT_SOURCE_API_SOCK_INFO_IN;
    tr2.origin = RECVFROM_DATA_ORIGIN;
    tr2.offset = offset_data;
    taint_mem(s->bufStart, eax, (void *)&tr2);
  }
*/

  /* Taint address structure */
/*
  if (s->from_ptr != 0) {
    hook_taint_record_t tr3;
    tr3.source = TAINT_SOURCE_API_SOCK_INFO_IN;
    tr3.origin = RECVFROM_ADDR_ORIGIN;
    tr3.offset = offset_addr;
    taint_mem(s->from_ptr, addrLen, (void *)&tr3);
    offset_addr += addrLen;
  }
*/

  offset_bytes += 4;
  offset_data += eax;
#endif // #ifdef TAINT_ENABLED

  ++call_no;

  if (s) free(s);

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t userAgentStrPtr;
  uint32_t accessType;
  uint32_t proxyNameStrPtr;
  uint32_t proxyBypassStrPtr;
  uint32_t dwFlags;
} internetopen_t;


void InternetOpenA_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[6]; // All parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
   * HINTERNET InternetOpen(IN LPCTSTR lpszAgent, IN DWORD dwAccessType,
   *   IN LPCTSTR lpszProxyName, IN LPCTSTR lpszProxyBypass, IN DWORD dwFlags);
   *
   *   0 -> Return address
   *   1 -> Pointer to a null-terminated string that specifies the name of the 
   *          application or entity calling the WinINet functions. 
   *   2 -> Type of access required
   *   3 -> Pointer to a null-terminated string that specifies the name of 
   *          the proxy server(s) to use. Set to NULL if not needed.
   *   4 -> Pointer to a null-terminated string that specifies an optional 
   *          list of host names or IP addresses, or both, 
   *          that should not be routed through the proxy when 
   *          dwAccessType is set to INTERNET_OPEN_TYPE_PROXY
   *   5 -> Options
   */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog","Call to %s::%s\n",
    mod_name, fun_name);

  /* Read agent string */
  char agentStr[1024];
  int agentLen = get_string(stack[1], agentStr, 1024);

  /* Print parameters */
  WRITE("tracenetlog","\tAgent: %s (%d) AccessType: %u Options: %u\n", 
    agentStr, agentLen, stack[2], stack[5]);

  /* Store values needed by return hook */
  internetopen_t *s = malloc(sizeof(internetopen_t));
  if (s == NULL) return;
  s->eip = eip;
  s->userAgentStrPtr = stack[1];
  s->accessType = stack[2];
  s->proxyNameStrPtr = stack[3];
  s->proxyBypassStrPtr = stack[4];
  s->dwFlags = stack[5];

#if STOP_TRACE_AFTER_OPEN != 0
  tracing_stop();
#endif

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], InternetOpenA_ret, s,
    sizeof(internetopen_t));

  return;
}

void InternetOpenA_ret(void *opaque)
{
  /* Remove return hook */
  internetopen_t *s = (internetopen_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> number of bytes received */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Start writing to the trace if successful call */
  if (eax != 0) {
    skip_trace_write = 0;
  }

  /* Log function info */
  WRITE("tracenetlog", "\tHandle: 0x%x\n", eax);

  if (s) free(s);

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t af;
  uint32_t type;
  uint32_t protocol;
} socket_t;


void socket_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[4]; // All parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
   *   SOCKET WSAAPI socket(IN int af, IN int type, IN int protocol);
   *   0 -> Return address
   *   1 -> Address family
   *   2 -> Socket type
   *   3 -> Protocol
   */

 /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog","Creating socket using function %s::%s\n",
    mod_name, fun_name);

  /* Print parameters */
  WRITE("tracenetlog","\tFamily: %u Type: %u Protocol: %u\n",
    stack[1], stack[2], stack[3]);

  /* Store values needed by return hook */
  socket_t *s = malloc(sizeof(socket_t));
  if (s == NULL) return;
  s->eip = eip;
  s->af = stack[1];
  s->type = stack[2];
  s->protocol = stack[3];

#if STOP_TRACE_AFTER_OPEN != 0
  tracing_stop();
#endif

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], socket_ret, s,
    sizeof(socket_t));

  return;
}

void socket_ret(void *opaque)
{
  /* Remove return hook */
  socket_t *s = (socket_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> number of bytes received */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Start writing to the trace if successful call */
  if (eax != 0xffffffff) {
    skip_trace_write = 0;
  }

  /* Log function info */
  WRITE("tracenetlog", "\tHandle: 0x%x\n", eax);

  if (s) free(s);

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t internetHandle;
  uint32_t urlPtr;
  uint32_t headerPtr;
  uint32_t headerLen;
  uint32_t flags;
  uint32_t context;
} internetopenurl_t;


void InternetOpenUrlA_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[7]; // All parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
   * HINTERNET InternetOpenUrl(IN HINTERNET hInternet, IN LPCTSTR lpszUrl,
   *   IN LPCTSTR lpszHeaders, IN DWORD dwHeadersLength, IN DWORD dwFlags,
   *   IN DWORD_PTR dwContext);
   *
   *   0 -> Return address
   *   1 -> The handle to the current Internet session
   *   2 -> The URL ASCII string
   *   3 -> Pointer to a null-terminated string that specifies the headers to 
   *          be sent to the HTTP server
   *   4 -> The size of the additional headers, in TCHARs. If this parameter is
   *          -1 and the headers pointer is not NULL, then the headers string 
   *          is assumed to be null-terminated and the length is calculated
   *   5 -> Flags
   *   6 -> A pointer to a variable that specifies the application-defined 
   *          that is passed, along with the returned handle, 
   *          to any callback function
   */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog","Call to %s::%s\n",
    mod_name, fun_name);

  /* Read URL string */
  char urlStr[1024];
  int urlLen = get_string(stack[2], urlStr, 1024);

  /* Read Headers string */
  char headersStr[1024];
  int headersLen = get_string(stack[3], headersStr, 1024);

  /* Print parameters */
  WRITE("tracenetlog","\tHandle: 0x%x Url: %s (%d)\n\tHeaders: %s (%d)\n\t"
        "Flags: 0x%08x Context: %p\n",
        stack[1], urlStr, urlLen, headersStr, headersLen, stack[5], stack[6]);

  /* Store values needed by return hook */
  internetopenurl_t *s = malloc(sizeof(internetopenurl_t));
  if (s == NULL) return;
  s->eip = eip;
  s->internetHandle = stack[1];
  s->urlPtr = stack[2];
  s->headerPtr = stack[3];
  s->headerLen = stack[4];
  s->flags = stack[5];
  s->context = stack[6];

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], InternetOpenUrlA_ret, s,
    sizeof(internetopenurl_t));

  return;
}

void InternetOpenUrlA_ret(void *opaque)
{
  /* Remove return hook */
  internetopenurl_t *s = (internetopenurl_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> url handle */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Start writing to the trace if successful call */
  if (eax != 0) {
    WRITE("tracenetlog", "\tUrlHandle: 0x%x\n", eax);
  }
  else {
    WRITE("tracenetlog", "\tUrlHandle: <null>\n");
  }

  if (s) free(s);

  return;
}

typedef struct {
  uint32_t eip;
  uint32_t hook_handle;
  uint32_t internetHandle;
  uint32_t bufPtr;
  uint32_t bufLen;
  uint32_t numReadPtr;
} internetreadfile_t;


void InternetReadFile_call(void *opaque)
{
  uint32_t eip;
  uint32_t stack[5]; // All parameters are 4-byte long
  int read_err = 0;

  /* If not tracing yet, return */
  if (tracepid == 0) return;

  /* Read stack starting at ESP */
  read_err = DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 
                            sizeof(stack), stack);
  if (read_err) return;

  /*
   * BOOL InternetReadFile(IN HINTERNET hFile, OUT LPVOID lpBuffer, 
   *   IN DWORD dwNumberOfBytesToRead, OUT LPDWORD lpdwNumberOfBytesRead);
   *
   *   0 -> Return address
   *   1 -> Handle returned from InternetOpenUrl or HttpOpenRequest
   *   2 -> Pointer to a buffer that receives the data
   *   3 -> Number of bytes to be read
   *   4 -> Pointer to a variable that receives the number of bytes read
   */

  /* Check which function we are jumping to */
  eip = DECAF_getPC(cpu_single_env);
  char mod_name[512];
  char fun_name[512];
  get_function_name(eip,(char *)&mod_name,(char *)&fun_name);

  WRITE("tracenetlog","Call to %s::%s\n",
    mod_name, fun_name);

  /* Print parameters */
  WRITE("tracenetlog","\tHandle: 0x%x BufPtr: %p NumToRead: %d "
        "NumReadPtr: %p\n",
        stack[1], stack[2], stack[3], stack[4] );

  /* Store values needed by return hook */
  internetreadfile_t *s = malloc(sizeof(internetreadfile_t));
  if (s == NULL) return;
  s->eip = eip;
  s->internetHandle = stack[1];
  s->bufPtr = stack[2];
  s->bufLen = stack[3];
  s->numReadPtr = stack[4];

  /* Hook return of call */
  s->hook_handle = hookapi_hook_return(stack[0], InternetReadFile_ret, s,
    sizeof(internetreadfile_t));

  return;
}

void InternetReadFile_ret(void *opaque)
{
  static int call_no = 0;
  uint32_t read_err;

  /* Remove return hook */
  internetreadfile_t *s = (internetreadfile_t *)opaque;
  hookapi_remove_hook(s->hook_handle);

  /* Check return value -> succes/failure */
  uint32_t eax = cpu_single_env->regs[R_EAX];

  /* Check number of bytes read */
  uint32_t num_bytes_read = 0;
  read_err = read_mem(s->numReadPtr, sizeof(num_bytes_read), 
    (unsigned char*)&num_bytes_read);
  if (read_err) {
    if (s) free(s);
    return;
  }

  /* Read data */
  unsigned char *data = (unsigned char *) malloc(num_bytes_read);
  read_err = read_mem(s->bufPtr, num_bytes_read, data);
  if (read_err) {
    if (s) free(s);
    return;
  }

  /* Log function info */
  WRITE("tracenetlog", "\tResult: 0x%x\n\tNumBytesRead: %d\n",
    eax, num_bytes_read);

  /* Print the network data */
  WRITE ("tracenetlog", "\tDATA: 0x");
  unsigned int j;
  for (j = 0; j < num_bytes_read; j++) {
    WRITE ("tracenetlog","%02x", data[j]);
  }
  WRITE ("tracenetlog","\n");

#ifdef TAINT_ENABLED
  static int offset_bytes  = 0;
  static int offset_data  = 0;
  /* Taint the number of bytes received */
  hook_taint_record_t tr;
  tr.source = TAINT_SOURCE_API_SOCK_INFO_IN;
  tr.origin = INTERNETREADFILE_BYTES_ORIGIN;
  tr.offset = offset_bytes;
  taint_mem(s->numReadPtr, sizeof(num_bytes_read), (void *)&tr);

  /* Taint the data received */
  if (num_bytes_read > 0) {
    hook_taint_record_t tr2;
    tr2.source = TAINT_SOURCE_API_SOCK_INFO_IN;
    tr2.origin = INTERNETREADFILE_DATA_ORIGIN;
    tr2.offset = offset_data;
    taint_mem(s->bufPtr, num_bytes_read, (void *)&tr2);
  }
  offset_bytes += 4;
  offset_data += eax;
#endif // #ifdef TAINT_ENABLED
  ++call_no;


  if (s) free(s);

  return;
}

