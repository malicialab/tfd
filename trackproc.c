/* 
 *  process tracking
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

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#ifdef TRACE_VERSION_50
#include "trace50.h"
#else
#include "trace.h"
#endif
#include "trackproc.h"

/* Tracked Process information */
typedef struct {
  uint32_t m_uiHandle; // Process handle
  uint32_t m_uiPID;    // Process PID
  int m_iParent;       // Index of parent process in array
} TrackProcInfo;

/* Total number of processes being tracked (includes parent) */
static int l_iNumProc;

/* Flag to mark whether we are tracking process creation */
static int l_iRunning;

/* Array of processes. Zero index is parent, rest are children */
TrackProcInfo l_arTrackProcInfo[MAX_CHILDPROC];

void trackproc_start(uint32_t pid)
{
  int i;

  /* Process tracking running */
  l_iRunning = 1;

  /* Parent process being tracked */
  l_iNumProc = 1;

  /* Set parent information */
  l_arTrackProcInfo[0].m_uiPID = pid;
  l_arTrackProcInfo[0].m_uiHandle = -1;
  l_arTrackProcInfo[0].m_iParent = -1;

  /* Initialize children information */
  for (i = 1; i < MAX_CHILDPROC; i ++) {
    l_arTrackProcInfo[i].m_uiHandle = -1;
    l_arTrackProcInfo[i].m_uiPID = -1;
    l_arTrackProcInfo[i].m_iParent = -1;
  }

}

void trackproc_stop()
{
  l_iRunning = 0;
  l_iNumProc = 0;
}

uint32_t trackproc_get_root_pid()
{
  return (l_arTrackProcInfo[0].m_uiPID);
}

int trackproc_is_running()
{
  //fprintf(stderr, "in running... %d\n", l_iRunning);
  return (l_iRunning);
}

int trackproc_find_handle(uint32_t uiHandle)
{
  int i;
  for (i = 0; i < l_iNumProc; i ++) {
    if (l_arTrackProcInfo[i].m_uiHandle == uiHandle)
      return (i);
  }
  return (-1);
}

int trackproc_find_pid(uint32_t uiPID)
{
  int i;
  for (i = 0; i < l_iNumProc; i ++) {
    if (l_arTrackProcInfo[i].m_uiPID == uiPID)
      return (i);
  }
  return (-1);
}

int trackproc_add_new_handle(uint32_t uiHandle, uint32_t uiParentPID)
{
  /* Check that maximum number of children is not exceeded */
  if (l_iNumProc >= MAX_CHILDPROC) {
    monitor_printf(default_mon, 
                    "Maximum number of child processes exceeded, ignoring\n");
    return -1;
  }
  /* Check if the handle is already in the array */
  if (trackproc_find_handle(uiHandle) >= 0) {
    return -2;
  }
  l_arTrackProcInfo[l_iNumProc].m_uiHandle = uiHandle;
  l_arTrackProcInfo[l_iNumProc].m_uiPID = -1;

  int iParentIndex = trackproc_find_pid(uiParentPID);

  /* Check that parent process is in array */
  if (iParentIndex < 0) {
    return -3;
  }

  l_arTrackProcInfo[l_iNumProc].m_iParent = iParentIndex;

  /* Increase number of processes being tracked */
  l_iNumProc++;

  return 0;
}

void trackproc_set_pid(uint32_t uiHandle, uint32_t uiPID)
{
  int iPos;
  iPos = trackproc_find_handle(uiHandle);
  if (iPos == -1)
    return;

  l_arTrackProcInfo[iPos].m_uiPID = uiPID;
  //reset the handle value (it can be reused by another process)
  l_arTrackProcInfo[iPos].m_uiHandle = -1;

  monitor_printf(default_mon, "Process %u forked child %u (Handle: 0x%x)\n", 
    l_arTrackProcInfo[l_arTrackProcInfo[iPos].m_iParent].m_uiPID,
    uiPID,  uiHandle);

}

uint32_t trackproc_get_parent_pid(uint32_t uiPID)
{
  int iPos = trackproc_find_pid(uiPID);
  if (iPos == -1)
    return -1;
  return (l_arTrackProcInfo[l_arTrackProcInfo[iPos].m_iParent].m_uiPID);
}

unsigned int trackproc_found_child() {
  return (l_iNumProc > 1);
}

ProcRecord ** trackproc_get_tracked_processes_info(CPUState * env,
  uint32_t tracked_pid, size_t * num_tracked_proc)
{
  ProcRecord ** proc_arr = NULL;
  procinfo_t * pinfo_arr = NULL;
  size_t num_procs;
  char proc_name[512];
  uint32_t cr3, curr_pid;
  unsigned int i;
  //unsigned int j;

  if (tracked_pid == -1) {
    num_procs = VMI_get_all_processes_count_c();
    pinfo_arr = (procinfo_t *) malloc(num_procs * sizeof(procinfo_t));
    proc_arr = (ProcRecord **) malloc(l_iNumProc * sizeof(ProcRecord *));
    if (pinfo_arr && proc_arr) {
      VMI_find_all_processes_info_c(num_procs, pinfo_arr);
      for (i = 0; i < l_iNumProc; i++) {
        proc_arr[i] = trackproc_get_process_info(env, cr3);
      }
      *num_tracked_proc = num_procs;
    }
    else {
      *num_tracked_proc = 0;
    }
  }
  else {
    proc_arr = (ProcRecord **) malloc(l_iNumProc * sizeof(ProcRecord *));

    if (proc_arr) {
      for (i = 0; i < l_iNumProc; i++) {
        curr_pid = l_arTrackProcInfo[i].m_uiPID;
        VMI_find_process_by_pid_c(curr_pid, proc_name, 512, &cr3);
        if (cr3 != -1) {
          proc_arr[i] = trackproc_get_process_info(env, cr3);
        }
        else {
          proc_arr[i] = NULL;
        }
      }
      *num_tracked_proc = l_iNumProc;
    }
    else {
      *num_tracked_proc = 0;
    }
  }

  return proc_arr;
}

ProcRecord * trackproc_get_process_info(CPUState * env, uint32_t cr3) {
  ProcRecord * pr;
  tmodinfo_t * pmr = NULL;
  unsigned int i;

  // Clear process record
  pr = (ProcRecord *) malloc (sizeof(ProcRecord));
  if (!pr)
    return NULL;

  // Set PID and process name
  VMI_find_process_by_cr3_c(cr3, pr->name, MAX_STRING_LEN, &pr->pid);

  // Set number of modules
  pr->n_mods = VMI_get_loaded_modules_count_c(pr->pid);

  // Build module array
  pmr = (tmodinfo_t *) malloc(pr->n_mods * sizeof(tmodinfo_t));
  pr->mod_arr = (ModuleRecord *) malloc(pr->n_mods * sizeof(ModuleRecord));
  if (pmr && pr->mod_arr) {
    VMI_get_proc_modules_c(pr->pid, pr->n_mods, pmr);
    for (i = 0; i < pr->n_mods; i++) {
      strncpy(pr->mod_arr[i].name, pmr[i].name, MAX_STRING_LEN - 1);
      pr->mod_arr[i].base = pmr[i].base;
      pr->mod_arr[i].size = pmr[i].size;
      pr->ldt_base = (&env->ldt)->base;
    }
  }
  else {
    pr->n_mods = -1;
    pr->mod_arr = NULL;
  }

  return pr;
}

