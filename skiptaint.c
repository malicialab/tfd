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

/* NOTE: We need to use VMI_get_current_tid_c() in the functions that use
     the current thread id, because the current_tid variable is only
     updated at insn_begin, while the hook executes before insn_begin
     is executed. 
     If there is a thread switch at the hook instruction (Which does happen)
     we would set the skiptaint flag incorrectly */


#include "skiptaint.h"

int thread_skiptaint[MAX_NUMBER_OF_THREADS][2];

void init_st() {
  int i;
  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    thread_skiptaint[i][0] = 0;
    thread_skiptaint[i][1] = 0;
  }
}

void reset_st(uint32_t tid) {
  int i;
  uint32_t id = (tid > 0) ? tid : VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      thread_skiptaint[i][1] = 0;
      return;
    }
  }
}

void reset_cst() {
  int i;
  uint32_t id = VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      thread_skiptaint[i][1] = 0;
      return;
    }
  }
}

int get_st(uint32_t tid) {
  int i;
  uint32_t id = (tid > 0) ? tid : VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      return thread_skiptaint[i][1];
    }
  }
  return 0;
}

int get_cst() {
  int i;
  uint32_t id = VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      return thread_skiptaint[i][1];
    }
  }
  return 0;
}

int inc_st(uint32_t tid) {
  int i = 0;
  uint32_t id = (tid > 0) ? tid : VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      return ++thread_skiptaint[i][1];
    }
    else if (thread_skiptaint[i][0] == 0) {
      thread_skiptaint[i][0] = id;
      thread_skiptaint[i][1] = 1;
      return 1;
    }
  }
  fprintf(stderr,"inc_st: no space available for thread %u\n", id);
  return -1;
}

int inc_cst() {
  int i = 0;
  uint32_t id = VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      return ++thread_skiptaint[i][1];
    }
    else if (thread_skiptaint[i][0] == 0) {
      thread_skiptaint[i][0] = id;
      thread_skiptaint[i][1] = 1;
      return 1;
    }
  }
  fprintf(stderr,"inc_st: no space available for thread %u\n", id);
  return -1;
}


int dec_st(uint32_t tid) {
  int i;
  uint32_t id = (tid > 0) ? tid : VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      if (thread_skiptaint[i][1] > 0)
        return --thread_skiptaint[i][1];
      else
        return 0;
    }
    else if (thread_skiptaint[i][0] == 0) {
      thread_skiptaint[i][0] = id;
      thread_skiptaint[i][1] = 0;
      return 0;
    }
  }
  fprintf(stderr,"dec_st: no space available for thread %u\n", id);
  return -1;
}

int dec_cst() {
  int i;
  uint32_t id = VMI_get_current_tid_c(NULL);

  for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
    if (thread_skiptaint[i][0] == id) {
      if (thread_skiptaint[i][1] > 0)
        return --thread_skiptaint[i][1];
      else
        return 0;
    }
    else if (thread_skiptaint[i][0] == 0) {
      thread_skiptaint[i][0] = id;
      thread_skiptaint[i][1] = 0;
      return 0;
    }
  }
  fprintf(stderr,"dec_st: no space available for thread %u\n", id);
  return -1;
}


