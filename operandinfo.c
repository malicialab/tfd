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

#include <sys/time.h>
#include <assert.h>
#include "operandinfo.h"
#include "config.h"
#include "tfd.h"
#include "DECAF_main.h"
#ifdef TAINT_ENABLED
#include "shared/tainting/taintcheck_opt.h"
#endif

/* Flag that states if tainted data has already been seen during trace */
int received_tainted_data = 0;



/* Copy the given taint record into the given operand
     and check whether this is the first tainted operand seen
*/
inline void record_taint_value(OperandVal * op) {
  struct timeval ftime;

  if (0 == received_tainted_data) {
    received_tainted_data = 1;
    if (gettimeofday(&ftime, 0) == 0) {
      monitor_printf(default_mon, "Time of first tainted data: %ld.%ld\n",
        ftime.tv_sec, ftime.tv_usec);
    }

  }

}

/* Build an operand tainted flag, transforming byte mask to bit mask */
uint16_t build_operand_taintmask(uint64_t orig)
{
  uint16_t temp = 0;
  int i = 0;
  while (i < 8) {
    if (((orig >> i * 8) & 0xff) != 0)
      temp = temp | (0x1 << i);
    i++;
  }
  return temp;
}

/* Set the taint information of the given operand */
void set_operand_taint(CPUState* env, OperandVal *op) {
#ifdef TAINT_ENABLED
  switch (op->type) {
    case TRegister: {
      int regnum = REGNUM(REGOP_ADDR(*op));
      int offset = getOperandOffset(op);
      if(regnum!=-1){
        uint64_t orig = 
          taintcheck_register_check(regnum, offset, op->length, env);
        op->tainted = build_operand_taintmask(orig);
      }
      break;
    }
    case TMemLoc: {
      uint64_t orig = 0;
      taintcheck_check_virtmem(MEMOP_ADDR(*op), op->length, (uint8_t *)&orig);
      op->tainted = build_operand_taintmask(orig);
      break;
    }
    default:
      op->tainted = 0;
      break;
  }

  if (op->tainted) {
    insn_tainted=1;
    record_taint_value(op);
  }
#else
  op->tainted = 0;
#endif // #ifdef TAINT_ENABLED
}

