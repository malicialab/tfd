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

#include "readwrite.h"
#include "config.h"
#include "tfd.h"
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "assert.h"
#include "xed-interface.h"

void get_new_access (
  xed_operand_action_enum_t curr_access,
  xed_operand_action_enum_t *old_access, 
  xed_operand_action_enum_t *new_access) 
{
  switch(curr_access) {
    case XED_OPERAND_ACTION_RW: {
      *old_access = XED_OPERAND_ACTION_R;
      *new_access = XED_OPERAND_ACTION_W;
      break;
    }
    case XED_OPERAND_ACTION_RCW: {
      *old_access = XED_OPERAND_ACTION_R;
      *new_access = XED_OPERAND_ACTION_CW;
      break;
    }
    case XED_OPERAND_ACTION_CRW: {
      *old_access = XED_OPERAND_ACTION_CR;
      *new_access = XED_OPERAND_ACTION_W;
      break;
    }
    default: {
      *old_access = curr_access;
      *new_access = curr_access;
      break;
    }
  }
 
}

// Update all written operands with current value
void update_written_operands (CPUState* env, EntryHeader *eh) {
  int i = 0, first_empty_idx = 0;
  xed_operand_action_enum_t old_access, new_access;
  

    // Find number of operands
    while ((eh->operand[i].type != TNone) && (i < MAX_NUM_OPERANDS)) {
      i++;
    }
    first_empty_idx = i;

    // Modify operands
    i = 0;
    while ((eh->operand[i].type != TNone) && (i < MAX_NUM_OPERANDS)) {
      switch(eh->operand[i].access) {
        case XED_OPERAND_ACTION_W:
        case XED_OPERAND_ACTION_CW: {
          // Just update the operand value
          if (eh->operand[i].type == TRegister) {
            int regnum = REGNUM(REGOP_ADDR(eh->operand[i]));
            REGOP_VAL(eh->operand[i]) = env->regs[regnum];
          }
          else if (eh->operand[i].type == TMemLoc) {
            DECAF_read_mem(env, MEMOP_ADDR(eh->operand[i]),
              (int)(eh->operand[i].length),
              (uint8_t *)&(MEMOP_VAL(eh->operand[i])));
          }
#ifndef TRACE_VERSION_50
          else if (eh->operand[i].type == TMMXRegister) {
            int regnum = eh->operand[i].addr.reg_addr;
            eh->operand[i].value.val64 = MMXVAL(env,regnum);
          }
          else if (eh->operand[i].type == TFloatRegister) {
            int regnum = eh->operand[i].addr.reg_addr;
            eh->operand[i].value.float_val = FLOATVAL(env,regnum);
          }
          else if (eh->operand[i].type == TFloatControlRegister) {
            if (eh->operand[i].addr.reg_addr == fpu_status_reg) {
              eh->operand[i].value.val32 = (uint32_t) *(&env->fpus);
            }
            else if (eh->operand[i].addr.reg_addr == fpu_control_reg) {
              eh->operand[i].value.val32 = (uint32_t) *(&env->fpuc);
            }
          }
          else if (eh->operand[i].type == TXMMRegister) {
            int regnum = eh->operand[i].addr.reg_addr;
            eh->operand[i].value.xmm_val._q[0] = XMMVAL(env,regnum,0);
            eh->operand[i].value.xmm_val._q[1] = XMMVAL(env,regnum,1);
          }
#endif
          break;
        }
        case XED_OPERAND_ACTION_RW:
        case XED_OPERAND_ACTION_RCW:
        case XED_OPERAND_ACTION_CRW: {
          // Copy operand to empty slot
          assert(first_empty_idx < MAX_NUM_OPERANDS);
          assert(first_empty_idx != i);
          memcpy((void *)&(eh->operand[first_empty_idx]),
                            (void *)&(eh->operand[i]),sizeof(OperandVal)); 

          // Update the number of operands
          eh->num_operands++;

          // Update operand access for both operands
          get_new_access(eh->operand[i].access,&old_access,&new_access);
          eh->operand[i].access = old_access;
          eh->operand[first_empty_idx].access = new_access;

          // Update value for new operand
         // Update value for new operand
          if (eh->operand[i].type == TRegister) {
            int regnum = REGNUM(REGOP_ADDR(eh->operand[i]));
            REGOP_VAL(eh->operand[first_empty_idx]) = env->regs[regnum];
          }
          else if (eh->operand[i].type == TMemLoc) {
            DECAF_read_mem(env, MEMOP_ADDR(eh->operand[i]),
              (int)(eh->operand[i].length),
              (uint8_t *)&(MEMOP_VAL(eh->operand[first_empty_idx])));
          }
#ifndef TRACE_VERSION_50
          else if (eh->operand[i].type == TMMXRegister) {
            int regnum = eh->operand[i].addr.reg_addr;
            eh->operand[first_empty_idx].value.val64 = MMXVAL(env,regnum);
          }
          else if (eh->operand[i].type == TFloatRegister) {
            int regnum = eh->operand[i].addr.reg_addr;
            eh->operand[first_empty_idx].value.float_val = 
              FLOATVAL(env,regnum);
          }
          else if (eh->operand[i].type == TFloatControlRegister) {
            if (eh->operand[i].addr.reg_addr == fpu_status_reg) {
              eh->operand[first_empty_idx].value.val32 =
                (uint32_t) *(&env->fpus);
            }
            else if (eh->operand[i].addr.reg_addr == fpu_control_reg) {
              eh->operand[first_empty_idx].value.val32 =
                (uint32_t) *(&env->fpuc);
            }
          }
#endif

          first_empty_idx++;
        }
        default: {
          break;
        }
      }

      i++;
    }

}

