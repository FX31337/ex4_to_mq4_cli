
/*
 * libdasm -- simple x86 disassembly library
 * (c) 2004 - 2006  jt / nologin.org
 *
 * libdasm.c:
 * This file contains most code of libdasm. Check out
 * libdasm.h for function definitions.
 *
 */

#include <stdio.h>
#include <string.h>
#include "libdasm.h"
#include "opcode_tables.h"


// Endianess conversion routines (thanks Ero)

__inline__ BYTE FETCH8(BYTE *addr) {
	// So far byte cast seems to work on all tested platforms
	return *(BYTE *)addr;
}

__inline__ WORD FETCH16(BYTE *addr) {
#if defined __X86__
	// Direct cast only for x86
	return *(WORD *)addr;
#else
	// Revert to memcpy
	WORD val;
	memcpy(&val, addr, 2);
#if defined __LITTLE_ENDIAN__
	return val;
#else
	return  ((val & 0xff00) >> 8) |
		((val & 0x00ff) << 8);

#endif // __LITTLE_ENDIAN__
#endif // __X86__
}

__inline__ DWORD FETCH32(BYTE *addr) {
#if defined __X86__
	return *(DWORD *)addr;
#else
	DWORD val;
	memcpy(&val, addr, 4);
#if defined __LITTLE_ENDIAN__
	return val;
#else
	return  ((val & (0xff000000)) >> 24) |
		((val & (0x00ff0000)) >> 8)  |
		((val & (0x0000ff00)) << 8)  |
		((val & (0x000000ff)) << 24);

#endif // __LITTLE_ENDIAN__
#endif // __X86__
}

// Check for address/operand size override

__inline__ enum Mode MODE_CHECK_ADDR(enum Mode mode, int flags) {
	if (((mode == MODE_32) && (MASK_PREFIX_ADDR(flags) == 0)) ||
    	    ((mode == MODE_16) && (MASK_PREFIX_ADDR(flags) == 1)))
		return MODE_32;
	else
		return MODE_16;
}
__inline__ enum Mode MODE_CHECK_OPERAND(enum Mode mode, int flags) {
	if (((mode == MODE_32) && (MASK_PREFIX_OPERAND(flags) == 0)) ||
    	    ((mode == MODE_16) && (MASK_PREFIX_OPERAND(flags) == 1)))
		return MODE_32;
	else
		return MODE_16;
}


// Parse 2 and 3-byte opcodes

int get_real_instruction2(BYTE *addr, int *flags) {
    // opcode extensions for 2-byte opcodes
    if (*addr == 0x00) {
        // Clear extension
        *flags &= 0xffffff00;
        *flags |= EXT_G6;
    }
    else if (*addr == 0x01) {
        *flags &= 0xffffff00;
        *flags |= EXT_G7;
    }
    else if (*addr == 0x71) {
        *flags &= 0xffffff00;
        *flags |= EXT_GC;
    }
    else if (*addr == 0x72) {
        *flags &= 0xffffff00;
        *flags |= EXT_GD;
    }
    else if (*addr == 0x73) {
        *flags &= 0xffffff00;
        *flags |= EXT_GE;
    }
    else if (*addr == 0xae) {
        *flags &= 0xffffff00;
        *flags |= EXT_GF;
    }
    else if (*addr == 0xba) {
        *flags &= 0xffffff00;
        *flags |= EXT_G8;
    }
    else if (*addr == 0xc7) {
        *flags &= 0xffffff00;
        *flags |= EXT_G9;
    }

	return 0;
}

// Parse instruction flags, get opcode index

int get_real_instruction(BYTE *addr, int *index, int *flags) {
    if (*addr == 0x0f) {
        // 2-byte opcode
        *index += 1;
        *flags |= EXT_T2;
    }
    else if (*addr == 0x2e) { // Prefix group 2
        *index += 1;
        // Clear previous flags from same group (undefined effect)
        *flags &= 0xff00ffff;
        *flags |= PREFIX_CS_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0x36) {
        *index += 1;
        *flags &= 0xff00ffff;
        *flags |= PREFIX_SS_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0x3e) {
        *index += 1;
        *flags &= 0xff00ffff;
        *flags |= PREFIX_DS_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0x26) {
        *index += 1;
        *flags &= 0xff00ffff;
        *flags |= PREFIX_ES_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0x64) {
        *index += 1;
        *flags &= 0xff00ffff;
        *flags |= PREFIX_FS_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0x65) {
        *index += 1;
        *flags &= 0xff00ffff;
        *flags |= PREFIX_GS_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0x66) { // Prefix group 3 or 3-byte opcode
        // Do not clear flags from the same group!!!!
        *index += 1;
        *flags |= PREFIX_OPERAND_SIZE_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0x67) { // Prefix group 4
        // Do not clear flags from the same group!!!!
        *index += 1;
        *flags |=  PREFIX_ADDR_SIZE_OVERRIDE;
        get_real_instruction(addr + 1, index, flags);
    }

    else if (*addr == 0x80) { // Extension group 1, check
        *flags |=  EXT_G1_1;
    }
    else if (*addr == 0x81) {
        *flags |=  EXT_G1_2;
    }
    else if (*addr == 0x82) {
        *flags |=  EXT_G1_1;
    }
    else if (*addr == 0x83) {
        *flags |=  EXT_G1_3;
    }

	// Extension group 2
    else if (*addr == 0xc0) {
        *flags |=  EXT_G2_1;
    }
    else if (*addr == 0xc1) {
        *flags |=  EXT_G2_2;
    }
    else if (*addr == 0xd0) {
        *flags |=  EXT_G2_3;
    }
    else if (*addr == 0xd1) {
        *flags |=  EXT_G2_4;
    }
    else if (*addr == 0xd2) {
        *flags |=  EXT_G2_5;
    }
    else if (*addr == 0xd3) {
        *flags |=  EXT_G2_6;
    }

	// Escape to co-processor
    else if (
        *addr == 0xd8 ||
        *addr == 0xd9 ||
        *addr == 0xda ||
        *addr == 0xdb ||
        *addr == 0xdc ||
        *addr == 0xdd ||
        *addr == 0xde ||
        *addr == 0xdf
    ) {
        *index += 1;
        *flags |=  EXT_CP;
    }

	// Prefix group 1 or 3-byte opcode
    else if (*addr == 0xf0) {
        *index += 1;
        *flags &= 0x00ffffff;
        *flags |=  PREFIX_LOCK;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0xf2) {
        *index += 1;
        *flags &= 0x00ffffff;
        *flags |=  PREFIX_REPNE;
        get_real_instruction(addr + 1, index, flags);
    }
    else if (*addr == 0xf3) {
        *index += 1;
        *flags &= 0x00ffffff;
        *flags |=  PREFIX_REP;
        get_real_instruction(addr + 1, index, flags);
    }

	// Extension group 3
    else if (*addr == 0xf6) {
        *flags |=  EXT_G3_1;
    }
    else if (*addr == 0xf7) {
        *flags |=  EXT_G3_2;
    }

	// Extension group 4
    else if (*addr == 0xfe) {
        *flags |=  EXT_G4;
    }

	// Extension group 5
    else if (*addr == 0xff) {
        *flags |=  EXT_G5;
    }

	return 0;
}

// Parse operand and fill OPERAND structure

/*
 * This function is quite complex.. I'm not perfectly happy
 * with the logic yet. Anyway, the idea is to
 *
 * - check out modrm and sib
 * - based on modrm/sib and addressing method (AM_X),
 *   figure out the operand members and fill the struct
 *
 */
int get_operand(PINST inst, int oflags, PINSTRUCTION instruction,
	POPERAND op, BYTE *data, int offset, enum Mode mode, int iflags) {
	BYTE *addr = data + offset;
	int index = 0, sib = 0, scale = 0;
	int reg      = REG_NOP;
	int basereg  = REG_NOP;
	int indexreg = REG_NOP;
	int dispbytes = 0;
	enum Mode pmode;

	// Is this valid operand?
	if (oflags == FLAGS_NONE) {
		op->type = OPERAND_TYPE_NONE;
		return 1;
	}
	// Copy flags
	op->flags = oflags;

	// Set operand registers
	op->reg      = REG_NOP;
	op->basereg  = REG_NOP;
	op->indexreg = REG_NOP;

	// Offsets
	op->dispoffset = 0;
	op->immoffset  = 0;

	// Parse modrm and sib
	if (inst->modrm) {
		pmode = MODE_CHECK_ADDR(mode, iflags);

		// Update length only once!
		if (!instruction->length) {
			instruction->modrm = *addr;
			instruction->length += 1;
		}
		// Register
		reg =  MASK_MODRM_REG(*addr);

		// Displacement bytes
		// SIB can also specify additional displacement, see below
		if (MASK_MODRM_MOD(*addr) == 0) {
			if ((pmode == MODE_32) && (MASK_MODRM_RM(*addr) == REG_EBP))
				dispbytes = 4;
			if ((pmode == MODE_16) && (MASK_MODRM_RM(*addr) == REG_ESI))
				dispbytes = 2;
		} else if (MASK_MODRM_MOD(*addr) == 1) {
			dispbytes = 1;

		} else if (MASK_MODRM_MOD(*addr) == 2) {
			dispbytes = (pmode == MODE_32) ? 4 : 2;
		}
		// Base and index registers

		// 32-bit mode
		if (pmode == MODE_32) {
			if ((MASK_MODRM_RM(*addr) == REG_ESP) &&
					(MASK_MODRM_MOD(*addr) != 3)) {
				sib = 1;
				instruction->sib = *(addr + 1);

				// Update length only once!
				if (instruction->length == 1) {
					instruction->sib = *(addr + 1);
					instruction->length += 1;
				}
				basereg  = MASK_SIB_BASE( *(addr + 1));
				indexreg = MASK_SIB_INDEX(*(addr + 1));
				scale    = MASK_SIB_SCALE(*(addr + 1)) * 2;
				// Fix scale *8
				if (scale == 6)
					scale += 2;

				// Special case where base=ebp and MOD = 0
				if ((basereg == REG_EBP) && !MASK_MODRM_MOD(*addr)) {
					basereg = REG_NOP;
						dispbytes = 4;
				}
				if (indexreg == REG_ESP)
					indexreg = REG_NOP;
			} else {
				if (!MASK_MODRM_MOD(*addr) && (MASK_MODRM_RM(*addr) == REG_EBP))
					basereg = REG_NOP;
				else
					basereg = MASK_MODRM_RM(*addr);
			}
		// 16-bit
		} else {
            if (MASK_MODRM_RM(*addr) == 0) {
                basereg  = REG_EBX;
                indexreg = REG_ESI;
            }
            else if (MASK_MODRM_RM(*addr) == 1) {
                basereg  = REG_EBX;
                indexreg = REG_EDI;
            }
            else if (MASK_MODRM_RM(*addr) == 2) {
                basereg  = REG_EBP;
                indexreg = REG_ESI;
            }
            else if (MASK_MODRM_RM(*addr) == 3) {
                basereg  = REG_EBP;
                indexreg = REG_EDI;
            }
            else if (MASK_MODRM_RM(*addr) == 4) {
                basereg  = REG_ESI;
                indexreg = REG_NOP;
            }
            else if (MASK_MODRM_RM(*addr) == 5) {
                basereg  = REG_EDI;
                indexreg = REG_NOP;
            }
            else if (MASK_MODRM_RM(*addr) == 6) {
                if (!MASK_MODRM_MOD(*addr))
                    basereg = REG_NOP;
                else
                    basereg = REG_EBP;
                indexreg = REG_NOP;
            }
            else if (MASK_MODRM_RM(*addr) == 7) {
                basereg  = REG_EBX;
                indexreg = REG_NOP;
            }

			if (MASK_MODRM_MOD(*addr) == 3) {
				basereg  = MASK_MODRM_RM(*addr);
				indexreg = REG_NOP;
			}
		}
	}

	// Operand addressing method -specific parsing
	if (MASK_AM(oflags) == AM_REG) { // Register encoded in instruction
		op->type = OPERAND_TYPE_REGISTER;
		op->reg  = MASK_REG(oflags);
	}
	else if (MASK_AM(oflags) == AM_IND) {
		op->type    = OPERAND_TYPE_MEMORY;
		op->basereg = MASK_REG(oflags);
	}
	else if (MASK_AM(oflags) == AM_M) {
		if (MASK_MODRM_MOD(*addr) == 3)
			return 0;
		goto skip_rest;
		goto continue_AM_R;
	}
	else if (MASK_AM(oflags) == AM_R) {
continue_AM_R:
		if (MASK_MODRM_MOD(*addr) != 3)
			return 0;

		goto skip_rest;
	}

	else if (
		MASK_AM(oflags) == AM_Q ||
		MASK_AM(oflags) == AM_W ||
		MASK_AM(oflags) == AM_E
	) {
skip_rest:
		op->type = OPERAND_TYPE_MEMORY;
		op->dispbytes          = dispbytes;
		instruction->dispbytes = dispbytes;
		op->basereg            = basereg;
		op->indexreg           = indexreg;
		op->scale              = scale;

		index = (sib) ? 1 : 0;
		if (dispbytes)
			op->dispoffset = index + 1 + offset;

		if (dispbytes == 0) {
		}
		else if (dispbytes == 1) {
			op->displacement = FETCH8(addr + 1 + index);
			// Always sign-extend
			if (op->displacement >= 0x80)
				op->displacement |= 0xffffff00;
		}
		else if (dispbytes == 2) {
			op->displacement = FETCH16(addr + 1 + index);
		}
		else if (dispbytes == 4) {
			op->displacement = FETCH32(addr + 1 + index);
		}

		// MODRM defines register
		if ((basereg != REG_NOP) && (MASK_MODRM_MOD(*addr) == 3)) {
			op->type = OPERAND_TYPE_REGISTER;
			op->reg  = basereg;
		}
	}
	else if (MASK_AM(oflags) == AM_I1) {
		op->type = OPERAND_TYPE_IMMEDIATE;
		op->immbytes  = 1;
		op->immediate = 1;
	}
	else if (MASK_AM(oflags) == AM_J) {
		op->type = OPERAND_TYPE_IMMEDIATE;
		// Always sign-extend
		oflags |= F_s;
		goto continue_AM_I;
	}
	else if (MASK_AM(oflags) == AM_I) {
continue_AM_I:
		op->type = OPERAND_TYPE_IMMEDIATE;
		index  = (inst->modrm) ? 1 : 0;
		index += (sib) ? 1 : 0;
		index += instruction->immbytes;
		index += instruction->dispbytes;
		op->immoffset = index + offset;

		// check mode
		mode = MODE_CHECK_OPERAND(mode, iflags);

		if (MASK_OT(oflags) == OT_b) {
			op->immbytes  = 1;
			op->immediate = FETCH8(addr + index);
			if ((op->immediate >= 0x80) &&
				(MASK_FLAGS(oflags) == F_s))
				op->immediate |= 0xffffff00;
		}
		else if (MASK_OT(oflags) == OT_v) {
			op->immbytes  = (mode == MODE_32) ?
				4 : 2;
			op->immediate = (mode == MODE_32) ?
				FETCH32(addr + index) :
				FETCH16(addr + index);
		}
		else if (MASK_OT(oflags) == OT_w) {
			op->immbytes  = 2;
			op->immediate =	FETCH16(addr + index);
		}

		instruction->immbytes += op->immbytes;
	}
	else if (MASK_AM(oflags) == AM_A) {
		op->type = OPERAND_TYPE_IMMEDIATE;
		// check mode
		mode = MODE_CHECK_OPERAND(mode, iflags);

		op->dispbytes    = (mode == MODE_32) ? 6 : 4;
		op->displacement = (mode == MODE_32) ?
			FETCH32(addr) : FETCH16(addr);
		op->section = FETCH16(addr + op->dispbytes - 2);

		instruction->dispbytes    = op->dispbytes;
		instruction->sectionbytes = 2;
	}
	else if (MASK_AM(oflags) == AM_O) {
		op->type = OPERAND_TYPE_MEMORY;

		if (MASK_OT(oflags) == OT_b) {
			op->dispbytes    = 1;
			op->displacement = FETCH8(addr);
		}
		else if (MASK_OT(oflags) == OT_v) {
			op->dispbytes    = (mode == MODE_32) ? 4 : 2;
			op->displacement = (mode == MODE_32) ?
				FETCH32(addr) : FETCH16(addr);
		}

		instruction->dispbytes = op->dispbytes;
		op->dispoffset = offset;
	}
	else if (MASK_AM(oflags) == AM_G) {
		op->type = OPERAND_TYPE_REGISTER;
		op->reg  = reg;
	}
	else if (
		MASK_AM(oflags) == AM_C || 	// control register encoded in MODRM
		MASK_AM(oflags) == AM_D || 	// debug register encoded in MODRM
		MASK_AM(oflags) == AM_S || 	// Segment register encoded in MODRM
		MASK_AM(oflags) == AM_T || 	// TEST register encoded in MODRM
		MASK_AM(oflags) == AM_P || 	// MMX register encoded in MODRM
		MASK_AM(oflags) == AM_V 	// XMM register encoded in MODRM
	) {
		op->type = OPERAND_TYPE_REGISTER;
		op->reg  = MASK_MODRM_REG(instruction->modrm);
	}

	return 1;
}

// Fetch instruction

/*
 * The operation is quite straightforward:
 *
 * - determine actual opcode (skip prefixes etc.)
 * - figure out which instruction table to use
 * - index the table with opcode
 * - parse operands
 * - fill instruction structure
 *
 * Only point where this gets hairy is those *brilliant*
 * opcode extensions....
 *
 */
int get_instruction(PINSTRUCTION inst, BYTE *addr, enum Mode mode) {
	PINST ptr = NULL;
	int index = 0;
	int flags = 0;

	memset(inst, 0, sizeof(INSTRUCTION));

	// Parse flags, skip prefixes etc.
	get_real_instruction(addr, &index, &flags);

	// Select instruction table

	// No extensions - normal 1-byte opcode:
	if (MASK_EXT(flags) == 0) {
		inst->opcode = *(addr + index);
		ptr = &inst_table1[inst->opcode];

	// FPU opcodes
	} else if (MASK_EXT(flags) == EXT_CP) {
		if (*(addr + index) < 0xc0) {
			// MODRM byte adds the additional byte
			index--;
			inst->fpuindex = *(addr + index) - 0xd8;
			inst->opcode   = *(addr + index + 1);
			ptr = &inst_table4[inst->fpuindex]
				[MASK_MODRM_REG(inst->opcode)];
		} else {
			inst->fpuindex = *(addr + index - 1) - 0xd8;
			inst->opcode   = *(addr + index);
			ptr = &inst_table4[inst->fpuindex]
				[inst->opcode - 0xb8];
		}
	// 2 or 3-byte opcodes
	} else if (MASK_EXT(flags) == EXT_T2) {
		inst->opcode = *(addr + index);

		// Parse flags, skip prefixes etc. (again)
		get_real_instruction2(addr + index, &flags);

		// 2-byte opcode table
		ptr = &inst_table2[inst->opcode];

		// 3-byte opcode tables
		if (MASK_TYPE_FLAGS(ptr->type) == TYPE_3) {
			// prefix 0x66
			if (MASK_PREFIX_OPERAND(flags) == 1) {
				ptr = &inst_table3_66[inst->opcode];

			// prefix 0xf2
			} else if (MASK_PREFIX_G1(flags) == 2) {
				ptr = &inst_table3_f2[inst->opcode];

			// prefix 0xf3
			} else if (MASK_PREFIX_G1(flags) == 3) {
				ptr = &inst_table3_f3[inst->opcode];

			}
		}
	}
	// Opcode extension tables
	if (MASK_EXT(flags) && (MASK_EXT(flags) < EXT_T2)) {
		inst->opcode   = *(addr + index);
		inst->extindex = MASK_MODRM_REG(*(addr + index + 1));

        if (MASK_EXT(flags) == EXT_GC) {
            // prefix 0x66
            if (MASK_PREFIX_OPERAND(flags) == 1)
                ptr = &inst_table_ext12_66[inst->extindex];
            else
                ptr = &inst_table_ext12[inst->extindex];
        }
        else if (MASK_EXT(flags) == EXT_GD) {
            // prefix 0x66
            if (MASK_PREFIX_OPERAND(flags) == 1)
                ptr = &inst_table_ext13_66[inst->extindex];
            else
                ptr = &inst_table_ext13[inst->extindex];
        }
        else if (MASK_EXT(flags) == EXT_GE) {
            // prefix 0x66
            if (MASK_PREFIX_OPERAND(flags) == 1)
                ptr = &inst_table_ext14_66[inst->extindex];
            else
                ptr = &inst_table_ext14[inst->extindex];
        }
        else if (MASK_EXT(flags) == EXT_G7) {
        // monitor/mwait
        // XXX: hack.....
            if (MASK_MODRM_MOD(*(addr + index + 1)) == 3) {
                if (inst->extindex != 1)
                    return 0;
                if (MASK_MODRM_RM(*(addr + index + 1)) == 0) {
                    ptr = &inst_monitor;
                    // index is incremented to get
                    // correct instruction len
                    index++;
                } else if (MASK_MODRM_RM(*(addr + index + 1)) == 1) {
                    ptr = &inst_mwait;
                    index++;
                } else
                    return 0;

            } else {
                ptr = &inst_table_ext7[inst->extindex];
            }
        }
        else {
            ptr = &inst_table_ext[(MASK_EXT(flags)) - 1]
                [inst->extindex];
        }
	}
	// Index points now to first byte after prefixes/escapes
	index++;

	// MODRM byte offset
	if (ptr->modrm)
		inst->modrm_offset = index;

	// Illegal instruction
	if (!ptr)
		return 0;
        if (!ptr->mnemonic)
		return 0;

	// Copy instruction type
	inst->type = MASK_TYPE_VALUE(ptr->type);

	// Eflags affected by this instruction
	inst->eflags_affected = ptr->eflags_affected;
	inst->eflags_used = ptr->eflags_used;

	// Pointer to instruction table
	inst->ptr = ptr;


	// Parse operands
	if (!get_operand(ptr, ptr->flags1, inst, &inst->op1, addr, index,
			mode, flags))
		return 0;
	if (!get_operand(ptr, ptr->flags2, inst, &inst->op2, addr, index,
			mode, flags))
		return 0;
	if (!get_operand(ptr, ptr->flags3, inst, &inst->op3, addr, index,
			mode, flags))
		return 0;

	// Implied operands
	inst->iop_read    = ptr->iop_read;
	inst->iop_written = ptr->iop_written;

	// Add modrm/sib, displacement and immediate bytes in size
	inst->length += index + inst->immbytes + inst->dispbytes;

	// Copy addressing mode
	inst->mode = mode;

	// Copy instruction flags
	inst->flags = flags;

	return inst->length;
}

// Helper functions

