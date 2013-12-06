/* radare2 - LGPL - Copyright 2013 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <x86.h>

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	int n, ret = cs_open (CS_ARCH_X86, mode, &handle);
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = 0;
	if (ret == CS_ERR_OK) {
		n = cs_disasm_dyn (handle, (ut8*)buf, len, addr, 1, &insn);
		if (n<1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->size = insn[0].size;
			switch (insn[0].id) {
			case X86_INS_PUSH:
			case X86_INS_PUSHA:
			case X86_INS_PUSHF:
				op->type = R_ANAL_OP_TYPE_PUSH;
				break;
			case X86_INS_POP:
			case X86_INS_POPA:
			case X86_INS_POPF:
			case X86_INS_POPCNT:
				op->type = R_ANAL_OP_TYPE_POP;
				break;
			case X86_INS_RET:
			case X86_INS_RETF:
			case X86_INS_IRET:
			case X86_INS_IRETD:
			case X86_INS_IRETQ:
			case X86_INS_SYSRET:
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case X86_INS_INT3:
			case X86_INS_INTO:
			case X86_INS_INT:
				op->type = R_ANAL_OP_TYPE_TRAP;
				break;
			case X86_INS_JNE:
			case X86_INS_JNS:
			case X86_INS_JNP:
			case X86_INS_JNO:
			case X86_INS_JLE:
			case X86_INS_JA:
			case X86_INS_JAE:
			case X86_INS_JB:
			case X86_INS_JBE:
			case X86_INS_JO:
			case X86_INS_JS:
			case X86_INS_JE:
			case X86_INS_JG:
			case X86_INS_JP:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = insn[0].x86.operands[0].imm;
				op->fail = addr+op->size;
				break;
			case X86_INS_CALL:
			case X86_INS_CALLW:
			case X86_INS_LCALL:
				op->type = R_ANAL_OP_TYPE_CALL;
				// TODO: what if UCALL?
				// TODO: use imm_size
				op->jump = insn[0].x86.operands[0].imm;
				op->fail = addr+op->size;
				break;
			case X86_INS_JMP:
			case X86_INS_LJMP:
			case X86_INS_JMPQ:
				// TODO: what if UJMP?
				op->jump = insn[0].x86.operands[0].imm;
				op->type = R_ANAL_OP_TYPE_JMP;
				break;
			case X86_INS_ADD:
			case X86_INS_FADD:
			case X86_INS_ADDPD:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			}
		}
		cs_close (handle);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_x86_cs = {
	.name = "x86.cs",
	.desc = "Capstone X86 analysis",
	.license = "BSD",
	.arch = R_SYS_ARCH_X86,
	.bits = 16|32|64,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_cs
};
#endif
