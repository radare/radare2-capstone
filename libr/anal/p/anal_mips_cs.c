/* radare2 - LGPL - Copyright 2013 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>
#include <mips.h>

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode = CS_MODE_BIG_ENDIAN; // CS_MODE_MICRO, N64
	int n, ret = cs_open (CS_ARCH_MIPS, mode, &handle);
	op->length = 0;
	if (ret != CS_ERR_OK) goto fin;
	n = cs_disasm_dyn (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n<1) goto beach;
	if (insn[0].size<1)
		goto beach;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->length = insn[0].size;
	switch (insn[0].id) {
	case MIPS_INS_BREAK:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case MIPS_INS_JAL:
	case MIPS_INS_JALR:
	case MIPS_INS_JALRC:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case MIPS_INS_J:
	case MIPS_INS_JR:
	case MIPS_INS_JRC:
	case MIPS_INS_B:
	case MIPS_INS_BZ:
	case MIPS_INS_BNEZ:
	case MIPS_INS_BTEQZ:
	case MIPS_INS_BTNEZ:
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	}
	beach:
	cs_close (handle);
	fin:
	return op->length;
}

RAnalPlugin r_anal_plugin_mips_cs = {
	.name = "mips.cs",
	.desc = "Capstone MIPS analyzer",
	.license = "BSD",
	.arch = R_SYS_ARCH_MIPS,
	.bits = 16|32|64,
	.op = &analop,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_mips_cs
};
#endif
