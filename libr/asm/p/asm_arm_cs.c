/* radare2 - LGPL - Copyright 2013 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode = (a->bits==16)? CS_MODE_THUMB: CS_MODE_ARM;
	int n, ret = (a->bits==64)?
		cs_open (CS_ARCH_ARM64, mode, &handle):
		cs_open (CS_ARCH_ARM, mode, &handle);
	op->inst_len = -1;
	strcpy (op->buf_asm, "invalid");
	if (ret) {
		ret = -1;
		goto beach;
	}
	n = cs_disasm_dyn (handle, (ut8*)buf, R_MIN (4, len), 0, 1, &insn);
	if (n<1) {
		ret = -1;
		goto beach;
	}
	if (insn[0].size<1) {
		ret = -1;
		goto beach;
	}
	op->inst_len = insn[0].size;
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn[0].mnemonic,
		insn[0].op_str[0]?" ":"",
		insn[0].op_str);
	beach:
	cs_close (handle);
	return op->inst_len;
}

RAsmPlugin r_asm_plugin_arm_cs = {
	.name = "arm.cs",
	.desc = "Capstone ARM disassembler",
	.license = "BSD",
	.arch = "arm",
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_cs
};
#endif
