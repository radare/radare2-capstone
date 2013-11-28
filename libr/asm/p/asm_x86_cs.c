/* radare2 - LGPL - Copyright 2013 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut64 handle;
	cs_insn *insn;
	int mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	int n, ret = cs_open (CS_ARCH_X86, mode, &handle);
	op->inst_len = 0;
	if (ret) goto beach;
	n = cs_disasm_dyn (handle, (char*)buf, len, 0, 1, &insn);
	if (n<1) goto beach;
	if (insn[0].size<1)
		goto beach;
	op->inst_len = insn[0].size;
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn[0].mnemonic,
		insn[0].op_str[0]?" ":"",
		insn[0].op_str);
	beach:
	cs_close (handle);
	return op->inst_len;
}

RAsmPlugin r_asm_plugin_x86_cs = {
	.name = "x86.cs",
	.desc = "Capstone X86 disassembler",
	.arch = "x86",
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_cs
};
#endif
