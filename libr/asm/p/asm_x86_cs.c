/* radare2 - LGPL - Copyright 2013 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	csh handle;
	cs_insn insn;
	int mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	int n, ret = cs_open (CS_ARCH_X86, mode, &handle);
	ut64 off = a->pc;
	op->size = 0;
	if (ret) goto beach;
	n = cs_disasm (handle, (ut8*)buf, len, off, 1, &insn);
	if (n<1) goto beach;
	if (insn.size<1)
		goto beach;
	op->size = insn.size;
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn.mnemonic,
		insn.op_str[0]?" ":"",
		insn.op_str);
	beach:
	cs_close (handle);
	return op->size;
}

RAsmPlugin r_asm_plugin_x86_cs = {
	.name = "x86.cs",
	.desc = "Capstone X86 disassembler",
	.license = "BSD",
	.arch = "x86",
	.bits = 16|32|64,
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
