/* radare2 - LGPL - Copyright 2013 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn = NULL;
	//int mode = CS_MODE_64 | CS_MODE_BIG_ENDIAN; // CS_MODE_MICRO, N64
        int mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	int n, ret = cs_open (CS_ARCH_MIPS, mode, &handle);
	memset (op, sizeof (RAsmOp), 0);
	op->size = 4;
	if (ret) goto fin;
	n = cs_disasm_dyn (handle, (ut8*)buf, len, a->pc, 1, &insn);
	if (n<1) {
		strcpy (op->buf_asm, "invalid");
		op->size = 4;
		ret = -1;
		goto beach;
	} else ret = 4;
	if (insn[0].size<1)
		goto beach;
	op->size = insn[0].size;
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn[0].mnemonic,
		insn[0].op_str[0]? " ": "",
		insn[0].op_str);
	beach:
	cs_close (handle);
	fin:
	return ret;
}

RAsmPlugin r_asm_plugin_mips_cs = {
	.name = "mips.cs",
	.desc = "Capstone MIPS disassembler",
	.license = "BSD",
	.arch = "mips",
	.bits = 16|32|64,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mips_cs
};
#endif
