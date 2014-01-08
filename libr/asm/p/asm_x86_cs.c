/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static int bufi = 0;
static char buf[2990240];

static void *my_malloc(size_t s) {
	char *ret;
	printf ("MALLOC %d / %d\n", s, bufi);
	ret = buf+bufi;
	bufi += (s*2);
	return ret;
}

static void *my_calloc(size_t c, size_t s) {
return calloc(c, s);
	printf ("--> calloc %d %zu\n", c, s);
	return my_malloc (c*s);
}

static void *my_realloc(void *p, size_t s) {
//return realloc (p, s);
eprintf ("REALLOC %d\n", s);
	return p;
}

static void my_free(void *p) {
	printf ("FREE %p\n", p);
//free (p);
}

static csh handle = 0;

static int the_end(void *p) {
	if (handle) {
		cs_close (handle);
		handle = 0;
	}
	return R_TRUE;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = 0;
	int mode, n, ret;
	ut64 off = a->pc;
	cs_insn* insn = NULL;

	mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	if (handle && mode != omode) {
		cs_close (handle);
		handle = 0;
	}
	op->size = 0;
	omode = mode;
	if (handle == 0) {
		cs_opt_mem mem = {
			.malloc = my_malloc,
			.calloc = my_calloc,
			.realloc = my_realloc,
			.free = my_free
		};
		//cs_option (handle, CS_OPT_MEM, (size_t)&mem);
		ret = cs_open (CS_ARCH_X86, mode, &handle);
		if (ret) return 0;
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	n = cs_disasm_ex (handle, (const ut8*)buf, len, off, 1, &insn);
	if (n>0) {
		if (insn->size>0) {
			op->size = insn->size;
			if (insn->op_str) {
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
					insn->mnemonic, insn->op_str[0]?" ":"",
					insn->op_str);
			} else {
				eprintf ("op_str is null wtf\n");
			}
		}
	}
	cs_free (insn, n);
eprintf ("-------8<-------\n");
	bufi = 0;
	return op->size;
}

RAsmPlugin r_asm_plugin_x86_cs = {
	.name = "x86.cs",
	.desc = "Capstone X86 disassembler",
	.license = "BSD",
	.arch = "x86",
	.bits = 16|32|64,
	.init = NULL,
	.fini = the_end,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_cs
};
#endif
