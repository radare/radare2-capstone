/* Vala/Capstone Example - 2013 - pancake <pancake@nopcode.org> */

using Capstone;

void main() {
	Insn* insn;
	size_t handle;

	var ret = Capstone.open (Capstone.Arch.X86, Capstone.Mode.B32, out handle);
	if (ret != Capstone.Error.OK) {
		stderr.printf ("Error initializing capstone\n");
		return;
	}

	uint8 *bytes = (void*)"\xe9\x43\x48\x80\x00";
	//uint8 *bytes = (void*)"\xc5\xf1\x6c\xc0\x90\xcc";
	int bytes_len = 5;

	int n = Capstone.disasm_dyn (handle, 
		(void*)bytes, bytes_len,
		0x8048000, 0, out insn);
	if (n == 0) {
		stderr.printf ("invalid\n");
	} else if (n>0) {
		for (int i = 0; i<n; i++) {
			var op = &insn[i];
			stdout.printf ("%s %s\n",
				(string)op.mnemonic,
				(string)op.op_str);
			stdout.printf ("--> %d\n", (int)op.id);
			if (op.id == Capstone.X86Insn.JMP) {
				if (op.x86.operands[0].type == X86OpType.IMM) {
					uint64 imm = op.x86.operands[0].imm;
					stdout.printf ("=== 0x%lx\n",
						(ulong)imm);
				}
			}
		}
	}
	Capstone.close (handle);
}
