/* Vala/Capstone Example - 2013 - pancake <pancake@nopcode.org> */

using Capstone;

void main() {
	Insn* insn;
	Handle handle;

	var ret = open (Capstone.Arch.MIPS, Capstone.Mode.@32, out handle);
	if (ret != Capstone.Error.OK) {
		stderr.printf ("Error initializing capstone\n");
		return;
	}

	uint8 *bytes = (void*)"\x1c\x00\x40\x14";
	int bytes_len = 4;

	var n = disasm_dyn (handle, (void*)bytes, bytes_len,
		0x01000, 0, out insn);
	if (n == 0) {
		stderr.printf ("invalid\n");
	} else if (n>0) {
		for (int i = 0; i<n; i++) {
			var op = &insn[i];
			stdout.printf ("%s %s\n",
				(string)op.mnemonic,
				(string)op.op_str);
			if (op.id == MipsInsn.BNEZ) {
				stdout.printf ("Works fine!\n");
			} else {
				stdout.printf ("Invalid decomposition :(!\n");
				stdout.printf ("op.id=%d (should be %d)\n", (int)op.id,
					MipsInsn.BNEZ);
			}
		}
	}
	close (handle);
}
