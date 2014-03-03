/* Vala/Capstone Example - 2014 - pancake */

using Capstone;

void main() {
	Insn* insn;
	Handle csh;

	var ret = Capstone.open (Capstone.Arch.ARM, Capstone.Mode.ARM, out csh);
	if (ret != Capstone.Error.OK) {
		stderr.printf ("Error initializing capstone\n");
		return;
	}

	uint8 *bytes = (void*)"\xe9\x43\x48\x80\xe9\x43\x48\x80";
	//uint8 *bytes = (void*)"\xc5\xf1\x6c\xc0\x90\xcc";
	int bytes_len = 8; //5;

	var n = Capstone.disasm_ex (csh, 
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
		}
	}
	Capstone.free (insn, n);
	Capstone.close (ref csh);
}
