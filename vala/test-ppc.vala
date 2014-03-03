/* Vala/Capstone Example - 2014 - pancake */

using Capstone;

void main() {
	Insn* insn;
	Handle csh;

	var ret = open (Capstone.Arch.PPC, Capstone.Mode.@32, out csh);
	if (ret != Capstone.Error.OK) {
		print ("Error initializing capstone\n");
		return;
	}

	uint8 *bytes = (void*)"\x48\x83\xc7\x68";
	int bytes_len = 4;

	// not needed
	//csh.option (OptionType.DETAIL, OptionValue.ON);

	var n = disasm_ex (csh,
		(void*)bytes, bytes_len,
		0x01000, 0, out insn);
	if (n == 0) {
		print ("invalid\n");
	} else if (n>0) {
		uint64 off = 0x1000;
		Insn *op = insn;
		for (int i = 0; i<n; i++, op++) {
			print ("0x%x:  %s %s\n",
				(int)off,
				(string)op.mnemonic,
				(string)op.op_str);
			if (op.id == PpcInsn.XORI) {
				print ("Works fine!\n");
			} else {
				print ("Invalid decomposition :(!\n");
			}
			off += op.size;
		}
	}
	Capstone.free (insn, n);
	close (ref csh);
}
