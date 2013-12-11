/* Vala/Capstone Example - 2013 - pancake <pancake@nopcode.org> */

using Capstone;


void *bytes = "\xe9\x43\x48\x80\x00";
//uint8 *bytes = (void*)"\xc5\xf1\x6c\xc0\x90\xcc";
int bytes_len = 5;

void main() {
	Insn* insn;
	Handle handle;

	var ret = Capstone.open (Arch.X86, Mode.@32, out handle);
	if (ret != Capstone.Error.OK) {
		stderr.printf ("Error initializing capstone\n");
		return;
	}

	var n = Capstone.disasm_dyn (handle, 
		(void*)bytes, bytes_len,
		0x8048000, 0, out insn);
	if (n == 0) {
		print ("invalid\n");
	} else if (n>0) {
		for (int i = 0; i<n; i++) {
			var op = &insn[i];
			print ((string)op.mnemonic+" "+(string)op.op_str+"\n");
			print (@"op.id=$(op.id)\n");
			if (op.id == X86Insn.JMP) {
				if (op.x86.operands[0].type == X86OpType.IMM) {
					uint64 imm = op.x86.operands[0].imm;
					stdout.printf ("=== 0x%lx\n",
						(ulong)imm);
				}
			}
		}
	}
	Capstone.free (insn);
	Capstone.close (handle);
}
