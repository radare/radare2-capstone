/* Vala/Capstone Example - 2013-2014 - pancake */

using Capstone;


void *bytes = "\xe9\x43\x48\x80\x00\x90";
//uint8 *bytes = (void*)"\xc5\xf1\x6c\xc0\x90\xcc";
int bytes_len = 6;

public void* mycalloc(size_t nmemb, size_t size) {
	return GLib.malloc (nmemb * size);
}

void main() {
	Insn* insn;
	Handle csh;

	OptionMem mem = OptionMem ();
	mem.malloc = GLib.malloc;
	mem.calloc = mycalloc;
	mem.realloc = GLib.realloc;
	mem.free = GLib.free;

	// Use GLib allocator functions
	void *p = &mem;
	Capstone.option (null, OptionType.MEM, (size_t)p);

	var ret = Capstone.open (Arch.X86, Mode.@32, out csh);
	if (ret != Capstone.Error.OK) {
		stderr.printf ("Error initializing capstone\n");
		return;
	}

	csh.option (OptionType.DETAIL, OptionValue.ON);

	var n = Capstone.disasm_ex (csh, 
		(void*)bytes, bytes_len,
		0x8048000, 0, out insn);
	if (n == 0) {
		print ("invalid\n");
	} else if (n>0) {
		Insn* op = insn;
		for (int i = 0; i<n; i++, op++) {
			print ("-----\n");
			print ((string)op.mnemonic+" "+(string)op.op_str+"\n");
			print (@"op.id=$(op.id)\n");
			if (op.detail != null) {
				var x86 = op->detail->x86;
				switch (op.id) {
				case X86Insn.JMP:
					if (x86.operands[0].type == X86OpType.IMM) {
						uint64 imm = x86.operands[0].imm;
						stdout.printf ("=== 0x%lx\n",
							(ulong)imm);
					}
					break;
				}
			}
		}
	}
	Capstone.free (insn, n);
	csh.close ();
}
