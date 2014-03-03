/* Vala/Capstone Example - 2013-2014 - pancake */

using Capstone;

void *bytes = "\xe9\x43\x48\x80\x00\x90\x89\xd8";
//uint8 *bytes = (void*)"\xc5\xf1\x6c\xc0\x90\xcc";
int bytes_len = 8;

public void* mycalloc(size_t nmemb, size_t size) {
	return GLib.malloc (nmemb * size);
}

void main() {
	var use_glib_malloc = false;
	Insn* insn;
	Handle csh;

	if (use_glib_malloc) {
		// Use GLib allocator functions
		OptionMem mem = OptionMem ();
		mem.malloc = GLib.malloc;
		mem.calloc = mycalloc;
		mem.realloc = GLib.realloc;
		mem.free = GLib.free;
		// TODO: mem.vsnprintf = string.vprintf;
		void *p = &mem;
		Capstone.option (0, OptionType.MEM, (size_t)p);
	}

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
			if (Capstone.support (Support.DIET)) {
				var x86 = op->detail->x86;
				var str = "";
				for (int j=0;j<x86.op_count;j++) {
					Capstone.X86Op x86op = x86.operands[j];
					switch (x86op.type) {
					case X86OpType.IMM:
						str += ", 0x%lx".printf ((ulong)x86op.imm);
						break;
					case X86OpType.REG:
						str += ", r%u".printf (x86op.reg);
						break;
					default:
						str += " (%d %d)".printf (x86op.type, x86.op_count);
						break;
					}
				}
				print ("op%u%s\n".printf (op.id, str));
			} else {
				print (@"op.id=$(op.id)\n");
				print ((string)op.mnemonic+": "+(string)op.op_str+"\n");
				if (op.detail != null) {
					var x86 = op->detail->x86;
					switch (op.id) {
					case X86Insn.JMP:
						if (x86.operands[0].type == X86OpType.IMM) {
							uint64 imm = x86.operands[0].imm;
							stdout.printf ("=== 0x%lx\n", (ulong)imm);
						}
						break;
					}
				}
			}
		}
	}
	Capstone.free (insn, n);
	Capstone.close (ref csh);
	//csh.close ();
}
