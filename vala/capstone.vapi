[CCode (cprefix="CS_")]
namespace Capstone {
	[CCode (cname="cs_insn", cheader_filename="capstone.h")]
	public struct Insn {
		uint32 id;
		uint64 addr;
		uint16 size;
		char bytes[16];
		char mnemonic[32];
		char op_str[96];
		uint32 regs_read[32];
		uint32 regs_read_count;
		uint32 regs_write[32];
		uint32 regs_write_count;
		uint32 groups[8];
		uint32 groups_count;
		// union
#if CS_X86
		Capstone.X86 x86;
#endif
#if CS_ARM
		Capstone.ARM arm;
#endif
#if CS_ARM64
		Capstone.ARM64 arm64;
#endif
#if CS_MIPS
		Capstone.MIPS mips;
#endif
	}

	[CCode (cheader_filename="capstone.h", cprefix="CS_ARCH_")]
	public enum Arch {
		ARM = 0,
		ARM64 = 1,
		MIPS = 2,
		X86 = 3
	}

	[CCode (cheader_filename="capstone.h", cprefix="CS_MODE_")]
	public enum OptType {
		SYNTAX = 1
	}
	public enum OptValue {
		SYNTAX_INTEL = 1,
		SYNTAX_ATT = 2
	}

	[CCode (cheader_filename="capstone.h", cprefix="CS_MODE_")]
	public enum Mode {
		LITTLE_ENDIAN = 0,
		ARM = 0,
		@16 = 1<<1,
		@32 = 1<<2,
		@64 = 1<<3,
		THUMB = 1<<4,
		MICRO = 1<<4,
		N64 = 1<<5,
		BIG_ENDIAN = 1<<31
	}

	[CCode (cname="cs_err", cheader_filename="capstone.h", cprefix="CS_ERR_")]
	public enum Error {
		OK = 0,
		MEM,
		ARCH,
		HANDLE,
		CSH,
		MODE,
		OPTION
	}

	[CCode (cname="cs_errno")]
	public static Error errno (size_t handle);

	[CCode (cname="cs_version")]
	public static void version (out int major, out int minor);

	[CCode (cname="cs_option")]
	public static Error option (size_t handle, OptType type, size_t value);

	[CCode (cname="cs_open")]
	public static Error open (Arch arch, Mode mode, out size_t handle);

	[CCode (cname="cs_close")]
	public static int close (size_t handle);

	[CCode (cname="cs_reg_name")]
	public static string reg_name (size_t handle, uint reg);

	[CCode (cname="cs_insn_name")]
	public static string insn_name (size_t handle, uint insn);

	[CCode (cname="cs_insn_group")]
	public static string insn_group (size_t handle, Insn *insn, uint group_id);

	[CCode (cname="cs_reg_read")]
	public static string reg_read (size_t handle, Insn *insn, uint reg_id);

	[CCode (cname="cs_reg_write")]
	public static string reg_write (size_t handle, Insn *insn, uint reg_id);

	[CCode (cname="cs_op_count")]
	public static int op_count (size_t handle, Insn *insn, uint op_type);

	[CCode (cname="cs_op_index")]
	public static int op_index (size_t handle, Insn *insn, uint op_type, uint post);

	[CCode (cname="cs_disasm")]
	public static size_t disasm (size_t handle, void* code, size_t len, uint64 addr, int count, out Insn* insn);

	[CCode (cname="cs_disasm_dyn")]
	public static size_t disasm_dyn (size_t handle, void* code, size_t len, uint64 addr, int count, out Insn* insn);
}
