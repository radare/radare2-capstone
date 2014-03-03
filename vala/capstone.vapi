[CCode (cprefix="CS_")]
namespace Capstone {
	[CCode (cprefix="CS_OPT_")]
	public enum OptionType {
		SYNTAX = 1,
		DETAIL,
		MODE,
		MEM
	}

	[CCode (cprefix="CS_API_")]
	public enum API {
		MAJOR,
		MINOR
	}

	[CCode (has_target=false)]
	public delegate void* Malloc(size_t size);
	[CCode (has_target=false)]
	public delegate void* Calloc(size_t nmemb, size_t size);
	[CCode (has_target=false)]
	public delegate void* Realloc(void *ptr, size_t size);
	[CCode (has_target=false)]
	public delegate void Free(void *ptr);
	[CCode (has_target=false)]
	public delegate string Vsnprintf(void *str, string fmt, size_t size, string ptr);

	[CCode (cname="cs_opt_mem", free_function="", destroy_function="")]
	public struct OptionMem {
		public Malloc malloc;
		public Calloc calloc;
		public Realloc realloc;
		public Free free;
		public Vsnprintf vsnprintf;
	}

	[CCode (cprefix="CS_OPT_")]
	public enum OptionValue {
		OFF = 0,
		ON = 3,
		SYNTAX_DEFAULT = 0,
		SYNTAX_INTEL,
		SYNTAX_ATT,
		SYNTAX_NOREGNAME
	}

	[CCode (cprefix="CS_SUPPORT_")]
	public enum Support {
		DIET = 1<<16;
	}

	[CCode (cname="cs_detail", cheader_filename="capstone.h")]
	public struct Detail {
		uint8 regs_read[12];
		uint8 regs_read_count;
		uint8 regs_write[20];
		uint8 regs_write_count;
		uint8 groups[8];
		uint8 groups_count;
		// union
#if CS_PPC
		Capstone.PPC ppc;
#endif
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

	[CCode (cname="cs_insn", cheader_filename="capstone.h", cprefix="cs_", free_function="")]
	public struct Insn {
		uint id;
		uint64 addr;
		uint16 size;
		char bytes[16];
		char mnemonic[32];
		char op_str[160];
		Detail *detail;
	}

	[CCode (cheader_filename="capstone.h", cprefix="CS_ARCH_")]
	public enum Arch {
		ARM = 0,
		ARM64 = 1,
		MIPS = 2,
		X86 = 3,
		PPC = 4,
		MAX = 5,
		ALL = 0xFFFF
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
		OPTION,
		DETAIL,
		MEMSETUP,
		VERSION,
		DIET
	}

	[SimpleType]
	[GIR (name = "size_t")]
	[CCode (cname="size_t", cheader_filename="sys/types.h", cprefix="cs_")]
	public struct Handle {
		public Error option (OptionType type, size_t value);
		public Error errno();
		public Error close();
		public unowned string reg_name (uint reg_id);
		public unowned string insn_name (uint insn_id);
		public bool insn_group (Insn *insn, uint group_id);
		public bool reg_read (Insn *insn, uint reg_id);
		public bool reg_write (Insn *insn, uint reg_id);
		public int op_count (Insn *insn, uint op_type);
		public int op_index (Insn *insn, uint op_type, uint position);
	}

	[CCode (cname="cs_errno")]
	public static Error errno (Handle handle);

	[CCode (cname="cs_strerror")]
	public static unowned string strerror(Error err);

	[CCode (cname="cs_version")]
	public static int version (out int major, out int minor);

	[CCode (cname="cs_support")]
	public static bool supports (int arch);

	[CCode (cname="cs_option")]
	public static Error option (size_t handle, OptionType type, size_t value);

	[CCode (cname="cs_open")]
	public static Error open (Arch arch, Mode mode, out Handle handle);

	[CCode (cname="cs_close")]
	public static int close (ref Handle handle);

	[CCode (cname="cs_reg_name")]
	public static string reg_name (Handle handle, uint reg);

	[CCode (cname="cs_insn_name")]
	public static string insn_name (Handle handle, uint insn);

	[CCode (cname="cs_insn_group")]
	public static string insn_group (Handle handle, Insn *insn, uint group_id);

	[CCode (cname="cs_free")]
	public static void free (Insn *mem, size_t count);

	[CCode (cname="cs_reg_read")]
	public static string reg_read (Handle handle, Insn *insn, uint reg_id);

	[CCode (cname="cs_reg_write")]
	public static string reg_write (Handle handle, Insn *insn, uint reg_id);

	[CCode (cname="cs_op_count")]
	public static int op_count (Handle handle, Insn *insn, uint op_type);

	[CCode (cname="cs_op_index")]
	public static int op_index (Handle handle, Insn *insn, uint op_type, uint post);

	[CCode (cname="cs_support")]
	public static bool support (int query);

	[CCode (cname="cs_disasm_ex")]
	public static size_t disasm_ex (Handle handle, void* code, size_t len, uint64 addr, size_t count, out Insn* insn);
}
