OBJ_X86CS=asm_x86cs.o
STATIC_OBJ+=$(OBJ_X86CS)

$(TARGET_X86CS): $(OBJ_X86CS)
	$(CC) $(call libname, asm_x86cs) $(LDFLAGS) \
		$(CFLAGS) -o asm_x86cs.$(EXT_SO) $(OBJ_X86CS)
