PREFIX?=/usr
SO_EXT=dylib
# r2
CFLAGS=$(shell pkg-config --cflags r_asm)
LDFLAGS=$(shell pkg-config --libs r_asm)
# capstone
CFLAGS+=-I/usr/include/capstone
LDFLAGS+=/usr/lib/libcapstone.a

all:
	${CC} -fPIC -shared -o asm_x86_cs.${SO_EXT} \
		$(CFLAGS) $(LDFLAGS) asm_x86_cs.c
	${CC} -fPIC -shared -o asm_arm_cs.${SO_EXT} \
		$(CFLAGS) $(LDFLAGS) asm_arm_cs.c
	${CC} -fPIC -shared -o asm_mips_cs.${SO_EXT} \
		$(CFLAGS) $(LDFLAGS) asm_mips_cs.c

install:
	cp asm_x86_cs.${SO_EXT} ${PREFIX}/lib/radare2/last/
	cp asm_arm_cs.${SO_EXT} ${PREFIX}/lib/radare2/last/
	cp asm_mips_cs.${SO_EXT} ${PREFIX}/lib/radare2/last/

uninstall:
	rm -f ${PREFIX}/lib/radare2/last/asm_x86_cs.${SO_EXT}
	rm -f ${PREFIX}/lib/radare2/last/asm_arm_cs.${SO_EXT}
	rm -f ${PREFIX}/lib/radare2/last/asm_mips_cs.${SO_EXT}

clean:
	rm -f *.${SO_EXT}
