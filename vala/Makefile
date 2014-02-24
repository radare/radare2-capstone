CS_FLAGS=--vapidir . --pkg capstone
CS_X86_FLAGS=-D CS_X86 --pkg capstone.x86 ${CS_FLAGS}
CS_ARM_FLAGS=-D CS_ARM --pkg capstone.arm ${CS_FLAGS}
CS_MIPS_FLAGS=-D CS_MIPS --pkg capstone.mips ${CS_FLAGS}
CS_PPC_FLAGS=-D CS_PPC --pkg capstone.ppc ${CS_FLAGS}

all:
	valac $(CS_X86_FLAGS) test-x86.vala 
	valac $(CS_ARM_FLAGS) test-arm.vala
	valac $(CS_MIPS_FLAGS) test-mips.vala
	valac $(CS_PPC_FLAGS) test-ppc.vala 

CSD=node cs-dump-enums.js
ARCHS=arm arm64 x86 ppc mips
.PHONY: all clean enums doc
enums:
	@rm -rf enums
	@mkdir -p enums
	@for a in $(ARCHS) ; do \
		for b in `$(CSD) $$a 2> enums/CSVERSION | grep // |awk '{print $$2}'` ; do \
			f="enums/$$a.$$b"; \
			printf "[ ] $$f ..." ; \
			$(CSD) $$a $$b 2> /dev/null > $$f ; \
			printf "\r[x] $$f    \n" ; \
		done ; \
	done

enums-sync:

enums-diff:

clean:
	rm -rf enums
	rm -f test-arm test-mips test-x86 test-ppc

doc:
	valadoc -o capstone *.vapi
