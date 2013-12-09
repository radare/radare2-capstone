CS_FLAGS=--vapidir . --pkg capstone
CS_X86_FLAGS=-D CS_X86 --pkg capstone.x86 ${CS_FLAGS}
CS_ARM_FLAGS=-D CS_ARM --pkg capstone.arm ${CS_FLAGS}

all:
	valac $(CS_X86_FLAGS) test.vala 
	valac $(CS_ARM_FLAGS) test-arm.vala
