radare2-capstone
================

This package contains the plugins for r2 to use capstone
as disassembler and code analysis.

Dependencies:
-------------
radare2 (from git)

	git clone git://github.com/radare/radare2
	cd radare2
	sys/install.sh

capstone (> 1.0)

	git clone https://github.com/aquynh/capstone.git
	cd capstone
	git co ppc # next
	make -j 8
	make install PREFIX=/usr

How to build
------------

The plugins will be installed in the plugin's directory
of the available radare2.

	make
	sudo make install

How to use
----------

	rasm2 -a x86.cs -d 90
	r2 -a arm.cs elf-arm-linux-ls
	r2 -a mips.cs -e asm.cpu=n64 n64.rom

