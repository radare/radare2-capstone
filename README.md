radare2-capstone
================

This package contains the plugins for r2 to use capstone
as disassembler and code analysis.

Dependencies:
-------------
* radare2 (from git)
* capstone (1.0)

How to build
------------

The plugins will be installed in the plugin's directory
of the available radare2.

	$ make
	$ sudo make install

How to use
----------

	$ rasm2 -a x86.cs -d 90
	$ r2 -a arm.cs /bin/ls
	$ r2 -a mips.cs mips-elf-file
