DIRS=libr
.PHONY: all clean install uninstall
all clean install uninstall:
	$(foreach dir,${DIRS},${MAKE} -C $(dir) $@;)
