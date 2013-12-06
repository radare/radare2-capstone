ARCHS=x86 arm mips

#arm x86 mips

R2DIR=$(shell r2 -hh| grep LIBR_PLUGINS|awk '{print $$2}')

DESTDIR?=
LFX=$(DESTDIR)$(R2DIR)
ifeq ($(shell uname),Darwin)
SO_EXT=dylib
else
SO_EXT=so
endif
# r2
CFLAGS=$(shell pkg-config --cflags r_anal)
LDFLAGS=$(shell pkg-config --libs r_anal)
# capstone
CFLAGS+=$(shell pkg-config --cflags capstone)
LDFLAGS+=$(shell pkg-config --libs capstone)

CFLAGS+=-g
LDFLAGS+=-g

LIBS=$(addprefix anal_,$(addsuffix _cs.$(SO_EXT), $(ARCHS)))

all: $(LIBS)

%.o: %.c
	${CC} -fPIC -c $(CFLAGS) $<

define PLUGIN_template
$(1): $(2)
	${CC} -fPIC -shared -o $(1) $(CFLAGS) $(LDFLAGS) $(2)
endef

$(foreach lib,$(LIBS),$(eval \
	$(call PLUGIN_template,$(lib),$(subst .$(SO_EXT),.o,$(lib)))))

install:
	@echo PREFIX ${LFX}
	@$(foreach arch,${ARCHS},\
		echo INSTALL anal_$(arch)_cs.$(SO_EXT) ; \
		cp -f anal_$(arch)_cs.$(SO_EXT) $(LFX) ; \
	)

uninstall:
	@echo PREFIX ${LFX}
	@$(foreach arch,${ARCHS},\
		echo UNINSTALL anal_$(arch)_cs.$(SO_EXT) ; \
		rm -f $(LFX)/anal_$(arch)_cs.$(SO_EXT)   ; \
	)

clean:
	rm -f *.${SO_EXT} *.o

.PHONY: all install uninstall clean
