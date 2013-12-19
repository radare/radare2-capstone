ARCHS=x86 arm mips
include ../../../config.mk

#arm x86 mips

R2DIR=$(shell r2 -hh| grep LIBR_PLUGINS|awk '{print $$2}')

DESTDIR?=
LFX=$(DESTDIR)$(R2DIR)
ifeq ($(shell uname),Darwin)
SO_EXT=dylib
else
SO_EXT=so
endif
PKG_CONFIG=pkg-config
# r2
CFLAGS=$(shell $(PKG_CONFIG) --cflags r_anal)
LDFLAGS=$(shell $(PKG_CONFIG) --libs r_anal)
# capstone
ifeq ($(CS_STATIC),1)
CFLAGS+=$(shell $(PKG_CONFIG) --cflags capstone)
LDFLAGS+=$(shell $(PKG_CONFIG) --variable=archive capstone)
else
CFLAGS+=$(shell $(PKG_CONFIG) --cflags capstone)
LDFLAGS+=$(shell $(PKG_CONFIG) --libs capstone)
endif

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
