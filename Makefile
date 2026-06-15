# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Ant Group Corporation.

#!/usr/bin/make -f

ifeq (,$(BUILD_KERNEL))
    BUILD_KERNEL=$(shell uname -r)
endif

KBUILD_MODPOST_WARN = 1

EXTRA_CFLAGS += -I$(src)

ifeq ($(DEBUG),y)
	EXTRA_CFLAGS += -DDEBUG
endif

# Build the AMD SVM engine alongside the Intel VMX engine. Both engines are
# linked into the single self-contained module; the matching one is bound at
# load time based on the CPU vendor.
EXTRA_CFLAGS += -DSLIMVM_HAVE_SVM

obj-m := slimvm.o
slimvm-objs := \
	vmx.o \
	core.o \
	ept.o \
	instance.o \
	mm.o \
	vcpu.o \
	vmcs.o \
	exception.o \
	seccomp.o \
	proc.o \
	svm.o \
	npt.o \
	exception_svm.o
list-m := slimvm

# KSRC should be set to the path to your sources
# modules are installed into KMISC
KVER  := $(BUILD_KERNEL)

# Allow KSRC to be overridden from command line for cross-compilation
ifeq (,$(KSRC))
    KSRC := /lib/modules/$(KVER)/build
endif

KMISC := /lib/modules/$(KVER)/kernel/drivers/misc
PWD=$(shell pwd)

all: modules

clean:
	rm -f *.mod.c *.mod *.o *.ko .*.cmd .*.flags .lst *.lst *.order *.symvers
	rm -rf .tmp_versions

distclean: clean
	rm -f tags TAGS

modules:
	$(MAKE) -C $(KSRC) M=$(PWD) modules

.PHONY: TAGS tags

install: modules
	install -d $(KMISC)
	install -m 644 -c $(addsuffix .ko,$(list-m)) $(KMISC)
	/sbin/depmod -a ${KVER}

uninstall:
	rm -rf $(addprefix $(KMISC)/,$(addsuffix .ko,$(list-m)))
	/sbin/depmod -a ${KVER}
