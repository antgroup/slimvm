/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * slimvm.h - public header for SlimVM support
 */

#pragma once

#ifndef __ASSEMBLY__

#include <linux/types.h>

/*
 * IOCTL interface
 */
#define SLIMVM_MINOR 233

#define SLIMVM_RUN _IOR(SLIMVM_MINOR, 0x01, struct slimvm_config)
#define SLIMVM_SET_TSS_ADDR _IO(SLIMVM_MINOR, 0x07)
#define SLIMVM_CREATE_VCPU _IO(SLIMVM_MINOR, 0x08)
#define SLIMVM_RELEASE_VCPU _IO(SLIMVM_MINOR, 0x09)
#define SLIMVM_NMI _IO(SLIMVM_MINOR, 0x0a)

#define SLIMVM_NR_INTERRUPTS 256

#define slimvm_info(str, args...) \
	printk(KERN_INFO "SlimVM Info: " str, ##args)
#define slimvm_error(str, args...) \
	printk(KERN_ERR "SlimVM Error: " str, ##args)

extern int slimvm_debug_enable;
#define slimvm_debug(str, args...)								\
	do {														\
		if (slimvm_debug_enable)								\
			printk(KERN_DEBUG "SlimVM Debug: " str, ##args);	\
	} while (0)

/*
 * Copy from arch/x86/include/uapi/asm/kvm.h.
 */
struct slimvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};

struct slimvm_dtable {
	__u64 base;
	__u16 limit;
	__u16 padding[3];
};

struct slimvm_regs {
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
} __attribute__((packed));

struct slimvm_sregs {
	struct slimvm_segment cs, ds, es, fs, gs, ss;
	struct slimvm_segment tr, ldt;
	struct slimvm_dtable gdt, idt;
	__u64 cr0, cr2, cr3, cr4, cr8;
	__u64 efer;
	__u64 apic_base;
	__u64 interrupt_bitmap[(SLIMVM_NR_INTERRUPTS + 63) / 64];
} __attribute__((packed));

struct slimvm_config {
	struct slimvm_regs user_regs;
	struct slimvm_sregs sys_regs;
	__s64 sid;
	__s64 status;
	__u64 vcpu;
	__u64 page_fault_physical;
	__u64 mem_region_num;
	__u64 mem_region_addr;
} __attribute__((packed));

#endif /* __ASSEMBLY__ */

/*
 * The exit reasons of slimvm are divided into two parts,
 * one part is lower than 0x80, consistent with definitions
 * inside gvisor, while the other part starts from 0x80
 * for internal use.
 */
#define SLIMVM_RET_EXCEPTION 0x1
#define SLIMVM_RET_IO 0x2
#define SLIMVM_RET_HYPERCALL 0x3
#define SLIMVM_RET_DEBUG 0x4
#define SLIMVM_RET_HLT 0x5
#define SLIMVM_RET_MMIO 0x6
#define SLIMVM_RET_IRQ_WINDOW_OPEN 0x7
#define SLIMVM_RET_SHUTDOWN 0x8
#define SLIMVM_RET_FAIL_ENTRY 0x9
#define SLIMVM_RET_INTR 0xa
#define SLIMVM_RET_INTERNAL_ERROR 0x11
#define SLIMVM_RET_MSR_WRITE 0x20

#define SLIMVM_RET_EXIT 0x80
#define SLIMVM_RET_EPT_VIOLATION 0x81
/* AMD NPT uses the same exit-reason code as Intel EPT. */
#define SLIMVM_RET_NPT_VIOLATION SLIMVM_RET_EPT_VIOLATION
#define SLIMVM_RET_UNHANDLED_VMEXIT 0x82
#define SLIMVM_RET_NOENTER 0x83

/* MSRs address */
#define MSR_PLATFORM_INFO 0x000000ce
#define MSR_MISC_FEATURES_ENABLES 0x00000140

/*
 * Hack for kallsyms_lookup_name() as commit 0bd476e6c6719
 * ("kallsyms: unexport kallsyms_lookup_name() and kallsyms_on_each_symbol()")
 * unexports it.
 */
extern unsigned long (*kln_hack)(const char *name);
