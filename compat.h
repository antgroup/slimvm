/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (c) 2026 Ant Group Corporation.
 */

#ifndef __SLIMVM_COMPAT_H_
#define __SLIMVM_COMPAT_H_

#include <linux/version.h>
#include <linux/mm.h>

#include <asm/desc.h>

/* Hygon vendor id (added upstream in 4.20); fall back for older trees. */
#ifndef X86_VENDOR_HYGON
#define X86_VENDOR_HYGON 9
#endif

DECLARE_PER_CPU(struct desc_ptr, host_gdt);

#include <asm/fpu/api.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#include <asm/fpu/internal.h>
#endif

#include <linux/sched/mm.h> /* mmdrop() */
#include <linux/mm.h>

/*
 * guest_enter_irqoff() / guest_exit_irqoff() are not exported to modules on
 * recent kernels. Provide local copies (matching the in-tree definitions) so
 * both engines can account guest cputime. Shared by vmx.c and svm.c.
 */
#include <linux/context_tracking.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
static __always_inline void slimvm_guest_enter_irqoff(void)
{
	instrumentation_begin();
	vtime_account_guest_enter();
	instrumentation_end();

	if (!context_tracking_guest_enter()) {
		instrumentation_begin();
		rcu_virt_note_context_switch(smp_processor_id());
		instrumentation_end();
	}
}

static __always_inline void slimvm_guest_exit_irqoff(void)
{
	context_tracking_guest_exit();

	instrumentation_begin();
	vtime_account_guest_exit();
	instrumentation_end();
}
#define guest_enter_irqoff slimvm_guest_enter_irqoff
#define guest_exit_irqoff slimvm_guest_exit_irqoff
#endif

#if !defined(VMX_EPT_AD_BIT)
#define VMX_EPT_AD_BIT          (1ull << 21)
#define VMX_EPT_AD_ENABLE_BIT   (1ull << 6)
#endif

#ifndef VMX_EPT_EXTENT_INDIVIDUAL_BIT
#define VMX_EPT_EXTENT_INDIVIDUAL_BIT           (1ull << 24)
#endif

#ifndef X86_CR4_PCIDE
#define X86_CR4_PCIDE		0x00020000 /* enable PCID support */
#endif

#ifndef SECONDARY_EXEC_ENABLE_INVPCID
#define SECONDARY_EXEC_ENABLE_INVPCID	0x00001000
#endif

#ifndef X86_CR4_FSGSBASE
#define X86_CR4_FSGSBASE	X86_CR4_RDWRGSFS
#endif

#ifndef AR_TYPE_BUSY_64_TSS
#define AR_TYPE_BUSY_64_TSS VMX_AR_TYPE_BUSY_64_TSS
#endif

static inline u16 read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

#ifndef load_ldt
static inline void load_ldt(u16 sel)
{
	asm("lldt %0" : : "rm"(sel));
}
#endif

#ifndef __addr_ok
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define __addr_ok(addr) ((unsigned long __force)(addr) < TASK_SIZE_MAX)
#else
#define __addr_ok(addr) ((unsigned long __force)(addr) < user_addr_max())
#endif
#endif

static inline struct page *alloc_pages_exact_node(int nid, gfp_t gfp_mask,
						  unsigned int order)
{
	return alloc_pages_node(nid, gfp_mask, order);
}

static inline unsigned long read_cr3(void)
{
	return __read_cr3();
}

static inline void compat_fpu_restore(void)
{
	if (test_thread_flag(TIF_NEED_FPU_LOAD))
		switch_fpu_return();
}

static inline unsigned long vmx_read_gdt_addr(void)
{
	return (unsigned long)(void *)get_current_gdt_ro();
}

static inline unsigned long vmx_read_tr_base(int cpu)
{
	return (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss;
}

static inline void vmx_invalidate_tss_limit(void)
{
	invalidate_tss_limit();
}

static inline void vmx_load_fixmap_gdt(void)
{
	load_fixmap_gdt(raw_smp_processor_id());
}

static inline void native_store_idt(struct desc_ptr *dtr)
{
	store_idt(dtr);
}

static inline unsigned long gate_offset_compat(const gate_desc *g)
{
	return gate_offset(g);
}

#ifdef VMX_EPT_DEFAULT_MT
#define SLIMVM_VMX_EPT_DEFAULT (VMX_EPT_DEFAULT_MT | \
				VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT)
#else
#define SLIMVM_VMX_EPT_DEFAULT (VMX_EPTP_MT_WB | VMX_EPTP_PWL_4)
#endif

#ifndef VMX_EPT_AD_ENABLE_BIT
#define VMX_EPT_AD_ENABLE_BIT VMX_EPTP_AD_ENABLE_BIT
#endif

static inline long
get_user_pages_unlocked_compat(unsigned long start, unsigned long nr_pages,
			       struct page **pages, unsigned int flags)
{
	return get_user_pages_unlocked(start, nr_pages, pages, flags);
}
#endif /* __SLIMVM_COMPAT_H_ */
