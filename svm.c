/**
 *  svm.c - The Hygon SVM driver for Dune
 *
 * This file is derived from Linux KVM SVM support.
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Original Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This modified version is simpler because it avoids the following
 * features that are not requirements for Dune:
 *  * Real-mode emulation
 *  * Nested virtualization support
 *  * I/O hardware emulation
 *  * Any of the more esoteric X86 features and registers
 *  * KVM-specific functionality
 *
 * In essence we provide only the minimum functionality needed to run
 * a process in svm guest-mode rather than the full hardware emulation
 * needed to support an entire OS.
 *
 * This driver is a research prototype and as such has the following
 * limitations:
 *
 * FIXME: Backward compatability is currently a non-goal, and only recent
 * full-featured (NPT) hardware is supported by this driver.
 *
 * FIXME: We need to support hotplugged physical CPUs.
 *
 * Authors:
 *   Haibo    Tu     <tuhaibo@hygon.cn>
 *   Jiandong Zhuang <zhuangjiandong@hygon.cn>
 */

#include <linux/context_tracking.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <asm/kvm.h>

#include <asm/desc.h>
#include <asm/svm.h>
#include <asm/unistd_64.h>
#include <asm/virtext.h>
#include <asm/traps.h>
#include <asm/bitops.h>
#include <asm/prctl.h>
#include <asm/perf_event.h>
#include <asm/mach_traps.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#include <asm/fpu/xcr.h>
#endif

#include "compat.h"
#include "svm.h"
#include "slimvm.h"
#include "exception.h"
#include "seccomp.h"

#define MSR_INVALID			0xffffffffU

/*
 * Per the AMD APM the IOPM (I/O permission bitmap) covers the full 64K I/O
 * port space and the MSRPM (MSR permission bitmap) covers three MSR ranges,
 * so they must be 3 and 2 pages respectively (same sizes KVM uses).
 */
#define IOPM_SIZE	(PAGE_SIZE * 3)
#define MSRPM_SIZE	(PAGE_SIZE * 2)

static u32 *msr_bitmap;
static u32 *io_bitmap;
static struct vmcb_config vmcb_config;
static bool has_fsgsbase, has_pcid, has_osxsave, has_xsave;

static u64 __read_mostly host_xcr0;

static __read_mostly struct preempt_ops svm_preempt_ops;

#include <asm/syscall.h>

static sys_call_ptr_t svm_syscall_table[NR_syscalls] __cacheline_aligned;

static DEFINE_PER_CPU(struct svm_vcpu *, svm_local_vcpu);
static DEFINE_PER_CPU(struct svm_vcpu *, current_svm_vcpu);

#ifndef SVM_VMLOAD
#define SVM_VMLOAD ".byte 0x0f, 0x01, 0xda"
#endif
#ifndef SVM_VMRUN
#define SVM_VMRUN  ".byte 0x0f, 0x01, 0xd8"
#endif
#ifndef SVM_VMSAVE
#define SVM_VMSAVE ".byte 0x0f, 0x01, 0xdb"
#endif
#ifndef SVM_CLGI
#define SVM_CLGI   ".byte 0x0f, 0x01, 0xdd"
#endif
#ifndef SVM_STGI
#define SVM_STGI   ".byte 0x0f, 0x01, 0xdc"
#endif

#define MSR_STAR_IDX			0
#define MSR_LSTAR_IDX			1
#define MSR_CSTAR_IDX			2
#define MSR_SYSCALL_MASK_IDX		3
#define MSR_KERNEL_GS_BASE_IDX		4

static const u32 svm_msr_index[] = {
#ifdef CONFIG_X86_64
	MSR_STAR, MSR_LSTAR, MSR_CSTAR, MSR_SYSCALL_MASK, MSR_KERNEL_GS_BASE,
#endif
};

#define NR_SVM_MSR ARRAY_SIZE(svm_msr_index)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
typedef long (*do_fork_hack) (struct kernel_clone_args *args);
#elif defined(CONFIG_FORK2)
typedef long (*do_fork_hack) (struct task_struct *, struct task_struct *,
		unsigned long, unsigned long, unsigned long,
		int __user *, int __user *, unsigned long);
#else
typedef long (*do_fork_hack) (unsigned long, unsigned long, unsigned long,
		int __user *, int __user *, unsigned long);
#endif
typedef void (*do_exit_hack) (long);
typedef void (*do_group_exit_hack) (int);

static do_fork_hack __svm_do_fork = NULL;
static do_exit_hack __svm_do_exit = NULL;
static do_group_exit_hack __svm_do_group_exit = NULL;

typedef void (*task_work_run_hack) (void);
typedef void (*mem_cgroup_handle_over_high_hack) (void);
static task_work_run_hack __svm_task_work_run = NULL;
static mem_cgroup_handle_over_high_hack __svm_mem_cgroup_handle_over_high = NULL;

static inline void clgi(void)
{
	asm volatile (SVM_CLGI);
}

static inline void stgi(void)
{
	asm volatile (SVM_STGI);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static inline void vmcb_set_intercept(struct vmcb_control_area *control, u32 bit)
{
	WARN_ON_ONCE(bit >= 32 * MAX_INTERCEPT);
	__set_bit(bit, (unsigned long *)&control->intercepts);
}

static inline void vmcb_clr_intercept(struct vmcb_control_area *control, u32 bit)
{
	WARN_ON_ONCE(bit >= 32 * MAX_INTERCEPT);
	__clear_bit(bit, (unsigned long *)&control->intercepts);
}

static inline bool vmcb_is_intercept(struct vmcb_control_area *control, u32 bit)
{
	WARN_ON_ONCE(bit >= 32 * MAX_INTERCEPT);
	return test_bit(bit, (unsigned long *)&control->intercepts);
}
#endif

static inline void set_exception_intercept(struct svm_vcpu *svm, int bit)
{
	struct vmcb *vmcb = svm->vmcb;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	WARN_ON_ONCE(bit >= 32);
	vmcb_set_intercept(&vmcb->control, INTERCEPT_EXCEPTION_OFFSET + bit);
#else
	vmcb->control.intercept_exceptions |= (1ULL << bit);
#endif
}

static inline void clr_exception_intercept(struct svm_vcpu *svm, int bit)
{
	struct vmcb *vmcb = svm->vmcb;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	WARN_ON_ONCE(bit >= 32);
	vmcb_clr_intercept(&vmcb->control, INTERCEPT_EXCEPTION_OFFSET + bit);
#else
	vmcb->control.intercept_exceptions &= ~(1ULL << bit);
#endif
}

static inline void mark_dirty(struct vmcb *vmcb, int bit)
{
	vmcb->control.clean &= ~(1 << bit);
}

#define VMCB_ALWAYS_DIRTY_MASK	((1U << VMCB_INTR) | (1U << VMCB_CR2))
static inline void mark_all_clean(struct vmcb *vmcb)
{
	vmcb->control.clean = ((1 << VMCB_DIRTY_MAX) - 1)
			       & ~VMCB_ALWAYS_DIRTY_MASK;
}

static inline void mark_all_dirty(struct vmcb *vmcb)
{
	vmcb->control.clean = 0;
}

static inline void set_intercept(struct svm_vcpu *svm, int bit)
{
	struct vmcb *vmcb = svm->vmcb;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	vmcb_set_intercept(&vmcb->control, bit);
#else
	vmcb->control.intercept |= (1ULL << bit);
#endif
	mark_dirty(vmcb, VMCB_INTERCEPTS);
	return;
}

static inline void clr_intercept(struct svm_vcpu *svm, int bit)
{
	struct vmcb *vmcb = svm->vmcb;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	vmcb_clr_intercept(&vmcb->control, bit);
#else
	vmcb->control.intercept &= ~(1ULL << bit);
#endif
	mark_dirty(vmcb, VMCB_INTERCEPTS);
}

inline bool cpu_has_svm_npt_ad_bits(void)
{
	/*
	 * hygon product support ad bits
	 */

	return true;
}

static void __maybe_unused init_seg(struct vmcb_seg *seg)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK |
		SVM_SELECTOR_WRITE_MASK | SVM_SELECTOR_G_MASK; /* Read/Write Data Segment */
	seg->limit = 0xffffffff;
	seg->base = 0;
}

static void __maybe_unused init_sys_seg(struct vmcb_seg *seg, uint32_t type)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | type;
	seg->limit = 0xffff;
	seg->base = 0;
}

static void reload_tss(void)
{
	struct desc_struct *gdt;
	struct ldttss_desc *tss_desc;

	gdt = get_current_gdt_rw();
	tss_desc = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);
	tss_desc->type = 9; /* available 32/64-bit TSS */

	load_TR_desc();
}

static const u32 msrpm_ranges[] = {0, 0xc0000000, 0xc0010000};

#define NUM_MSR_MAPS ARRAY_SIZE(msrpm_ranges)
#define MSRS_RANGE_SIZE 2048
#define MSRS_IN_RANGE (MSRS_RANGE_SIZE * 8 / 2)

static u32 svm_msrpm_offset(u32 msr)
{
	u32 offset;
	int i;

	for (i = 0; i < NUM_MSR_MAPS; i++) {
		if (msr < msrpm_ranges[i] ||
				msr >= msrpm_ranges[i] + MSRS_IN_RANGE)
			continue;

		offset  = (msr - msrpm_ranges[i]) / 4; /* 4 msrs per u8 */
		offset += (i * MSRS_RANGE_SIZE);       /* add range offset */

		/* Now we have the u8 offset - but need the u32 offset */
		return offset / 4;
	}

	/* MSR not in any range */
	return MSR_INVALID;
}

/*
 * Note: This function is from linux kernel
 * @msrpm: mser permissions map area
 * @msr:   target msr
 * @read:  1 - allow guest read, 0 - intercept guest read
 * @write: 1 - allow guest write, 0 - intercept guest write
 */
static void set_msr_interception(u32 *msrpm, unsigned msr,
		int read, int write)
{
	u8 bit_read, bit_write;
	unsigned long tmp;
	u32 offset;

	/*
	 * If this warning triggers extend the direct_access_msrs list at the
	 * beginning of the file
	 */
	offset    = svm_msrpm_offset(msr);
	bit_read  = 2 * (msr & 0x0f);
	bit_write = 2 * (msr & 0x0f) + 1;
	tmp       = msrpm[offset];

	BUG_ON(offset == MSR_INVALID);

	read  ? clear_bit(bit_read,  &tmp) : set_bit(bit_read,  &tmp);
	write ? clear_bit(bit_write, &tmp) : set_bit(bit_write, &tmp);

	msrpm[offset] = tmp;
}

/**
 * copy from tracehook_notify_resume defined in linux/tracehook.h
 * svm_tracehook_notify_resume - report when about to return to guest mode
 * @regs:		guest-mode registers of @current task
 *
 * This is called when %TIF_NOTIFY_RESUME has been set.  Now we are
 * about to return to guest mode, and the guest state in @regs can be
 * inspected or adjusted.  The caller in arch code has cleared
 * %TIF_NOTIFY_RESUME before the call.  If the flag gets set again
 * asynchronously, this will be called again before we return to
 * guest mode.
 *
 * Called without locks.
 */
static inline void svm_tracehook_notify_resume(void)
{
	/*
	 * The caller just cleared TIF_NOTIFY_RESUME. This barrier
	 * pairs with task_work_add()->set_notify_resume() after
	 * hlist_add_head(task->task_works);
	 */
	smp_mb__after_atomic();
	if (unlikely(current->task_works))
		__svm_task_work_run();

	__svm_mem_cgroup_handle_over_high();
}

static int enter_guestmode_loop(struct svm_vcpu *svm, u32 cached_flags)
{
	while (true) {
		local_irq_enable();

		if (cached_flags & _TIF_NEED_RESCHED)
			schedule();

		if (cached_flags & _TIF_NOTIFY_RESUME) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			svm_tracehook_notify_resume();
		}

		if (cached_flags & _TIF_SIGPENDING) {
			/*
			 * A signal forces us to leave the run ioctl before the
			 * vcpu has produced a real VM exit, so svm->status may
			 * still hold a stale value (e.g. 0 from init). Report a
			 * valid "interrupted" status to HR3 so bluepillHandler
			 * treats it as a benign signal exit instead of an
			 * invalid status. Follows Linux KVM, whose
			 * kvm_handle_signal_exit() sets run->exit_reason =
			 * KVM_EXIT_INTR for any pending signal (fatal or not).
			 * See https://elixir.bootlin.com/linux/v6.1/source/include/linux/kvm_host.h#L2255
			 */
			if (__fatal_signal_pending(current)) {
				svm->status = SLIMVM_RET_INTR;
				local_irq_disable();
				return -1;
			}

			if (svm_signal_handler(svm)) {
				svm->status = SLIMVM_RET_INTR;
				local_irq_disable();
				return -1;
			}
		}

		local_irq_disable();
		cached_flags = READ_ONCE(current_thread_info()->flags);
		if (!(cached_flags & ENTER_UESTMODE_FLAGS))
			break;
	}

	return 0;
}

static int prepare_enter_guestmode(struct svm_vcpu *svm)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags;
	int r = 0;

	if (svm->shutdown || svm->instance->shutdown)
		return -1;

	/*
	 * In order to return to guest mode, we need to be with none of
	 * _TIF_SIGPENDING, _TIF_NOTIFY_RESUME, or _TIF_NEED_RESCHED set.
	 * Several of these flags can be set at any time on preemptable
	 * kernels if we have IRQs on, so we need to loop. Disabling
	 * preemption wouldn't help: doing the work to clear some of
	 * the flags can sleep.
	 */
	local_irq_disable();
	cached_flags = READ_ONCE(ti->flags);

	if (unlikely(cached_flags & ENTER_UESTMODE_FLAGS))
		r = enter_guestmode_loop(svm, cached_flags);

	local_irq_enable();

	return r;
}

static int svm_get_cpl(struct svm_vcpu *svm)
{
	struct vmcb *vmcb = svm->vmcb;

	return vmcb->save.cpl;
}

static void svm_load_host_msrs(struct svm_vcpu *svm)
{
	struct vmcb *vmcb = svm->vmcb;
	u64 *host_user_msrs = svm->host_user_msrs;

	if (!svm->guest_msrs_loaded)
		return;

	if (vmcb->save.star != host_user_msrs[MSR_STAR_IDX])
		wrmsrl(svm_msr_index[MSR_STAR_IDX], host_user_msrs[MSR_STAR_IDX]);

	if (vmcb->save.lstar != host_user_msrs[MSR_LSTAR_IDX])
		wrmsrl(svm_msr_index[MSR_LSTAR_IDX], host_user_msrs[MSR_LSTAR_IDX]);

	if (vmcb->save.cstar != host_user_msrs[MSR_CSTAR_IDX])
		wrmsrl(svm_msr_index[MSR_CSTAR_IDX], host_user_msrs[MSR_CSTAR_IDX]);

	if (vmcb->save.sfmask != host_user_msrs[MSR_SYSCALL_MASK_IDX])
		wrmsrl(svm_msr_index[MSR_SYSCALL_MASK_IDX], host_user_msrs[MSR_SYSCALL_MASK_IDX]);

	if (vmcb->save.kernel_gs_base != host_user_msrs[MSR_KERNEL_GS_BASE_IDX])
		wrmsrl(svm_msr_index[MSR_KERNEL_GS_BASE_IDX], host_user_msrs[MSR_KERNEL_GS_BASE_IDX]);

	svm->guest_msrs_loaded = false;
}

static void svm_save_host_msrs(struct svm_vcpu *svm)
{
	int i;

	for (i = 0; i < NR_SVM_MSR; ++i)
		rdmsrl(svm_msr_index[i], svm->host_user_msrs[i]);
}

static inline u16 svm_read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

#ifndef svm_load_ldt
static inline void svm_load_ldt(u16 sel)
{
	asm("lldt %0" : : "rm"(sel));
}
#endif

static inline void svm_load_guest_xcr0(struct svm_vcpu *svm,
		struct slimvm_config *conf)
{
	u64 cr4 = conf->sys_regs.cr4;

	if (!has_xsave)
		return;

	/*
	 * XCR0 cannot be set to 0, we use it to adjust the initialize state.
	 */
	if (svm->xcr0 == 0)
		return;

	if ((cr4 | X86_CR4_OSXSAVE) && !svm->guest_xcr0_loaded) {
		xsetbv(XCR_XFEATURE_ENABLED_MASK, svm->xcr0);
		svm->guest_xcr0_loaded = 1;
	}
}

static inline void svm_put_guest_xcr0(struct svm_vcpu *svm)
{
	if (!has_xsave)
		return;

	if (svm->guest_xcr0_loaded) {
		if (svm->xcr0 != host_xcr0)
			xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
		svm->guest_xcr0_loaded = 0;
	}
}

static __init int setup_vmcb_config(struct vmcb_config *vmcb_conf)
{
	vmcb_conf->size = PAGE_SIZE;
	vmcb_conf->order = get_order(vmcb_config.size);

	return 0;
}

static struct vmcb *__svm_alloc_vmcb(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcb *vmcb;

	pages = alloc_pages_exact_node(node, GFP_KERNEL, vmcb_config.order);
	if (!pages)
		return NULL;
	vmcb = page_address(pages);
	memset(vmcb, 0, vmcb_config.size);

	return vmcb;
}

/**
 * svm_alloc_vmcb - allocates a VMCB region
 *
 * NOTE: Assumes the new region will be used by the current CPU.
 *
 * Returns a valid VMCB region.
 */
static struct vmcb *svm_alloc_vmcb(void)
{
	return __svm_alloc_vmcb(raw_smp_processor_id());
}

/**
 * svm_free_vmcb - frees a VMCB region
 */
static void svm_free_vmcb(struct vmcb *vmcb)
{
	free_pages((unsigned long)vmcb, vmcb_config.order);
}

static void __load_vcpu(struct svm_vcpu *svm, int cpu)
{
	if (unlikely(cpu != svm->cpu)) {
		svm->asid_generation = 0;
		mark_all_dirty(svm->vmcb);
		svm->cpu = cpu;
	}
}

static void __put_vcpu(struct svm_vcpu *vcpu)
{

}

void svm_set_vcpu_mode(struct svm_vcpu *svm, u8 mode)
{
	svm->mode = mode;
	smp_wmb();
}

bool svm_check_vcpu_mode(struct svm_vcpu *svm, u8 mode)
{
	return (svm->mode == mode);
}

static void svm_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct svm_vcpu *svm = container_of(pn, struct svm_vcpu, preempt_notifier);

	rdmsrl(MSR_GS_BASE, svm->host_state.gs_base);
	savesegment(fs, svm->host_state.fs_sel);
	savesegment(gs, svm->host_state.gs_sel);
	svm->host_state.ldt_sel = svm_read_ldt();
	svm_save_host_msrs(svm);
	__load_vcpu(svm, cpu);
	svm->scheded = 1;
	this_cpu_write(current_svm_vcpu, svm);
}

static void svm_sched_out(struct preempt_notifier *pn,
		struct task_struct *next)
{
	struct svm_vcpu *svm = container_of(pn, struct svm_vcpu, preempt_notifier);

	__put_vcpu(svm);
	svm_load_ldt(svm->host_state.ldt_sel);
	wrmsrl(MSR_KERNEL_GS_BASE, current->thread.gsbase);
	loadsegment(fs, svm->host_state.fs_sel);
	load_gs_index(svm->host_state.gs_sel);
	svm_load_host_msrs(svm);
	wrmsrl(MSR_FS_BASE, current->thread.fsbase);
	svm_put_guest_xcr0(svm);
	this_cpu_write(current_svm_vcpu, NULL);
}

static void __svm_vcpu_kick(void *p)
{
}

void svm_shutdown_all_vcpus(struct instance *instp)
{
	int vcpu_no, cpu, me;
	struct svm_vcpu *svm;
	cpumask_var_t cpus;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);
	me = get_cpu();

	spin_lock(&instp->vcpu_lock);
	for_each_set_bit(vcpu_no, instp->vcpu_bitmap, VM_MAX_VCPUS) {
		svm = instp->vcpus[vcpu_no];
		if (!svm)
			continue;

		svm->shutdown = 1;

		cpu = svm->cpu;
		if (cpus != NULL && cpu != -1 && cpu != me &&
				!svm_check_vcpu_mode(svm, OUTSIDE_ROOT_MODE))
			cpumask_set_cpu(cpu, cpus);
	}
	spin_unlock(&instp->vcpu_lock);

	if (unlikely(cpus == NULL)) {
		smp_call_function_many(cpu_online_mask,
				__svm_vcpu_kick, NULL, 1);
	} else if (!cpumask_empty(cpus)) {
		smp_call_function_many(cpus,
				__svm_vcpu_kick, NULL, 1);
	}

	instp->shutdown = 1;

	put_cpu();
	free_cpumask_var(cpus);
}

void svm_sync_all_vcpus(struct instance *instp)
{
	struct svm_vcpu *svm;
	int vcpu_no;

	while (true) {
		bool r = true;

		spin_lock(&instp->vcpu_lock);
		for_each_set_bit(vcpu_no, instp->vcpu_bitmap,
				VM_MAX_VCPUS) {
			svm= instp->vcpus[vcpu_no];
			if (!svm)
				continue;

			r &= svm_check_vcpu_mode(svm, OUTSIDE_ROOT_MODE);
		}
		spin_unlock(&instp->vcpu_lock);
		if (r)
			break;
	}
}

/**
 * svm_dump_cpu - prints the CPU state
 * @vcpu: VCPU to print
 */
static void svm_dump_cpu(struct svm_vcpu *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct vmcb_save_area *save = &svm->vmcb->save;

	pr_err("VMCB Control Area:\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	pr_err("%-20s%04x\n", "cr_read:", control->intercepts[INTERCEPT_CR] & 0xffff);
	pr_err("%-20s%04x\n", "cr_write:", control->intercepts[INTERCEPT_CR] >> 16);
	pr_err("%-20s%04x\n", "dr_read:", control->intercepts[INTERCEPT_DR] & 0xffff);
	pr_err("%-20s%04x\n", "dr_write:", control->intercepts[INTERCEPT_DR] >> 16);
	pr_err("%-20s%08x\n", "exceptions:", control->intercepts[INTERCEPT_EXCEPTION]);
	pr_err("%-20s%08x %08x\n", "intercepts:",
	       control->intercepts[INTERCEPT_WORD3],
	       control->intercepts[INTERCEPT_WORD4]);
	pr_err("%-20s%d\n", "pause filter count:", control->pause_filter_count);
	pr_err("%-20s%d\n", "pause filter threshold:",
	       control->pause_filter_thresh);
	pr_err("%-20s%016llx\n", "iopm_base_pa:", control->iopm_base_pa);
	pr_err("%-20s%016llx\n", "msrpm_base_pa:", control->msrpm_base_pa);
	pr_err("%-20s%016llx\n", "tsc_offset:", control->tsc_offset);
	pr_err("%-20s%d\n", "asid:", control->asid);
	pr_err("%-20s%d\n", "tlb_ctl:", control->tlb_ctl);
	pr_err("%-20s%08x\n", "int_ctl:", control->int_ctl);
	pr_err("%-20s%08x\n", "int_vector:", control->int_vector);
	pr_err("%-20s%08x\n", "int_state:", control->int_state);
	pr_err("%-20s%08x\n", "exit_code:", control->exit_code);
	pr_err("%-20s%016llx\n", "exit_info1:", control->exit_info_1);
	pr_err("%-20s%016llx\n", "exit_info2:", control->exit_info_2);
	pr_err("%-20s%08x\n", "exit_int_info:", control->exit_int_info);
	pr_err("%-20s%08x\n", "exit_int_info_err:", control->exit_int_info_err);
	pr_err("%-20s%lld\n", "nested_ctl:", control->nested_ctl);
	pr_err("%-20s%016llx\n", "nested_cr3:", control->nested_cr3);
	pr_err("%-20s%016llx\n", "avic_vapic_bar:", control->avic_vapic_bar);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	pr_err("%-20s%016llx\n", "ghcb:", control->ghcb_gpa);
#endif
	pr_err("%-20s%08x\n", "event_inj:", control->event_inj);
	pr_err("%-20s%08x\n", "event_inj_err:", control->event_inj_err);
	pr_err("%-20s%lld\n", "virt_ext:", control->virt_ext);
	pr_err("%-20s%016llx\n", "next_rip:", control->next_rip);
	pr_err("%-20s%016llx\n", "avic_backing_page:", control->avic_backing_page);
	pr_err("%-20s%016llx\n", "avic_logical_id:", control->avic_logical_id);
	pr_err("%-20s%016llx\n", "avic_physical_id:", control->avic_physical_id);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	pr_err("%-20s%016llx\n", "vmsa_pa:", control->vmsa_pa);
#endif
	pr_err("VMCB State Save Area:\n");
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "es:",
	       save->es.selector, save->es.attrib,
	       save->es.limit, save->es.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "cs:",
	       save->cs.selector, save->cs.attrib,
	       save->cs.limit, save->cs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "ss:",
	       save->ss.selector, save->ss.attrib,
	       save->ss.limit, save->ss.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "ds:",
	       save->ds.selector, save->ds.attrib,
	       save->ds.limit, save->ds.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "fs:",
	       save->fs.selector, save->fs.attrib,
	       save->fs.limit, save->fs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "gs:",
	       save->gs.selector, save->gs.attrib,
	       save->gs.limit, save->gs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "gdtr:",
	       save->gdtr.selector, save->gdtr.attrib,
	       save->gdtr.limit, save->gdtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "ldtr:",
	       save->ldtr.selector, save->ldtr.attrib,
	       save->ldtr.limit, save->ldtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "idtr:",
	       save->idtr.selector, save->idtr.attrib,
	       save->idtr.limit, save->idtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "tr:",
	       save->tr.selector, save->tr.attrib,
	       save->tr.limit, save->tr.base);
	pr_err("cpl:            %d                efer:         %016llx\n",
	       save->cpl, save->efer);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "cr0:", save->cr0, "cr2:", save->cr2);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "cr3:", save->cr3, "cr4:", save->cr4);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "dr6:", save->dr6, "dr7:", save->dr7);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "rip:", save->rip, "rflags:", save->rflags);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "rsp:", save->rsp, "rax:", save->rax);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "star:", save->star, "lstar:", save->lstar);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "cstar:", save->cstar, "sfmask:", save->sfmask);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "kernel_gs_base:", save->kernel_gs_base,
	       "sysenter_cs:", save->sysenter_cs);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "sysenter_esp:", save->sysenter_esp,
	       "sysenter_eip:", save->sysenter_eip);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "gpat:", save->g_pat, "dbgctl:", save->dbgctl);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "br_from:", save->br_from, "br_to:", save->br_to);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "excp_from:", save->last_excp_from,
	       "excp_to:", save->last_excp_to);
#else
	pr_err("%-20s%04x\n", "cr_read:", control->intercept_cr & 0xffff);
	pr_err("%-20s%04x\n", "cr_write:", control->intercept_cr >> 16);
	pr_err("%-20s%04x\n", "dr_read:", control->intercept_dr & 0xffff);
	pr_err("%-20s%04x\n", "dr_write:", control->intercept_dr >> 16);
	pr_err("%-20s%08x\n", "exceptions:", control->intercept_exceptions);
	pr_err("%-20s%016llx\n", "intercepts:", control->intercept);
	pr_err("%-20s%d\n", "pause filter count:", control->pause_filter_count);
	pr_err("%-20s%016llx\n", "iopm_base_pa:", control->iopm_base_pa);
	pr_err("%-20s%016llx\n", "msrpm_base_pa:", control->msrpm_base_pa);
	pr_err("%-20s%016llx\n", "tsc_offset:", control->tsc_offset);
	pr_err("%-20s%d\n", "asid:", control->asid);
	pr_err("%-20s%d\n", "tlb_ctl:", control->tlb_ctl);
	pr_err("%-20s%08x\n", "int_ctl:", control->int_ctl);
	pr_err("%-20s%08x\n", "int_vector:", control->int_vector);
	pr_err("%-20s%08x\n", "int_state:", control->int_state);
	pr_err("%-20s%08x\n", "exit_code:", control->exit_code);
	pr_err("%-20s%016llx\n", "exit_info1:", control->exit_info_1);
	pr_err("%-20s%016llx\n", "exit_info2:", control->exit_info_2);
	pr_err("%-20s%08x\n", "exit_int_info:", control->exit_int_info);
	pr_err("%-20s%08x\n", "exit_int_info_err:", control->exit_int_info_err);
	pr_err("%-20s%lld\n", "nested_ctl:", control->nested_ctl);
	pr_err("%-20s%016llx\n", "nested_cr3:", control->nested_cr3);
	pr_err("%-20s%016llx\n", "avic_vapic_bar:", control->avic_vapic_bar);
	pr_err("%-20s%08x\n", "event_inj:", control->event_inj);
	pr_err("%-20s%08x\n", "event_inj_err:", control->event_inj_err);
	pr_err("%-20s%lld\n", "virt_ext", control->virt_ext);
	pr_err("%-20s%016llx\n", "next_rip:", control->next_rip);
	pr_err("%-20s%016llx\n", "avic_backing_page:", control->avic_backing_page);
	pr_err("%-20s%016llx\n", "avic_logical_id:", control->avic_logical_id);
	pr_err("%-20s%016llx\n", "avic_physical_id:", control->avic_physical_id);
	pr_err("VMCB State Save Area:\n");
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"es:", save->es.selector, save->es.attrib,
			save->es.limit, save->es.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"cs:", save->cs.selector, save->cs.attrib,
			save->cs.limit, save->cs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"ss:", save->ss.selector, save->ss.attrib,
			save->ss.limit, save->ss.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"ds:", save->ds.selector, save->ds.attrib,
			save->ds.limit, save->ds.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"fs:", save->fs.selector, save->fs.attrib,
			save->fs.limit, save->fs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"gs:", save->gs.selector, save->gs.attrib,
			save->gs.limit, save->gs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"gdtr:", save->gdtr.selector, save->gdtr.attrib,
			save->gdtr.limit, save->gdtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"ldtr:", save->ldtr.selector, save->ldtr.attrib,
			save->ldtr.limit, save->ldtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"idtr:", save->idtr.selector, save->idtr.attrib,
			save->idtr.limit, save->idtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
			"tr:", save->tr.selector, save->tr.attrib,
			save->tr.limit, save->tr.base);
	pr_err("cpl:            %d                efer:         %016llx\n",
			save->cpl, save->efer);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"cr0:", save->cr0, "cr2:", save->cr2);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"cr3:", save->cr3, "cr4:", save->cr4);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"dr6:", save->dr6, "dr7:", save->dr7);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"rip:", save->rip, "rflags:", save->rflags);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"rsp:", save->rsp, "rax:", save->rax);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"star:", save->star, "lstar:", save->lstar);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"cstar:", save->cstar, "sfmask:", save->sfmask);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"kernel_gs_base:", save->kernel_gs_base,
			"sysenter_cs:", save->sysenter_cs);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"sysenter_esp:", save->sysenter_esp,
			"sysenter_eip:", save->sysenter_eip);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"gpat:", save->g_pat, "dbgctl:", save->dbgctl);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"br_from:", save->br_from, "br_to:", save->br_to);
	pr_err("%-15s %016llx %-13s %016llx\n",
			"excp_from:", save->last_excp_from,
			"excp_to:", save->last_excp_to);
#endif

	pr_err("Guest Gerneral Register:\n");
	pr_err("%-15s %016llx %-13s %016llx\n", "rbx:",
			svm->regs[VCPU_REGS_RBX], "rcx:", svm->regs[VCPU_REGS_RCX]);
	pr_err("%-15s %016llx %-13s %016llx\n", "rdx:",
			svm->regs[VCPU_REGS_RDX], "rdi:", svm->regs[VCPU_REGS_RDI]);
	pr_err("%-15s %016llx %-13s %016llx\n", "rsi:",
			svm->regs[VCPU_REGS_RSI], "r8:", svm->regs[VCPU_REGS_R8]);
	pr_err("%-15s %016llx %-13s %016llx\n", "r9:",
			svm->regs[VCPU_REGS_R9], "r10:", svm->regs[VCPU_REGS_R10]);
	pr_err("%-15s %016llx %-13s %016llx\n", "r11:",
			svm->regs[VCPU_REGS_R11], "r12:", svm->regs[VCPU_REGS_R12]);
	pr_err("%-15s %016llx %-13s %016llx\n", "r13:",
			svm->regs[VCPU_REGS_R13], "r14:", svm->regs[VCPU_REGS_R14]);
	pr_err("%-15s %016llx\n", "r15:",
			svm->regs[VCPU_REGS_R15]);
}

u64 construct_nptp(unsigned long root_hpa)
{
	u64 nptp = 0;

	/* TODO write the value reading from MSR */
	nptp |= (root_hpa & PAGE_MASK);

	return nptp;
}

static inline u32 svm_segment_access_rights(struct slimvm_segment *var)
{
	u32 ar;

	if (var->unusable || !var->present)
		ar = 1 << 16;
	else {
		ar = var->type & SVM_SELECTOR_TYPE_MASK;
		ar |= (var->s & 1) << SVM_SELECTOR_S_SHIFT;
		ar |= (var->dpl & 3) << SVM_SELECTOR_DPL_SHIFT;
		ar |= (var->present & 1) << SVM_SELECTOR_P_SHIFT;
		ar |= (var->avl & 1) << SVM_SELECTOR_AVL_SHIFT;
		ar |= (var->l & 1) << SVM_SELECTOR_L_SHIFT;
		ar |= (var->db & 1) << SVM_SELECTOR_DB_SHIFT;
		ar |= (var->g & 1) << SVM_SELECTOR_G_SHIFT;
	}

	return ar;
}

static void svm_get_cpu_feature(void)
{
	unsigned int eax, ebx, ecx, edx;

	eax = 0x7;
	ecx = 0x0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	has_fsgsbase = !!(ebx & (1 << 0));

	eax = 0x1;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	has_pcid = !!(ecx & (1 << 17));
	has_osxsave = !!(ecx & (1 << 27));
	has_xsave = !!(ecx & (1 << 26));
}

/**
 * svm_setup_initial_guest_state - configures the initial state of guest registers
 */
static int svm_setup_initial_guest_state(struct svm_vcpu *svm,
		struct slimvm_config *conf)
{
	struct vmcb_save_area *save = &svm->vmcb->save;

#define CR0_ALWAYS_ON_FLAG X86_CR0_NE
	if (!has_pcid && (conf->sys_regs.cr4 & X86_CR4_PCIDE))
		return -1;

	if (!has_osxsave && (conf->sys_regs.cr4 & X86_CR4_OSXSAVE))
		return -1;

	if (!has_fsgsbase && (conf->sys_regs.cr4 & X86_CR4_FSGSBASE))
		return -1;

	/* configure control and data registers */
	save->cr0 = conf->sys_regs.cr0 | CR0_ALWAYS_ON_FLAG;
	save->cr3 = conf->sys_regs.cr3;
	save->cr4 = conf->sys_regs.cr4;

	save->efer = EFER_NX | EFER_SVME | EFER_LME | EFER_LMA | EFER_SCE | EFER_FFXSR;

	save->gdtr.base = conf->sys_regs.gdt.base;
	save->gdtr.limit = conf->sys_regs.gdt.limit;
	save->idtr.base = conf->sys_regs.idt.base;
	save->idtr.limit = conf->sys_regs.idt.limit;

	save->dr7 = 0;

	/* guest segment bases */
	save->cs.base = conf->sys_regs.cs.base;
	save->ds.base = conf->sys_regs.ds.base;
	save->es.base = conf->sys_regs.es.base;
	save->gs.base = conf->sys_regs.gs.base;
	save->fs.base = conf->sys_regs.fs.base;
	save->ss.base = conf->sys_regs.ss.base;
	save->tr.base = conf->sys_regs.tr.base;

	/* guest segment access rights */
	save->cs.attrib = svm_segment_access_rights(&conf->sys_regs.cs);
	save->ds.attrib = svm_segment_access_rights(&conf->sys_regs.ds);
	save->es.attrib = svm_segment_access_rights(&conf->sys_regs.es);
	save->gs.attrib = svm_segment_access_rights(&conf->sys_regs.gs);
	save->fs.attrib = svm_segment_access_rights(&conf->sys_regs.fs);
	save->ss.attrib = svm_segment_access_rights(&conf->sys_regs.ss);
	save->tr.attrib = svm_segment_access_rights(&conf->sys_regs.tr);

	/* guest segment limits*/
	save->cs.limit = conf->sys_regs.cs.limit;
	save->ds.limit = conf->sys_regs.ds.limit;
	save->es.limit = conf->sys_regs.es.limit;
	save->gs.limit = conf->sys_regs.gs.limit;
	save->fs.limit = conf->sys_regs.fs.limit;
	save->ss.limit = conf->sys_regs.ss.limit;

	/* guest segment selector */
	save->cs.selector = conf->sys_regs.cs.selector;
	save->ds.selector = conf->sys_regs.ds.selector;
	save->es.selector = conf->sys_regs.es.selector;
	save->gs.selector = conf->sys_regs.gs.selector;
	save->fs.selector = conf->sys_regs.fs.selector;
	save->ss.selector = conf->sys_regs.ss.selector;

	/* guest LDTR */
	save->ldtr.selector = conf->sys_regs.ldt.selector;
	save->ldtr.attrib = svm_segment_access_rights(&conf->sys_regs.ldt);
	save->ldtr.base = conf->sys_regs.ldt.base;
	save->ldtr.limit = conf->sys_regs.ldt.limit;

	/* guest TSS */
	save->tr.base = conf->sys_regs.tr.base;
	save->tr.attrib = svm_segment_access_rights(&conf->sys_regs.tr);
	save->tr.limit = conf->sys_regs.tr.limit;

	/* initialize sysenter */
	save->sysenter_cs = 0;
	save->sysenter_esp = 0;
	save->sysenter_eip = 0;

	mark_all_dirty(svm->vmcb);

	return 0;
}

/* svm_setup_vmcb - configures the vmcb with starting parameters */
static void svm_setup_vmcb(struct svm_vcpu *svm)
{
	u64 gpat;
	struct vmcb *vmcb = svm->vmcb;

	vmcb->control.int_ctl = V_INTR_MASKING_MASK;
	vmcb->control.nested_ctl = 1;
	vmcb->control.nested_cr3 = svm->instance->eptp;

	/* Initialize MSRs */
	rdmsrl(MSR_IA32_CR_PAT, gpat);
	vmcb->save.g_pat = gpat;

	vmcb->control.tsc_offset = 0;
	vmcb->control.iopm_base_pa = __sme_pa(io_bitmap);
	vmcb->control.msrpm_base_pa = __sme_pa(msr_bitmap);

	/* configure the control area */
	set_intercept(svm, INTERCEPT_INTR);
	set_intercept(svm, INTERCEPT_NMI);
	set_intercept(svm, INTERCEPT_SMI);
	//set_intercept(svm, INTERCEPT_SELECTIVE_CR0);
	//set_intercept(svm, INTERCEPT_RDPMC);
	//set_intercept(svm, INTERCEPT_CPUID);
	//set_intercept(svm, INTERCEPT_INVLPG);
	//set_intercept(svm, INTERCEPT_INVLPGA);
	set_intercept(svm, INTERCEPT_IOIO_PROT);
	set_intercept(svm, INTERCEPT_MSR_PROT);
	//set_intercept(svm, INTERCEPT_TASK_SWITCH);
	set_intercept(svm, INTERCEPT_SHUTDOWN);
	set_intercept(svm, INTERCEPT_VMRUN);
	set_intercept(svm, INTERCEPT_VMMCALL);
	set_intercept(svm, INTERCEPT_VMLOAD);
	set_intercept(svm, INTERCEPT_VMSAVE);
	//set_intercept(svm, INTERCEPT_STGI);
	//set_intercept(svm, INTERCEPT_CLGI);
	//set_intercept(svm, INTERCEPT_SKINIT);
	set_intercept(svm, INTERCEPT_HLT);
	set_intercept(svm, INTERCEPT_WBINVD);
	//set_intercept(svm, INTERCEPT_MONITOR);
	//set_intercept(svm, INTERCEPT_MWAIT);
	set_intercept(svm, INTERCEPT_XSETBV);

	/*
	 * FIXME: disable VM EXIT configuration for guest exception
	 *
	 * X86_TRAP_DB and X86_TRAP_BP is used for support application
	 * debugging.
	 *
	 * for kernel mode runsc code debug, we could directly using gdb,
	 * because runsc kernel code have the same HVA and GVA,
	 * and the exceptions in runsc GR0 mode will cause VM exit, when
	 * run in HR3 the exception instruction will be re-runed, this is
	 * the way how we could debug runsc kernel mode.
	 *
	 * for application run in HR3, maybe we could debug application
	 * inside Guest mode.
	 *
	 * so now, we have no requirement to enable VM exit configurations
	 * on exception X86_TRAP_DB and X86_TRAP_BP.
	 */

	mark_all_dirty(svm->vmcb);

	return;
}

static void svm_vcpu_flush_tlb(struct svm_vcpu *svm)
{
	struct vmcb *vmcb = svm->vmcb;

	vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ASID;

	return ;
}

static void iret_interception(struct svm_vcpu *svm)
{
	clr_intercept(svm, INTERCEPT_IRET);
	svm->hflags &= ~HF_NMI_MASK;
	return;
}

static void svm_process_nmi(struct svm_vcpu *svm)
{
	svm->nmi_pending = true;
}

static int svm_inject_nmi(struct svm_vcpu *svm)
{
	if (!svm_nmi_allowed(svm)) {
		slimvm_error("svm: failed to inject nmi");
		svm_dump_cpu(svm);
		return -EINVAL;
	}

	if (!(svm->hflags & HF_NMI_MASK)) {
		set_intercept(svm, INTERCEPT_IRET);
		svm->hflags |= HF_NMI_MASK;
		/* inject NMI */
		svm->vmcb->control.event_inj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_NMI;
		svm->nmi_pending = false;
	}

	return 0;
}

/*
 * Request an interrupt window: program a dummy virtual interrupt (V_IRQ) and
 * intercept VINTR so the CPU exits with SVM_EXIT_VINTR as soon as the guest is
 * able to take an interrupt (RFLAGS.IF set, no interrupt shadow). This is the
 * AMD analogue of VMX's interrupt-window exiting and is taken straight from
 * KVM's svm_set_vintr(). The window exit lets us retry the bounce injection
 * at a legal injection point instead of corrupting guest state by forcing it
 * in now.
 */
static void svm_set_vintr(struct svm_vcpu *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;

	set_intercept(svm, INTERCEPT_VINTR);

	/*
	 * A dummy V_IRQ whose only purpose is to cause the VINTR vmexit; the
	 * real event is delivered via EVENTINJ once the window is open.
	 */
	control->int_vector = 0x0;
	control->int_ctl &= ~V_INTR_PRIO_MASK;
	control->int_ctl |= V_IRQ_MASK | (0xf << V_INTR_PRIO_SHIFT);
	mark_dirty(svm->vmcb, VMCB_INTR);
}

static void svm_clear_vintr(struct svm_vcpu *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;

	clr_intercept(svm, INTERCEPT_VINTR);
	control->int_ctl &= ~(V_IRQ_MASK | V_INTR_PRIO_MASK);
	control->int_vector = 0;
	mark_dirty(svm->vmcb, VMCB_INTR);
}

static void svm_inject_bounce(struct svm_vcpu *svm)
{
	/*
	 * If the guest can't take the #VE right now (IF clear or in an
	 * interrupt shadow), don't force it - that produces spurious NPF /
	 * VMRUN failures. Instead request an interrupt window and retry on the
	 * resulting SVM_EXIT_VINTR. Mirrors vmx_inject_bounce().
	 */
	if (!svm_interrupt_allowed(svm)) {
		svm_set_vintr(svm);
		return;
	}

	svm_clear_vintr(svm);

	if (!svm_inject_vector(svm, VIRTUAL_EXCEPTION_VECTOR))
		svm->bounce_pending = false;
}

/**
 * svm_setup_registers - setup general purpose registers
 */
static void svm_setup_registers(struct svm_vcpu *svm,
		struct slimvm_config *conf)
{
	struct vmcb *vmcb = svm->vmcb;

	svm->regs[VCPU_REGS_RAX] = conf->user_regs.rax;
	svm->regs[VCPU_REGS_RBX] = conf->user_regs.rbx;
	svm->regs[VCPU_REGS_RCX] = conf->user_regs.rcx;
	svm->regs[VCPU_REGS_RDX] = conf->user_regs.rdx;
	svm->regs[VCPU_REGS_RSI] = conf->user_regs.rsi;
	svm->regs[VCPU_REGS_RDI] = conf->user_regs.rdi;
	svm->regs[VCPU_REGS_RBP] = conf->user_regs.rbp;
	svm->regs[VCPU_REGS_R8]  = conf->user_regs.r8;
	svm->regs[VCPU_REGS_R9]  = conf->user_regs.r9;
	svm->regs[VCPU_REGS_R10] = conf->user_regs.r10;
	svm->regs[VCPU_REGS_R11] = conf->user_regs.r11;
	svm->regs[VCPU_REGS_R12] = conf->user_regs.r12;
	svm->regs[VCPU_REGS_R13] = conf->user_regs.r13;
	svm->regs[VCPU_REGS_R14] = conf->user_regs.r14;
	svm->regs[VCPU_REGS_R15] = conf->user_regs.r15;

	vmcb->save.rip = conf->user_regs.rip;
	vmcb->save.rsp = conf->user_regs.rsp;
	vmcb->save.rflags = conf->user_regs.rflags;
}

/**
 * svm_copy_registers_to_conf - copy registers to slimvm_config
 */
static void svm_copy_registers_to_conf(struct svm_vcpu *svm,
		struct slimvm_config *conf)
{
	struct vmcb *vmcb = svm->vmcb;

	conf->user_regs.rax = svm->regs[VCPU_REGS_RAX];
	conf->user_regs.rbx = svm->regs[VCPU_REGS_RBX];
	conf->user_regs.rcx = svm->regs[VCPU_REGS_RCX];
	conf->user_regs.rdx = svm->regs[VCPU_REGS_RDX];
	conf->user_regs.rsi = svm->regs[VCPU_REGS_RSI];
	conf->user_regs.rdi = svm->regs[VCPU_REGS_RDI];
	conf->user_regs.rbp = svm->regs[VCPU_REGS_RBP];
	conf->user_regs.r8 = svm->regs[VCPU_REGS_R8];
	conf->user_regs.r9 = svm->regs[VCPU_REGS_R9];
	conf->user_regs.r10 = svm->regs[VCPU_REGS_R10];
	conf->user_regs.r11 = svm->regs[VCPU_REGS_R11];
	conf->user_regs.r12 = svm->regs[VCPU_REGS_R12];
	conf->user_regs.r13 = svm->regs[VCPU_REGS_R13];
	conf->user_regs.r14 = svm->regs[VCPU_REGS_R14];
	conf->user_regs.r15 = svm->regs[VCPU_REGS_R15];

	svm_get_cpu();
	conf->user_regs.rip = vmcb->save.rip;
	conf->user_regs.rsp = vmcb->save.rsp;
	conf->user_regs.rflags = vmcb->save.rflags;
	svm_put_cpu();
}

static void svm_copy_status_to_conf(struct svm_vcpu *svm,
		struct slimvm_config *conf)
{
	conf->status = svm->status;
}

/**
 * svm_create_vcpu - allocates and initializes a new virtual cpu
 *
 * Returns: A new VCPU structure
 */
struct svm_vcpu *svm_create_vcpu(struct slimvm_config *conf,
		struct instance *instp, int vcpu_no)
{
	struct svm_vcpu *svm;
	sigset_t sigset;

	svm = kzalloc(sizeof(struct svm_vcpu), GFP_KERNEL);
	if (!svm)
		return NULL;

	svm->vcpu_no = vcpu_no;

	svm->vmcb = svm_alloc_vmcb();
	if (!svm->vmcb)
		goto fail_vmcb;

	svm->vmcb_pa = __sme_set(virt_to_phys(svm->vmcb));

	svm->cpu = -1;
	svm->instance = instp;
	svm->syscall_table = (void *) &svm_syscall_table;

	svm->host_user_msrs = kzalloc(sizeof(u64) * NR_SVM_MSR, GFP_KERNEL);
	if (!svm->host_user_msrs)
		goto fail_host_user_msrs;

	svm_get_cpu();
	svm_setup_vmcb(svm);
	if (svm_setup_initial_guest_state(svm, conf)) {
		slimvm_error("Initialize guest state failed!");
		svm_put_cpu();
		goto fail_initial_guest_state;
	}
	svm_setup_registers(svm, conf);
	svm_put_cpu();

	sigfillset(&sigset);
	sigdelsetmask(&sigset, sigmask(SIGKILL) | sigmask(SIGSTOP) |
			sigmask(SIG_BOUNCE) | sigmask(SIGPROF));
	svm->sigset_active = 1;
	svm->sigset = sigset;
	svm->bounce_pending = false;
	svm->nmi_pending = false;
	svm->asid_generation = 0;
	svm->asid = 0;

	preempt_notifier_init(&svm->preempt_notifier, &svm_preempt_ops);

	return svm;

fail_initial_guest_state:
	kfree(svm->host_user_msrs);
fail_host_user_msrs:
	svm_free_vmcb(svm->vmcb);
fail_vmcb:
	kfree(svm);
	return NULL;
}

/**
 * svm_destroy_vcpu - destroys and frees an existing virtual cpu
 * @vcpu: the VCPU to destroy
 */
void svm_destroy_vcpu(struct svm_vcpu *svm)
{
	svm_get_cpu();
	svm_put_cpu();

	this_cpu_write(svm_local_vcpu, NULL);
	svm_free_vmcb(svm->vmcb);
	kfree(svm->host_user_msrs);
	kfree(svm);
}

static int svm_load_vcpu(struct svm_vcpu *svm)
{
	int cpu;

	cpu = get_cpu();
	preempt_notifier_register(&svm->preempt_notifier);

	svm_save_host_msrs(svm);
	rdmsrl(MSR_GS_BASE, svm->host_state.gs_base);
	savesegment(fs, svm->host_state.fs_sel);
	savesegment(gs, svm->host_state.gs_sel);
	svm->host_state.ldt_sel = svm_read_ldt();
	__load_vcpu(svm, cpu);
	svm->scheded = 1;

	this_cpu_write(current_svm_vcpu, svm);

	put_cpu();

	return 0;
}

static void svm_put_vcpu(struct svm_vcpu *svm)
{
	preempt_disable();

	__put_vcpu(svm);

	loadsegment(fs, svm->host_state.fs_sel);
	load_gs_index(svm->host_state.gs_sel);
	svm_load_host_msrs(svm);
	wrmsrl(MSR_FS_BASE, current->thread.fsbase);
	svm_put_guest_xcr0(svm);
	preempt_notifier_unregister(&svm->preempt_notifier);
	preempt_enable();
	this_cpu_write(current_svm_vcpu, NULL);
}

int svm_inject_event(struct svm_vcpu *svm, u64 vector)
{
	/*
	 * Inject the bounce vector (#VE, vector 20) as a virtual external
	 * interrupt (SVM_EVTINJ_TYPE_INTR), exactly as KVM's svm_inject_irq()
	 * delivers interrupts. Hardware completes the IDT vectoring at VM entry
	 * (re-running atomically if reading the IDT/handler page faults in NPT),
	 * so unlike SVM_EVTINJ_TYPE_SOFT it carries no next_rip and never races
	 * with the in-guest syscall fast-path (jmp *%rcx) - the TYPE_SOFT path
	 * corrupted guest state on ~19% of bounces in TestBounceStress.
	 *
	 * External-interrupt delivery ignores CPL and the gate DPL, so this
	 * injects regardless of guest CPL, matching the VMX engine. The caller
	 * (svm_inject_bounce) has already verified via svm_interrupt_allowed()
	 * that the guest can take the event (IF set, no interrupt shadow);
	 * otherwise it requests a VINTR window and retries.
	 */
	svm->vmcb->control.event_inj =
		SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_INTR | vector;

	return 0;
}

void svm_make_pt_regs(struct svm_vcpu *svm, struct pt_regs *regs, int sysnr)
{
	struct vmcb *vmcb = svm->vmcb;

	regs->ax = sysnr;
	regs->orig_ax = svm->regs[VCPU_REGS_RAX];
	regs->bx = svm->regs[VCPU_REGS_RBX];
	regs->cx = svm->regs[VCPU_REGS_RCX];
	regs->dx = svm->regs[VCPU_REGS_RDX];
	regs->si = svm->regs[VCPU_REGS_RSI];
	regs->di = svm->regs[VCPU_REGS_RDI];
	regs->r8 = svm->regs[VCPU_REGS_R8];
	regs->r9 = svm->regs[VCPU_REGS_R9];
	regs->r10 = svm->regs[VCPU_REGS_R10];
	regs->r11 = svm->regs[VCPU_REGS_R11];
	regs->r12 = svm->regs[VCPU_REGS_R12];
	regs->r13 = svm->regs[VCPU_REGS_R13];
	regs->r14 = svm->regs[VCPU_REGS_R14];
	regs->r15 = svm->regs[VCPU_REGS_R15];
	regs->bp = svm->regs[VCPU_REGS_RBP];

	svm_get_cpu();
	regs->ip = vmcb->save.rip;
	regs->sp = vmcb->save.rsp;
	/* FIXME: do we need to set up other flags? */
	regs->flags = (vmcb->save.rflags & 0xFF) |
		X86_EFLAGS_IF | 0x2;
	svm_put_cpu();

	/*
	 * NOTE: Since Nanovm processes use the kernel's LSTAR
	 * syscall address, we need special logic to handle
	 * certain system calls (fork, clone, etc.) The specifc
	 * issue is that we can not jump to a high address
	 * in a child process since it is not running in Nanovm.
	 * Our solution is to adopt a special Nanovm convention
	 * where the desired %RIP address is provided in %RCX.
	 */
	if (!(__addr_ok(regs->ip)))
		regs->ip = regs->cx;

	regs->cs = __USER_CS;
	regs->ss = __USER_DS;
}

static inline long
svm_do_fork(unsigned long clone_flags, unsigned long stack_start,
		struct pt_regs *regs, unsigned long stack_size,
		int __user *parent_tidptr, int __user *child_tidptr,
		unsigned long tls)
{
	struct pt_regs tmp;
	struct pt_regs *me = current_pt_regs();
	long ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	struct kernel_clone_args args = {
		.flags		= (lower_32_bits(clone_flags) & ~CSIGNAL),
		.pidfd		= parent_tidptr,
		.child_tid	= child_tidptr,
		.parent_tid	= parent_tidptr,
		.exit_signal	= (lower_32_bits(clone_flags) & CSIGNAL),
		.stack		= stack_start,
		.stack_size	= stack_size,
		.tls		= tls,
	};
#endif

	memcpy(&tmp, me, sizeof(struct pt_regs));
	memcpy(me, regs, sizeof(struct pt_regs));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	ret = __svm_do_fork(&args);
#elif defined(CONFIG_FORK2)
	ret = __svm_do_fork(current, current, clone_flags, stack_start,
			stack_size, parent_tidptr, child_tidptr, tls);
#else
	ret = __svm_do_fork(clone_flags, stack_start, stack_size,
			parent_tidptr, child_tidptr, tls);
#endif


	memcpy(me, &tmp, sizeof(struct pt_regs));
	return ret;
}

static long svm_sys_clone(struct pt_regs *regs)
{
	unsigned long newsp = regs->si;

	if (!newsp)
		newsp = regs->sp;

	return svm_do_fork(regs->di, newsp, regs, 0,
			(int *)regs->dx, (int *)regs->r10, regs->r8);
}

static long svm_sys_fork(struct pt_regs *regs)
{
	return svm_do_fork(SIGCHLD, regs->sp, regs, 0, NULL, NULL, 0);
}

static long svm_sys_vfork(struct pt_regs *regs)
{
	return svm_do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->sp,
			      regs, 0, NULL, NULL, 0);
}

static int svm_exit_syscall(struct pt_regs *regs)
{
	struct svm_vcpu *svm = this_cpu_read(current_svm_vcpu);

	svm_put_vcpu(svm);

	svm_set_vcpu_mode(svm, OUTSIDE_ROOT_MODE);
	vcpu_release(svm->instance, svm->vcpu_no);

	__svm_do_exit((regs->di & 0xff) << 8);

	return 0;
}

static int svm_exit_group(struct pt_regs *regs)
{
	/* NOTE: we're supposed to send a signal to other threads before
	 * exiting. Because we don't yet support signals we do nothing
	 * extra for now.
	 */
	struct svm_vcpu *svm = this_cpu_read(current_svm_vcpu);

	svm_put_vcpu(svm);

	svm_set_vcpu_mode(svm, OUTSIDE_ROOT_MODE);
	vcpu_release(svm->instance, svm->vcpu_no);

	__svm_do_group_exit((long) (regs->di & 0xff) << 8);

	return 0;
}

static int svm_init_syscall(void)
{
	void *syscall_table = (void *) kln_hack("sys_call_table");

	if (!syscall_table) {
		slimvm_error("Failed to lookup symbol sys_call_table");
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	__svm_do_fork = (do_fork_hack) kln_hack("kernel_clone");
#else
	__svm_do_fork = (do_fork_hack) kln_hack("_do_fork");
#endif
	if (!__svm_do_fork) {
		slimvm_error("Failed to lookup symbol _do_fork");
		return -EINVAL;
	}

	__svm_do_exit = (do_exit_hack) kln_hack("do_exit");
	if (!__svm_do_exit) {
		slimvm_error("Failed to lookup symbol do_exit");
		return -EINVAL;
	}

	__svm_do_group_exit = (do_group_exit_hack) kln_hack("do_group_exit");
	if (!__svm_do_group_exit) {
		slimvm_error("Failed to lookup symbol do_group_exit");
		return -EINVAL;
	}

	__svm_task_work_run = (task_work_run_hack) kln_hack("task_work_run");
	if (!__svm_task_work_run) {
		slimvm_error("task_work_run not found\n");
		return -EINVAL;
	}

	__svm_mem_cgroup_handle_over_high = (mem_cgroup_handle_over_high_hack)
		kln_hack("mem_cgroup_handle_over_high");
	if (!__svm_mem_cgroup_handle_over_high) {
		slimvm_error("mem_cgroup_handle_over_high not found\n");
		return -EINVAL;
	}

	memcpy(svm_syscall_table, syscall_table,
			sizeof(sys_call_ptr_t) * NR_syscalls);

	svm_syscall_table[__NR_exit] = (void *) &svm_exit_syscall;
	svm_syscall_table[__NR_exit_group] = (void *) &svm_exit_group;
	svm_syscall_table[__NR_clone] = (void *) &svm_sys_clone;
	svm_syscall_table[__NR_fork] = (void *) &svm_sys_fork;
	svm_syscall_table[__NR_vfork] = (void *) &svm_sys_vfork;

	return 0;
}

#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif

#define HIGHER_HALF_CANONICAL_ADDR 0xFFFF800000000000

static inline void svm_handle_nmi(struct svm_vcpu *svm)
{
	struct pt_regs regs;

	/* for NMI in GR3, let it be handled in stgi() */
	if (svm->flags & X86_EFLAGS_IF)
		return;

	this_cpu_write(svm_local_vcpu, svm);

	svm_make_pt_regs(svm, &regs, svm->regs[VCPU_REGS_RAX]);
	regs.flags = svm->flags;
	regs.ip = svm->regs[VCPU_REGS_RIP];

	/* In sentry GR0, we will use address among
	 *   [HIGHER_HALF_CANONICAL_ADDR, 2^64-1)
	 * when syscall just happens. To avoid conflicting with hr0,
	 * we correct these address into hr3 address.
	 */
	regs.ip &= ~HIGHER_HALF_CANONICAL_ADDR;
	regs.bp &= ~HIGHER_HALF_CANONICAL_ADDR;
	regs.sp &= ~HIGHER_HALF_CANONICAL_ADDR;

	fn_do_nmi(&regs);

	this_cpu_write(svm_local_vcpu, NULL);
}

/*
 * ---------------------------------------------------------------------------
 * SVM hardware enable + ASID management.
 *
 * Absorbed from the standalone avirt-hygon driver (avirt_svm.c, derived from
 * Linux KVM SVM support) so that SlimVM stays self-contained and does not
 * depend on an external module - mirroring how the VMX engine performs VMXON
 * on all CPUs itself.
 * ---------------------------------------------------------------------------
 */

struct svm_cpu_data {
	int cpu;

	u64 asid_generation;
	u32 max_asid;
	u32 next_asid;
	u32 min_asid;

	struct page *save_area;
};

static DEFINE_PER_CPU(struct svm_cpu_data *, svm_cpu_data);
static atomic_t svm_enable_failed;
static DEFINE_PER_CPU(int, svm_enabled);

/*
 * svm_update_asid - assign an ASID to the vcpu, bumping the generation (and
 * requesting a full TLB flush) when the per-CPU ASID space is exhausted.
 */
static void svm_update_asid(struct vmcb *vmcb, u64 *generation, u32 *asid)
{
	struct svm_cpu_data *sd = per_cpu(svm_cpu_data, raw_smp_processor_id());

	if (*generation == sd->asid_generation)
		return;

	if (sd->next_asid > sd->max_asid) {
		++sd->asid_generation;
		sd->next_asid = sd->min_asid;
		vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
		mark_dirty(vmcb, VMCB_ASID);
	}

	*generation = sd->asid_generation;
	*asid = sd->next_asid++;
}

/* Low-level enable of SVM mode on the current CPU. */
static int __svm_hardware_enable(struct svm_cpu_data *sd)
{
	uint64_t efer;

	rdmsrl(MSR_EFER, efer);
	if (efer & EFER_SVME)
		return -EBUSY;

	wrmsrl(MSR_EFER, efer | EFER_SVME);
	wrmsrl(MSR_VM_HSAVE_PA, __sme_page_pa(sd->save_area));

	return 0;
}

/*
 * Allocate the per-CPU svm_cpu_data and host save area for @cpu. Run from a
 * sleepable context (svm_hardware_enable_all), never from the on_each_cpu IPI
 * callback, which must not allocate.
 */
static int svm_cpu_init(int cpu)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned int max_sev_asid;
	struct svm_cpu_data *sd;

	sd = kzalloc(sizeof(struct svm_cpu_data), GFP_KERNEL);
	if (!sd) {
		slimvm_error("svm: cannot allocate svm_cpu_data\n");
		return -ENOMEM;
	}

	sd->cpu = cpu;
	sd->save_area = alloc_page(GFP_KERNEL);
	if (!sd->save_area) {
		kfree(sd);
		return -ENOMEM;
	}
	clear_page(page_address(sd->save_area));

	/* Reserve ASIDs used by SEV (CPUID 0x8000001f leaf). */
	cpuid(0x8000001f, &eax, &ebx, &ecx, &edx);
	max_sev_asid = ecx;
	sd->asid_generation = 1;
	sd->max_asid = cpuid_ebx(SVM_CPUID_FUNC) - 1;
	sd->next_asid = sd->max_asid + 1;
	sd->min_asid = max_sev_asid + 1;

	per_cpu(svm_cpu_data, cpu) = sd;

	return 0;
}

static void svm_cpu_uninit(int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_cpu_data, cpu);

	if (!sd)
		return;

	per_cpu(svm_cpu_data, cpu) = NULL;
	__free_page(sd->save_area);
	kfree(sd);
}

/*
 * IPI callback: must not sleep or allocate. The per-CPU state was already set
 * up by svm_cpu_init(); here we only flip EFER.SVME and program the host save
 * area.
 */
static void svm_hardware_enable(void *unused)
{
	struct svm_cpu_data *sd = per_cpu(svm_cpu_data, raw_smp_processor_id());
	int ret;

	if (!sd) {
		atomic_inc(&svm_enable_failed);
		return;
	}

	ret = __svm_hardware_enable(sd);
	if (ret) {
		atomic_inc(&svm_enable_failed);
		slimvm_error("svm: failed to enable SVM, err = %d\n", ret);
		return;
	}

	this_cpu_write(svm_enabled, 1);
}

/*
 * IPI callback: must not sleep or free memory. Only flip EFER.SVME off; the
 * per-CPU save area is released by svm_cpu_uninit() from a sleepable context.
 */
static void svm_hardware_disable(void *unused)
{
	uint64_t efer;

	if (__this_cpu_read(svm_enabled)) {
		rdmsrl(MSR_EFER, efer);
		wrmsrl(MSR_EFER, efer & ~EFER_SVME);
		wrmsrl(MSR_VM_HSAVE_PA, 0);
		this_cpu_write(svm_enabled, 0);
	}
}

/**
 * svm_run_vcpu - launches the CPU into guest mode
 * @vcpu: the svm instance to launch
 */
static int __noclone svm_run_vcpu(struct svm_vcpu *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct vmcb_save_area *save = &svm->vmcb->save;

	save->rax = svm->regs[VCPU_REGS_RAX];
	save->cr2 = svm->cr2;

	svm_update_asid(svm->vmcb, &svm->asid_generation, &svm->asid);
	if (unlikely(svm->asid != svm->vmcb->control.asid)) {
		svm->vmcb->control.asid = svm->asid;
		mark_dirty(svm->vmcb, VMCB_ASID);
	}

	clgi();

	local_irq_enable();

	asm volatile (
			"push %%" _ASM_BP "; \n\t"
			"mov %c[rbx](%[svm]), %%" _ASM_BX " \n\t"
			"mov %c[rcx](%[svm]), %%" _ASM_CX " \n\t"
			"mov %c[rdx](%[svm]), %%" _ASM_DX " \n\t"
			"mov %c[rsi](%[svm]), %%" _ASM_SI " \n\t"
			"mov %c[rdi](%[svm]), %%" _ASM_DI " \n\t"
			"mov %c[rbp](%[svm]), %%" _ASM_BP " \n\t"
#ifdef CONFIG_X86_64
			"mov %c[r8](%[svm]),  %%r8  \n\t"
			"mov %c[r9](%[svm]),  %%r9  \n\t"
			"mov %c[r10](%[svm]), %%r10 \n\t"
			"mov %c[r11](%[svm]), %%r11 \n\t"
			"mov %c[r12](%[svm]), %%r12 \n\t"
			"mov %c[r13](%[svm]), %%r13 \n\t"
			"mov %c[r14](%[svm]), %%r14 \n\t"
			"mov %c[r15](%[svm]), %%r15 \n\t"
#endif
			/* Enter guest mode */
			"push %%" _ASM_AX " \n\t"
			"mov %c[vmcb](%[svm]), %%" _ASM_AX " \n\t"
			SVM_VMLOAD "\n\t"
			SVM_VMRUN "\n\t"
			SVM_VMSAVE "\n\t"
			"pop %%" _ASM_AX " \n\t"

			/* Save guest registers, load host registers */
			"mov %%" _ASM_BX ", %c[rbx](%[svm]) \n\t"
			"mov %%" _ASM_CX ", %c[rcx](%[svm]) \n\t"
			"mov %%" _ASM_DX ", %c[rdx](%[svm]) \n\t"
			"mov %%" _ASM_SI ", %c[rsi](%[svm]) \n\t"
			"mov %%" _ASM_DI ", %c[rdi](%[svm]) \n\t"
			"mov %%" _ASM_BP ", %c[rbp](%[svm]) \n\t"
#ifdef CONFIG_X86_64
			"mov %%r8,  %c[r8](%[svm]) \n\t"
			"mov %%r9,  %c[r9](%[svm]) \n\t"
			"mov %%r10, %c[r10](%[svm]) \n\t"
			"mov %%r11, %c[r11](%[svm]) \n\t"
			"mov %%r12, %c[r12](%[svm]) \n\t"
			"mov %%r13, %c[r13](%[svm]) \n\t"
			"mov %%r14, %c[r14](%[svm]) \n\t"
			"mov %%r15, %c[r15](%[svm]) \n\t"
#endif
			"pop %%" _ASM_BP
			:
			: [svm]"a"(svm),
		[vmcb]"i"(offsetof(struct svm_vcpu, vmcb_pa)),
		[rbx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RBP]))
#ifdef CONFIG_X86_64
			, [r8]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R15]))
#endif
			: "cc", "memory"
#ifdef CONFIG_X86_64
			, "rbx", "rcx", "rdx", "rsi", "rdi"
			, "r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15"
#else
			, "ebx", "ecx", "edx", "esi", "edi"
#endif
			);

#ifdef CONFIG_X86_64
	wrmsrl(MSR_GS_BASE, svm->host_state.gs_base);
#else
	loadsegment(fs, svm->host_state.fs_sel);
#ifndef CONFIG_X86_32_LAZY_GS
	loadsegment(gs, svm->host_state.gs_sel);
#endif
#endif
	reload_tss();

	local_irq_disable();

	svm->cr2 = save->cr2;
	svm->regs[VCPU_REGS_RAX] = save->rax;
	svm->regs[VCPU_REGS_RIP] = save->rip;
	svm->flags = save->rflags;

	/*
	 * On AMD platform, the NMI generated by PMU will be held pending until
	 * the `stgi` instruction is executed. And the pending NMI will be serviced
	 * immediately when we execute the `stgi` instruction.
	 *
	 * Here we call svm_handle_nmi() before stgi() to let perf NMI handler use
	 * the pt_regs generated from svm and get the correct GR0 call stack.
	 */
	if (unlikely(control->exit_code == SVM_EXIT_NMI))
		svm_handle_nmi(svm);

	stgi();

	svm->vmcb->control.tlb_ctl = TLB_CONTROL_DO_NOTHING;

	mark_all_clean(svm->vmcb);

	return control->exit_code;
}

static inline void svm_step_instruction(struct svm_vcpu *svm)
{
	unsigned long rip;
	struct vmcb *vmcb = svm->vmcb;

	svm_get_cpu();
	rip = vmcb->control.next_rip;
	vmcb->save.rip = rip;
	svm_put_cpu();

	svm->regs[VCPU_REGS_RIP] = rip;

	return;
}

static inline void svm_process_step_instructions(int reason, struct svm_vcpu *svm)
{
	if (reason == SVM_EXIT_VMMCALL||
			reason == SVM_EXIT_CPUID ||
			reason == SVM_EXIT_MSR ||
			reason == SVM_EXIT_HLT ||
			reason == SVM_EXIT_XSETBV)
		svm_step_instruction(svm);
}

static int svm_handle_npt_violation(struct svm_vcpu *svm)
{
	unsigned long gpa;
	int exit_qual, ret;
	struct vmcb *vmcb = svm->vmcb;
	struct instance *instp;

	svm_get_cpu();
	exit_qual = vmcb->control.exit_info_1;
	gpa = __sme_clr(vmcb->control.exit_info_2);
	svm_put_cpu();

	ret = svm_do_npt_violation(svm->instance, gpa, 0, exit_qual);

	/*
	 * if the ret is -ERESTARTSYS, it means that the current has SIGKILL
	 * signal.
	 */
	switch (ret) {
	case 0:
	case -ERESTARTSYS:
		break;
	case -ENOMEM:
		/* Return -ENOMEM to HR3. */
		break;
	default:
		instp = svm->instance;

		slimvm_debug(
		"svm: sandbox %08lx NPT fault (err: %d) GPA: 0x%lx",
			instp->sid, ret, gpa);
		/*
		 * FIXME:
		 * If a NPT fault failure occur, the guest instance should be killed forcely.
		 * It should be a bug for guest instance or slimvm.
		 */
		svm->status = SLIMVM_RET_NPT_VIOLATION;
		if (slimvm_debug_enable) {
			svm_dump_cpu(svm);
		}
		break;
	}

	return ret;
}

static noinline void svm_handle_syscall(struct svm_vcpu *svm)
{
	__u64 orig_rax;
	struct vmcb *vmcb= svm->vmcb;
	struct pt_regs regs;

	orig_rax = svm->regs[VCPU_REGS_RAX];
	if (unlikely(orig_rax >= NR_syscalls)) {
		svm->regs[VCPU_REGS_RAX] = -ENOSYS;
		return;
	}

	svm_make_pt_regs(svm, &regs, orig_rax);

	svm->regs[VCPU_REGS_RAX] = svm_syscall_table[orig_rax](&regs);

	if (signal_pending(current)) {
		/* Whee! Actually interrrupted by signal. */
		switch (svm->regs[VCPU_REGS_RAX]) {
			case -ERESTARTNOHAND:
			case -ERESTART_RESTARTBLOCK:
				svm->regs[VCPU_REGS_RAX] = -EINTR;
				break;
			case -ERESTARTSYS:
				/*
				 * __NR_futex and __NR_ppoll are handled and invoke
				 * again from Sentry and runtime. sentry would change
				 * syscall path when to upgrade nanovm platform.
				 *
				 * TODO: Handle all syscalls in general when it is
				 * interrrupted by signal and returns -ERESTARTSYS.
				 */
				if (orig_rax == __NR_futex || orig_rax == __NR_ppoll) {
					svm->regs[VCPU_REGS_RAX] = -EINTR;
					break;
				}
				fallthrough;
			case -ERESTARTNOINTR:
				svm->regs[VCPU_REGS_RAX] = orig_rax;
				svm_get_cpu();
				vmcb->save.rip -= 3;
				svm_put_cpu();
				break;
		}
	} else {
		switch (svm->regs[VCPU_REGS_RAX]) {
			case -ERESTARTNOHAND:
			case -ERESTARTSYS:
			case -ERESTARTNOINTR:
				svm->regs[VCPU_REGS_RAX] = orig_rax;
				svm_get_cpu();
				vmcb->save.rip -= 3;
				svm_put_cpu();
				break;
			case -ERESTART_RESTARTBLOCK:
				svm->regs[VCPU_REGS_RAX] = __NR_restart_syscall;
				svm_get_cpu();
				vmcb->save.rip -= 3;
				svm_put_cpu();
				break;
		}
	}
}

static void svm_handle_cpuid(struct svm_vcpu *svm)
{
	unsigned int eax, ebx, ecx, edx;

	eax = svm->regs[VCPU_REGS_RAX];
	ecx = svm->regs[VCPU_REGS_RCX];
	native_cpuid(&eax, &ebx, &ecx, &edx);
	svm->regs[VCPU_REGS_RAX] = eax;
	svm->regs[VCPU_REGS_RBX] = ebx;
	svm->regs[VCPU_REGS_RCX] = ecx;
	svm->regs[VCPU_REGS_RDX] = edx;
}

static int __maybe_unused svm_handle_nmi_exception(struct svm_vcpu *svm)
{
	u32 int_info;
	struct vmcb *vmcb = svm->vmcb;

	svm_get_cpu();
	int_info = vmcb->control.exit_int_info;
	svm_put_cpu();

	if ((int_info & SVM_EXITINTINFO_TYPE_MASK) == SVM_EXITINTINFO_TYPE_NMI)
		return 0;

	/* Check & handle debug exceptions */
	// pr_debug("svm: got interrupt, int_info 0x%x Interrupt: 0x%x, rip 0x%016llx\n",
	//		int_info, int_info & SVM_EXITINTINFO_VEC_MASK, vmcb->save.rip);

	svm_exception_handler(int_info, svm);

	svm->status = int_info & SVM_EXITINTINFO_VEC_MASK;
	return 0;
}

static int svm_handle_msr_read(struct svm_vcpu *svm)
{
	u32 msr_addr;
	u64 msr_data;

	msr_addr = svm->regs[VCPU_REGS_RCX];

	switch (msr_addr) {
	case MSR_STAR:
		msr_data = svm->vmcb->save.star;
		break;
	case MSR_LSTAR:
		msr_data = svm->vmcb->save.lstar;
		break;
	case MSR_CSTAR:
		msr_data = svm->vmcb->save.cstar;
		break;
	case MSR_KERNEL_GS_BASE:
		msr_data = svm->vmcb->save.kernel_gs_base;
		break;
	case MSR_SYSCALL_MASK:
		msr_data = svm->vmcb->save.sfmask;
		break;
	default:
		slimvm_error("%s unspport msr [0x%x] read\n", __func__, msr_addr);
		return -1;
	}

	svm->regs[VCPU_REGS_RAX] = msr_data & -1u;
	svm->regs[VCPU_REGS_RDX] = msr_data >> 32;

	return 0;
}

static int svm_handle_msr_write(struct svm_vcpu *svm)
{
	u32 msr_addr;
	u64 msr_data;
	struct vmcb *vmcb = svm->vmcb;

	msr_addr = svm->regs[VCPU_REGS_RCX];
	msr_data = (svm->regs[VCPU_REGS_RAX] & -1u)
		   | ((u64)(svm->regs[VCPU_REGS_RDX] & -1u) << 32);

	switch(msr_addr) {
	case MSR_STAR:
		vmcb->save.star = msr_data;
		break;
	case MSR_LSTAR:
		vmcb->save.lstar = msr_data;
		break;
	case MSR_CSTAR:
		vmcb->save.cstar = msr_data;
		break;
	case MSR_KERNEL_GS_BASE:
		vmcb->save.kernel_gs_base = msr_data;
		break;
	case MSR_SYSCALL_MASK:
		vmcb->save.sfmask = msr_data;
		break;
	default:
		slimvm_error("%s unspport msr [0x%x] write\n", __func__, msr_addr);
		return -1;
	}

	return 0;
}

static int handle_msr(struct svm_vcpu *svm)
{
	if (svm->vmcb->control.exit_info_1)
		return svm_handle_msr_write(svm);
	else
		return svm_handle_msr_read(svm);
}

/*
 * svm_handle_interrupt_events
 *
 * interrupt events need to be injected into guest
 */
static void svm_handle_interrupt_events(struct svm_vcpu *svm, u32 exit_int_info)
{
	if (exit_int_info & SVM_EXITINTINFO_VALID) {
		/* soft interrupt events inject push nrip on the stack */
		if ((exit_int_info & SVM_EXITINTINFO_TYPE_MASK) == SVM_EXITINTINFO_TYPE_SOFT) {
			// slimvm_info("rip 0x%016llx, nrip 0x%016llx", svm->vmcb->save.rip,
			//		svm->vmcb->control.next_rip);
			svm->vmcb->control.next_rip = svm->vmcb->save.rip;
		}

		/* inject interrupt event*/
		if (exit_int_info & SVM_EXITINTINFO_VALID_ERR)
			svm->vmcb->control.event_inj_err =
				svm->vmcb->control.exit_int_info_err;
		svm->vmcb->control.event_inj = exit_int_info;
		// slimvm_info("exit code 0x%x, inject info 0x%x", svm->vmcb->control.exit_code, exit_int_info);
	}

	return;
}

/*
 * TODO
 */
static void svm_set_interrupt_shadow(struct svm_vcpu *svm, int mask)
{

	if (mask == 0)
		svm->vmcb->control.int_state &= ~SVM_INTERRUPT_SHADOW_MASK;
	else
		svm->vmcb->control.int_state |= SVM_INTERRUPT_SHADOW_MASK;

	return;
}

static void skip_emulated_instruction(struct svm_vcpu *svm)
{
	svm_get_cpu();

	/* skipping an emulated instruction also counts */
	svm_set_interrupt_shadow(svm, 0);

	svm_put_cpu();
}

static int emulate_vcpu_halt(struct svm_vcpu *svm)
{
	skip_emulated_instruction(svm);
	svm->status = SLIMVM_RET_HLT;

	return 1;
}

static int handle_halt(struct svm_vcpu *svm)
{
	return emulate_vcpu_halt(svm);
}

/*
 * Handle xsetbv instruction from guest.
 */
static int handle_xsetbv(struct svm_vcpu *svm)
{
	u64 xcr0 = (svm->regs[VCPU_REGS_RAX] & -1u)
		| ((u64)(svm->regs[VCPU_REGS_RDX] & -1u) << 32);
	u32 index = svm->regs[VCPU_REGS_RCX];

	/*
	 * FIXME: we should adjust the CPL is 0 or 3.
	 * Wait anthor patch to fix this.
	 */

	/* Only support XCR_XFEATURE_ENABLED_MASK(xcr0) now  */
	if (index != XCR_XFEATURE_ENABLED_MASK)
		return 1;

	if (!(xcr0 & XFEATURE_MASK_FP))
		return 1;

	if ((xcr0 & XFEATURE_MASK_YMM) && !(xcr0 & XFEATURE_MASK_SSE))
		return 1;

	if ((!(xcr0 & XFEATURE_MASK_BNDREGS)) !=
			(!(xcr0 & XFEATURE_MASK_BNDCSR)))
		return 1;

	if (xcr0 & XFEATURE_MASK_AVX512) {
		if (!(xcr0 & XFEATURE_MASK_YMM))
			return 1;
		if ((xcr0 & XFEATURE_MASK_AVX512) != XFEATURE_MASK_AVX512)
			return 1;
	}

	svm->xcr0 = xcr0;
	return 0;
}

static inline void svm_process_vcpu_requests(struct svm_vcpu *svm)
{
	if (svm->requests) {
		if (svm_check_request(SLIMVM_REQ_TLB_FLUSH, svm))
			svm_vcpu_flush_tlb(svm);
		if (svm_check_request(SLIMVM_REQ_NMI, svm))
			svm_process_nmi(svm);
	}

	return;
}

/**
 * svm_launch - the main loop for a svm Nanovm process
 * @conf: the launch configuration
 */
int svm_launch(struct svm_vcpu *svm, struct slimvm_config *conf)
{
	int reason, last_vmexit = 0, done = 0, r = 0;
	u32 exit_int_info;
	sigset_t sigsaved;
	struct vmcb *vmcb = svm->vmcb;

	if (svm->sigset_active)
		sigprocmask(SIG_SETMASK, &svm->sigset, &sigsaved);

	svm_load_vcpu(svm);

	while(1) {
		if (prepare_enter_guestmode(svm))
			break;

		preempt_disable();

		svm_process_vcpu_requests(svm);

		/*
		 * We assume that a Nanovm process will always use
		 * the FPU whenever it is entered, and thus we go
		 * ahead and load FPU state here. The reason is
		 * that we don't monitor or trap FPU usage inside
		 * a Nanovm process.
		 */
		compat_fpu_restore();

		if (svm->bounce_pending)
			svm_inject_bounce(svm);

		/*
		 * Sentry relies on NMI to send SIGBUS to GR3 application.
		 * Here we try best to inject NMI to guest, otherwise,
		 * return error to HR3.
		 */
		if (svm->nmi_pending) {
			r = svm_inject_nmi(svm);
			if (r) {
				svm_set_vcpu_mode(svm, OUTSIDE_GUEST_MODE);
				preempt_enable();
				break;
			}
		}

		/*
		 * For handling trap, debugger maybe modify the guest registers.
		 * The new register values should be written into guest.
		 * But, to avoid vcpu is rescheduled while handle trap signals, we
		 * should write the guest registers after update vapic address.
		 */
		if (unlikely(svm->debug_mode))
			svm_exceptions_restore_guest_regs(svm); //TODO, exception.c

		local_irq_disable();
		svm_set_vcpu_mode(svm, IN_GUEST_MODE);

		if (svm_check_vcpu_mode(svm, EXITING_GUEST_MODE) ||
				svm->requests || need_resched()) {
			svm_set_vcpu_mode(svm, OUTSIDE_GUEST_MODE);
			local_irq_enable();
			preempt_enable();
			continue;
		}

		if (svm->scheded) {
			svm_load_guest_xcr0(svm, conf);
			svm->scheded = 0;
		} else {
			if (last_vmexit == SVM_EXIT_XSETBV)
				svm_load_guest_xcr0(svm, conf);
		}

		svm->guest_msrs_loaded = true;

		guest_enter_irqoff();

		reason = svm_run_vcpu(svm);

		svm_set_vcpu_mode(svm, OUTSIDE_GUEST_MODE);

		last_vmexit = reason;


		exit_int_info = vmcb->control.exit_int_info;
		svm_handle_interrupt_events(svm, exit_int_info);

		guest_exit_irqoff();

		local_irq_enable();
		preempt_enable();

		svm_process_step_instructions(reason, svm);

		switch (reason) {
			case SVM_EXIT_VMMCALL:
				if (likely(!svm_get_cpl(svm))) {
					if (!do_seccomp_filter(svm->regs)) {
						svm_handle_syscall(svm);
					} else {
						done = 1;
						svm_shutdown_all_vcpus(svm->instance);
					}
				}
				break;
			case SVM_EXIT_CPUID:
				svm_handle_cpuid(svm);
				break;
			case SVM_EXIT_NPF:
				r = svm_handle_npt_violation(svm);
				if (r < 0) {
					done = SLIMVM_RET_INTERNAL_ERROR;
					svm->status = done;
				}
				/*
				 * On success, leave svm->status untouched. Follows
				 * Linux KVM, where npf_interception() resumes the
				 * guest without touching run->exit_reason. Writing 0
				 * here would leak a transient invalid status to HR3
				 * if the vcpu later leaves the ioctl right after.
				 */
				break;
			case SVM_EXIT_HLT:
				done = handle_halt(svm);
				break;
			case SVM_EXIT_NMI:
				break;
			case SVM_EXIT_IRET:
				iret_interception(svm);
				break;
			case SVM_EXIT_MSR:
				done = handle_msr(svm);
				break;
			case SVM_EXIT_XSETBV:
				handle_xsetbv(svm);
				break;
			case SVM_EXIT_VINTR:
				/*
				 * The interrupt window requested by svm_inject_bounce()
				 * is now open. Tear down the dummy V_IRQ; the pending
				 * bounce is re-injected by svm_inject_bounce() at the
				 * top of the next iteration, where the guest can now
				 * legally take it. Mirrors VMX's INTERRUPT_WINDOW exit.
				 */
				svm_clear_vintr(svm);
				break;
			case SVM_EXIT_INTR:
				break;
			default:
				if (reason == SVM_EXIT_SHUTDOWN || reason == SVM_EXIT_ERR)
					svm->status = SLIMVM_RET_FAIL_ENTRY;
				else
					svm->status = SLIMVM_RET_UNHANDLED_VMEXIT;
				slimvm_error("unhandler exit reason 0x%08x\n", reason);
				svm_dump_cpu(svm);
				done = 1;
		}

		if (done || svm->shutdown)
			break;
	}

	svm_put_vcpu(svm);

	svm_copy_status_to_conf(svm, conf);
	svm_copy_registers_to_conf(svm, conf);

	if (svm->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	svm_set_vcpu_mode(svm, OUTSIDE_ROOT_MODE);

	if (signal_pending(current))
		r = -EINTR;


	return r;
}

/**
 * svm_hardware_enable_all - the main initialization routine for the SVM engine
 */
int svm_hardware_enable_all(void)
{
	int r, cpu;
	const char *msg;

	if (!cpu_has_svm(&msg)) {
		slimvm_error("svm: %s\n", msg);
		return -EIO;
	}

	if (!boot_cpu_has(X86_FEATURE_NPT)) {
		slimvm_error("svm: CPU is missing NPT feature\n");
		return -EIO;
	}

	fn_do_nmi = (void *) kln_hack("exc_nmi");
	if (!fn_do_nmi) {
		slimvm_error("failed to get exc_nmi\n");
		return -EINVAL;
	}

	svm_get_cpu_feature();

	if (svm_init_syscall()) {
		slimvm_error("failed to get syscall table");
		return -EINVAL;
	}

	if (exceptions_init()) {
		slimvm_error("failed to init exceptions (get_signal)\n");
		return -EINVAL;
	}

	if (setup_vmcb_config(&vmcb_config)) {
		slimvm_error("failed to setup vmcb config");
		return -EIO;
	}

	msr_bitmap = (u32 *)__get_free_pages(GFP_KERNEL, get_order(MSRPM_SIZE));
	if (!msr_bitmap) {
		slimvm_error("svm: Allocate msr_bitmap failed!");
		return -ENOMEM;
	}
	memset(msr_bitmap, 0xff, MSRPM_SIZE);

#ifdef CONFIG_X86_64
	set_msr_interception(msr_bitmap, MSR_FS_BASE, 1, 1);
	set_msr_interception(msr_bitmap, MSR_GS_BASE, 1, 1);
	set_msr_interception(msr_bitmap, MSR_STAR, 1, 1);
	set_msr_interception(msr_bitmap, MSR_LSTAR, 1, 1);
	set_msr_interception(msr_bitmap, MSR_CSTAR, 1, 1);
	set_msr_interception(msr_bitmap, MSR_SYSCALL_MASK, 1, 1);
	set_msr_interception(msr_bitmap, MSR_KERNEL_GS_BASE, 1, 1);
#endif

	io_bitmap = (u32 *)__get_free_pages(GFP_KERNEL, get_order(IOPM_SIZE));
	if (!io_bitmap) {
		free_pages((unsigned long)msr_bitmap, get_order(MSRPM_SIZE));
		slimvm_error("svm: Allocate io_bitmap failed!");
		return -ENOMEM;
	}
	memset(io_bitmap, 0xff, IOPM_SIZE);

	if (has_xsave)
		host_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	svm_preempt_ops.sched_in = svm_sched_in;
	svm_preempt_ops.sched_out = svm_sched_out;

	/*
	 * Allocate per-CPU state in this sleepable context. The on_each_cpu()
	 * callback below runs in IPI context and must not allocate.
	 */
	for_each_possible_cpu(cpu) {
		r = svm_cpu_init(cpu);
		if (r)
			goto failed;
	}

	/* Enable SVM (EFER.SVME + host save area) on all CPUs. */
	atomic_set(&svm_enable_failed, 0);
	on_each_cpu(svm_hardware_enable, NULL, 1);
	if (atomic_read(&svm_enable_failed)) {
		r = -EBUSY;
		goto failed;
	}

	slimvm_info("slimvm svm init\n");

	return 0;

failed:
	on_each_cpu(svm_hardware_disable, NULL, 1);
	for_each_possible_cpu(cpu)
		svm_cpu_uninit(cpu);
	free_pages((unsigned long)msr_bitmap, get_order(MSRPM_SIZE));
	free_pages((unsigned long)io_bitmap, get_order(IOPM_SIZE));
	return r;
}

/**
 * svm_hardware_disable_all - the main removal routine for the SVM engine
 */
void svm_hardware_disable_all(void)
{
	int cpu;

	on_each_cpu(svm_hardware_disable, NULL, 1);

	/* Free per-CPU state here, not in the IPI callback above. */
	for_each_possible_cpu(cpu)
		svm_cpu_uninit(cpu);

	free_pages((unsigned long)msr_bitmap, get_order(MSRPM_SIZE));
	free_pages((unsigned long)io_bitmap, get_order(IOPM_SIZE));
}

/* ---- vendor ops adapters: cast the opaque handle back to svm_vcpu ---- */

static struct slimvm_vcpu *svm_ops_create_vcpu(struct slimvm_config *conf,
					       struct instance *instp,
					       int vcpu_no)
{
	return (struct slimvm_vcpu *)svm_create_vcpu(conf, instp, vcpu_no);
}

static void svm_ops_destroy_vcpu(struct slimvm_vcpu *vcpu)
{
	svm_destroy_vcpu((struct svm_vcpu *)vcpu);
}

static int svm_ops_launch(struct slimvm_vcpu *vcpu, struct slimvm_config *conf)
{
	return svm_launch((struct svm_vcpu *)vcpu, conf);
}

static void svm_ops_set_vcpu_mode(struct slimvm_vcpu *vcpu, u8 mode)
{
	svm_set_vcpu_mode((struct svm_vcpu *)vcpu, mode);
}

static bool svm_ops_vcpu_is_shutdown(struct slimvm_vcpu *vcpu)
{
	return ((struct svm_vcpu *)vcpu)->shutdown;
}

static void svm_ops_make_nmi_request(struct slimvm_vcpu *vcpu)
{
	svm_make_request(SVM_REQ_NMI, (struct svm_vcpu *)vcpu);
}

struct slimvm_engine_ops svm_ops = {
	.name			= "svm",
	.hardware_enable_all	= svm_hardware_enable_all,
	.hardware_disable_all	= svm_hardware_disable_all,
	.create_vcpu		= svm_ops_create_vcpu,
	.destroy_vcpu		= svm_ops_destroy_vcpu,
	.launch			= svm_ops_launch,
	.set_vcpu_mode		= svm_ops_set_vcpu_mode,
	.vcpu_is_shutdown	= svm_ops_vcpu_is_shutdown,
	.make_nmi_request	= svm_ops_make_nmi_request,
	.shutdown_all_vcpus	= svm_shutdown_all_vcpus,
	.sync_all_vcpus		= svm_sync_all_vcpus,
	.instance_alloc_ptp	= instance_alloc_nptp,
	.instance_init_pt	= instance_init_npt,
	.instance_destroy_pt	= instance_destroy_npt,
};
