/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (c) 2026 Ant Group Corporation.
 *
 *  vmx.c - The Intel VT-x driver for SlimVM
 *
 * This file is derived from Linux KVM VT-x support.
 *
 * This modified version is simpler because it avoids the following
 * features that are not requirements for SlimVM:
 *  * Real-mode emulation
 *  * Nested VT-x support
 *  * I/O hardware emulation
 *  * Any of the more esoteric X86 features and registers
 *  * KVM-specific functionality
 *
 * In essence we provide only the minimum functionality needed to run
 * a process in vmx non-root mode rather than the full hardware emulation
 * needed to support an entire OS.
 *
 * This driver is a research prototype and as such has the following
 * limitations:
 *
 *   1. Backward compatibility is currently a non-goal, and only recent
 *      full-featured (EPT, PCID, VPID, etc.) Intel hardware is supported
 *      by this driver.
 *
 *   2. SlimVM requires exclusive access to VT-x, so it is conflicted with
 *      KVM and other HV solutions.
 *
 *   3. Hotplugged physical CPUs are unsupported.
 */

#include <asm/virtext.h>
#include <linux/context_tracking.h>

#include <asm/virtext.h>
#include <asm/traps.h>
#include <asm/fpu/xcr.h>
#include <asm/syscall.h>

#include "vmx.h"
#include "compat.h"
#include "exception.h"
#include "seccomp.h"

/* Refer to arch/x86/include/asm/msr-index.h */
#undef MSR_IA32_FEATURE_CONTROL
#undef FEATURE_CONTROL_LOCKED
#undef FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX
#undef FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX

#define MSR_IA32_FEATURE_CONTROL                        0x0000003a
#define FEATURE_CONTROL_LOCKED                          BIT(0)
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX        BIT(1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX       BIT(2)

static atomic_t vmx_enable_failed;

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);

static struct vmcs_config vmcs_config;
static bool has_fsgsbase, has_pcid, has_osxsave, has_xsave;

u64 __read_mostly host_xcr0;

static unsigned long *msr_bitmap;

static __read_mostly struct preempt_ops slimvm_preempt_ops;

#define STACK_DEPTH 12

static sys_call_ptr_t slimvm_syscall_table[NR_syscalls] __cacheline_aligned;

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
DEFINE_PER_CPU(struct desc_ptr, host_gdt);
DEFINE_PER_CPU(struct vmx_vcpu *, local_vcpu);
static DEFINE_PER_CPU(struct vmx_vcpu *, vmx_current_vcpu);
static DEFINE_PER_CPU(int, vmx_enabled);

struct vmx_capability vmx_capability;

#define VMX_SEGMENT_FIELD(seg)				  \
	[VCPU_SREG_##seg] = {				   \
		.selector = GUEST_##seg##_SELECTOR,	     \
		.base = GUEST_##seg##_BASE,		     \
		.limit = GUEST_##seg##_LIMIT,		   \
		.ar_bytes = GUEST_##seg##_AR_BYTES,	     \
	}

static const struct vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static const u32 vmx_msr_index[] = {
#ifdef CONFIG_X86_64
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_KERNEL_GS_BASE,
#endif
	MSR_EFER, MSR_STAR, MSR_MISC_FEATURES_ENABLES,
};

typedef long (*do_fork_hack) (struct kernel_clone_args *args);
typedef void (*do_exit_hack) (long);
typedef void (*do_group_exit_hack) (int);

static do_fork_hack __slimvm_do_fork;
static do_exit_hack __slimvm_do_exit;
static do_group_exit_hack __slimvm_do_group_exit;

/*
 * tracehook_notify_resume defined in linux/tracehook.h is a static inline function,
 * task_work_run is called in it, and task_work_run is not exported, so we
 * can not directly call tracehook_notify_resume in linux/tracehook.h, but we can
 * implement our slimvm_tracehook_notify_resume, and directly call the address of
 * task_work_run in it.
 */
typedef void (*task_work_run_hack) (void);
typedef void (*mem_cgroup_handle_over_high_hack) (void);
static task_work_run_hack __slimvm_task_work_run;
static mem_cgroup_handle_over_high_hack __slimvm_mem_cgroup_handle_over_high;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
static __always_inline void guest_enter_irqoff(void)
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

static __always_inline void guest_exit_irqoff(void)
{
	context_tracking_guest_exit();

	instrumentation_begin();
	/* Flush the guest cputime we spent on the guest */
	vtime_account_guest_exit();
	instrumentation_end();
}
#endif

/**
 * copy from tracehook_notify_resume defined in linux/tracehook.h
 * slimvm_tracehook_notify_resume - report when about to return to guest mode
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
static inline void slimvm_tracehook_notify_resume(void)
{
	/*
	 * The caller just cleared TIF_NOTIFY_RESUME. This barrier
	 * pairs with task_work_add()->set_notify_resume() after
	 * hlist_add_head(task->task_works);
	 */
	smp_mb__after_atomic();
	if (unlikely(current->task_works))
		__slimvm_task_work_run();

	__slimvm_mem_cgroup_handle_over_high();
}

static int enter_guestmode_loop(struct vmx_vcpu *vcpu, u32 cached_flags)
{
	while (true) {
		local_irq_enable();

		if (cached_flags & _TIF_NEED_RESCHED)
			schedule();

		if (cached_flags & _TIF_NOTIFY_RESUME) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			slimvm_tracehook_notify_resume();
		}

		if (cached_flags & _TIF_SIGPENDING) {
			/*
			 * A signal forces us to leave the run ioctl before the
			 * vcpu has produced a real VM exit, so vcpu->status may
			 * still hold a stale value (e.g. 0 from init). Report a
			 * valid "interrupted" status to HR3 so bluepillHandler
			 * treats it as a benign signal exit instead of an
			 * invalid status. Follows Linux KVM, whose
			 * kvm_handle_signal_exit() sets run->exit_reason =
			 * KVM_EXIT_INTR for any pending signal (fatal or not).
			 * See https://elixir.bootlin.com/linux/v6.1/source/include/linux/kvm_host.h#L2255
			 */
			if (__fatal_signal_pending(current)) {
				vcpu->status = SLIMVM_RET_INTR;
				local_irq_disable();
				return -1;
			}

			if (slimvm_signal_handler(vcpu)) {
				vcpu->status = SLIMVM_RET_INTR;
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

static int prepare_enter_guestmode(struct vmx_vcpu *vcpu)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags;
	int r = 0;

	if (vcpu->shutdown || vcpu->instance->shutdown)
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
		r = enter_guestmode_loop(vcpu, cached_flags);

	local_irq_enable();

	return r;
}

#define NR_SHARED_MSRS ARRAY_SIZE(vmx_msr_index)
#define NR_MSRS (NR_SHARED_MSRS + \
		 1 /* MSR_PLATFORM_INFO */ + \
		 1 /* PADDING */)

inline bool cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

inline bool cpu_has_vmx_invvpid_single(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT;
}

inline bool cpu_has_vmx_invvpid_global(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
}

inline bool cpu_has_vmx_invept_context(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

inline bool cpu_has_vmx_invept_global(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

inline bool cpu_has_vmx_ept_ad_bits(void)
{
	return vmx_capability.ept & VMX_EPT_AD_BIT;
}

static inline void __vmxon(u64 addr)
{
	asm volatile(ASM_VMX_VMXON_RAX
				 : : "a"(&addr), "m"(addr)
				 : "memory", "cc");
}

static inline void __vmxoff(void)
{
	asm volatile(ASM_VMX_VMXOFF : : : "cc");
}

static inline void __invvpid(int ext, u16 vpid, gva_t gva)
{
	struct {
		u64 vpid : 16;
		u64 rsvd : 48;
		u64 gva;
	} operand = {vpid, 0, gva};

	asm volatile(ASM_VMX_INVVPID
				 /* CF==1 or ZF==1 --> rc = -1 */
				 "; ja 1f ; ud2 ; 1:"
				 : : "a"(&operand), "c"(ext) : "cc", "memory");
}

static inline void __invept(int ext, u64 eptp, gpa_t gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile (ASM_VMX_INVEPT
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
}

static inline void vpid_sync_vcpu_global(void)
{
	if (cpu_has_vmx_invvpid_global())
		__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);
}

static inline void ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static inline void ept_sync_context(u64 eptp)
{
	if (cpu_has_vmx_invept_context())
		__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
	else
		ept_sync_global();
}

static int __find_msr_index(struct vmx_vcpu *vcpu, u32 msr)
{
	int i;

	for (i = 0; i < vcpu->nmsrs; ++i)
		if (vcpu->guest_msrs[i].index == msr)
			return i;
	return -1;
}

static struct msr_entry *find_msr_entry(struct vmx_vcpu *vcpu, u32 msr)
{
	int i;

	i = __find_msr_index(vcpu, msr);
	if (i >= 0)
		return &vcpu->guest_msrs[i];

	return NULL;
}

#ifdef CONFIG_X86_64
static void move_msr_up(struct vmx_vcpu *vcpu, int from, int to)
{
	struct msr_entry tmp;

	tmp = vcpu->guest_msrs[to];
	vcpu->guest_msrs[to] = vcpu->guest_msrs[from];
	vcpu->guest_msrs[from] = tmp;
	tmp = vcpu->host_msrs[to];
	vcpu->host_msrs[to] = vcpu->host_msrs[from];
	vcpu->host_msrs[from] = tmp;
}
#endif

static u32 vmx_read_guest_seg_ar(struct vmx_vcpu *vcpu, unsigned seg)
{
	unsigned int ret;
	vmx_get_cpu(vcpu);
	ret = vmcs_read32(vmx_segment_fields[seg].ar_bytes);
	vmx_put_cpu(vcpu);
	return ret;
}

static int vmx_get_cpl(struct vmx_vcpu *vcpu)
{
	unsigned int ar;
	ar = vmx_read_guest_seg_ar(vcpu, VCPU_SREG_SS);
	return VMX_AR_DPL(ar);
}

static bool __compare_msr(struct vmx_vcpu *vcpu, int n)
{
	return (vcpu->guest_msrs[n].index == vcpu->host_msrs[n].index &&
		vcpu->guest_msrs[n].data == vcpu->host_msrs[n].data);
}

static int __get_msr_index(struct vmx_vcpu *vcpu, u32 msr)
{
	int idx;

	switch (msr) {
	case MSR_SYSCALL_MASK:
		idx = vcpu->msr_index.sys_call_mask;
		break;
	case MSR_LSTAR:
		idx = vcpu->msr_index.lstar;
		break;
	case MSR_KERNEL_GS_BASE:
		idx = vcpu->msr_index.kernel_gs_base;
		break;
	case MSR_EFER:
		idx = vcpu->msr_index.efer;
		break;
	case MSR_STAR:
		idx = vcpu->msr_index.star;
		break;
	case MSR_MISC_FEATURES_ENABLES:
		idx = vcpu->msr_index.feature_enable;
		break;
	default:
		idx = __find_msr_index(vcpu, msr);
	};

	return idx;
}

static void load_host_msr(struct vmx_vcpu *vcpu, u32 msr)
{
	int i;

	i = __get_msr_index(vcpu, msr);
	if (i < 0 || i >= vcpu->save_nmsrs)
		return;

	if (__compare_msr(vcpu, i))
		return;

	wrmsrl(vcpu->host_msrs[i].index, vcpu->host_msrs[i].data);
}

static void vmx_load_host_msrs(struct vmx_vcpu *vcpu)
{
	int i;

	if (!vcpu->guest_msrs_loaded)
		return;

	for (i = 0; i < NR_SHARED_MSRS; ++i)
		load_host_msr(vcpu, vmx_msr_index[i]);

	vcpu->guest_msrs_loaded = 0;
}

static void load_guest_msr(struct vmx_vcpu *vcpu, u32 msr)
{
	int i;

	i = __get_msr_index(vcpu, msr);
	if (i < 0 || i >= vcpu->save_nmsrs)
		return;

	if (__compare_msr(vcpu, i))
		return;

	wrmsrl(vcpu->guest_msrs[i].index, vcpu->guest_msrs[i].data);
}

static void vmx_load_guest_msrs(struct vmx_vcpu *vcpu)
{
	int i;

	for (i = 0; i < NR_SHARED_MSRS; ++i)
		load_guest_msr(vcpu, vmx_msr_index[i]);

	vcpu->guest_msrs_loaded = 1;
}

static void save_guest_msr(struct vmx_vcpu *vcpu, u32 msr)
{
	int i;

	i = __get_msr_index(vcpu, msr);
	if (i < 0 || i >= vcpu->save_nmsrs)
		return;

	rdmsrl(vcpu->guest_msrs[i].index, vcpu->guest_msrs[i].data);
}

static void save_host_msr(struct vmx_vcpu *vcpu, u32 msr)
{
	int i;

	i = __get_msr_index(vcpu, msr);
	if (i < 0 || i >= vcpu->save_nmsrs)
		return;

	rdmsrl(vcpu->host_msrs[i].index, vcpu->host_msrs[i].data);
}

static void vmx_save_host_msrs(struct vmx_vcpu *vcpu)
{
	int i;

	for (i = 0; i < NR_SHARED_MSRS; ++i)
		save_host_msr(vcpu, vmx_msr_index[i]);
}

static inline void vmx_load_guest_xcr0(struct vmx_vcpu *vcpu,
		struct slimvm_config *conf)
{
	if (!has_xsave)
		return;

	/* XCR0 cannot be set to 0. */
	if (vcpu->xcr0 == 0)
		return;

	if (!vcpu->guest_xcr0_loaded) {
		if (vcpu->xcr0 != host_xcr0)
			xsetbv(XCR_XFEATURE_ENABLED_MASK, vcpu->xcr0);
		vcpu->guest_xcr0_loaded = 1;
	}
}

static inline void vmx_put_guest_xcr0(struct vmx_vcpu *vcpu)
{
	if (!has_xsave)
		return;

	if (vcpu->guest_xcr0_loaded) {
		if (vcpu->xcr0 != host_xcr0)
			xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
		vcpu->guest_xcr0_loaded = 0;
	}
}

static void vmx_load_host_state(struct vmx_vcpu *vcpu)
{
	if (vcpu->host_state.gs_ldt_reload_needed) {
		load_ldt(vcpu->host_state.ldt_sel);
		load_gs_index(vcpu->host_state.gs_sel);
	}

	if (vcpu->host_state.fs_reload_needed)
		loadsegment(fs, vcpu->host_state.fs_sel);
}

static void vmx_save_host_state(struct vmx_vcpu *vcpu)
{
	unsigned long cr3, cr4;

	cr3 = read_cr3();
	if (unlikely(cr3 != vcpu->host_state.cr3)) {
		vmcs_writel(HOST_CR3, cr3);
		vcpu->host_state.cr3 = cr3;
	}

	cr4 = cr4_read_shadow();
	if (unlikely(cr4 != vcpu->host_state.cr4)) {
		vmcs_writel(HOST_CR4, cr4);
		vcpu->host_state.cr4 = cr4;
	}

	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	vcpu->host_state.ldt_sel = read_ldt();
	vcpu->host_state.gs_ldt_reload_needed = vcpu->host_state.ldt_sel;
	savesegment(fs, vcpu->host_state.fs_sel);
	if (!(vcpu->host_state.fs_sel & 7)) {
		vmcs_write16(HOST_FS_SELECTOR, vcpu->host_state.fs_sel);
		vcpu->host_state.fs_reload_needed = 0;
	} else {
		vmcs_write16(HOST_FS_SELECTOR, 0);
		vcpu->host_state.fs_reload_needed = 1;
	}
	savesegment(gs, vcpu->host_state.gs_sel);
	if (!(vcpu->host_state.gs_sel & 7))
		vmcs_write16(HOST_GS_SELECTOR, vcpu->host_state.gs_sel);
	else {
		vmcs_write16(HOST_GS_SELECTOR, 0);
		vcpu->host_state.gs_ldt_reload_needed = 1;
	}
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS | PIN_BASED_POSTED_INTR;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

	rdmsrl(MSR_IA32_VMX_PINBASED_CTLS, vmx_capability.pin_based);
	if (vmx_capability.pin_based & (((u64)1) << 55)) {
		rdmsrl(MSR_IA32_VMX_TRUE_PINBASED_CTLS, vmx_capability.pin_based);
	}

	min = CPU_BASED_HLT_EXITING |
#ifdef CONFIG_X86_64
	      CPU_BASED_CR8_LOAD_EXITING |
	      CPU_BASED_CR8_STORE_EXITING |
#endif
	      CPU_BASED_CR3_LOAD_EXITING |
	      CPU_BASED_CR3_STORE_EXITING |
	      CPU_BASED_MOV_DR_EXITING |
	      CPU_BASED_USE_TSC_OFFSETTING |
	      CPU_BASED_INVLPG_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	      CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;
#ifdef CONFIG_X86_64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
					   ~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 =  SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_ENABLE_RDTSCP |
			SECONDARY_EXEC_ENABLE_INVPCID |
			SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
	}

	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
		      vmx_capability.ept, vmx_capability.vpid);
	}
	rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS2, vmx_capability.secondary);

	min = 0;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_ACK_INTR_ON_EXIT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0)
		return -EIO;

	min = 0;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	/* filter all of the IO ports */
	_cpu_based_exec_control |= CPU_BASED_UNCOND_IO_EXITING;
	_cpu_based_exec_control &= ~CPU_BASED_USE_IO_BITMAPS;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl	 = _vmexit_control;
	vmcs_conf->vmentry_ctrl	= _vmentry_control;

	return 0;
}

static struct vmcs *__vmx_alloc_vmcs(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = alloc_pages_exact_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);
	vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
	return vmcs;
}

/**
 * vmx_alloc_vmcs - allocates a VMCS region
 *
 * NOTE: Assumes the new region will be used by the current CPU.
 *
 * Returns a valid VMCS region.
 */
static struct vmcs *vmx_alloc_vmcs(void)
{
	return __vmx_alloc_vmcs(raw_smp_processor_id());
}

/**
 * vmx_free_vmcs - frees a VMCS region
 */
static void vmx_free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_config.order);
}

/*
 * Set up the vmcs's constant host-state fields, i.e., host-state fields that
 * will not change in the lifetime of the guest.
 * Note that host-state that does change is set elsewhere. E.g., host-state
 * that is set differently for each CPU is set in vmx_vcpu_load(), not here.
 */
static void vmx_setup_constant_host_state(struct vmx_vcpu *vcpu)
{
	u32 low32, high32;
	unsigned long host_rip;

	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);  /* 22.2.3 */
	vmcs_writel(HOST_CR4, __read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3 */

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	vmcs_writel(HOST_IDTR_BASE, (unsigned long)vcpu->idt_base);   /* 22.2.4 */

	asm("mov $.Lkvm_vmx_return, %0" : "=r"(host_rip));
	vmcs_writel(HOST_RIP, host_rip);

	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low32);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, read_msr(MSR_IA32_SYSENTER_EIP));

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, low32, high32);
		vmcs_write64(HOST_IA32_PAT, low32 | ((u64) high32 << 32));
	}

	vmcs_write16(HOST_FS_SELECTOR, 0);	    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);	    /* 22.2.4 */

#ifdef CONFIG_X86_64
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif
}

static void __vmx_get_cpu_helper(void *ptr)
{
	struct vmx_vcpu *vcpu = ptr;

	WARN_ON(raw_smp_processor_id() != vcpu->cpu);
	vmcs_clear(vcpu->vmcs);
	if (__this_cpu_read(local_vcpu) == vcpu)
		this_cpu_write(local_vcpu, NULL);
}

static void __load_vcpu(struct vmx_vcpu *vcpu, int cpu)
{
	if (__this_cpu_read(local_vcpu) != vcpu) {
		this_cpu_write(local_vcpu, vcpu);

		if (vcpu->cpu != cpu) {
			unsigned long sysenter_esp;

			if (vcpu->cpu >= 0)
				smp_call_function_single(vcpu->cpu,
					__vmx_get_cpu_helper, (void *) vcpu, 1);

			vmx_make_request(VMX_REQ_TLB_FLUSH, vcpu);

			vcpu->launched = 0;
			vmcs_load(vcpu->vmcs);

			/*
			 * Linux uses per-cpu TSS and GDT, so set these when switching
			 * processors.
			 */
			vmcs_writel(HOST_TR_BASE, vmx_read_tr_base(cpu));
			vmcs_writel(HOST_GDTR_BASE, vmx_read_gdt_addr());
			rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
			vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp);

			vcpu->cpu = cpu;
		} else
			vmcs_load(vcpu->vmcs);
	}
}

static void __put_vcpu(struct vmx_vcpu *vcpu)
{
	vmx_invalidate_tss_limit();
	vmx_load_fixmap_gdt();
}

/**
 * vmx_get_cpu - called before using a cpu
 * @vcpu: VCPU that will be loaded.
 *
 * Disables preemption. Call vmx_put_cpu() when finished.
 */
void vmx_get_cpu(struct vmx_vcpu *vcpu)
{
	int cpu = get_cpu();

	__load_vcpu(vcpu, cpu);
}

/**
 * vmx_put_cpu - called after using a cpu
 * @vcpu: VCPU that was loaded.
 */
void vmx_put_cpu(struct vmx_vcpu *vcpu)
{
	put_cpu();
}

void vmx_set_vcpu_mode(struct vmx_vcpu *vcpu, u8 mode)
{
	vcpu->mode = mode;
	smp_wmb();
}

bool vmx_check_vcpu_mode(struct vmx_vcpu *vcpu, u8 mode)
{
	return (vcpu->mode == mode);
}

static void slimvm_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct vmx_vcpu *vcpu = container_of(pn, struct vmx_vcpu,
					preempt_notifier);

	vmx_save_host_msrs(vcpu);

	__load_vcpu(vcpu, cpu);
	this_cpu_write(vmx_current_vcpu, vcpu);

	vcpu->scheded = 1;
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
}

static void slimvm_sched_out(struct preempt_notifier *pn,
		struct task_struct *next)
{
	struct vmx_vcpu *vcpu = container_of(pn, struct vmx_vcpu,
					preempt_notifier);

	__put_vcpu(vcpu);
	this_cpu_write(vmx_current_vcpu, NULL);
	vmx_load_host_msrs(vcpu);
	vmx_put_guest_xcr0(vcpu);
}

static void __vmx_vcpu_kick(void *p)
{
}

void vmx_shutdown_all_vcpus(struct instance *instp)
{
	int vcpu_no, cpu, me;
	struct vmx_vcpu *vcpu;
	cpumask_var_t cpus;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);
	me = get_cpu();

	spin_lock(&instp->vcpu_lock);
	for_each_set_bit(vcpu_no, instp->vcpu_bitmap, VM_MAX_VCPUS) {
		vcpu = instp->vcpus[vcpu_no];
		if (!vcpu)
			continue;

		vcpu->shutdown = 1;

		cpu = vcpu->cpu;
		if (cpus != NULL && cpu != -1 && cpu != me &&
			!vmx_check_vcpu_mode(vcpu, OUTSIDE_ROOT_MODE))
			cpumask_set_cpu(cpu, cpus);
	}
	spin_unlock(&instp->vcpu_lock);

	if (unlikely(cpus == NULL)) {
		smp_call_function_many(cpu_online_mask,
			__vmx_vcpu_kick, NULL, 1);
	} else if (!cpumask_empty(cpus)) {
		smp_call_function_many(cpus,
			__vmx_vcpu_kick, NULL, 1);
	}

	instp->shutdown = 1;

	put_cpu();
	free_cpumask_var(cpus);
}

void vmx_sync_all_vcpus(struct instance *instp)
{
	struct vmx_vcpu *vcpu;
	int vcpu_no;

	while (true) {
		bool r = true;

		spin_lock(&instp->vcpu_lock);
		for_each_set_bit(vcpu_no, instp->vcpu_bitmap,
				 VM_MAX_VCPUS) {
			vcpu = instp->vcpus[vcpu_no];
			if (!vcpu)
				continue;

			r &= vmx_check_vcpu_mode(vcpu, OUTSIDE_ROOT_MODE);
		}
		spin_unlock(&instp->vcpu_lock);
		if (r)
			break;
	}
}

static void vmx_dump_sel(char *name, uint32_t sel)
{
	pr_err("%s sel=0x%04x, attr=0x%05x, limit=0x%08x, base=0x%016lx\n",
	       name, vmcs_read32(sel),
	       vmcs_read32(sel + GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR),
	       vmcs_read32(sel + GUEST_ES_LIMIT - GUEST_ES_SELECTOR),
	       vmcs_readl(sel + GUEST_ES_BASE - GUEST_ES_SELECTOR));
}

static void vmx_dump_dtsel(char *name, uint32_t limit)
{
	pr_err("%s limit=0x%08x, base=0x%016lx\n",
	       name, vmcs_read32(limit),
	       vmcs_readl(limit + GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
}

/**
 * vmx_dump_cpu - prints the CPU state
 * @vcpu: VCPU to print
 */
static void vmx_dump_cpu(struct vmx_vcpu *vcpu)
{
	unsigned long flags;
	int i, n;
	unsigned long *sp, val;
	u32 vmentry_ctl;
	u32 vmexit_ctl;
	u32 cpu_based_exec_ctrl;
	u32 pin_based_exec_ctrl;
	u32 secondary_exec_control = 0;
	unsigned long cr4;
	u64 efer;

	vmx_get_cpu(vcpu);
	vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);
	vmexit_ctl = vmcs_read32(VM_EXIT_CONTROLS);
	cpu_based_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	pin_based_exec_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	if (cpu_has_secondary_exec_ctrls())
		secondary_exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
	cr4 = vmcs_readl(GUEST_CR4);
	efer = vmcs_read64(GUEST_IA32_EFER);

	vcpu->regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
	vcpu->regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
	flags = vmcs_readl(GUEST_RFLAGS);

	pr_err("*** Guest State ***\n");
	pr_err("CR0: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       vmcs_readl(GUEST_CR0), vmcs_readl(CR0_READ_SHADOW),
	       vmcs_readl(CR0_GUEST_HOST_MASK));
	pr_err("CR4: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       cr4, vmcs_readl(CR4_READ_SHADOW), vmcs_readl(CR4_GUEST_HOST_MASK));
	pr_err("CR3 = 0x%016lx\n", vmcs_readl(GUEST_CR3));
	if ((secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT) &&
	    (cr4 & X86_CR4_PAE) && !(efer & EFER_LMA)) {
		pr_err("PDPTR0 = 0x%016llx  PDPTR1 = 0x%016llx\n",
		       vmcs_read64(GUEST_PDPTR0), vmcs_read64(GUEST_PDPTR1));
		pr_err("PDPTR2 = 0x%016llx  PDPTR3 = 0x%016llx\n",
		       vmcs_read64(GUEST_PDPTR2), vmcs_read64(GUEST_PDPTR3));
	}
	pr_err("RSP = 0x%016lx  RIP = 0x%016lx\n",
	       vmcs_readl(GUEST_RSP), vmcs_readl(GUEST_RIP));
	pr_err("RFLAGS=0x%08lx	 DR7 = 0x%016lx\n",
	       vmcs_readl(GUEST_RFLAGS), vmcs_readl(GUEST_DR7));
	pr_err("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
	       vmcs_readl(GUEST_SYSENTER_ESP),
	       vmcs_read32(GUEST_SYSENTER_CS), vmcs_readl(GUEST_SYSENTER_EIP));
	vmx_dump_sel("CS:  ", GUEST_CS_SELECTOR);
	vmx_dump_sel("DS:  ", GUEST_DS_SELECTOR);
	vmx_dump_sel("SS:  ", GUEST_SS_SELECTOR);
	vmx_dump_sel("ES:  ", GUEST_ES_SELECTOR);
	vmx_dump_sel("FS:  ", GUEST_FS_SELECTOR);
	vmx_dump_sel("GS:  ", GUEST_GS_SELECTOR);
	vmx_dump_dtsel("GDTR:", GUEST_GDTR_LIMIT);
	vmx_dump_sel("LDTR:", GUEST_LDTR_SELECTOR);
	vmx_dump_dtsel("IDTR:", GUEST_IDTR_LIMIT);
	vmx_dump_sel("TR:  ", GUEST_TR_SELECTOR);
	pr_info("vmx: --- Begin VCPU Dump ---\n");
	pr_info("vmx: CPU %d VPID %d\n", vcpu->cpu, vcpu->vpid);
	pr_info("vmx: RIP 0x%016llx RFLAGS 0x%08lx\n",
	       vcpu->regs[VCPU_REGS_RIP], flags);
	pr_info("vmx: RAX 0x%016llx RCX 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RAX], vcpu->regs[VCPU_REGS_RCX]);
	pr_info("vmx: RDX 0x%016llx RBX 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RDX], vcpu->regs[VCPU_REGS_RBX]);
	pr_info("vmx: RSP 0x%016llx RBP 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RSP], vcpu->regs[VCPU_REGS_RBP]);
	pr_info("vmx: RSI 0x%016llx RDI 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RSI], vcpu->regs[VCPU_REGS_RDI]);
	pr_info("vmx: R8  0x%016llx R9  0x%016llx\n",
			vcpu->regs[VCPU_REGS_R8], vcpu->regs[VCPU_REGS_R9]);
	pr_info("vmx: R10 0x%016llx R11 0x%016llx\n",
			vcpu->regs[VCPU_REGS_R10], vcpu->regs[VCPU_REGS_R11]);
	pr_info("vmx: R12 0x%016llx R13 0x%016llx\n",
			vcpu->regs[VCPU_REGS_R12], vcpu->regs[VCPU_REGS_R13]);
	pr_info("vmx: R14 0x%016llx R15 0x%016llx\n",
			vcpu->regs[VCPU_REGS_R14], vcpu->regs[VCPU_REGS_R15]);
	pr_info("vmx: FS.base 0x%016lx GS.base 0x%016lx\n",
			vmcs_readl(GUEST_FS_BASE), vmcs_readl(GUEST_GS_BASE));

	pr_info("vmx: Dumping Stack Contents...\n");
	sp = (unsigned long *) vcpu->regs[VCPU_REGS_RSP];
	for (i = 0; i < STACK_DEPTH; i++)
		if (get_user(val, &sp[i]))
			pr_info("vmx: RSP%+-3ld ?\n",
				i * sizeof(long));
		else
			pr_info("vmx: RSP%+-3ld 0x%016lx\n",
				i * sizeof(long), val);

	pr_err("*** Control State ***\n");
	pr_err("PinBased=%08x CPUBased=%08x SecondaryExec=%08x\n",
	       pin_based_exec_ctrl, cpu_based_exec_ctrl, secondary_exec_control);
	pr_err("EntryControls=%08x ExitControls=%08x\n", vmentry_ctl, vmexit_ctl);
	pr_err("ExceptionBitmap=%08x PFECmask=%08x PFECmatch=%08x\n",
	       vmcs_read32(EXCEPTION_BITMAP),
	       vmcs_read32(PAGE_FAULT_ERROR_CODE_MASK),
	       vmcs_read32(PAGE_FAULT_ERROR_CODE_MATCH));
	pr_err("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
	       vmcs_read32(VM_ENTRY_INTR_INFO_FIELD),
	       vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE),
	       vmcs_read32(VM_ENTRY_INSTRUCTION_LEN));
	pr_err("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
	       vmcs_read32(VM_EXIT_INTR_INFO),
	       vmcs_read32(VM_EXIT_INTR_ERROR_CODE),
	       vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
	pr_err("        reason=%08x qualification=%016lx\n",
	       vmcs_read32(VM_EXIT_REASON), vmcs_readl(EXIT_QUALIFICATION));
	pr_err("IDTVectoring: info=%08x errcode=%08x\n",
	       vmcs_read32(IDT_VECTORING_INFO_FIELD),
	       vmcs_read32(IDT_VECTORING_ERROR_CODE));
	pr_err("TSC Offset = 0x%016llx\n", vmcs_read64(TSC_OFFSET));
	if ((secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT))
		pr_err("EPT pointer = 0x%016llx\n", vmcs_read64(EPT_POINTER));
	n = vmcs_read32(CR3_TARGET_COUNT);
	for (i = 0; i + 1 < n; i += 4)
		pr_err("CR3 target%u=%016lx target%u=%016lx\n",
		       i, vmcs_readl(CR3_TARGET_VALUE0 + i * 2),
		       i + 1, vmcs_readl(CR3_TARGET_VALUE0 + i * 2 + 2));
	if (i < n)
		pr_err("CR3 target%u=%016lx\n",
		       i, vmcs_readl(CR3_TARGET_VALUE0 + i * 2));
	if (secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING)
		pr_err("PLE Gap=%08x Window=%08x\n",
		       vmcs_read32(PLE_GAP), vmcs_read32(PLE_WINDOW));
	if (secondary_exec_control & SECONDARY_EXEC_ENABLE_VPID)
		pr_err("Virtual processor ID = 0x%04x\n",
		       vmcs_read16(VIRTUAL_PROCESSOR_ID));

	vmx_put_cpu(vcpu);
	pr_info("vmx: --- End VCPU Dump ---\n");
}

u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp = SLIMVM_VMX_EPT_DEFAULT;

	if (cpu_has_vmx_ept_ad_bits())
		eptp |= VMX_EPT_AD_ENABLE_BIT;
	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static inline u32 vmx_segment_access_rights(struct slimvm_segment *var)
{
	u32 ar;

	if (var->unusable || !var->present)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}

	return ar;
}

static void slimvm_get_cpu_feature(void)
{
	unsigned int eax, ebx, ecx, edx;

	/*
	 * Detail information Returned by CPUID Instruction please
	 * refers to Intel® 64 and IA-32 Architectures Software
	 * Developer’s Manual page 794.
	 */
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
 * vmx_setup_initial_guest_state - configures the initial state of guest registers
 */
static int vmx_setup_initial_guest_state(struct slimvm_config *conf)
{
#define CR0_ALWAYS_ON_FLAG X86_CR0_NE
#define CR4_ALWAYS_ON_FLAG X86_CR4_VMXE
	/*
	 * Check CR4 setting.
	 */
	if (!has_pcid && (conf->sys_regs.cr4 & X86_CR4_PCIDE))
		return -1;

	if (!has_osxsave && (conf->sys_regs.cr4 & X86_CR4_OSXSAVE))
		return -1;

	if (!has_fsgsbase && (conf->sys_regs.cr4 & X86_CR4_FSGSBASE))
		return -1;

	/* configure control and data registers */
	vmcs_writel(GUEST_CR0, conf->sys_regs.cr0 | CR0_ALWAYS_ON_FLAG);
	vmcs_writel(CR0_READ_SHADOW, conf->sys_regs.cr0);
	vmcs_writel(GUEST_CR3, conf->sys_regs.cr3);
	vmcs_writel(GUEST_CR4, conf->sys_regs.cr4 | CR4_ALWAYS_ON_FLAG);
	vmcs_writel(CR4_READ_SHADOW, conf->sys_regs.cr4);

	vmcs_writel(GUEST_IA32_EFER, conf->sys_regs.efer);
	vmcs_writel(GUEST_GDTR_BASE, conf->sys_regs.gdt.base);
	vmcs_writel(GUEST_GDTR_LIMIT, conf->sys_regs.gdt.limit);
	vmcs_writel(GUEST_IDTR_BASE, conf->sys_regs.idt.base);
	vmcs_writel(GUEST_IDTR_LIMIT, conf->sys_regs.idt.limit);
	vmcs_writel(GUEST_DR7, 0);

	/* guest segment bases */
	vmcs_writel(GUEST_CS_BASE, conf->sys_regs.cs.base);
	vmcs_writel(GUEST_DS_BASE, conf->sys_regs.ds.base);
	vmcs_writel(GUEST_ES_BASE, conf->sys_regs.es.base);
	vmcs_writel(GUEST_GS_BASE, conf->sys_regs.gs.base);
	vmcs_writel(GUEST_SS_BASE, conf->sys_regs.ss.base);
	vmcs_writel(GUEST_FS_BASE, conf->sys_regs.fs.base);
	vmcs_writel(GUEST_TR_BASE, conf->sys_regs.tr.base);

	/* guest segment access rights */
	vmcs_writel(GUEST_CS_AR_BYTES, vmx_segment_access_rights(&conf->sys_regs.cs));
	vmcs_writel(GUEST_DS_AR_BYTES, vmx_segment_access_rights(&conf->sys_regs.ds));
	vmcs_writel(GUEST_ES_AR_BYTES, vmx_segment_access_rights(&conf->sys_regs.es));
	vmcs_writel(GUEST_FS_AR_BYTES, vmx_segment_access_rights(&conf->sys_regs.fs));
	vmcs_writel(GUEST_GS_AR_BYTES, vmx_segment_access_rights(&conf->sys_regs.gs));
	vmcs_writel(GUEST_SS_AR_BYTES, vmx_segment_access_rights(&conf->sys_regs.ss));
	vmcs_writel(GUEST_TR_AR_BYTES, vmx_segment_access_rights(&conf->sys_regs.tr));

	/* guest segment limits */
	vmcs_write32(GUEST_CS_LIMIT, conf->sys_regs.cs.limit);
	vmcs_write32(GUEST_DS_LIMIT, conf->sys_regs.ds.limit);
	vmcs_write32(GUEST_ES_LIMIT, conf->sys_regs.es.limit);
	vmcs_write32(GUEST_FS_LIMIT, conf->sys_regs.fs.limit);
	vmcs_write32(GUEST_GS_LIMIT, conf->sys_regs.gs.limit);
	vmcs_write32(GUEST_SS_LIMIT, conf->sys_regs.ss.limit);

	/* configure segment selectors */
	vmcs_write16(GUEST_CS_SELECTOR, conf->sys_regs.cs.selector);
	vmcs_write16(GUEST_DS_SELECTOR, conf->sys_regs.ds.selector);
	vmcs_write16(GUEST_ES_SELECTOR, conf->sys_regs.es.selector);
	vmcs_write16(GUEST_FS_SELECTOR, conf->sys_regs.fs.selector);
	vmcs_write16(GUEST_GS_SELECTOR, conf->sys_regs.gs.selector);
	vmcs_write16(GUEST_SS_SELECTOR, conf->sys_regs.ss.selector);
	vmcs_write16(GUEST_TR_SELECTOR, conf->sys_regs.tr.selector);

	/* guest LDTR */
	vmcs_write16(GUEST_LDTR_SELECTOR, conf->sys_regs.ldt.selector);
	vmcs_writel(GUEST_LDTR_AR_BYTES,
		vmx_segment_access_rights(&conf->sys_regs.ldt));
	vmcs_writel(GUEST_LDTR_BASE, conf->sys_regs.ldt.base);
	vmcs_writel(GUEST_LDTR_LIMIT, conf->sys_regs.ldt.limit);

	/* guest TSS */
	vmcs_writel(GUEST_TR_BASE, conf->sys_regs.tr.base);
	vmcs_writel(GUEST_TR_AR_BYTES,
		vmx_segment_access_rights(&conf->sys_regs.tr));
	vmcs_writel(GUEST_TR_LIMIT, conf->sys_regs.tr.limit);

	/* initialize sysenter */
	vmcs_write32(GUEST_SYSENTER_CS, 0);
	vmcs_writel(GUEST_SYSENTER_ESP, 0);
	vmcs_writel(GUEST_SYSENTER_EIP, 0);

	/* other random initialization */
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	return 0;
}

static void __vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, u32 msr)
{
	int f = sizeof(unsigned long);
	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		__clear_bit(msr, msr_bitmap + 0x000 / f); /* read-low */
		__clear_bit(msr, msr_bitmap + 0x800 / f); /* write-low */
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		__clear_bit(msr, msr_bitmap + 0x400 / f); /* read-high */
		__clear_bit(msr, msr_bitmap + 0xc00 / f); /* write-high */
	}
}

static void setup_msr(struct vmx_vcpu *vcpu)
{
	int save_nmsrs = 0;
	int index;

	index = __find_msr_index(vcpu, MSR_SYSCALL_MASK);
	if (index >= 0)
		move_msr_up(vcpu, index, save_nmsrs++);
	vcpu->msr_index.sys_call_mask = index;

	index = __find_msr_index(vcpu, MSR_LSTAR);
	if (index >= 0)
		move_msr_up(vcpu, index, save_nmsrs++);
	vcpu->msr_index.lstar = index;

	index = __find_msr_index(vcpu, MSR_KERNEL_GS_BASE);
	if (index >= 0)
		move_msr_up(vcpu, index, save_nmsrs++);
	vcpu->msr_index.kernel_gs_base = index;

	index = __find_msr_index(vcpu, MSR_EFER);
	if (index >= 0)
		move_msr_up(vcpu, index, save_nmsrs++);
	vcpu->msr_index.efer = index;

	index = __find_msr_index(vcpu, MSR_STAR);
	if (index >= 0)
		move_msr_up(vcpu, index, save_nmsrs++);
	vcpu->msr_index.star = index;

	index = __find_msr_index(vcpu, MSR_PLATFORM_INFO);
	if (index >= 0)
		move_msr_up(vcpu, index, save_nmsrs++);

	index = __find_msr_index(vcpu, MSR_MISC_FEATURES_ENABLES);
	if (index >= 0)
		move_msr_up(vcpu, index, save_nmsrs++);
	vcpu->msr_index.feature_enable = index;

	vcpu->save_nmsrs = save_nmsrs;

	/* XXX enable only MSRs in set */
	vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));

	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(&vcpu->msr_autoload.host));
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(&vcpu->msr_autoload.guest));
}

/* vmx_setup_vmcs - configures the vmcs with starting parameters */
static void vmx_setup_vmcs(struct vmx_vcpu *vcpu)
{
	u32 data_low, data_high;
	u64 data;
	int i, j;

	vmcs_write16(VIRTUAL_PROCESSOR_ID, vcpu->vpid);
	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		vmcs_config.cpu_based_exec_ctrl);

	if (cpu_has_secondary_exec_ctrls()) {
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
			     vmcs_config.cpu_based_2nd_exec_ctrl);
	}

	vmcs_write64(EPT_POINTER, vcpu->instance->eptp);

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	vmcs_write32(CR3_TARGET_COUNT, 0);	   /* 22.2.1 */

	/* Initialize MSRs */
	for (i = 0; i < NR_SHARED_MSRS; ++i) {
		u32 index = vmx_msr_index[i];

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;

		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;

		j = vcpu->nmsrs;
		data = data_low | ((u64)data_high << 32);
		vcpu->host_msrs[j].index = index;
		vcpu->host_msrs[j].data = data;
		vcpu->host_msrs[j].reserved = 0;
		vcpu->guest_msrs[j] = vcpu->host_msrs[j];
		++vcpu->nmsrs;
	}

	/* MSR_PLATFORM_INFO */
	if (rdmsr_safe(MSR_PLATFORM_INFO, &data_low, &data_high) < 0) {
		data_low = 0;
		data_high = 0;
	}
	j = vcpu->nmsrs;
	data = data_low | ((u64)data_high << 32);
	vcpu->host_msrs[j].index = MSR_PLATFORM_INFO;
	vcpu->host_msrs[j].data = data;
	vcpu->host_msrs[j].reserved = 0;
	vcpu->guest_msrs[j] = vcpu->host_msrs[j];
	++vcpu->nmsrs;

	setup_msr(vcpu);

	vmcs_config.vmentry_ctrl |= VM_ENTRY_IA32E_MODE;

	/*
	 * always load IA32_EFER manually, as guest efer is mostly the
	 * same as host efer.
	 *
	 * but NOTE that letting the CPU switch IA32_EFER is much faster
	 * than switching it manually. The slowness of manual switching is
	 * because writing to EFER with WRMSR triggers a TLB flush, even
	 * if the only bit you're touching is SCE (so the page table format
	 * is not affected).  Doing the write as part of vmentry / vmexit,
	 * instead, does not flush the TLB, probably because all processors
	 * that have EPT also have VPID.
	 */
	vmcs_config.vmentry_ctrl &= ~VM_ENTRY_LOAD_IA32_EFER;
	vmcs_config.vmexit_ctrl &= ~VM_EXIT_LOAD_IA32_EFER;

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0ul);
	vmcs_writel(CR4_GUEST_HOST_MASK, ~0ul);

	vmcs_writel(TSC_OFFSET, 0);

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
	vmcs_write32(EXCEPTION_BITMAP, 0);

	vmx_setup_constant_host_state(vcpu);
}

/**
 * vmx_allocate_vpid - reserves a vpid and sets it in the VCPU
 * @vmx: the VCPU
 */
static int vmx_allocate_vpid(struct vmx_vcpu *vmx)
{
	int vpid;

	spin_lock(&vmx_vpid_lock);
	vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);
	if (vpid < VMX_NR_VPIDS)
		__set_bit(vpid, vmx_vpid_bitmap);
	else
		vpid = 0;
	spin_unlock(&vmx_vpid_lock);

	vmx->vpid = vpid;

	return vmx->vpid;
}

/**
 * vmx_free_vpid - frees a vpid
 * @vmx: the VCPU
 */
static void vmx_free_vpid(struct vmx_vcpu *vmx)
{
	int vpid = vmx->vpid;

	spin_lock(&vmx_vpid_lock);
	if (vpid != 0 && vpid < VMX_NR_VPIDS)
		__clear_bit(vpid, vmx_vpid_bitmap);
	spin_unlock(&vmx_vpid_lock);
}

static void vmx_vcpu_flush_tlb(struct vmx_vcpu *vcpu)
{
	struct instance *instp = vcpu->instance;

	ept_sync_context(instp->eptp);
}

static void vmx_process_nmi(struct vmx_vcpu *vcpu)
{
	vcpu->nmi_pending = true;
}

static int vmx_inject_nmi(struct vmx_vcpu *vcpu)
{
	if (vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
	    (GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS)) {
		slimvm_error("vmx: failed to inject nmi");
		vmx_dump_cpu(vcpu);
		return -EINVAL;
	}

	/* inject NMI */
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		     INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
	vcpu->nmi_pending = false;

	return 0;
}

static void vmx_set_interrupt_window_exiting(bool enable)
{
	u32 exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);

	if (enable)
		exec_control |= CPU_BASED_INTR_WINDOW_EXITING;
	else
		exec_control &= ~CPU_BASED_INTR_WINDOW_EXITING;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);
}

static void vmx_inject_bounce(struct vmx_vcpu *vcpu)
{
	if (!vmx_interrupt_allowed()) {
		vmx_set_interrupt_window_exiting(true);
		return;
	}

	vmx_set_interrupt_window_exiting(false);
	slimvm_inject_vector(vcpu, VIRTUAL_EXCEPTION_VECTOR);
	vcpu->bounce_pending = false;
}

/**
 * vmx_setup_registers - setup general purpose registers
 */
static void vmx_setup_registers(struct vmx_vcpu *vcpu,
			struct slimvm_config *conf)
{
	vcpu->regs[VCPU_REGS_RAX] = conf->user_regs.rax;
	vcpu->regs[VCPU_REGS_RBX] = conf->user_regs.rbx;
	vcpu->regs[VCPU_REGS_RCX] = conf->user_regs.rcx;
	vcpu->regs[VCPU_REGS_RDX] = conf->user_regs.rdx;
	vcpu->regs[VCPU_REGS_RSI] = conf->user_regs.rsi;
	vcpu->regs[VCPU_REGS_RDI] = conf->user_regs.rdi;
	vcpu->regs[VCPU_REGS_RBP] = conf->user_regs.rbp;
	vcpu->regs[VCPU_REGS_R8]  = conf->user_regs.r8;
	vcpu->regs[VCPU_REGS_R9]  = conf->user_regs.r9;
	vcpu->regs[VCPU_REGS_R10] = conf->user_regs.r10;
	vcpu->regs[VCPU_REGS_R11] = conf->user_regs.r11;
	vcpu->regs[VCPU_REGS_R12] = conf->user_regs.r12;
	vcpu->regs[VCPU_REGS_R13] = conf->user_regs.r13;
	vcpu->regs[VCPU_REGS_R14] = conf->user_regs.r14;
	vcpu->regs[VCPU_REGS_R15] = conf->user_regs.r15;

	vmcs_writel(GUEST_RIP, conf->user_regs.rip);
	vmcs_writel(GUEST_RSP, conf->user_regs.rsp);
	vmcs_writel(GUEST_RFLAGS, conf->user_regs.rflags);
}

/**
 * vmx_copy_registers_to_conf - copy registers to slimvm_config
 */
static void vmx_copy_registers_to_conf(struct vmx_vcpu *vcpu,
				struct slimvm_config *conf)
{
	conf->user_regs.rax = vcpu->regs[VCPU_REGS_RAX];
	conf->user_regs.rbx = vcpu->regs[VCPU_REGS_RBX];
	conf->user_regs.rcx = vcpu->regs[VCPU_REGS_RCX];
	conf->user_regs.rdx = vcpu->regs[VCPU_REGS_RDX];
	conf->user_regs.rsi = vcpu->regs[VCPU_REGS_RSI];
	conf->user_regs.rdi = vcpu->regs[VCPU_REGS_RDI];
	conf->user_regs.rbp = vcpu->regs[VCPU_REGS_RBP];
	conf->user_regs.r8 = vcpu->regs[VCPU_REGS_R8];
	conf->user_regs.r9 = vcpu->regs[VCPU_REGS_R9];
	conf->user_regs.r10 = vcpu->regs[VCPU_REGS_R10];
	conf->user_regs.r11 = vcpu->regs[VCPU_REGS_R11];
	conf->user_regs.r12 = vcpu->regs[VCPU_REGS_R12];
	conf->user_regs.r13 = vcpu->regs[VCPU_REGS_R13];
	conf->user_regs.r14 = vcpu->regs[VCPU_REGS_R14];
	conf->user_regs.r15 = vcpu->regs[VCPU_REGS_R15];

	vmx_get_cpu(vcpu);
	conf->user_regs.rip = vmcs_readl(GUEST_RIP);
	conf->user_regs.rsp = vmcs_readl(GUEST_RSP);
	conf->user_regs.rflags = vmcs_readl(GUEST_RFLAGS);
	vmx_put_cpu(vcpu);
}

static void vmx_copy_status_to_conf(struct vmx_vcpu *vcpu,
			struct slimvm_config *conf)
{
	conf->status = vcpu->status;
}

/**
 * vmx_create_vcpu - allocates and initializes a new virtual cpu
 *
 * Returns: A new VCPU structure
 */
struct vmx_vcpu *vmx_create_vcpu(struct slimvm_config *conf,
				struct instance *instp)
{
	struct vmx_vcpu *vcpu;
	struct desc_ptr dt;
	sigset_t sigset;

	vcpu = kzalloc(sizeof(struct vmx_vcpu), GFP_KERNEL);
	if (!vcpu)
		return NULL;

	vcpu->vmcs = vmx_alloc_vmcs();
	if (!vcpu->vmcs)
		goto fail_vmcs;

	if (!vmx_allocate_vpid(vcpu))
		goto fail_vpid;

	vcpu->cpu = -1;
	vcpu->instance = instp;
	vcpu->syscall_table = (void *) &slimvm_syscall_table;

	vcpu->guest_msrs = kmalloc_array(NR_MSRS, sizeof(struct msr_entry),
				GFP_KERNEL);
	if (!vcpu->guest_msrs) {
		goto fail_guest_msrs;
	}

	vcpu->host_msrs = kmalloc_array(NR_MSRS, sizeof(struct msr_entry),
				  GFP_KERNEL);
	if (!vcpu->host_msrs)
		goto fail_host_msrs;

	native_store_idt(&dt);
	vcpu->idt_base = (void *)dt.address;

	vmx_get_cpu(vcpu);
	vmx_setup_vmcs(vcpu);
	if (vmx_setup_initial_guest_state(conf)) {
		slimvm_error("Initialize guest state failed!");
		vmx_put_cpu(vcpu);
		goto fail_initial_guest_state;
	}
	vmx_setup_registers(vcpu, conf);
	vmx_put_cpu(vcpu);

	sigfillset(&sigset);
	sigdelsetmask(&sigset, sigmask(SIGKILL) | sigmask(SIGSTOP) |
		sigmask(SIG_BOUNCE) | sigmask(SIGPROF));
	vcpu->sigset_active = 1;
	vcpu->sigset = sigset;
	vcpu->bounce_pending = false;
	vcpu->nmi_pending = false;

	preempt_notifier_init(&vcpu->preempt_notifier, &slimvm_preempt_ops);

	return vcpu;

fail_initial_guest_state:
	kfree(vcpu->host_msrs);
fail_host_msrs:
	kfree(vcpu->guest_msrs);
fail_guest_msrs:
	vmx_free_vpid(vcpu);
fail_vpid:
	vmx_free_vmcs(vcpu->vmcs);
fail_vmcs:
	kfree(vcpu);
	return NULL;
}

/**
 * vmx_destroy_vcpu - destroys and frees an existing virtual cpu
 * @vcpu: the VCPU to destroy
 */
void vmx_destroy_vcpu(struct vmx_vcpu *vcpu)
{
	vmx_get_cpu(vcpu);
	ept_sync_context(vcpu->instance->eptp);
	vmcs_clear(vcpu->vmcs);
	this_cpu_write(local_vcpu, NULL);
	vmx_put_cpu(vcpu);
	vmx_free_vpid(vcpu);
	vmx_free_vmcs(vcpu->vmcs);
	kfree(vcpu->host_msrs);
	kfree(vcpu->guest_msrs);
	kfree(vcpu);
}

static int vmx_load_vcpu(struct vmx_vcpu *vcpu)
{
	int cpu;

	cpu = get_cpu();
	preempt_notifier_register(&vcpu->preempt_notifier);

	vmx_save_host_msrs(vcpu);

	__load_vcpu(vcpu, cpu);
	this_cpu_write(vmx_current_vcpu, vcpu);

	vcpu->scheded = 1;
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
	put_cpu();

	return 0;
}

static void vmx_put_vcpu(struct vmx_vcpu *vcpu)
{
	preempt_disable();

	__put_vcpu(vcpu);
	this_cpu_write(vmx_current_vcpu, NULL);

	vmx_load_host_msrs(vcpu);
	vmx_put_guest_xcr0(vcpu);
	preempt_notifier_unregister(&vcpu->preempt_notifier);
	preempt_enable();
}

void make_pt_regs(struct vmx_vcpu *vcpu, struct pt_regs *regs,
		  int sysnr)
{
	regs->ax = sysnr;
	regs->orig_ax = vcpu->regs[VCPU_REGS_RAX];
	regs->bx = vcpu->regs[VCPU_REGS_RBX];
	regs->cx = vcpu->regs[VCPU_REGS_RCX];
	regs->dx = vcpu->regs[VCPU_REGS_RDX];
	regs->si = vcpu->regs[VCPU_REGS_RSI];
	regs->di = vcpu->regs[VCPU_REGS_RDI];
	regs->r8 = vcpu->regs[VCPU_REGS_R8];
	regs->r9 = vcpu->regs[VCPU_REGS_R9];
	regs->r10 = vcpu->regs[VCPU_REGS_R10];
	regs->r11 = vcpu->regs[VCPU_REGS_R11];
	regs->r12 = vcpu->regs[VCPU_REGS_R12];
	regs->r13 = vcpu->regs[VCPU_REGS_R13];
	regs->r14 = vcpu->regs[VCPU_REGS_R14];
	regs->r15 = vcpu->regs[VCPU_REGS_R15];
	regs->bp = vcpu->regs[VCPU_REGS_RBP];

	vmx_get_cpu(vcpu);
	regs->ip = vmcs_readl(GUEST_RIP);
	regs->sp = vmcs_readl(GUEST_RSP);
	/* FIXME: do we need to set up other flags? */
	regs->flags = (vmcs_readl(GUEST_RFLAGS) & 0xFF) |
		      X86_EFLAGS_IF | 0x2;
	vmx_put_cpu(vcpu);

	/*
	 * NOTE: Since SlimVM processes use the kernel's LSTAR
	 * syscall address, we need special logic to handle
	 * certain system calls (fork, clone, etc.) The specific
	 * issue is that we can not jump to a high address
	 * in a child process since it is not running in SlimVM.
	 * Our solution is to adopt a special SlimVM convention
	 * where the desired %RIP address is provided in %RCX.
	 */
	if (!(__addr_ok(regs->ip)))
		regs->ip = regs->cx;

	regs->cs = __USER_CS;
	regs->ss = __USER_DS;
}

static inline long
slimvm_do_fork(unsigned long clone_flags, unsigned long stack_start,
	     struct pt_regs *regs, unsigned long stack_size,
	     int __user *parent_tidptr, int __user *child_tidptr,
	     unsigned long tls)
{
	struct pt_regs tmp;
	struct pt_regs *me = current_pt_regs();
	long ret;
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

	memcpy(&tmp, me, sizeof(struct pt_regs));
	memcpy(me, regs, sizeof(struct pt_regs));

	ret = __slimvm_do_fork(&args);

	memcpy(me, &tmp, sizeof(struct pt_regs));
	return ret;

}

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
static long slimvm_sys_clone(struct pt_regs *regs)
{
	unsigned long newsp;

	newsp = regs->si;
	if (!newsp)
		newsp = regs->sp;

	/* According to Linux syscall convention, parameters as follows:
	 *   %rdi %rsi %rdx %r10 %r8 %r9.
	 */
	return slimvm_do_fork(regs->di, newsp, regs, 0, (int *)regs->dx,
			      (int *)regs->r10, regs->r8);
}
#else
static long slimvm_sys_clone(unsigned long clone_flags, unsigned long newsp,
		void __user *parent_tid, void __user *child_tid,
		unsigned long tls)
{
	struct vmx_vcpu *vcpu = this_cpu_read(vmx_current_vcpu);
	struct pt_regs regs;

	if (!vcpu) {
		printk("vcpu is null!\n");
		return -1;
	}

	make_pt_regs(vcpu, &regs, __NR_clone);
	if (!newsp)
		newsp = regs.sp;

	return slimvm_do_fork(clone_flags, newsp, &regs, 0, parent_tid, child_tid,
			      tls);
}
#endif

static long slimvm_sys_fork(void)
{
	struct vmx_vcpu *vcpu = this_cpu_read(vmx_current_vcpu);
	struct pt_regs regs;

	if (!vcpu)
		return -ENOENT;

	make_pt_regs(vcpu, &regs, __NR_fork);

	return slimvm_do_fork(SIGCHLD, regs.sp, &regs, 0, NULL, NULL, 0);
}

static long slimvm_sys_vfork(void)
{
	struct vmx_vcpu *vcpu = this_cpu_read(vmx_current_vcpu);
	struct pt_regs regs;

	if (!vcpu)
		return -ENOENT;

	make_pt_regs(vcpu, &regs, __NR_vfork);

	return slimvm_do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs.sp,
			      &regs, 0, NULL, NULL, 0);
}

static int slimvm_exit(int error_code)
{
	struct vmx_vcpu *vcpu = this_cpu_read(vmx_current_vcpu);

	if (!vcpu)
		return -ENOENT;

	vmx_put_vcpu(vcpu);

	vmx_set_vcpu_mode(vcpu, OUTSIDE_ROOT_MODE);
	vcpu_release(vcpu->instance, vcpu->vcpu_no);

	__slimvm_do_exit((error_code & 0xff) << 8);

	return 0;
}

static int slimvm_exit_group(int error_code)
{
	/* NOTE: we're supposed to send a signal to other threads before
	 * exiting. Because we don't yet support signals we do nothing
	 * extra for now.
	 */
	struct vmx_vcpu *vcpu = this_cpu_read(vmx_current_vcpu);

	if (!vcpu)
		return -ENOENT;

	vmx_put_vcpu(vcpu);

	vmx_set_vcpu_mode(vcpu, OUTSIDE_ROOT_MODE);
	vcpu_release(vcpu->instance, vcpu->vcpu_no);

	__slimvm_do_group_exit((long) (error_code & 0xff) << 8);

	return 0;
}

static int vmx_init_syscall(void)
{
	void *syscall_table = (void *) kln_hack("sys_call_table");

	if (!syscall_table) {
		slimvm_error("Failed to lookup symbol sys_call_table");
		return -EINVAL;
	}

	__slimvm_do_fork = (do_fork_hack) kln_hack("kernel_clone");
	if (!__slimvm_do_fork) {
		slimvm_error("Failed to lookup symbol _do_fork");
		return -EINVAL;
	}

	__slimvm_do_exit = (do_exit_hack) kln_hack("do_exit");
	if (!__slimvm_do_exit) {
		slimvm_error("Failed to lookup symbol do_exit");
		return -EINVAL;
	}

	__slimvm_do_group_exit = (do_group_exit_hack) kln_hack("do_group_exit");
	if (!__slimvm_do_group_exit) {
		slimvm_error("Failed to lookup symbol do_group_exit");
		return -EINVAL;
	}

	__slimvm_task_work_run = (task_work_run_hack) kln_hack("task_work_run");
	if (!__slimvm_task_work_run) {
		slimvm_error("task_work_run not found\n");
		return -EINVAL;
	}

	__slimvm_mem_cgroup_handle_over_high = (mem_cgroup_handle_over_high_hack)
					kln_hack("mem_cgroup_handle_over_high");
	if (!__slimvm_mem_cgroup_handle_over_high) {
		slimvm_error("mem_cgroup_handle_over_high not found\n");
		return -EINVAL;
	}

	memcpy(slimvm_syscall_table, syscall_table,
		sizeof(sys_call_ptr_t) * NR_syscalls);

	slimvm_syscall_table[__NR_exit] = (void *) &slimvm_exit;
	slimvm_syscall_table[__NR_exit_group] = (void *) &slimvm_exit_group;
	slimvm_syscall_table[__NR_clone] = (void *) &slimvm_sys_clone;
	slimvm_syscall_table[__NR_fork] = (void *) &slimvm_sys_fork;
	slimvm_syscall_table[__NR_vfork] = (void *) &slimvm_sys_vfork;

	return 0;
}

#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif

/**
 * vmx_run_vcpu - launches the CPU into non-root mode
 * @vcpu: the vmx instance to launch
 */
static int __noclone vmx_run_vcpu(struct vmx_vcpu *vcpu)
{
	asm(
		/* Store host registers */
		"push %%"R "dx; push %%"R "bp;"
		"push %%"R "cx \n\t" /* placeholder for guest rcx */
		"push %%"R "cx \n\t"
		"cmp %%"R "sp, %c[host_rsp](%0) \n\t"
		"je 1f \n\t"
		"mov %%"R "sp, %c[host_rsp](%0) \n\t"
		ASM_VMX_VMWRITE_RSP_RDX "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%0), %%"R "ax \n\t"
		"mov %%cr2, %%"R "dx \n\t"
		"cmp %%"R "ax, %%"R "dx \n\t"
		"je 2f \n\t"
		"mov %%"R "ax, %%cr2 \n\t"
		"2: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%"R "ax \n\t"
		"mov %c[rbx](%0), %%"R "bx \n\t"
		"mov %c[rdx](%0), %%"R "dx \n\t"
		"mov %c[rsi](%0), %%"R "si \n\t"
		"mov %c[rdi](%0), %%"R "di \n\t"
		"mov %c[rbp](%0), %%"R "bp \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
#endif
		"mov %c[rcx](%0), %%"R "cx \n\t" /* kills %0 (ecx) */

		/* Enter guest mode */
		"jne .Llaunched \n\t"
		ASM_VMX_VMLAUNCH "\n\t"
		"jmp .Lkvm_vmx_return \n\t"
		".Llaunched: " ASM_VMX_VMRESUME "\n\t"
		".Lkvm_vmx_return: "
		/* Save guest registers, load host registers, keep flags */
		"mov %0, %c[wordsize](%%"R "sp) \n\t"
		"pop %0 \n\t"
		"mov %%"R "ax, %c[rax](%0) \n\t"
		"mov %%"R "bx, %c[rbx](%0) \n\t"
		"pop"Q" %c[rcx](%0) \n\t"
		"mov %%"R "dx, %c[rdx](%0) \n\t"
		"mov %%"R "si, %c[rsi](%0) \n\t"
		"mov %%"R "di, %c[rdi](%0) \n\t"
		"mov %%"R "bp, %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
#endif
		"mov %%rax, %%r10 \n\t"
		"mov %%rdx, %%r11 \n\t"

		"mov %%cr2, %%"R "ax   \n\t"
		"mov %%"R "ax, %c[cr2](%0) \n\t"

		"pop  %%"R "bp; pop  %%"R "dx \n\t"
		"setbe %c[fail](%0) \n\t"

		"mov $" __stringify(__USER_DS) ", %%rax \n\t"
		"mov %%rax, %%ds \n\t"
		"mov %%rax, %%es \n\t"
	      : : "c"(vcpu), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vmx_vcpu, launched)),
		[fail]"i"(offsetof(struct vmx_vcpu, fail)),
		[host_rsp]"i"(offsetof(struct vmx_vcpu, host_rsp)),
		[rax]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vmx_vcpu, cr2)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
		, R "ax", R "bx", R "di", R "si"
#ifdef CONFIG_X86_64
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
	);

	vcpu->regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
	if (unlikely(vcpu->fail)) {
		slimvm_error("vmx: failure detected (err %x)",
			vmcs_read32(VM_INSTRUCTION_ERROR));
		vcpu->status = SLIMVM_RET_FAIL_ENTRY;
		return VMX_EXIT_REASONS_FAILED_VMENTRY;
	}
	vcpu->launched = 1;

	return vmcs_read32(VM_EXIT_REASON);
}

static inline void vmx_step_instruction(struct vmx_vcpu *vcpu)
{
	unsigned long rip;
	rip = vmcs_readl(GUEST_RIP);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);

	vmcs_writel(GUEST_RIP, rip);
	vcpu->regs[VCPU_REGS_RIP] = rip;
}

static inline void vmx_process_step_instructions(int reason, struct vmx_vcpu *vcpu)
{
	switch (reason) {
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_MSR_WRITE:
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_HLT:
	case EXIT_REASON_XSETBV:
		vmx_step_instruction(vcpu);
		break;
	}
}

static int vmx_handle_ept_misconfig(struct vmx_vcpu *vcpu)
{
	unsigned long gpa;
	unsigned long *epte;
	int ret;

	vmx_get_cpu(vcpu);
	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	vmx_put_cpu(vcpu);

	ret = vmx_do_ept_misconfig(vcpu->instance, gpa, &epte);
	slimvm_error("ept-misconfig: gpa[0x%lx] epte[0x%lx] ret[%d]\n",
			gpa, *epte, ret);
	vmx_dump_cpu(vcpu);

	return 0;
}

static int vmx_handle_ept_violation(struct vmx_vcpu *vcpu)
{
	unsigned long gva, gpa;
	int exit_qual, ret;
	struct instance *instp;

	vmx_get_cpu(vcpu);
	exit_qual = vmcs_read32(EXIT_QUALIFICATION);
	gva = vmcs_readl(GUEST_LINEAR_ADDRESS);
	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	vmx_put_cpu(vcpu);

	if (exit_qual & (1 << 6)) {
		slimvm_error("EPT: GPA 0x%lx exceeds GAW!", gpa);
		return -EINVAL;
	}

	ret = vmx_do_ept_violation(vcpu->instance, gpa, gva, exit_qual);
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
		instp = vcpu->instance;

		slimvm_debug(
		"vmx: sandbox %08lx EPT fault (err: %d) GPA: 0x%lx GVA: 0x%lx",
			instp->sid, ret, gpa, gva);
		/*
		 * FIXME:
		 * If a EPT fault failure occur, the guest instance should be killed forcely.
		 * It should be a bug for guest instance or slimvm.
		 */
		vcpu->status = SLIMVM_RET_EPT_VIOLATION;
		if (slimvm_debug_enable)
			vmx_dump_cpu(vcpu);
		break;
	}

	return ret;
}

static noinline void vmx_handle_syscall(struct vmx_vcpu *vcpu)
{
	__u64 orig_rax;
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
	struct pt_regs regs;
#endif

	orig_rax = vcpu->regs[VCPU_REGS_RAX];
	if (unlikely(orig_rax >= NR_syscalls)) {
		vcpu->regs[VCPU_REGS_RAX] = -ENOSYS;
		return;
	}

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
	/* Since commit fa697140f9a2 ("syscalls/x86: Use 'struct pt_regs' based
	 * syscall calling convention for 64-bit syscalls")
	 */
	make_pt_regs(vcpu, &regs, orig_rax);
	vcpu->regs[VCPU_REGS_RAX] = slimvm_syscall_table[orig_rax](&regs);
#else
	asm(
		"mov %c[rax](%0), %%"R "ax \n\t"
		"mov %c[rdi](%0), %%"R "di \n\t"
		"mov %c[rsi](%0), %%"R "si \n\t"
		"mov %c[rdx](%0), %%"R "dx \n\t"
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[syscall](%0), %%r10 \n\t"
		"mov %0, %%r11 \n\t"
		"push %0 \n\t"
		"mov %c[r10](%0), %%"R "cx \n\t"
		"shl $3, %%rax \n\t"
		"add %%r10, %%rax\n\t"
		"call *(%%rax) \n\t"
		"pop %0 \n\t"
		"mov %%"R "ax, %c[rax](%0) \n\t"

		: : "c"(vcpu),
		[syscall]"i"(offsetof(struct vmx_vcpu, syscall_table)),
		[rax]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RAX])),
		[rdi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDI])),
		[rsi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RSI])),
		[rdx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDX])),
		[r10]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R10])),
		[r8]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R9]))
	      : "cc", "memory", R "ax", R "dx", R "di", R "si", "r8", "r9", "r10"
	);
#endif

	if (signal_pending(current)) {
		/* Whee! Actually interrupted by signal. */
		switch (vcpu->regs[VCPU_REGS_RAX]) {
		case -ERESTARTNOHAND:
		case -ERESTART_RESTARTBLOCK:
			vcpu->regs[VCPU_REGS_RAX] = -EINTR;
			break;
		case -ERESTARTSYS:
			/*
			 * __NR_futex and __NR_ppoll are handled and invoke
			 * again from Sentry and runtime. sentry would change
			 * syscall path when to upgrade slimvm platform.
			 *
			 * TODO: Handle all syscalls in general when it is
			 * interrupted by signal and returns -ERESTARTSYS.
			 */
			if (orig_rax == __NR_futex || orig_rax == __NR_ppoll) {
				vcpu->regs[VCPU_REGS_RAX] = -EINTR;
				break;
			}
			fallthrough;
		case -ERESTARTNOINTR:
			vcpu->regs[VCPU_REGS_RAX] = orig_rax;
			vmx_get_cpu(vcpu);
			vmcs_writel(GUEST_RIP, vmcs_readl(GUEST_RIP) - 3);
			vmx_put_cpu(vcpu);
			break;
		}
	} else {
		switch (vcpu->regs[VCPU_REGS_RAX]) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			vcpu->regs[VCPU_REGS_RAX] = orig_rax;
			vmx_get_cpu(vcpu);
			vmcs_writel(GUEST_RIP, vmcs_readl(GUEST_RIP) - 3);
			vmx_put_cpu(vcpu);
			break;
		case -ERESTART_RESTARTBLOCK:
			vcpu->regs[VCPU_REGS_RAX] = __NR_restart_syscall;
			vmx_get_cpu(vcpu);
			vmcs_writel(GUEST_RIP, vmcs_readl(GUEST_RIP) - 3);
			vmx_put_cpu(vcpu);
			break;
		}
	}
}

static void vmx_handle_cpuid(struct vmx_vcpu *vcpu)
{
	unsigned int eax, ebx, ecx, edx;

	eax = vcpu->regs[VCPU_REGS_RAX];
	ecx = vcpu->regs[VCPU_REGS_RCX];
	native_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->regs[VCPU_REGS_RAX] = eax;
	vcpu->regs[VCPU_REGS_RBX] = ebx;
	vcpu->regs[VCPU_REGS_RCX] = ecx;
	vcpu->regs[VCPU_REGS_RDX] = edx;
}

static int vmx_handle_nmi_exception(struct vmx_vcpu *vcpu)
{
	u32 intr_info;

	vmx_get_cpu(vcpu);
	intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	vmx_put_cpu(vcpu);

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return 0;

	/* Check & handle debug exceptions */
	pr_debug("vmx: got interrupt, intr_info 0x%x Interrupt: 0x%x\n",
		 intr_info, intr_info & INTR_INFO_VECTOR_MASK);

	slimvm_exception_handler(intr_info, vcpu);

	vcpu->status = intr_info & INTR_INFO_VECTOR_MASK;

	return 0;
}

static int vmx_handle_msr_read(struct vmx_vcpu *vcpu)
{
	struct msr_entry *msr;
	u32 msr_addr;
	u64 msr_data;

	msr_addr = vcpu->regs[VCPU_REGS_RCX];

	msr = find_msr_entry(vcpu, msr_addr);
	if (msr)
		msr_data = msr->data;
	else
		return -1;

	vcpu->regs[VCPU_REGS_RAX] = msr_data & -1u;
	vcpu->regs[VCPU_REGS_RDX] = msr_data >> 32;

	return 0;
}

static int vmx_handle_msr_write(struct vmx_vcpu *vcpu)
{
	u32 msr_addr;
	u64 msr_data;
	struct msr_entry *msr;
	msr_addr = vcpu->regs[VCPU_REGS_RCX];
	msr_data = (vcpu->regs[VCPU_REGS_RAX] & -1u)
		   | ((u64)(vcpu->regs[VCPU_REGS_RDX] & -1u) << 32);

	msr = find_msr_entry(vcpu, msr_addr);
	if (msr)
		msr->data = msr_data;
	else if (msr_addr == MSR_CSTAR) {
		/* ignore IA32_CSTSR as it is not used in Intel CPU */
	} else {
		slimvm_error("unknown msr: 0x%x", msr_addr);
		return -1;
	}

	return 0;
}

/*
 * vmx_handle_external_interrupt - when posted interrupt processing is enabled,
 * the "Acknowledge interrupt on exit" VM-exit control must be enabled as well.
 * Thus, when an external interrupt is received, it is automatically acknowledged
 * and the vector information is stored in the VMCS, but it is never actually
 * handled by the Linux kernel.
 *
 * This function calls the appropriate handling function in the kernel as though
 * the interrupt were never intercepted.
 *
 * This code is from KVM.
 */
static void vmx_handle_external_interrupt(struct vmx_vcpu *vcpu, u32 exit_intr_info)
{
	if ((exit_intr_info & (INTR_INFO_VALID_MASK | INTR_INFO_INTR_TYPE_MASK))
		== (INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR)) {

		unsigned int vector;
		unsigned long entry;
		gate_desc *desc;
#ifdef CONFIG_X86_64
		unsigned long tmp;
#endif
		register unsigned long current_stack_pointer asm(_ASM_SP);
		vector =  exit_intr_info & INTR_INFO_VECTOR_MASK;
		desc = (gate_desc *)vcpu->idt_base + vector;
		entry = gate_offset_compat(desc);

		asm volatile(
#ifdef CONFIG_X86_64
			"mov %%" _ASM_SP ", %[sp]\n\t"
			"and $0xfffffffffffffff0, %%" _ASM_SP "\n\t"
			"push $%c[ss]\n\t"
			"push %[sp]\n\t"
#endif
			"pushf\n\t"
			__ASM_SIZE(push) " $%c[cs]\n\t"
			"call *%[entry]\n\t"
			:
#ifdef CONFIG_X86_64
			[sp]"=&r"(tmp),
#endif
			"+r" (current_stack_pointer)
			:
			[entry]"r"(entry),
			[ss]"i"(__KERNEL_DS),
			[cs]"i"(__KERNEL_CS)
			);
	    }
}

static void vmx_set_interrupt_shadow(struct vmx_vcpu *vcpu, int mask)
{
	u32 interruptibility_old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	u32 interruptibility = interruptibility_old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & 0x1)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	else if (mask & 0x2)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != interruptibility_old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static void skip_emulated_instruction(struct vmx_vcpu *vcpu)
{
	vmx_get_cpu(vcpu);

	/* skipping an emulated instruction also counts */
	vmx_set_interrupt_shadow(vcpu, 0);

	vmx_put_cpu(vcpu);
}

int emulate_vcpu_halt(struct vmx_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	vcpu->status = SLIMVM_RET_HLT;

	return 1;
}

static int handle_halt(struct vmx_vcpu *vcpu)
{
	return emulate_vcpu_halt(vcpu);
}

/*
 * Handle xsetbv instruction from guest.
 */
static int handle_xsetbv(struct vmx_vcpu *vcpu)
{
	u64 xcr0 = (vcpu->regs[VCPU_REGS_RAX] & -1u)
		   | ((u64)(vcpu->regs[VCPU_REGS_RDX] & -1u) << 32);
	u32 index = vcpu->regs[VCPU_REGS_RCX];

	/*
	 * FIXME: we should adjust the CPL is 0 or 3.
	 * Wait another patch to fix this.
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

	vcpu->xcr0 = xcr0;

	return 0;
}

static inline void vmx_process_vcpu_requests(struct vmx_vcpu *vcpu)
{
	if (vcpu->requests) {
		if (vmx_check_request(VMX_REQ_TLB_FLUSH, vcpu))
			vmx_vcpu_flush_tlb(vcpu);
		if (vmx_check_request(VMX_REQ_NMI, vcpu))
			vmx_process_nmi(vcpu);
	}
}

#define HIGHER_HALF_CANONICAL_ADDR 0xFFFF800000000000

void (*fn_do_nmi)(struct pt_regs *);

static inline void vmx_handle_nmi(struct vmx_vcpu *vcpu)
{
	struct pt_regs regs;

	this_cpu_write(local_vcpu, vcpu);
	vcpu->flags = vmcs_readl(GUEST_RFLAGS);
	if (vcpu->flags & X86_EFLAGS_IF)
		asm("int $2");
	else {
		make_pt_regs(vcpu, &regs, vcpu->regs[VCPU_REGS_RAX]);
		regs.flags = vcpu->flags;
		regs.ip = vcpu->regs[VCPU_REGS_RIP];

		/* In sentry GR0, we will use address among
		 *   [HIGHER_HALF_CANONICAL_ADDR, 2^64-1)
		 * when syscall just happens. To avoid conflicting with hr0,
		 * we correct these address into hr3 address.
		 */
		regs.ip &= ~HIGHER_HALF_CANONICAL_ADDR;
		regs.bp &= ~HIGHER_HALF_CANONICAL_ADDR;
		regs.sp &= ~HIGHER_HALF_CANONICAL_ADDR;

		fn_do_nmi(&regs);
	}
	this_cpu_write(local_vcpu, NULL);
}


/**
 * vmx_launch - the main loop for a VMX SlimVM process
 * @conf: the launch configuration
 */
int vmx_launch(struct vmx_vcpu *vcpu, struct slimvm_config *conf)
{
	int reason, last_vmexit = 0, done = 0, r = 0;
	u32 exit_intr_info;
	sigset_t sigsaved;

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	vmx_load_vcpu(vcpu);

	while (1) {
		if (prepare_enter_guestmode(vcpu))
			break;

		preempt_disable();

		/*
		 * * __NR_clone syscalls may change local_vcpu, load
		 * vcpu again if changed.
		 */
		__load_vcpu(vcpu, raw_smp_processor_id());

		vmx_process_vcpu_requests(vcpu);

		/*
		 * We assume that a SlimVM process will always use
		 * the FPU whenever it is entered, and thus we go
		 * ahead and load FPU state here. The reason is
		 * that we don't monitor or trap FPU usage inside
		 * a SlimVM process.
		 */
		compat_fpu_restore();

		if (vcpu->bounce_pending)
			vmx_inject_bounce(vcpu);

		/*
		 * Sentry relies on NMI to send SIGBUS to GR3 application.
		 * Here we try best to inject NMI to guest, otherwise,
		 * return error to HR3.
		 */
		if (vcpu->nmi_pending) {
			r = vmx_inject_nmi(vcpu);
			if (r) {
				vmx_set_vcpu_mode(vcpu, OUTSIDE_GUEST_MODE);
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
		if (unlikely(vcpu->debug_mode))
			exceptions_restore_guest_regs(vcpu);

		local_irq_disable();
		vmx_set_vcpu_mode(vcpu, IN_GUEST_MODE);

		if (vmx_check_vcpu_mode(vcpu, EXITING_GUEST_MODE) ||
			vcpu->requests || need_resched()) {
			vmx_set_vcpu_mode(vcpu, OUTSIDE_GUEST_MODE);
			local_irq_enable();
			preempt_enable();
			continue;
		}

		vmx_save_host_state(vcpu);
		if (vcpu->scheded) {
			vmx_load_guest_xcr0(vcpu, conf);
			vmx_load_guest_msrs(vcpu);
			vcpu->scheded = 0;
		} else {
			/*
			 * *SWAPGS instruction* swaps the contents of two specific MSRs
			 * (MSR_GS_BASE and MSR_KERNEL_GS_BASE) in host syscalls without
			 * rescheduled. Ignore them as below note:
			 *
			 * *NOTE* from Linux Documentation/x86/entry_64.txt:
			 * swapgs instruction is rather fragile: it must nest perfectly
			 * and only in single depth, it should only be used if entering
			 * from user mode to kernel mode and then when returning to
			 * user-space, and precisely so. If we mess that up even slightly,
			 * we crash. So when we have a secondary entry, already in
			 * kernel mode, we *must not* use SWAPGS blindly - nor must we
			 * forget doing a SWAPGS when it's not switched/swapped yet.
			 */
			switch (last_vmexit) {
			case EXIT_REASON_VMCALL:
			case EXIT_REASON_EPT_VIOLATION:
			case EXIT_REASON_EXTERNAL_INTERRUPT:
				load_guest_msr(vcpu, MSR_EFER);
				load_guest_msr(vcpu, MSR_KERNEL_GS_BASE);
				break;
			case EXIT_REASON_XSETBV:
				vmx_load_guest_xcr0(vcpu, conf);
				fallthrough;
			default:
				vmx_load_guest_msrs(vcpu);
			}
		}

		guest_enter_irqoff();

		reason = vmx_run_vcpu(vcpu);

		vmx_set_vcpu_mode(vcpu, OUTSIDE_GUEST_MODE);

		last_vmexit = reason;

		vmx_load_host_state(vcpu);

		/*
		 * *SWAPGS instruction* swaps the contents of two specific MSRs
		 * (MSR_GS_BASE and MSR_KERNEL_GS_BASE) in VMX non-root operation
		 * without VMEXIT.
		 */
		save_guest_msr(vcpu, MSR_KERNEL_GS_BASE);
		switch (reason) {
		case EXIT_REASON_VMCALL:
		case EXIT_REASON_EPT_VIOLATION:
		case EXIT_REASON_EXTERNAL_INTERRUPT:
			load_host_msr(vcpu, MSR_EFER);
			load_host_msr(vcpu, MSR_KERNEL_GS_BASE);
			vcpu->flags = vmcs_readl(GUEST_RFLAGS);
			break;
		default:
			vmx_load_host_msrs(vcpu);
		}

		/* We need to handle NMIs before interrupts are enabled */
		exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
		if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
		    (exit_intr_info & INTR_INFO_VALID_MASK))
			vmx_handle_nmi(vcpu);

		vmx_handle_external_interrupt(vcpu, exit_intr_info);

		guest_exit_irqoff();

		vmx_process_step_instructions(reason, vcpu);
		local_irq_enable();
		preempt_enable();

		switch (reason) {
		case EXIT_REASON_VMCALL:
			if (likely(!vmx_get_cpl(vcpu))) {
				if (!do_seccomp_filter(vcpu)) {
					vmx_handle_syscall(vcpu);
				} else {
					done = 1;
					vmx_shutdown_all_vcpus(vcpu->instance);
				}
			}
			break;
		case EXIT_REASON_CPUID:
			vmx_handle_cpuid(vcpu);
			break;
		case EXIT_REASON_EPT_VIOLATION:
			r = vmx_handle_ept_violation(vcpu);
			if (r < 0) {
				done = SLIMVM_RET_INTERNAL_ERROR;
				vcpu->status = done;
			}
			/*
			 * On success, leave vcpu->status untouched. Follows
			 * Linux KVM, where handle_ept_violation() resumes the
			 * guest (returns 1) without touching run->exit_reason.
			 * See https://elixir.bootlin.com/linux/v6.1/source/arch/x86/kvm/vmx/vmx.c#L5667
			 */
			break;
		case EXIT_REASON_EPT_MISCONFIG:
			vmx_handle_ept_misconfig(vcpu);
			vcpu->status = SLIMVM_RET_UNHANDLED_VMEXIT;
			done = 1;
			break;
		case EXIT_REASON_HLT:
			done = handle_halt(vcpu);
			break;
		case EXIT_REASON_EXCEPTION_NMI:
			if (vmx_handle_nmi_exception(vcpu))
				done = 1;
			break;
		case EXIT_REASON_MSR_WRITE:
			if (vmx_handle_msr_write(vcpu)) {
				vcpu->status = SLIMVM_RET_MSR_WRITE;
				done = 1;
			}
			break;
		case EXIT_REASON_MSR_READ:
			if (vmx_handle_msr_read(vcpu))
				done = 1;
			break;
		case EXIT_REASON_XSETBV:
			handle_xsetbv(vcpu);
			break;
		case EXIT_REASON_INTERRUPT_WINDOW:
			if (vcpu->bounce_pending)
				vmx_inject_bounce(vcpu);
			else
				vmx_set_interrupt_window_exiting(false);
			break;

		/*
		 * Do not return to HR3 when MCE during vmentry.
		 */
		case EXIT_REASON_MCE_DURING_VMENTRY:
		case EXIT_REASON_EXTERNAL_INTERRUPT:
			break;
		default:
			if (reason & VMX_EXIT_REASONS_FAILED_VMENTRY)
				vcpu->status = SLIMVM_RET_FAIL_ENTRY;
			else
				vcpu->status = SLIMVM_RET_UNHANDLED_VMEXIT;

			vmx_dump_cpu(vcpu);
			done = 1;
		}

		if (done || vcpu->shutdown)
			break;
	}

	vmx_put_vcpu(vcpu);

	vmx_copy_status_to_conf(vcpu, conf);
	vmx_copy_registers_to_conf(vcpu, conf);

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	vmx_set_vcpu_mode(vcpu, OUTSIDE_ROOT_MODE);

	if (signal_pending(current))
		r = -EINTR;

	return r;
}

/**
 * __vmx_enable - low-level enable of VMX mode on the current CPU
 * @vmxon_buf: an opaque buffer for use as the VMXON region
 */
static __init int __vmx_enable(struct vmcs *vmxon_buf)
{
	u64 phys_addr = __pa(vmxon_buf);
	u64 old, test_bits;

	if (__read_cr4() & X86_CR4_VMXE)
		return -EBUSY;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);

	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
	cr4_set_bits(X86_CR4_VMXE);

	__vmxon(phys_addr);
	vpid_sync_vcpu_global();
	ept_sync_global();

	return 0;
}

/**
 * vmx_enable - enables VMX mode on the current CPU
 * @unused: not used (required for on_each_cpu())
 *
 * Sets up necessary state for enable (e.g. a scratchpad for VMXON.)
 */
static __init void vmx_enable(void *unused)
{
	int ret;
	struct vmcs *vmxon_buf = __this_cpu_read(vmxarea);

	ret = __vmx_enable(vmxon_buf);
	if (ret)
		goto failed;
	this_cpu_write(vmx_enabled, 1);
	native_store_gdt(this_cpu_ptr(&host_gdt));

	return;

failed:
	atomic_inc(&vmx_enable_failed);
	slimvm_error("vmx: failed to enable VMX, err = %d", ret);
}

/**
 * vmx_disable - disables VMX mode on the current CPU
 */
static void vmx_disable(void *unused)
{
	if (__this_cpu_read(vmx_enabled)) {
		__vmxoff();
		cr4_clear_bits(X86_CR4_VMXE);
		this_cpu_write(vmx_enabled, 0);
	}
}

/**
 * vmx_free_vmxon_areas - cleanup helper function to free all VMXON buffers
 */
static void vmx_free_vmxon_areas(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (per_cpu(vmxarea, cpu)) {
			vmx_free_vmcs(per_cpu(vmxarea, cpu));
			per_cpu(vmxarea, cpu) = NULL;
		}
	}
}

/**
 * vmx_init - the main initialization routine for this driver
 */
__init int vmx_init(void)
{
	int r, cpu;

	slimvm_get_cpu_feature();

	r = vmx_init_syscall();
	if (r) {
		slimvm_error("failed to get syscall table");
		return -EINVAL;
	}

	r = setup_vmcs_config(&vmcs_config);
	if (r) {
		slimvm_error("failed to setup vmcs config");
		return -EIO;
	}

	msr_bitmap = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!msr_bitmap) {
		slimvm_error("vmx: Allocate msr_bitmap failed!");
		return -ENOMEM;
	}

	memset(msr_bitmap, 0xff, PAGE_SIZE);
	__vmx_disable_intercept_for_msr(msr_bitmap, MSR_FS_BASE);
	__vmx_disable_intercept_for_msr(msr_bitmap, MSR_GS_BASE);
	__vmx_disable_intercept_for_msr(msr_bitmap, MSR_KERNEL_GS_BASE);

	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */

	for_each_possible_cpu(cpu) {
		struct vmcs *vmxon_buf;

		vmxon_buf = __vmx_alloc_vmcs(cpu);
		if (!vmxon_buf) {
			r = -ENOMEM;
			goto failed1;
		}

		per_cpu(vmxarea, cpu) = vmxon_buf;
	}

	atomic_set(&vmx_enable_failed, 0);
	on_each_cpu(vmx_enable, NULL, 1);
	if (atomic_read(&vmx_enable_failed)) {
		r = -EBUSY;
		goto failed2;
	}

	if (has_xsave)
		host_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	slimvm_preempt_ops.sched_in = slimvm_sched_in;
	slimvm_preempt_ops.sched_out = slimvm_sched_out;

	return 0;

failed2:
	on_each_cpu(vmx_disable, NULL, 1);
failed1:
	vmx_free_vmxon_areas();
	free_page((unsigned long)msr_bitmap);
	return r;
}

/**
 * vmx_exit - the main removal routine for this driver
 */
void vmx_exit(void)
{
	on_each_cpu(vmx_disable, NULL, 1);
	vmx_free_vmxon_areas();
	free_page((unsigned long)msr_bitmap);
}
