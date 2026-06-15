/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * vmx.h - header file for SlimVM VMX driver.
 */

#ifndef __VMX_H_
#define __VMX_H_

#include <linux/types.h>
#include <asm/vmx.h>
#include <asm/signal.h>
#include <linux/kvm_types.h>
#include <linux/version.h>

#include "engine.h"
#include "instance.h"
#include "vmcs.h"


struct vmx_capability {
	u64 pin_based;
	u64 secondary;
	u32 ept;
	u32 vpid;
	int has_load_efer:1;
};

extern struct vmx_capability vmx_capability;

struct vmx_vcpu {
	struct list_head list;
	int cpu;
	int vpid;
	int launched;
	unsigned long requests;

#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
#endif

	bool guest_msrs_loaded;
	bool guest_xcr0_loaded;
	bool scheded;

	bool debug_mode;

	u8  mode;
	u8  fail;
	u64 exit_reason;
	u64 host_rsp;
	u64 regs[NR_VCPU_REGS];
	u64 cr2;
	s64 status;
	u64 xcr0;
	u64 flags;

	int shutdown;
	int save_nmsrs;
	int nmsrs;

	struct {
		unsigned long cr3;
		unsigned long cr4;
		u16 fs_sel, gs_sel, ldt_sel;
		u16 ds_sel, es_sel;
		int gs_ldt_reload_needed;
		int fs_reload_needed;
	} host_state;
	struct msr_autoload {
		struct vmx_msr_entry guest;
		struct vmx_msr_entry host;
	} msr_autoload;

	struct vmcs *vmcs;
	void *syscall_table;
	void *idt_base;
	struct msr_entry *host_msrs;
	struct msr_entry *guest_msrs;

	struct {
		int sys_call_mask;
		int kernel_gs_base;
		int feature_enable;
		int lstar;
		int efer;
		int star;
	} msr_index;

	struct instance *instance;
	int vcpu_no;
	sigset_t sigset;
	bool sigset_active;
	bool bounce_pending;
	bool nmi_pending;

	int vmexit_num;
	int vmcall_total;
};

/*
 * VMX request aliases over the shared SLIMVM_REQ_* bits (see engine.h).
 * Kept for readability of the VMX-internal call sites.
 */
#define VMX_REQ_TLB_FLUSH	SLIMVM_REQ_TLB_FLUSH
#define VMX_REQ_MMU_RELOAD	SLIMVM_REQ_MMU_RELOAD
#define VMX_REQ_PENDING_TIMER	SLIMVM_REQ_PENDING_TIMER
#define VMX_REQ_UNHALT		SLIMVM_REQ_UNHALT
#define VMX_REQ_NMI		SLIMVM_REQ_NMI

extern int vmx_hardware_enable_all(void);
extern void vmx_hardware_disable_all(void);
extern void vmx_cleanup(void);

extern int vmx_launch(struct vmx_vcpu *vcpu, struct slimvm_config *conf);

extern struct vmx_vcpu *vmx_create_vcpu(struct slimvm_config *conf,
					struct instance *instp, int vcpu_no);
extern void vmx_destroy_vcpu(struct vmx_vcpu *vcpu);
extern void vmx_shutdown_all_vcpus(struct instance *instp);
extern void vmx_sync_all_vcpus(struct instance *instp);
extern void vcpu_inject_nmi(struct instance *instp, int vcpu_no);

extern int vmx_do_ept_violation(struct instance *instp, unsigned long gpa,
	 unsigned long gva, int fault_flags);
extern int vmx_do_ept_misconfig(struct instance *instp,
		unsigned long gpa, unsigned long **epte);
extern u64 construct_eptp(unsigned long root_hpa);
extern void vmx_ept_sync_individual_addr(struct instance *instp, gpa_t gpa);

extern void vmx_get_cpu(struct vmx_vcpu *vcpu);
extern void vmx_put_cpu(struct vmx_vcpu *vcpu);

extern void vmx_set_vcpu_mode(struct vmx_vcpu *vcpu, u8 mode);
extern bool vmx_check_vcpu_mode(struct vmx_vcpu *vcpu, u8 mode);

extern void make_pt_regs(struct vmx_vcpu *vcpu, struct pt_regs *regs, int sysnr);

/* Exception handling entry points (exception.c). */
int slimvm_signal_handler(struct vmx_vcpu *vcpu);
int slimvm_exception_handler(u32 intr_info, struct vmx_vcpu *vcpu);
void slimvm_inject_vector(struct vmx_vcpu *vcpu, u64 vector);
void slimvm_inject_nmi(struct vmx_vcpu *vcpu);
void exceptions_restore_guest_regs(struct vmx_vcpu *vcpu);

extern void (*fn_do_nmi)(struct pt_regs *);

extern inline bool cpu_has_secondary_exec_ctrls(void);
extern inline bool cpu_has_vmx_invvpid_single(void);
extern inline bool cpu_has_vmx_invept_individual_addr(void);
extern inline bool cpu_has_vmx_invept_context(void);
extern inline bool cpu_has_vmx_invept_global(void);
extern inline bool cpu_has_vmx_ept_ad_bits(void);

static inline bool vmx_check_request(int req, struct vmx_vcpu *vcpu)
{
	if (test_bit(req, &vcpu->requests)) {
		clear_bit(req, &vcpu->requests);

		/*
		 * Ensure the rest of the request is visible to vmx_check_request's
		 * caller.  Paired with the smp_wmb in vmx_make_request.
		 */
		smp_mb__after_atomic();
		return true;
	}

	return false;
}

static inline void vmx_make_request(int req, struct vmx_vcpu *vcpu)
{
	/*
	 * Ensure the rest of the request is published to kvm_check_request's
	 * caller.  Paired with the smp_mb__after_atomic in kvm_check_request.
	 */
	smp_wmb();
	set_bit(req, &vcpu->requests);
}

static inline int vmx_vcpu_exiting_guest_mode(struct vmx_vcpu *vcpu)
{
	return cmpxchg(&vcpu->mode, IN_GUEST_MODE, EXITING_GUEST_MODE);
}

static inline int vmx_interrupt_allowed(void)
{
	return (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
		!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

static inline unsigned long read_msr(unsigned long msr)
{
	unsigned long value;

	rdmsrl(msr, value);

	return value;
}
#endif /* __VMX_H_ */
