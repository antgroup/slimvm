/*
 * svm.h - header file for SVM driver.
 */

#ifndef __SVM_H_
#define __SVM_H_

#include <linux/mmu_notifier.h>
#include <linux/types.h>
#include <asm/svm.h>
#include <linux/kvm_types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "engine.h"
#include "vmcb.h"
#include "instance.h"

#define HF_NMI_MASK (1 << 3)

#ifndef __sme_page_pa
#define __sme_page_pa(x) __sme_set(page_to_pfn(x) << PAGE_SHIFT)
#endif

typedef enum vcpu_reg svm_reg;


enum {
	VMCB_INTERCEPTS, /* Intercept vectors, TSC offset,
			    pause filter count */
	VMCB_PERM_MAP,   /* IOPM Base and MSRPM Base */
	VMCB_ASID,	 /* ASID */
	VMCB_INTR,	 /* int_ctl, int_vector */
	VMCB_NPT,        /* npt_en, nCR3, gPAT */
	VMCB_CR,	 /* CR0, CR3, CR4, EFER */
	VMCB_DR,         /* DR6, DR7 */
	VMCB_DT,         /* GDT, IDT */
	VMCB_SEG,        /* CS, DS, SS, ES, CPL */
	VMCB_CR2,        /* CR2 only */
	VMCB_LBR,        /* DBGCTL, BR_FROM, BR_TO, LAST_EX_FROM, LAST_EX_TO */
	VMCB_AVIC,       /* AVIC APIC_BAR, AVIC APIC_BACKING_PAGE,
			  * AVIC PHYSICAL_TABLE pointer,
			  * AVIC LOGICAL_TABLE pointer
			  */
	VMCB_DIRTY_MAX,
};

struct svm_vcpu {
	int cpu;
	int launched;
	unsigned long requests;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
#endif
	bool scheded;
	bool debug_mode;

	u8  mode;
	u8  fail;
	u64 exit_reason;
	u64 status;
	int shutdown;
	void *syscall_table;
	struct instance *instance;
	int vcpu_no;
	sigset_t sigset;
	bool sigset_active;
	bool bounce_pending;
	int vmexit_num;
	u32 hflags;

	struct list_head list;
	struct vmcb *vmcb;
	unsigned long vmcb_pa;

	u64 asid_generation;
	u32 asid;

	bool host_state_loaded;
	bool guest_msrs_loaded;
	bool guest_xcr0_loaded;

	u64 host_rsp;
	u64 regs[NR_VCPU_REGS];
	u64 cr2;
	u64 xcr0;
	u64 flags;

	int save_nmsrs;
	int nmsrs;

	u64 *host_user_msrs;

	struct {
		u64 gs_base;
		u16 fs_sel, gs_sel, ldt_sel;
		int gs_ldt_reload_needed;
		int fs_reload_needed;
	} host_state;

	bool nmi_pending;

	int vmmcall_total;
};

extern void svm_shutdown_all_vcpus(struct instance *instp);
extern void svm_sync_all_vcpus(struct instance *instp);
extern int svm_inject_event(struct svm_vcpu *vcpu, u64 vectors);

extern int svm_do_npt_violation(struct instance *instp, unsigned long gpa,
		unsigned long gva, int fault_flags);
extern u64 construct_nptp(unsigned long root_hpa);

extern void svm_npt_sync_vcpu(struct svm_vcpu *vcpu);
extern void svm_npt_sync_individual_addr(struct svm_vcpu *vcpu, unsigned long addr);

/* fn_do_nmi is a shared global, defined in core.c and resolved at init. */
extern void (*fn_do_nmi)(struct pt_regs *);

/*
 * SVM request aliases over the shared SLIMVM_REQ_* bits (see engine.h).
 */
#define SVM_REQ_TLB_FLUSH	SLIMVM_REQ_TLB_FLUSH
#define SVM_REQ_NMI		SLIMVM_REQ_NMI

extern inline bool cpu_has_svm_npt_ad_bits(void);

static inline bool svm_check_request(int req, struct svm_vcpu *vcpu)
{
	if (test_bit(req, &vcpu->requests)) {
		clear_bit(req, &vcpu->requests);

		/*
		 * Ensure the rest of the request is visible to svm_check_request's
		 * caller.  Paired with the smp_wmb in svm_make_request.
		 */
		smp_mb__after_atomic();
		return true;
	}

	return false;
}

static inline void svm_make_request(int req, struct svm_vcpu *vcpu)
{
	/*
	 * Ensure the rest of the request is published to vm_check_request's
	 * caller.  Paired with the smp_mb__after_atomic in vm_check_request.
	 */
	smp_wmb();
	set_bit(req, &vcpu->requests);
}

static inline int svm_vcpu_exiting_guest_mode(struct svm_vcpu *vcpu)
{
	return cmpxchg(&vcpu->mode, IN_GUEST_MODE, EXITING_GUEST_MODE);
}

/*
 * An event may be injected into the guest only when the guest can actually
 * take an interrupt: RFLAGS.IF must be set and the guest must not be in an
 * interrupt shadow (the instruction boundary right after STI/MOV SS). This
 * mirrors the VMX engine's vmx_interrupt_allowed() and KVM's
 * svm_interrupt_blocked(). Injecting while blocked corrupts guest state and
 * causes spurious NPF / VMRUN failures.
 *
 * SlimVM never sets GIF=0 (STGI/CLGI are not intercepted), so GIF is always
 * set and need not be checked here.
 */
static inline int svm_interrupt_allowed(struct svm_vcpu *svm)
{
	struct vmcb *vmcb = svm->vmcb;

	if (!(vmcb->save.rflags & X86_EFLAGS_IF))
		return false;

	if (vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK)
		return false;

	return true;
}

/*
 * NMIs are not maskable by RFLAGS.IF, so - unlike svm_interrupt_allowed() -
 * NMI injection only has to wait out an STI/MOV SS interrupt shadow. This
 * matches the VMX engine's vmx_inject_nmi(), which gates solely on
 * GUEST_INTR_STATE_STI/MOV_SS. Using svm_interrupt_allowed() here would wrongly
 * refuse to inject an NMI whenever the guest is running with interrupts
 * disabled (IF=0), e.g. the sentry kernel delivering an internal SIGBUS, which
 * then fails the run ioctl and kills the sandbox.
 */
static inline int svm_nmi_allowed(struct svm_vcpu *svm)
{
	return !(svm->vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK);
}


#define ADDR_TO_IDX(la, n) \
	((((unsigned long) (la)) >> (12 + 9 * (n))) & ((1 << 9) - 1))
#define PTE_ADDR	(~(PAGE_SIZE - 1))

/**
 * dump_pte - dump page table entry for va.
 */
static inline void dump_pte(u64 pgroot, u64 va)
{
	int i;
	u64 *dir = (u64 *)(pgroot & PTE_ADDR);
	u64 cur_dir = 0;

	printk(KERN_INFO "pgroot 0x%016llx, va 0x%016llx.\n", pgroot, va);
	for (i = 3; i >= 0; i--)
	{
		int idx = ADDR_TO_IDX(va, i);

		copy_from_user(&cur_dir, &dir[idx], sizeof(u64));
		printk(KERN_INFO "level %d, index %d, dir %p, cur_dir 0x%016llx.\n", i,
				idx, dir, cur_dir);

		dir = (u64 *)(cur_dir & PTE_ADDR);
	}
}

/**
 * svm_get_cpu - called before using a cpu
 * @vcpu: VCPU that will be loaded.
 *
 * Disables preemption. Call svm_put_cpu() when finished.
 */
static inline void svm_get_cpu(void)
{
	get_cpu();
}

/**
 * svm_put_cpu - called after using a cpu
 * @vcpu: VCPU that was loaded.
 */
static inline void svm_put_cpu(void)
{
	put_cpu();
}

void svm_set_vcpu_mode(struct svm_vcpu *svm, u8 mode);
bool svm_check_vcpu_mode(struct svm_vcpu *svm, u8 mode);
int svm_launch(struct svm_vcpu *vcpu, struct slimvm_config *conf);

int svm_hardware_enable_all(void);
void svm_hardware_disable_all(void);

int instance_init_npt(struct instance *instp);
void instance_destroy_npt(struct instance *instp);
int instance_alloc_nptp(struct instance *instp);

struct svm_vcpu *svm_create_vcpu(struct slimvm_config *conf,
		struct instance *instp, int vcpu_no);

void svm_destroy_vcpu(struct svm_vcpu *svm);

void svm_make_pt_regs(struct svm_vcpu *svm, struct pt_regs *regs, int sysnr);

/* Exception handling entry points (exception_svm.c). */
int svm_signal_handler(struct svm_vcpu *vcpu);
int svm_exception_handler(u32 intr_info, struct svm_vcpu *vcpu);
int svm_inject_vector(struct svm_vcpu *vcpu, u64 vector);
void svm_exceptions_restore_guest_regs(struct svm_vcpu *vcpu);
int exceptions_init(void);
void exceptions_exit(void);

#endif
