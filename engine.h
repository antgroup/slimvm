/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * engine.h - architecture-independent virtualization engine interface.
 *
 * SlimVM supports multiple hardware virtualization backends (Intel VT-x,
 * AMD/Hygon SVM, and in the future ARM). The shared glue code (core.c,
 * vcpu.c, instance.c, ...) never calls a backend directly: it goes through
 * the vendor operations table below, which is bound at module load time to
 * the engine matching the running CPU.
 *
 * This mirrors the kvm_x86_ops abstraction used by Linux KVM to share a
 * common core between kvm-intel.ko and kvm-amd.ko.
 */

#ifndef __SLIMVM_ENGINE_H_
#define __SLIMVM_ENGINE_H_

#include <linux/types.h>
#include <asm/thread_info.h>

struct instance;
struct slimvm_config;

/*
 * Opaque vcpu handle. Each engine defines its own concrete vcpu structure
 * (struct vmx_vcpu, struct svm_vcpu, ...) and casts this handle back to its
 * own type at the ops boundary - exactly as KVM embeds kvm_vcpu inside
 * vcpu_vmx / vcpu_svm.
 */
struct slimvm_vcpu;

/*
 * Thread flags that force a vcpu to leave guest mode and return to the run
 * loop so the condition can be serviced.
 */
#define ENTER_UESTMODE_FLAGS \
	(_TIF_NOTIFY_RESUME | \
	 _TIF_SIGPENDING | \
	 _TIF_NEED_RESCHED)

/*
 * General purpose register indices into vcpu->regs[]. The layout is shared by
 * every x86 engine; the inline asm of each backend depends on these exact
 * values. (ARM has a different register file - this enum will move down to an
 * x86-specific header when an ARM engine is added.)
 */
enum vcpu_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
#ifdef CONFIG_X86_64
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
#endif
	VCPU_REGS_RIP,
	NR_VCPU_REGS
};

enum {
	VCPU_SREG_ES,
	VCPU_SREG_CS,
	VCPU_SREG_SS,
	VCPU_SREG_DS,
	VCPU_SREG_FS,
	VCPU_SREG_GS,
	VCPU_SREG_TR,
	VCPU_SREG_LDTR,
};

/* vcpu->mode states, shared by all engines. */
enum {
	OUTSIDE_ROOT_MODE,
	IN_ROOT_MODE,
	OUTSIDE_GUEST_MODE,
	IN_GUEST_MODE,
	EXITING_GUEST_MODE,
};

/*
 * vcpu->requests bit members (copied from KVM).
 * Bits 0-3 are architecture-independent; 4-7 reserved.
 */
#define SLIMVM_REQ_TLB_FLUSH		0
#define SLIMVM_REQ_MMU_RELOAD		1
#define SLIMVM_REQ_PENDING_TIMER	2
#define SLIMVM_REQ_UNHALT		3
/* x86-specific request bits */
#define SLIMVM_REQ_NMI			17

struct msr_entry {
	u32 index;
	u32 reserved;
	u64 data;
};

/*
 * slimvm_engine_ops - the vendor operations table.
 *
 * Trimmed from kvm_x86_ops down to the entry points SlimVM actually needs.
 * Each engine fills one of these and exports it (vmx_ops / svm_ops); core.c
 * selects one at module load and publishes it through slimvm_ops.
 */
struct slimvm_engine_ops {
	const char *name;			/* "vmx" / "svm" / future "arm" */

	/* Per-CPU hardware enable/disable (VMXON / EFER.SVME / ...). */
	int  (*hardware_enable_all)(void);
	void (*hardware_disable_all)(void);

	/* vcpu lifecycle - handles are opaque to the shared glue. */
	struct slimvm_vcpu *(*create_vcpu)(struct slimvm_config *conf,
					   struct instance *instp, int vcpu_no);
	void (*destroy_vcpu)(struct slimvm_vcpu *vcpu);
	int  (*launch)(struct slimvm_vcpu *vcpu, struct slimvm_config *conf);
	void (*set_vcpu_mode)(struct slimvm_vcpu *vcpu, u8 mode);
	bool (*vcpu_is_shutdown)(struct slimvm_vcpu *vcpu);
	void (*make_nmi_request)(struct slimvm_vcpu *vcpu);

	void (*shutdown_all_vcpus)(struct instance *instp);
	void (*sync_all_vcpus)(struct instance *instp);

	/* Nested page table / instance management (EPT / NPT / stage-2). */
	int  (*instance_alloc_ptp)(struct instance *instp);
	int  (*instance_init_pt)(struct instance *instp);
	void (*instance_destroy_pt)(struct instance *instp);
};

/* The engine bound at module load, used everywhere by the shared glue. */
extern struct slimvm_engine_ops *slimvm_ops;

/* Per-engine ops, provided by each backend's translation unit. */
extern struct slimvm_engine_ops vmx_ops;
#ifdef SLIMVM_HAVE_SVM
extern struct slimvm_engine_ops svm_ops;
#endif

/*
 * slimvm_engine_init - detect the CPU vendor and bind slimvm_ops, then enable
 * the engine on all CPUs. Defined in core.c.
 */
int slimvm_engine_init(void);
void slimvm_engine_exit(void);

#endif /* __SLIMVM_ENGINE_H_ */
