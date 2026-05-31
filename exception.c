/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * Handle exceptions of slimvm.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/freezer.h>
#include <linux/string.h>
#include <linux/version.h>

#include <asm/vmx.h>
#include <asm/ptrace.h>
#include <asm/traps.h>

#include "exception.h"
#include "vmx.h"

#define DR6_RESERVED    (0xFFFF0FF0)

struct pt_regs backup_regs;

void exceptions_restore_guest_regs(struct vmx_vcpu *vcpu)
{
	struct pt_regs *user_regs;

	if (likely(!vcpu->debug_mode))
		return;

	user_regs = task_pt_regs(current);

	vmx_get_cpu(vcpu);
	vmcs_writel(GUEST_RIP, user_regs->ip);
	vmcs_writel(GUEST_RSP, user_regs->sp);
	vmcs_writel(GUEST_RFLAGS, user_regs->flags);
	vmx_put_cpu(vcpu);

	/*
	 * backup_regs only should be restored into kenrel stack while the vcpu
	 * return to HR3.
	 * In our design, this only occur while vcpu exit.
	 */
	memcpy(user_regs, &backup_regs, sizeof(struct pt_regs));

	/*
	 * The processing of a debug trap is completed.
	 */
	vcpu->debug_mode = false;
}

void slimvm_inject_vector(struct vmx_vcpu *vcpu, u64 vector)
{
	u64 irq_num = vector | INTR_INFO_VALID_MASK;

	vmx_get_cpu(vcpu);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, irq_num);
	vmx_put_cpu(vcpu);
}

int slimvm_signal_handler(struct vmx_vcpu *vcpu)
{
	unsigned long flags;
	bool had_bounce;

	/* Consume SIG_BOUNCE whenever it is present, even alongside other signals. */
	spin_lock_irqsave(&current->sighand->siglock, flags);
	had_bounce = sigismember(&current->pending.signal, SIG_BOUNCE);
	if (had_bounce) {
		sigdelset(&current->pending.signal, SIG_BOUNCE);
		recalc_sigpending();
	}
	spin_unlock_irqrestore(&current->sighand->siglock, flags);

	if (had_bounce)
		vcpu->bounce_pending = true;

	/*
	 * If a deliverable (unblocked) non-bounce signal remains pending, return
	 * to HR3 so the runtime can service it; the bounce is remembered via
	 * bounce_pending and injected on the next guest entry, so it is never
	 * lost. Otherwise stay in guest mode and let the run loop inject it.
	 */
	if (signal_pending(current))
		return -1;

	return 0;
}

static inline int slimvm_get_si_code(unsigned long condition)
{
	if (condition & DR_STEP)
		return TRAP_TRACE;
	if (condition & (DR_TRAP0 | DR_TRAP1 | DR_TRAP2 | DR_TRAP3))
		return TRAP_HWBKPT;
	return TRAP_BRKPT;
}

static inline void slimvm_do_debug(struct vmx_vcpu *vcpu)
{
	unsigned long dr6;
	struct kernel_siginfo info;
	int si_code;
	int error_code = 0;

	/* Ref to KVM */
	vmx_get_cpu(vcpu);
	dr6 = vmcs_readl(EXIT_QUALIFICATION);
	dr6 &= ~DR6_RESERVED;
	vmx_put_cpu(vcpu);

	clear_tsk_thread_flag(current, TIF_BLOCKSTEP);
	set_tsk_thread_flag(current, TIF_SINGLESTEP);

	// d53d9bc0cf78 ("x86/debug: Change thread.debugreg6 to thread.virtual_dr6")
	// a195f3d4528a ("x86/debug: Only clear/set ->virtual_dr6 for userspace #DB")
	// cb05143bdf42 ("x86/debug: Fix DR_STEP vs ptrace_get_debugreg(6)")
	current->thread.virtual_dr6 = dr6;
	current->thread.trap_nr = X86_TRAP_DB;
	/* error code is 0, while debug exception */
	current->thread.error_code = error_code;
	si_code = slimvm_get_si_code(dr6);

	memset(&info, 0, sizeof(info));
	info.si_signo = SIGTRAP;
	info.si_code = si_code;
	info.si_addr = NULL;

	vcpu->debug_mode = true;

	send_sig_info(SIGTRAP, &info, current);
}

static inline void slimvm_do_int3(struct vmx_vcpu *vcpu)
{
	current->thread.trap_nr = X86_TRAP_BP;
	current->thread.error_code = 0;

	vcpu->debug_mode = true;

	send_sig_info(SIGTRAP, SEND_SIG_PRIV, current);
}

int slimvm_exception_handler(u32 intr_info, struct vmx_vcpu *vcpu)
{
	u32 ex_no;

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;

	switch (ex_no) {
	case DB_VECTOR:
		/* Debug Interrupt */
		pr_debug("Catch DB_VECTOR\n");
		slimvm_do_debug(vcpu);
		break;
	case BP_VECTOR:
		/* Breakpoint Interrupt */
		pr_debug("Catch BP_VECTOR\n");
		slimvm_do_int3(vcpu);
		break;
	default:
		break;
	}

	return 0;
}
