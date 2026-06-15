/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * Handle exceptions of slimvm (AMD SVM engine).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/freezer.h>
#include <linux/string.h>
#include <linux/version.h>

#include <asm/ptrace.h>
#include <asm/traps.h>

#include "exception.h"
#include "svm.h"
#include "slimvm.h"

#define SIG_GUEST_FORBIDDEN_MASK (SIGSTOP | SIGTRAP)
#define DR6_RESERVED    (0xFFFF0FF0)

typedef int (*funcp_get_signal)(struct ksignal *ksig);
static funcp_get_signal svm_get_signal;

static struct pt_regs backup_regs;

void svm_exceptions_restore_guest_regs(struct svm_vcpu *vcpu)
{
	struct pt_regs *user_regs;

	if (likely(!vcpu->debug_mode))
		return;

	user_regs = task_pt_regs(current);

	svm_get_cpu();
	vcpu->vmcb->save.rip = user_regs->ip;
	vcpu->vmcb->save.rsp = user_regs->sp;
	vcpu->vmcb->save.rflags = user_regs->flags;
	svm_put_cpu();

	/*
	 * FIXME:
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

static void __maybe_unused save_guest_regs(struct svm_vcpu *vcpu)
{
	struct pt_regs regs;
	void *user_regs = task_pt_regs(current);

	u64 Reg_RAX;

	Reg_RAX = vcpu->regs[VCPU_REGS_RAX];

	svm_make_pt_regs(vcpu, &regs, Reg_RAX);

	/*
	 * While INT3 occurred in host, rip is added 1 to jump to INT3's next
	 * instruction automatically by cpu.
	 * But, while in guest, the rip is the "INT3" instruction. It needs to be
	 * changed manually.
	 *
	 * The state of trap_nr is not changed until next trap event.
	 */
	if (current->thread.trap_nr == X86_TRAP_BP)
		regs.ip++;

	/*
	 * ptrace() get user space's registers from the bottom of kernel stack.
	 * We store guest's registers in to this position.
	 */
	memcpy(&backup_regs, user_regs, sizeof(struct pt_regs));
	memcpy(user_regs, &regs, sizeof(struct pt_regs));
}

int svm_inject_vector(struct svm_vcpu *vcpu, u64 vector)
{
	return svm_inject_event(vcpu,vector);
}

int svm_signal_handler(struct svm_vcpu *vcpu)
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

static inline int svm_get_si_code(unsigned long condition)
{
	if (condition & DR_STEP)
		return TRAP_TRACE;
	else if (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3))
		return TRAP_HWBKPT;
	else
		return TRAP_BRKPT;
}

static inline void svm_do_debug(struct svm_vcpu *vcpu)
{
	unsigned long dr6 = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	struct kernel_siginfo info;
#else
	struct siginfo info;
#endif
	int si_code;
	int error_code = 0;

	/* Ref to KVM */
	svm_get_cpu();
	dr6 = vcpu->vmcb->save.dr6;
	dr6 &= ~DR6_RESERVED;
	svm_put_cpu();

	clear_tsk_thread_flag(current, TIF_BLOCKSTEP);
	set_tsk_thread_flag(current, TIF_SINGLESTEP);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	// d53d9bc0cf78 ("x86/debug: Change thread.debugreg6 to thread.virtual_dr6")
	// a195f3d4528a ("x86/debug: Only clear/set ->virtual_dr6 for userspace #DB")
	// cb05143bdf42 ("x86/debug: Fix DR_STEP vs ptrace_get_debugreg(6)")
	current->thread.virtual_dr6 = dr6;
#else
	current->thread.debugreg6 = dr6;
#endif
	current->thread.trap_nr = X86_TRAP_DB;
	/* error code is 0, while debug exception */
	current->thread.error_code = error_code;
	si_code = svm_get_si_code(dr6);

	memset(&info, 0, sizeof(info));
	info.si_signo = SIGTRAP;
	info.si_code = si_code;
	info.si_addr = NULL;

	vcpu->debug_mode = true;

	send_sig_info(SIGTRAP, &info, current);
}

static inline void svm_do_int3(struct svm_vcpu *vcpu)
{
	current->thread.trap_nr = X86_TRAP_BP;
	current->thread.error_code = 0;

	vcpu->debug_mode = true;

	send_sig_info(SIGTRAP, SEND_SIG_PRIV, current);
}

int svm_exception_handler(u32 intr_info, struct svm_vcpu *vcpu)
{
	u32 ex_no;

	ex_no = intr_info & 0xff;

	switch(ex_no) {
	case DB_VECTOR:
		/* Debug Interrupt */
		pr_debug("Catch DB_VECTOR\n");
		svm_do_debug(vcpu);

		break;
	case BP_VECTOR:
		/* Breakpoint Interrupt */
		pr_debug("Catch BP_VECTOR\n");
		svm_do_int3(vcpu);

		break;
	default:
		break;
	}

	return 0;
}

int exceptions_init()
{
	/*
	 * Get addr of unexported kernel function: get_signal()
	 */
	svm_get_signal =
		(funcp_get_signal)kln_hack("get_signal");
	if (!svm_get_signal)
		return -1;

	return 0;
}

void exceptions_exit()
{
}
