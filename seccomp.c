/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#include <linux/seccomp.h>
#include <linux/sched.h>
#include <linux/compiler.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/bpf.h>

#include "seccomp.h"
#include "slimvm.h"
#include "compat.h"

#ifdef CONFIG_SECCOMP_FILTER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#ifdef SECCOMP_ARCH_NATIVE
/**
 * struct action_cache - per-filter cache of seccomp actions per
 * arch/syscall pair
 *
 * @allow_native: A bitmap where each bit represents whether the
 *		  filter will always allow the syscall, for the
 *		  native architecture.
 * @allow_compat: A bitmap where each bit represents whether the
 *		  filter will always allow the syscall, for the
 *		  compat architecture.
 */
struct action_cache {
	DECLARE_BITMAP(allow_native, SECCOMP_ARCH_NATIVE_NR);
#ifdef SECCOMP_ARCH_COMPAT
	DECLARE_BITMAP(allow_compat, SECCOMP_ARCH_COMPAT_NR);
#endif
};
#else
struct action_cache { };
#endif

/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @refs: Reference count to manage the object lifetime.
 *	  A filter's reference count is incremented for each directly
 *	  attached task, once for the dependent filter, and if
 *	  requested for the user notifier. When @refs reaches zero,
 *	  the filter can be freed.
 * @users: A filter's @users count is incremented for each directly
 *         attached task (filter installation, fork(), thread_sync),
 *	   and once for the dependent filter (tracked in filter->prev).
 *	   When it reaches zero it indicates that no direct or indirect
 *	   users of that filter exist. No new tasks can get associated with
 *	   this filter after reaching 0. The @users count is always smaller
 *	   or equal to @refs. Hence, reaching 0 for @users does not mean
 *	   the filter can be freed.
 * @cache: cache of arch/syscall mappings to actions
 * @log: true if all actions except for SECCOMP_RET_ALLOW should be logged
 * @wait_killable_recv: Put notifying process in killable state once the
 *			notification is received by the userspace listener.
 * @prev: points to a previously installed, or inherited, filter
 * @prog: the BPF program to evaluate
 * @notif: the struct that holds all notification related information
 * @notify_lock: A lock for all notification-related accesses.
 * @wqh: A wait queue for poll if a notifier is in use.
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @refs).
 */
struct seccomp_filter {
	refcount_t refs;
	refcount_t users;
	bool log;
	bool wait_killable_recv;
	struct action_cache cache;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
	struct notification *notif;
	struct mutex notify_lock;
	wait_queue_head_t wqh;
};
#else
/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @refs: Reference count to manage the object lifetime.
 *	  A filter's reference count is incremented for each directly
 *	  attached task, once for the dependent filter, and if
 *	  requested for the user notifier. When @refs reaches zero,
 *	  the filter can be freed.
 * @users: A filter's @users count is incremented for each directly
 *         attached task (filter installation, fork(), thread_sync),
 *	   and once for the dependent filter (tracked in filter->prev).
 *	   When it reaches zero it indicates that no direct or indirect
 *	   users of that filter exist. No new tasks can get associated with
 *	   this filter after reaching 0. The @users count is always smaller
 *	   or equal to @refs. Hence, reaching 0 for @users does not mean
 *	   the filter can be freed.
 * @log: true if all actions except for SECCOMP_RET_ALLOW should be logged
 * @prev: points to a previously installed, or inherited, filter
 * @prog: the BPF program to evaluate
 * @notif: the struct that holds all notification related information
 * @notify_lock: A lock for all notification-related accesses.
 * @wqh: A wait queue for poll if a notifier is in use.
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @refs).
 */
struct seccomp_filter {
	refcount_t refs;
	refcount_t users;
	bool log;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
	struct notification *notif;
	struct mutex notify_lock;
	wait_queue_head_t wqh;
};
#endif
#endif

/* do_seccomp_filter - evaluates all seccomp filters against vmcall. */
int do_seccomp_filter(u64 *regs)
{
#ifdef CONFIG_SECCOMP_FILTER
	struct seccomp_filter *f;
	struct seccomp_data sd;
	u32 ret = SECCOMP_RET_ALLOW;

	/*
	 * Make sure that initialization or any changes to seccomp filter
	 * have been seen.
	 */
	rmb();

#ifdef lockless_dereference
	f = lockless_dereference(current->seccomp.filter);
#else
	/* Since this commit (4.15),
	 * -  "Add implicit smp_read_barrier_depends() to READ_ONCE()",
	 * lockless_dereference is removed, and we use READ_ONCE() instead.
	 */
	f = READ_ONCE(current->seccomp.filter);
#endif
	if (unlikely(f == NULL))
		return 0;

	/*
	 * Populate seccomp data as the format that BPF program executes
	 * over. The syscall number and syscall arguments are from GR0.
	 *
	 * __NR_restart_syscall may be reset during HR0 syscall.
	 */
	sd.nr = regs[VCPU_REGS_RAX];
	if (unlikely(sd.nr >= NR_syscalls ||
		     sd.nr == __NR_restart_syscall))
		return 0;

	sd.instruction_pointer = regs[VCPU_REGS_RIP];
	sd.arch = syscall_get_arch(current);
	sd.args[0] = regs[VCPU_REGS_RDI];
	sd.args[1] = regs[VCPU_REGS_RSI];
	sd.args[2] = regs[VCPU_REGS_RDX];
	sd.args[3] = regs[VCPU_REGS_R10];
	sd.args[4] = regs[VCPU_REGS_R8];
	sd.args[5] = regs[VCPU_REGS_R9];

	/*
	 * All filters in the list are evaluated and the lowest BPF return
	 * value always takes priority (ignoring the DATA).
	 */
	for (; f; f = f->prev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
		u32 cur_ret = bpf_prog_run(f->prog, (void *)&sd);
#else
		u32 cur_ret = BPF_PROG_RUN(f->prog, (void *)&sd);
#endif

		if ((cur_ret & SECCOMP_RET_ACTION) < (ret & SECCOMP_RET_ACTION))
			ret = cur_ret;
	}

	/*
	 * BPF returns one of the following values,
	 *   SECCOMP_RET_KILL [disallow]  - kill the task immediately
	 *   SECCOMP_RET_TRAP [disallow]  - disallow and force a SIGSYS
	 *   SECCOMP_RET_TRACE [disallow] - pass to a tracer or disallow
	 *   SECCOMP_RET_ERRNO [allow] - returns an errno
	 *   SECCOMP_RET_ALLOW [allow] - allow
	 *
	 * For SECCOMP_RET_ERRNO, update syscall number to NR_syscalls,
	 * then handle it as an invalid syscall later.
	 */
	switch (ret) {
	case SECCOMP_RET_ERRNO:
		regs[VCPU_REGS_RAX] = NR_syscalls;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
		fallthrough;
#endif
		/* fallthrough */
	case SECCOMP_RET_ALLOW:
		return 0;
	case SECCOMP_RET_KILL:
	case SECCOMP_RET_TRAP:
	case SECCOMP_RET_TRACE:
		slimvm_error("seccomp: syscall %d not allowed", sd.nr);
		return -EINVAL;
	};
#endif

	return 0;
}
