/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * instance.c - VM abstract interface.
 */

#include <linux/atomic.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <asm/bitops.h>

#include "slimvm.h"
#include "instance.h"
#include "proc.h"
#include "engine.h"
#include "mm.h"
#include "compat.h"

static DECLARE_BITMAP(instances_bitmap, INSTANCES_MAX_NUM);
static DEFINE_SPINLOCK(instances_lock);
static LIST_HEAD(instances_list);

void on_each_vm_instance(void (*action)(struct instance *ins, void *data),
		void *data)
{
	struct instance *instp;

	spin_lock(&instances_lock);
	list_for_each_entry(instp, &instances_list, list)
		action(instp, data);
	spin_unlock(&instances_lock);
}

int instance_get_vm_num(void)
{
	int num = 0;

	spin_lock(&instances_lock);
	num = __bitmap_weight(instances_bitmap, INSTANCES_MAX_NUM);
	spin_unlock(&instances_lock);

	return num;
}

int instance_get_vcpu_num(void)
{
	struct instance *instp;
	int num = 0;

	spin_lock(&instances_lock);
	list_for_each_entry(instp, &instances_list, list)
		num += __bitmap_weight(instp->vcpu_bitmap, VM_MAX_VCPUS);
	spin_unlock(&instances_lock);

	return num;
}

/*
 * Allocate id for a new slimvm.
 * Return:
 *	true: success.
 *	false: fail.
 */
static inline bool alloc_inst_id(struct instance *instp)
{
	u32 id;

	spin_lock(&instances_lock);
	id = find_first_zero_bit(instances_bitmap, INSTANCES_MAX_NUM);
	if (id < INSTANCES_MAX_NUM) {
		instp->id = id;
		__set_bit(id, instances_bitmap);
		list_add(&instp->list, &instances_list);
	}
	spin_unlock(&instances_lock);

	return (id < INSTANCES_MAX_NUM);
}

static inline void free_inst_id(struct instance *instp)
{
	if (instp->id < 0 || instp->id >= INSTANCES_MAX_NUM)
		return;

	spin_lock(&instances_lock);
	__clear_bit(instp->id, instances_bitmap);
	list_del(&instp->list);
	spin_unlock(&instances_lock);
}

/*
 * instance_create: allocates and initializes a new instance.
 *
 * Returns: A new instance structure
 */
struct instance *instance_create(void)
{
	struct instance *instp;

	instp = vzalloc(sizeof(struct instance));
	if (!instp)
		goto instp_err;

	instp->memp = kzalloc(sizeof(struct mem_region) * MAX_MEM_REGION_NUM,
			GFP_KERNEL);
	if (!instp->memp)
		goto memp_err;

	instp->id = -1;
	if (!alloc_inst_id(instp))
		goto id_err;

	spin_lock_init(&instp->vcpu_lock);
	spin_lock_init(&instp->ept_lock);
	mutex_init(&instp->mm_mutex);

	instp->mmu_notifier_seq = 0;
	instp->mmu_notifier_count = 0;

	if (slimvm_ops->instance_alloc_ptp(instp))
		goto id_err;
	preempt_notifier_inc();

	return instp;

id_err:
	kfree(instp->memp);
memp_err:
	vfree(instp);
instp_err:
	return ERR_PTR(-ENOMEM);
}

/*
 * instance_release: release a exist instance.
 */
int instance_release(struct instance *instp)
{
	int vcpu;

	slimvm_ops->shutdown_all_vcpus(instp);

	/*
	 * Calling this for leaked instance results in busy loop
	 * and never returns.
	 */
	if (!instp->force_release)
		slimvm_ops->sync_all_vcpus(instp);

	for_each_set_bit(vcpu, instp->vcpu_bitmap, VM_MAX_VCPUS)
		vcpu_release(instp, vcpu);

	slimvm_ops->instance_destroy_pt(instp);

	/*
	 * instp->mm will only be initialized when creating vcpu,
	 * so here we need to check whether instp->mm is valid.
	 */
	if (instp->mm)
		mmdrop(instp->mm);

	free_inst_id(instp);
	kfree(instp->memp);
	vfree(instp);

	preempt_notifier_dec();

	return 0;
}

/*
 * slimvm_reclaim_leaked_instances will go through the instance list,
 * find leaked instances and reclaim them.
 *
 * Notice: a leaked instance could be reclaimed only once, we achieve
 *         this by checking the field 'force_release', which is
 *         protected by instances_lock.
 */
void slimvm_reclaim_leaked_instances(void)
{
	struct instance *instp, *nxt;
	struct task_struct *tsk;
	unsigned int refcount;
	long i;
	LIST_HEAD(reclaim_list);

	spin_lock(&instances_lock);
	list_for_each_entry(instp, &instances_list, list) {
		/*
		 * check both fileds to avoid use-before-initialized due to CPU
		 * out-of-order execution.
		 */
		if (!instp->sandbox_tsk || !instp->sandbox_pid)
			continue;

		rcu_read_lock();
		tsk = pid_task(find_pid_ns(instp->sandbox_pid, &init_pid_ns),
				PIDTYPE_PID);
		rcu_read_unlock();

		/* check if force_release is set to avoid double reclaim. */
		if (tsk == instp->sandbox_tsk || instp->force_release)
			continue;
		/*
		 * sandbox process has already exited. we have to force release
		 * this leaked instance.
		 */
		instp->force_release = 1;
		slimvm_info("start to reclaim the instance (id: %d, spid: %d, sid: %08lx)",
			instp->id, instp->sandbox_pid, instp->sid);
		list_add(&instp->reclaim_list, &reclaim_list);
	}
	spin_unlock(&instances_lock);

	list_for_each_entry_safe(instp, nxt, &reclaim_list, reclaim_list) {
		refcount = atomic_long_read(&instp->running_vcpus);
		list_del(&instp->reclaim_list);
		for (i = 0; i < refcount; i++)
			fput(instp->filp);
	}
}

void *instance_get_vcpu(struct instance *instp, int vcpu_no)
{
	if (unlikely(vcpu_no < 0 || vcpu_no >= VM_MAX_VCPUS))
		return NULL;

	return instp->vcpus[vcpu_no];
}

void slimvm_record_sandbox(struct instance *instp)
{
	/* Even if a data race happens, it only causes same data overwrite. */
	if (likely(instp->sandbox_tsk))
		return;

	instp->sandbox_pid = task_tgid_nr(current);
	instp->sandbox_tsk = pid_task(find_pid_ns(instp->sandbox_pid, &init_pid_ns),
							PIDTYPE_PID);
}
