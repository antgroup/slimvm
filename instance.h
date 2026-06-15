/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#ifndef __SLIMVM_INSTANCE_H_
#define __SLIMVM_INSTANCE_H_

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/sysctl.h>
#include <linux/mmu_notifier.h>

#include "slimvm.h"
#include "engine.h"

#define INSTANCES_MAX_NUM 8192

/* Follow gvisor configure */
#define VM_MAX_VCPUS 0x800
#define MAX_MEM_REGION_NUM 50

struct instance {
	struct list_head list;
	int id;
	long sid;
	struct mmu_notifier mmu_notifier;
	spinlock_t ept_lock;
	unsigned long ept_root;
	unsigned long eptp;

	/*
	 * npt_mmu_users counts threads currently inside the NPT mmu_notifier
	 * callbacks (AMD engine only); instance_destroy_npt waits for it to
	 * drain. Unused by the Intel/EPT engine.
	 */
	atomic_t npt_mmu_users;

	/*
	 * memp is used for setting memory region.
	 * And it will be freed after setting memory region correctly.
	 */
	struct mem_region *memp;
	struct mm_struct *mm;
	int mem_region_num;
	struct mutex mm_mutex;

	uint64_t ept_4k_pages;
	uint64_t ept_2m_pages;
	uint64_t ept_invl_count;
	uint64_t ept_invl_range;
	uint64_t ept_invl_ipi;

	/*
	 * the initialization of memory region is delayed to SLIMVM_RUN,
	 * but the memory of runsc may be unmapped, so the hva_to_gpa
	 * returns ADDR_INVAL.
	 */
	unsigned long mmu_notifier_seq;
	unsigned long mmu_notifier_count;

	int shutdown;

	/*
	 * filp is the pointer of slimvm file in kernel, used to force
	 * release slimvm instance.
	 */
	struct file *filp;

	/*
	 * force_release is used to bypass check in instance release,
	 * used only in force release case.
	 */
	int force_release;

	/*
	 * reclaim_list is used to chain leaked instances for reclaiming.
	 */
	struct list_head reclaim_list;

	/*
	 * running_vcpus is the number of threads that enter slimvm by
	 * ioctl(), which hold the slimvm file reference and might
	 * exit without fput().
	 */
	atomic_long_t running_vcpus;

	/*
	 * sandbox_tsk is the pointer of sandbox process's task struct.
	 */
	struct task_struct *sandbox_tsk;

	/*
	 * sandbox_pid is the pid of sandbox process. We use this value
	 * to check if the sandbox process is still running.
	 */
	pid_t sandbox_pid;

	spinlock_t vcpu_lock;
	DECLARE_BITMAP(vcpu_bitmap, VM_MAX_VCPUS);
	/*
	 * Opaque vcpu handles. Each engine stores its own concrete vcpu type
	 * (struct vmx_vcpu * / struct svm_vcpu *) here; void * interconverts
	 * with both without casts so the engine code is unchanged.
	 */
	void *vcpus[VM_MAX_VCPUS];
};

extern struct instance *instance_create(void);
extern int instance_release(struct instance *instp);
extern void *instance_get_vcpu(struct instance *instp, int vcpu_no);

extern int instance_alloc_eptp(struct instance *instp);
extern int instance_init_ept(struct instance *instp);
extern void instance_destroy_ept(struct instance *instp);

extern int instance_get_vm_num(void);
extern int instance_get_vcpu_num(void);

extern int vcpu_alloc(struct instance *instp,
		      struct slimvm_config *conf);
extern void vcpu_release(struct instance *instp, int vcpu_no);
extern void vcpu_inject_nmi(struct instance *instp, int vcpu_no);

void on_each_vm_instance(void (*action)(struct instance *ins, void *data),
		void *data);

void slimvm_reclaim_leaked_instances(void);
void slimvm_record_sandbox(struct instance *instp);

#endif /* __SLIMVM_INSTANCE_H_ */
