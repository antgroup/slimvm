/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * vcpu.c - vcpu interface
 */

#include <linux/sched.h>
#include "instance.h"
#include "engine.h"

static inline int vcpu_allocate_vcpu_no(struct instance *instp)
{
	int vcpu_no = -1;

	spin_lock(&instp->vcpu_lock);

	vcpu_no = find_first_zero_bit(instp->vcpu_bitmap, VM_MAX_VCPUS);
	if (vcpu_no < VM_MAX_VCPUS)
		__set_bit(vcpu_no, instp->vcpu_bitmap);

	spin_unlock(&instp->vcpu_lock);

	if (vcpu_no >= VM_MAX_VCPUS)
		vcpu_no = -1;

	return vcpu_no;
}

static inline void vcpu_free_vcpu_no(struct instance *instp, int vcpu_no)
{
	spin_lock(&instp->vcpu_lock);
	if (vcpu_no >= 0)
		__clear_bit(vcpu_no, instp->vcpu_bitmap);
	spin_unlock(&instp->vcpu_lock);
}

int vcpu_alloc(struct instance *instp, struct slimvm_config *conf)
{
	struct slimvm_vcpu	*vcpu;
	int			vcpu_no;

	vcpu_no = vcpu_allocate_vcpu_no(instp);
	if (vcpu_no == -1) {
		slimvm_error("Allocate vcpu_no failed!");
		return -ENOMEM;
	}

	vcpu = slimvm_ops->create_vcpu(conf, instp, vcpu_no);
	if (!vcpu) {
		vcpu_free_vcpu_no(instp, vcpu_no);
		return -ENOMEM;
	}

	if (!cmpxchg(&instp->mm, NULL, current->mm))
		atomic_inc(&current->mm->mm_count);

	spin_lock(&instp->vcpu_lock);
	instp->vcpus[vcpu_no] = vcpu;
	spin_unlock(&instp->vcpu_lock);

	return vcpu_no;
}

void vcpu_release(struct instance *instp, int vcpu_no)
{
	struct slimvm_vcpu	*vcpu;

	spin_lock(&instp->vcpu_lock);
	if (!instp->vcpus[vcpu_no]) {
		spin_unlock(&instp->vcpu_lock);
		return;
	}

	vcpu = instp->vcpus[vcpu_no];
	__clear_bit(vcpu_no, instp->vcpu_bitmap);
	instp->vcpus[vcpu_no] = NULL;
	spin_unlock(&instp->vcpu_lock);

	slimvm_ops->destroy_vcpu(vcpu);
}

void vcpu_inject_nmi(struct instance *instp, int vcpu_no)
{
	struct slimvm_vcpu	*vcpu;

	spin_lock(&instp->vcpu_lock);
	if (!instp->vcpus[vcpu_no]) {
		spin_unlock(&instp->vcpu_lock);
		return;
	}
	vcpu = instp->vcpus[vcpu_no];
	slimvm_ops->make_nmi_request(vcpu);
	spin_unlock(&instp->vcpu_lock);
}
