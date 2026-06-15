/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * core.c - the SlimVM core
 *
 * SlimVM enables ordinary Linux processes to leverage the full range of x86
 * hardware protection and isolation mechanisms - including paging and
 * segmentation - via hardware virtualization infrastructure.
 *
 * Unlike traditional virtual machines, SlimVM-managed processes can execute
 * standard POSIX system calls while maintaining compatibility with Linux process
 * semantics, except for privileged hardware operations that remain isolated
 * through virtualization.
 */

#include <linux/miscdevice.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#include "engine.h"
#include "slimvm.h"
#include "instance.h"
#include "mm.h"
#include "proc.h"
#include "compat.h"

#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)) \
	&& !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)) \
	&& !(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0))
#error "Kernel version must be 5.10.y, 5.15.y or 6.1.y"
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A driver for SlimVM");

/* The virtualization engine bound at module load (see slimvm_engine_init). */
struct slimvm_engine_ops *slimvm_ops;

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

static int slimvm_enter(struct slimvm_config *conf, struct instance *instp)
{
	struct slimvm_vcpu *vcpu = NULL;
	int vcpu_no = conf->vcpu;

	if (unlikely(vcpu_no < 0 || vcpu_no >= VM_MAX_VCPUS))
		return -1;

	spin_lock(&instp->vcpu_lock);
	if (instp->shutdown) {
		slimvm_info("instance has been shutdown\n");
		spin_unlock(&instp->vcpu_lock);
		return -1;
	}

	vcpu = instp->vcpus[vcpu_no];
	if (!vcpu || slimvm_ops->vcpu_is_shutdown(vcpu)) {
		spin_unlock(&instp->vcpu_lock);
		return -1;
	}

	slimvm_ops->set_vcpu_mode(vcpu, IN_ROOT_MODE);
	spin_unlock(&instp->vcpu_lock);

	return slimvm_ops->launch(vcpu, conf);
}

static long slimvm_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	struct slimvm_config conf;
	struct instance *instp;
	u64 mr;
	int vcpu_no;
	long r = -EINVAL;

	switch (ioctl) {
	case SLIMVM_CREATE_VCPU:
		instp = (struct instance *) filp->private_data;
		if (!instp) {
			r = -EINVAL;
			goto out;
		}

		r = copy_from_user(&conf, (void __user *) arg,
				   sizeof(struct slimvm_config));
		if (r) {
			r = -EIO;
			goto out;
		}

		r = vcpu_no = vcpu_alloc(instp, &conf);
		if (vcpu_no < 0) {
			r = -ENOMEM;
			goto out;
		}

		/* record sandbox info for leak instance reclaim. */
		slimvm_record_sandbox(instp);

		break;

	case SLIMVM_RELEASE_VCPU:
		instp = (struct instance *) filp->private_data;
		if (!instp) {
			r = -EINVAL;
			goto out;
		}

		r = copy_from_user(&vcpu_no, (int __user *) arg, sizeof(int));
		if (r) {
			r = -EIO;
			goto out;
		}

		if (unlikely(vcpu_no < 0 || vcpu_no >= VM_MAX_VCPUS)) {
			r = -EINVAL;
			goto out;
		}

		vcpu_release(instp, vcpu_no);
		r = 0;

		break;

	case SLIMVM_RUN:
		instp = (struct instance *) filp->private_data;
		if (!instp) {
			r = -EINVAL;
			goto out;
		}

		r = copy_from_user(&conf, (int __user *) arg,
				   sizeof(struct slimvm_config));
		if (r) {
			r = -EIO;
			goto out;
		}

		mutex_lock(&instp->mm_mutex);
		mr = instp->mem_region_num;
		if (likely(mr)) {
			mutex_unlock(&instp->mm_mutex);
			goto slimvm_enter;
		}

		/*
		 * If the memory region number is too big, return failed
		 * directly. If we don't do this, memory may run out with
		 * lots of memory regions.
		 */
		if (conf.mem_region_num > MAX_MEM_REGION_NUM) {
			mutex_unlock(&instp->mm_mutex);
			r = -EINVAL;
			goto out;
		}

		r = copy_from_user(instp->memp,
				(void __user *)conf.mem_region_addr,
				sizeof(struct mem_region) * conf.mem_region_num);
		if (r) {
			mutex_unlock(&instp->mm_mutex);
			r = -EIO;
			goto out;
		}

		r = check_mem_region(instp, conf.mem_region_num);
		if (r) {
			mutex_unlock(&instp->mm_mutex);
			goto out;
		}
		instp->mem_region_num = conf.mem_region_num;
		instp->sid = conf.sid;

		r = slimvm_ops->instance_init_pt(instp);
		if (r) {
			mutex_unlock(&instp->mm_mutex);
			goto out;
		}

		mutex_unlock(&instp->mm_mutex);

slimvm_enter:
		atomic_long_add(1, &instp->running_vcpus);
		r = slimvm_enter(&conf, instp);
		atomic_long_sub(1, &instp->running_vcpus);
		if (r)
			break;

		r = copy_to_user((void __user *)arg, &conf,
				 sizeof(struct slimvm_config));
		if (r) {
			r = -EIO;
			goto out;
		}

		break;

	case SLIMVM_SET_TSS_ADDR:
		instp = (struct instance *) filp->private_data;
		if (!instp) {
			r = -EINVAL;
			goto out;
		}

		slimvm_set_tss_addr(instp, arg, 3 * PAGE_SIZE);
		r = 0;
		break;

	case SLIMVM_NMI:
		instp = (struct instance *) filp->private_data;
		if (!instp) {
			r = -EINVAL;
			goto out;
		}

		r = copy_from_user(&vcpu_no, (int __user *) arg, sizeof(int));
		if (r) {
			r = -EIO;
			goto out;
		}

		if (unlikely(vcpu_no < 0 || vcpu_no >= VM_MAX_VCPUS)) {
			r = -EINVAL;
			goto out;
		}

		vcpu_inject_nmi(instp, vcpu_no);
		r = 0;

		break;

	default:
		return -ENOTTY;
	}

out:
	return r;
}

static int slimvm_dev_open(struct inode *inode, struct file *filp)
{
	struct instance *inst;

	inst = instance_create();
	if (IS_ERR(inst)) {
		filp->private_data = NULL;
		slimvm_error("Failed to create instance\n");
		return -ENOMEM;
	}

	filp->private_data = inst;
	inst->filp = filp;

	return 0;
}

static int slimvm_dev_release(struct inode *inode, struct file *filp)
{
	if (!filp->private_data)
		return 0;

	instance_release((struct instance *)filp->private_data);

	return 0;
}

static const struct file_operations slimvm_chardev_ops = {
	.owner		= THIS_MODULE,
	.open		= slimvm_dev_open,
	.unlocked_ioctl	= slimvm_dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= slimvm_dev_ioctl,
#endif
	.llseek		= noop_llseek,
	.release	= slimvm_dev_release,
};

static struct miscdevice slimvm_dev = {
	MISC_DYNAMIC_MINOR,
	"slimvm",
	&slimvm_chardev_ops,
};

/*
 * On Linux kernels 5.7+, kallsyms_lookup_name() is no longer exported,
 * so we have to use kprobes to get the address.
 * Full credit to @f0lg0 for the idea.
 * Refer: https://github.com/xcellerator/linux_kernel_hacking/issues/3#issuecomment-757994563
 */
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kln_hack;

static int m_init(void)
{
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;

	kln_hack = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	return 0;
}

/*
 * slimvm_engine_init - bind slimvm_ops to the engine matching the running
 * CPU vendor, then enable it on all CPUs.
 */
int slimvm_engine_init(void)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_INTEL:
		slimvm_ops = &vmx_ops;
		break;
#ifdef SLIMVM_HAVE_SVM
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		slimvm_ops = &svm_ops;
		break;
#endif
	default:
		slimvm_error("unsupported CPU vendor %d\n",
			     boot_cpu_data.x86_vendor);
		return -EIO;
	}

	slimvm_info("using %s engine\n", slimvm_ops->name);

	return slimvm_ops->hardware_enable_all();
}

void slimvm_engine_exit(void)
{
	if (slimvm_ops)
		slimvm_ops->hardware_disable_all();
}

static int __init slimvm_init(void)
{
	int r;

	m_init();

	if (!slimvm_sysctl_init()) {
		slimvm_error("proc sysctl initializing failed!\n");
		return -1;
	}

	r = slimvm_engine_init();
	if (r) {
		slimvm_error("failed to initialize virtualization engine\n");
		slimvm_sysctl_exit();
		return r;
	}

	r = misc_register(&slimvm_dev);
	if (r) {
		slimvm_error("misc device register failed\n");
		slimvm_engine_exit();
		slimvm_sysctl_exit();
		return r;
	}

	slimvm_info("module slimvm loaded\n");

	return r;
}

static void __exit slimvm_exit(void)
{
	slimvm_sysctl_exit();

	misc_deregister(&slimvm_dev);
	slimvm_engine_exit();
	slimvm_info("module slimvm removed\n");
}

module_init(slimvm_init);
module_exit(slimvm_exit);
