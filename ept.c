/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * ept.c - Support for Intel's Extended Page Tables
 *
 * We support the EPT by making a sort of 'shadow' copy of the Linux
 * process page table. Mappings are created lazily as they are needed.
 * We keep the EPT synchronized with the process page table through
 * mmu_notifier callbacks.
 *
 * Some of the low-level EPT functions are based on KVM.
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <asm/io.h>
#endif
#include <asm-generic/io.h>

#include "vmx.h"
#include "compat.h"
#include "mm.h"

#define EPT_LEVELS	4	/* 0 through 3 */
#define SLIMVM_HPAGE_2M_SIZE	(1 << 21)

#define VMX_EPT_FAULT_READ	0x01
#define VMX_EPT_FAULT_WRITE	0x02
#define VMX_EPT_FAULT_INS	0x04

typedef unsigned long epte_t;

#define __EPTE_READ		0x01
#define __EPTE_WRITE	0x02
#define __EPTE_EXEC		0x04
#define __EPTE_IPAT		0x40
#define __EPTE_SZ		0x80
#define __EPTE_A		0x100
#define __EPTE_D		0x200
#define __EPTE_PFNMAP	0x800
#define __EPTE_TYPE(n)	(((n) & 0x7) << 3)

enum {
	EPTE_TYPE_UC = 0, /* uncachable */
	EPTE_TYPE_WC = 1, /* write combining */
	EPTE_TYPE_WT = 4, /* write through */
	EPTE_TYPE_WP = 5, /* write protected */
	EPTE_TYPE_WB = 6, /* write back */
};

#define __EPTE_NONE	0
#define __EPTE_FULL	(__EPTE_READ | __EPTE_WRITE | __EPTE_EXEC)

#define EPTE_PAGE_MASK	(~((unsigned long)(PAGE_SIZE - 1)))
#define EPTE_HPAGE_MASK	(~((unsigned long)(SLIMVM_HPAGE_2M_SIZE - 1)))
#define EPTE_FLAGS	((unsigned long)(PAGE_SIZE - 1))
#define HPAGE_PFN_MASK	0xFFFFFFFFFFFFFE00

#define EPTE_PAGE_TABLE         0 /* 4K */
#define EPTE_PAGE_DIRECTORY     1 /* 2M */
#define EPTE_PAGE_PDPE          2 /* 1G */

#define EPT_PDPE_SIZE	(1UL << 30)

#define ept_align_down(x, a) \
	((unsigned long)(x) & ~(((unsigned long)(a)) - 1))
#define ept_align_up(x, a) \
	((unsigned long)(x + a - 1) & ~(((unsigned long)(a)) - 1))

/*
 * Copied from arch/x86/mm/init.c
 */
static uint8_t __pte2cachemode_tbl[8] = {
	[__pte2cm_idx( 0        | 0         | 0        )] = _PAGE_CACHE_MODE_WB,
	[__pte2cm_idx(_PAGE_PWT | 0         | 0        )] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx( 0        | _PAGE_PCD | 0        )] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(_PAGE_PWT | _PAGE_PCD | 0        )] = _PAGE_CACHE_MODE_UC,
	[__pte2cm_idx( 0        | 0         | _PAGE_PAT)] = _PAGE_CACHE_MODE_WB,
	[__pte2cm_idx(_PAGE_PWT | 0         | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(0         | _PAGE_PCD | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(_PAGE_PWT | _PAGE_PCD | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC,
};

enum page_cache_mode pgprot2cachemode(pgprot_t pgprot)
{
	unsigned long masked;

	masked = pgprot_val(pgprot) & _PAGE_CACHE_MASK;
	if (likely(masked == 0))
		return 0;
	return __pte2cachemode_tbl[__pte2cm_idx(masked)];
}

static inline uintptr_t epte_addr(epte_t epte)
{
	return (epte & EPTE_PAGE_MASK);
}

static inline uintptr_t epte_page_vaddr(epte_t epte)
{
	return (uintptr_t) __va(epte_addr(epte));
}

static inline epte_t epte_flags(epte_t epte)
{
	return (epte & EPTE_FLAGS);
}

static inline int epte_present(epte_t epte)
{
	return (epte & __EPTE_FULL);
}

static inline int is_epte_huge(epte_t epte)
{
	return (epte & __EPTE_SZ);
}

static inline epte_t ept_flags(int write, bool pfnmap, unsigned long mtype)
{
	epte_t flags;

	flags = __EPTE_READ | __EPTE_EXEC |
		__EPTE_IPAT | __EPTE_TYPE(mtype);

	if (write)
		flags |= __EPTE_WRITE;

	if (pfnmap)
		flags |= __EPTE_PFNMAP;

	if (cpu_has_vmx_ept_ad_bits()) {
		flags |= __EPTE_A;
		if (write)
			flags |= __EPTE_D;
	}

	return (flags & EPTE_FLAGS);
}

#define ADDR_INVAL ((unsigned long) -1)

#define ADDR_TO_IDX(la, n) \
	((((unsigned long) (la)) >> (12 + 9 * (n))) & ((1 << 9) - 1))

/* Only used as a IPI handler. */
static void ack_flush(void *_completed) {}

static bool ept_flush_remote_tlbs(struct instance *instp, unsigned int req)
{
	bool called = true;
	struct vmx_vcpu *vcpu;
	int cpu, me, vcpu_no;
	cpumask_var_t cpus;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);

	me = get_cpu();
	spin_lock(&instp->vcpu_lock);
	for_each_set_bit(vcpu_no, instp->vcpu_bitmap, VM_MAX_VCPUS) {
		vcpu = instp->vcpus[vcpu_no];
		if (!vcpu)
			continue;

		vmx_make_request(req, vcpu);
		cpu = vcpu->cpu;

		/* Set ->requests bit before we read ->mode. */
		smp_mb__after_atomic();

		if (cpus != NULL && cpu != -1 && cpu != me &&
			vmx_vcpu_exiting_guest_mode(vcpu) != OUTSIDE_GUEST_MODE) {
			cpumask_set_cpu(cpu, cpus);
			instp->ept_invl_ipi++;
		}
	}
	spin_unlock(&instp->vcpu_lock);

	if (unlikely(cpus == NULL))
		smp_call_function_many(cpu_online_mask, ack_flush, NULL, 1);
	else if (!cpumask_empty(cpus))
		smp_call_function_many(cpus, ack_flush, NULL, 1);
	else
		called = false;

	put_cpu();
	free_cpumask_var(cpus);
	return called;
}

static int ept_lookup_gpa(struct instance *instp, gpa_t gpa, int level,
			  int create, epte_t **epte_out)
{
	epte_t *dir = (epte_t *) __va(instp->ept_root);
	int i;

	for (i = EPT_LEVELS - 1; i > level; i--) {
		int idx = ADDR_TO_IDX(gpa, i);

		if (!epte_present(dir[idx])) {
			void *page;

			if (!create)
				return -ENOENT;

			page = (void *) __get_free_page(GFP_ATOMIC);
			if (!page)
				return -ENOMEM;

			memset(page, 0, PAGE_SIZE);
			dir[idx] = epte_addr(virt_to_phys(page)) |
				   __EPTE_FULL;
		}

		if (is_epte_huge(dir[idx]) && i == EPTE_PAGE_DIRECTORY) {
			level = EPTE_PAGE_DIRECTORY;
			break;
		}

		dir = (epte_t *) epte_page_vaddr(dir[idx]);
	}

	*epte_out = &dir[ADDR_TO_IDX(gpa, level)];

	return 0;
}

static int ept_lookup_hva(struct instance *instp, struct mm_struct *mm,
		hva_t hva, int level, int create, epte_t **epte_out)
{
	gpa_t gpa;

	gpa = hva_to_gpa(instp, hva);
	if (gpa == ADDR_INVAL)
		return -EINVAL;

	return ept_lookup_gpa(instp, gpa, level, create, epte_out);
}

static void vmx_free_ept_pte_range(epte_t *pte)
{
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++) {
		if (!epte_present(pte[i]))
			continue;

		WRITE_ONCE(pte[i], __EPTE_NONE);
	}
}

static void vmx_free_ept_pmd_range(epte_t *pmd)
{
	epte_t *pte;
	int i;

	for (i = 0; i < PTRS_PER_PMD; i++) {
		pte = (epte_t *)epte_page_vaddr(pmd[i]);
		if (!epte_present(pmd[i]))
			continue;

		if (is_epte_huge(pmd[i])) {
			WRITE_ONCE(pmd[i], __EPTE_NONE);
			continue;
		}

		vmx_free_ept_pte_range(pte);
		WRITE_ONCE(pmd[i], __EPTE_NONE);
		free_page((unsigned long)pte);
	}
}

static void vmx_free_ept_pud_range(epte_t *pud)
{
	epte_t *pmd;
	int i;

	for (i = 0; i < PTRS_PER_PUD; i++) {
		pmd = (epte_t *)epte_page_vaddr(pud[i]);
		if (!epte_present(pud[i]))
			continue;

		vmx_free_ept_pmd_range(pmd);
		WRITE_ONCE(pud[i], __EPTE_NONE);
		free_page((unsigned long)pmd);
	}
}

static void vmx_free_ept(epte_t ept_root)
{
	epte_t *pgd = (epte_t *)__va(ept_root);
	epte_t *pud;
	int i;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		pud = (epte_t *)epte_page_vaddr(pgd[i]);
		if (!epte_present(pgd[i]))
			continue;

		vmx_free_ept_pud_range(pud);
		free_page((unsigned long)pud);
	}

	free_page((unsigned long)pgd);
}

static int ept_clear_epte(epte_t *epte)
{
	if (READ_ONCE(*epte) == __EPTE_NONE)
		return 0;

	WRITE_ONCE(*epte, __EPTE_NONE);

	return 1;
}

static int ept_clear_dir(epte_t *epte)
{
	unsigned long epte_value = READ_ONCE(*epte);
	struct page *page;

	if (epte_value == __EPTE_NONE)
		return 0;

	if (epte_value & __EPTE_PFNMAP) {
		WRITE_ONCE(*epte, __EPTE_NONE);
		return 0;
	}

	WRITE_ONCE(*epte, __EPTE_NONE);
	if (!is_epte_huge(epte_value)) {
		page = pfn_to_page(epte_value >> PAGE_SHIFT);
		put_page(page);
	}

	return 1;
}

static int ept_follow_pfn(struct instance *instp, int make_write,
	gpa_t gpa, hva_t hva, unsigned long *pfn, unsigned long *mtype)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long type;
	int ret;

	down_read(&mm->mmap_lock);
	vma = find_vma(mm, hva);
	if (!vma) {
		slimvm_debug("ept: sandbox %08lx VMA is null", instp->sid);
		up_read(&mm->mmap_lock);
		return -EFAULT;
	}

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP))) {
		up_read(&mm->mmap_lock);
		slimvm_debug(
		"ept: sandbox %08lx vm flags 0x%lx, not (VM_IO | VM_PFNMAP)",
		instp->sid, vma->vm_flags);

		return -EFAULT;
	}

	type = pgprot2cachemode(vma->vm_page_prot);
	if (type == _PAGE_CACHE_MODE_WB)
		*mtype = EPTE_TYPE_WB;
	else if (type == _PAGE_CACHE_MODE_WC)
		*mtype = EPTE_TYPE_WC;
	else
		*mtype = EPTE_TYPE_UC;

	ret = follow_pfn(vma, hva, pfn);
	up_read(&mm->mmap_lock);

	return ret;
}

static int mmu_notifier_retry(struct instance *instp, unsigned long seq)
{
	if (instp->mmu_notifier_count)
		return 1;

	/*
	 * Ensure the read of mmu_notifier_count happens before the read
	 * before mmu_notifier_seq.
	 */
	smp_rmb();
	if (instp->mmu_notifier_seq != seq)
		return 1;

	return 0;
}

/*
 * gpa_to_hva() is piecewise-linear per mem_region, so HVA is contiguous only
 * within one region. The 2M-aligned base and the next 2M boundary span exactly
 * 2M only if the range stays inside a single region; otherwise a 2M entry is
 * unsafe and we fall back to 4K.
 */
static int check_hugepage_consistency(struct instance *instp, gpa_t gpa)
{
	hva_t s, e, size;

	s = gpa_to_hva(instp, gpa & EPTE_HPAGE_MASK);
	e = gpa_to_hva(instp, (gpa + SLIMVM_HPAGE_2M_SIZE) & EPTE_HPAGE_MASK);
	size = e - s;

	if (s == ADDR_INVAL || e == ADDR_INVAL)
		return 0;

	return (size == SLIMVM_HPAGE_2M_SIZE);
}

static int mapping_level(struct instance *instp, gpa_t gpa)
{
	epte_t *epte;
	int ret;

	if (!check_hugepage_consistency(instp, gpa))
		return EPTE_PAGE_TABLE;

	ret = ept_lookup_gpa(instp, gpa, EPTE_PAGE_DIRECTORY, 0, &epte);
	if (!ret && epte_present(*epte) && !is_epte_huge(*epte))
		return EPTE_PAGE_TABLE;

	return EPTE_PAGE_DIRECTORY;
}

static void ept_dump_mm_stat(struct instance *instp)
{
	slimvm_info("         Counts Total (KB)\n");
	slimvm_info("4K: %10lld %lld\n", instp->ept_4k_pages,
			(instp->ept_4k_pages * 0x1000UL) >> 10);
	slimvm_info("2M: %10lld %lld\n", instp->ept_2m_pages,
			(instp->ept_2m_pages * 0x200000UL) >> 10);
}

static void ept_trace_mm_stat_map(struct instance *instp, epte_t epte)
{
	if ((epte == 0) || (epte & __EPTE_PFNMAP))
		return;

	if (is_epte_huge(epte))
		instp->ept_2m_pages++;
	else
		instp->ept_4k_pages++;
}

static void ept_trace_mm_stat_unmap(struct instance *instp, epte_t epte)
{
	if ((epte == 0) || (epte & __EPTE_PFNMAP))
		return;

	if (is_epte_huge(epte))
		instp->ept_2m_pages--;
	else
		instp->ept_4k_pages--;
}

static inline int __is_trans_compoundmap(struct page *page)
{
	struct page *hpage;

	if (!PageTransCompound(page))
		return 0;

	/* Anonymous transparent hugepage */
	if (PageAnon(page))
		return atomic_read(&page->_mapcount) < 0;

	hpage = compound_head(page);
	/* File transparent hugepage */
	return atomic_read(&page->_mapcount) ==
	       atomic_read(compound_mapcount_ptr(hpage));
}

static inline int __is_trans_hugepage(struct page *page)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (!PageCompound(page))
		return 0;

	page = compound_head(page);
	return page[1].compound_dtor == TRANSHUGE_PAGE_DTOR;
#else
	/* TRANSHUGE_PAGE_DTOR is compiled out without THP; fall back to 4K. */
	return 0;
#endif
}

/* Refer kvm_is_transparent_hugepage() in Linux Kernel. */
static inline int slimvm_is_transparent_hugepage(struct page *page)
{
	if (!__is_trans_compoundmap(page))
		return 0;

	return __is_trans_hugepage(compound_head(page));
}

static int ept_pin_user_page(int write, hva_t hva,
			struct page **page)
{
	unsigned int flags = FOLL_TOUCH | FOLL_HWPOISON;
	int npages;

	if (write) {
		/*
		 * Fast page fault is the fast path which fixes
		 * the guest page fault out of the mmu-lock on
		 * x86. Currently, the page fault can be fast
		 * only if the page table is present and it is
		 * caused by write-protect.
		 */
		npages = get_user_pages_fast_only(hva, 1, FOLL_WRITE, page);
		if (npages == 1)
			return npages;
	}

	flags |= write ? FOLL_WRITE : 0;
	npages = get_user_pages_unlocked_compat(hva, 1, page, flags);

	return npages;
}

static void release_epte_page(struct page *page, bool pfnmap, int write)
{
	if (unlikely(pfnmap))
		return;

	if (write && !PageReserved(page))
		SetPageDirty(page);

	put_page(page);
}

static int ept_set_epte(struct instance *instp, int make_write,
			gpa_t gpa, hva_t hva)
{
	epte_t *epte, flags, addr;
	struct page *page;
	unsigned long seq, pfn, mtype = EPTE_TYPE_WB;
	int ret, level = EPTE_PAGE_TABLE;
	bool pfnmap = false;

	seq = instp->mmu_notifier_seq;
	ret = ept_pin_user_page(make_write, hva, &page);
	if (ret == 1)
		pfn = page_to_pfn(page);
	else {
		if (ret == -ENOMEM)
			return ret;

		if (ret == -ERESTARTSYS || ret == -EBUSY)
			return 0;

		/*
		 * Mostly run on some special region with low frequency, such
		 * as VVAR memory region, or device mmio.
		 */
		ret = ept_follow_pfn(instp, make_write, gpa, hva, &pfn, &mtype);
		if (ret)
			return ret;

		pfnmap = true;
	}

	flags = ept_flags(make_write, pfnmap, mtype);
	spin_lock(&instp->ept_lock);
	if (mmu_notifier_retry(instp, seq))
		goto ept_unlock;

	if (!pfnmap && slimvm_is_transparent_hugepage(page) &&
	    mapping_level(instp, gpa) == EPTE_PAGE_DIRECTORY) {
		struct page *hpage = compound_head(page);

		WARN_ON((pfn & HPAGE_PFN_MASK) != page_to_pfn(hpage));
		pfn = page_to_pfn(hpage);
		flags |= __EPTE_SZ;
		level = EPTE_PAGE_DIRECTORY;
	}

	ret = ept_lookup_gpa(instp, gpa, level, 1, &epte);
	if (ret)
		goto ept_unlock;

	addr = (pfn << PAGE_SHIFT) | flags;

	if (epte_present(*epte)) {
		if (is_epte_huge(*epte) && level != EPTE_PAGE_DIRECTORY)
			goto ept_unlock;

		WARN_ON((epte_addr(*epte) >> PAGE_SHIFT) != pfn);
	} else {
		ept_trace_mm_stat_map(instp, addr);
	}

	WRITE_ONCE(*epte, addr);
	release_epte_page(page, pfnmap, make_write);

	spin_unlock(&instp->ept_lock);
	return 0;

ept_unlock:
	spin_unlock(&instp->ept_lock);
	release_epte_page(page, pfnmap, 0);
	return 0;
}

int vmx_do_ept_misconfig(struct instance *instp,
		unsigned long gpa, unsigned long **epte)
{
	return ept_lookup_gpa(instp, gpa, EPTE_PAGE_TABLE, 0, epte);
}

int vmx_do_ept_violation(struct instance *instp, unsigned long gpa,
		unsigned long gva, int fault_flags)
{
	hva_t hva;
	int ret, make_write;

	hva = gpa_to_hva(instp, gpa);
	if (unlikely(hva == ADDR_INVAL))
		return -EINVAL;

	make_write = (fault_flags & VMX_EPT_FAULT_WRITE) ? 1 : 0;
	ret = ept_set_epte(instp, make_write, gpa, hva);
	if (ret && slimvm_debug_enable)
		ept_dump_mm_stat(instp);

	return ret;
}

/**
 * ept_invalidate_page - removes a page from the EPT
 * @instp: the instance
 * @mm: the process's mm_struct
 * @addr: the address of the page
 *
 * Returns 1 if the page was removed, 0 otherwise
 */
static int ept_invalidate_page(struct instance *instp,
			       struct mm_struct *mm,
			       unsigned long addr)
{
	epte_t *epte;
	int ret;

	spin_lock(&instp->ept_lock);
	ret = ept_lookup_hva(instp, mm, addr, EPTE_PAGE_TABLE, 0, &epte);
	if (ret) {
		spin_unlock(&instp->ept_lock);
		return 0;
	}

	instp->mmu_notifier_seq++;

	/*
	 * This sequence increase will notify the slimvm page fault
	 * that the page that is going to be mapped could have been
	 * freed.
	 */
	smp_wmb();

	ept_trace_mm_stat_unmap(instp, *epte);
	ret = ept_clear_epte(epte);
	spin_unlock(&instp->ept_lock);

	if (ret)
		ept_flush_remote_tlbs(instp, VMX_REQ_TLB_FLUSH);

	return ret;
}

/**
 * ept_check_page_mapped - determines if a page is mapped in the ept
 * @instp: the instance
 * @mm: the process's mm_struct
 * @addr: the address of the page
 *
 * Returns 1 if the page is mapped, 0 otherwise
 */
static int ept_check_page_mapped(struct instance *instp,
				 struct mm_struct *mm,
				 unsigned long addr)
{
	epte_t *epte;
	int ret;

	spin_lock(&instp->ept_lock);
	ret = ept_lookup_hva(instp, mm, addr, EPTE_PAGE_TABLE, 0, &epte);
	spin_unlock(&instp->ept_lock);

	return !ret;
}

/**
 * ept_check_page_accessed - determines if a page was accessed using AD bits
 * @instp: the instance
 * @mm: the process's mm_struct
 * @addr: the address of the page
 * @flush: if true, clear the A bit
 *
 * Returns 1 if the page was accessed, 0 otherwise
 */
static int ept_check_page_accessed(struct instance *instp,
				   struct mm_struct *mm,
				   unsigned long addr,
				   bool flush)
{
	epte_t *epte;
	int ret, accessed;

	spin_lock(&instp->ept_lock);
	ret = ept_lookup_hva(instp, mm, addr, EPTE_PAGE_TABLE, 0, &epte);
	if (ret) {
		spin_unlock(&instp->ept_lock);
		return 0;
	}

	accessed = (*epte & __EPTE_A);
	if (flush & accessed)
		*epte = (*epte & ~__EPTE_A);
	spin_unlock(&instp->ept_lock);

	if (flush & accessed)
		ept_flush_remote_tlbs(instp, VMX_REQ_TLB_FLUSH);

	return accessed;
}

static inline struct instance *mmu_notifier_to_instance(struct mmu_notifier *mn)
{
	return container_of(mn, struct instance, mmu_notifier);
}

static void ept_clear_page_table(struct instance *instp,
				 struct mm_struct *mm,
				 unsigned long start,
				 unsigned long end)
{
	epte_t *epte;
	hva_t s, e;
	int ret;

	s = epte_addr(start);
	e = epte_addr(end + PAGE_SIZE - 1);

	while (s < e) {
		ret = ept_lookup_hva(instp, mm, s, EPTE_PAGE_TABLE, 0, &epte);
		if (!ret) {
			if (is_epte_huge(*epte)) {
				hva_t down, up;

				/*
				 * A 2M entry cannot be partially unmapped. If
				 * the range does not fully cover the 2M block,
				 * drop the whole entry so the next access
				 * re-faults, then skip to the next 2M block.
				 */
				down = ept_align_down(s, SLIMVM_HPAGE_2M_SIZE);
				up = ept_align_up(s, SLIMVM_HPAGE_2M_SIZE);

				if (s > down || e < up) {
					ept_trace_mm_stat_unmap(instp, *epte);
					ept_clear_epte(epte);
				}

				s = down + SLIMVM_HPAGE_2M_SIZE;
			} else {
				s += PAGE_SIZE;
				ept_trace_mm_stat_unmap(instp, *epte);
				ept_clear_epte(epte);
			}
		} else {
			s += PAGE_SIZE;
		}
	}
}

static void ept_clear_page_directory(struct instance *instp,
				     struct mm_struct *mm,
				     unsigned long start,
				     unsigned long end)
{
	epte_t *epte;
	hva_t s, e;
	int ret;

	/*
	 * For EPT page directory, only invalidate pages that are contained from
	 * start to end as a best effort.
	 */
	s = ept_align_up(start, SLIMVM_HPAGE_2M_SIZE);
	e = ept_align_down(end, SLIMVM_HPAGE_2M_SIZE);

	while (s < e) {
		ret = ept_lookup_hva(instp, mm, s,
				EPTE_PAGE_DIRECTORY, 0, &epte);
		if (!ret) {
			if (is_epte_huge(*epte))
				ept_trace_mm_stat_unmap(instp, *epte);

			ept_clear_dir(epte);
		}

		s += SLIMVM_HPAGE_2M_SIZE;
	}
}

static inline void
__ept_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
					  struct mm_struct *mm,
					  unsigned long start,
					  unsigned long end)
{
	struct instance *instp = mmu_notifier_to_instance(mn);

	spin_lock(&instp->ept_lock);
	instp->mmu_notifier_count++;

	ept_clear_page_table(instp, mm, start, end);
	ept_clear_page_directory(instp, mm, start, end);

	instp->ept_invl_count++;
	instp->ept_invl_range += (end - start);
	spin_unlock(&instp->ept_lock);

	ept_flush_remote_tlbs(instp, VMX_REQ_TLB_FLUSH);
}

static int ept_mmu_notifier_invalidate_range_start(struct mmu_notifier *subscription,
						   const struct mmu_notifier_range *range)
{
	__ept_mmu_notifier_invalidate_range_start(subscription,
						  range->mm,
						  range->start,
						  range->end);
	return 0;
}

static void __ept_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn)
{
	struct instance *instp = mmu_notifier_to_instance(mn);

	spin_lock(&instp->ept_lock);
	instp->mmu_notifier_seq++;

	/*
	 * The above sequence increase must be visible before the
	 * below count decrease.
	 */
	smp_wmb();

	instp->mmu_notifier_count--;
	spin_unlock(&instp->ept_lock);
}

static void ept_mmu_notifier_invalidate_range_end(struct mmu_notifier *subscription,
						  const struct mmu_notifier_range *range)
{
	__ept_mmu_notifier_invalidate_range_end(subscription);
}

static void ept_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long address,
					pte_t pte)
{
	struct instance *instp = mmu_notifier_to_instance(mn);

	/*
	 * NOTE: Recent linux kernels (seen on 3.7 at least) hold a lock
	 * while calling this notifier, making it impossible to call
	 * get_user_pages_fast(). As a result, we just invalidate the
	 * page so that the mapping can be recreated later during a fault.
	 */
	ept_invalidate_page(instp, mm, address);
}

static int ept_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      unsigned long start,
					      unsigned long end)
{
	struct instance *instp = mmu_notifier_to_instance(mn);
	int ret = 0;

	if (cpu_has_vmx_ept_ad_bits())
		for (; start < end; start += PAGE_SIZE)
			ret |= ept_invalidate_page(instp, mm, start);
	else
		for (; start < end; start += PAGE_SIZE)
			ret |= ept_check_page_accessed(instp, mm, start, true);

	return ret;
}

static int ept_mmu_notifier_test_young(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long address)
{
	struct instance *instp = mmu_notifier_to_instance(mn);

	if (cpu_has_vmx_ept_ad_bits())
		return ept_check_page_mapped(instp, mm, address);
	else
		return ept_check_page_accessed(instp, mm, address, false);
}

static void ept_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
}

static int ept_mmu_notifier_clear_young(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long start,
					unsigned long end)
{
	return 0;
}

static const struct mmu_notifier_ops ept_mmu_notifier_ops = {
	.invalidate_range_start	= ept_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= ept_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= ept_mmu_notifier_clear_flush_young,
	.clear_young		= ept_mmu_notifier_clear_young,
	.test_young		= ept_mmu_notifier_test_young,
	.change_pte		= ept_mmu_notifier_change_pte,
	.release		= ept_mmu_notifier_release,
};

static int ept_register_mmu_notifier(struct instance *instp)
{
	instp->mmu_notifier.ops = &ept_mmu_notifier_ops;
	return mmu_notifier_register(&instp->mmu_notifier, current->mm);
}

int instance_alloc_eptp(struct instance *instp)
{
	void *page;

	page = (void *) get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	instp->ept_root = __pa(page);
	instp->eptp = construct_eptp(instp->ept_root);

	return 0;
}

int instance_init_ept(struct instance *instp)
{
	return ept_register_mmu_notifier(instp);
}

void instance_destroy_ept(struct instance *instp)
{
	if (instp->ept_root)
		vmx_free_ept(instp->ept_root);

	if (instp->mmu_notifier.ops)
		mmu_notifier_unregister(&instp->mmu_notifier, instp->mm);
}
