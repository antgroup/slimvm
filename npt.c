/**
 * npt.c - Support for AMD's Nested Page Tables
 *
 * We support the NPT by making a sort of 'shadow' copy of the Linux
 * process page table. Mappings are created lazily as they are needed.
 * We keep the NPT synchronized with the process page table through
 * mmu_notifier callbacks.
 *
 * Some of the low-level NPT functions are based on KVM.
 */

#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <asm/pgtable.h>
#include <asm/io.h>

#include "svm.h"
#include "slimvm.h"
#include "compat.h"
#include "instance.h"
#include "mm.h"

#define NPT_LEVELS	4	/* 0 through 3 */
#define NANOVM_HPAGE_2M_SIZE	(1 << 21)

#define SVM_NPT_FAULT_READ	0x01
#define SVM_NPT_FAULT_WRITE	0x02
#define SVM_NPT_FAULT_INS	0x04

typedef unsigned long npte_t;

#define __NPTE_P   	     0x01   //P Bit, Bit 0, is present
#define __NPTE_R_W 	     0x02   //R/W Bit, Bit 1, writeable
#define __NPTE_U_S 	     0x04   //U/S Bit, Bit 2, userspace addressable
#define __NPTE_PWT 	     0x08   //PWT Bit, Bit 3, page write through
#define __NPTE_PCD 	     0x10   //PCD Bit, Bit 4, page cache disabled
#define __NPTE_A   	     0x20   //A Bit, Bit 5, was accessed (raised by CPU)
#define __NPTE_D   	     0x40   //D Bit, Bit 6, was written to (raised by CPU)
#define __NPTE_PAT 	     0x80   //PAT Bit, Bit 7, on 4KB pages
#define __NPTE_G   	     0x100  //G bit, Bit 8, Global TLB entry PPro+
#define __NPTE_SOFTW1	 0x200	//Bit 9, available for programmer
#define __NPTE_SOFTW2	 0x400	//Bit 10, available for programmer
#define __NPTE_SOFTW3	 0x800	//Bit 11, available for programmer
#define __NPTE_PFNMAP	 __NPTE_SOFTW1

#define __NPDPE_PS       0x80   //PS bit in huge page(1G/2M), Bit 7
#define __NPDPE_PAT      0x1000 //PAT bit in huge page(1G/2M), Bit 12

#define __NPTE_CACHE_TYPE(cm)	cachemode2protval(cm)

#define HPAGE_PFN_MASK  0xFFFFFFFFFFFFFE00

enum {
	NPTE_TYPE_UC = 0, /* uncachable */
	NPTE_TYPE_WC = 1, /* write combining */
	NPTE_TYPE_WT = 4, /* write through */
	NPTE_TYPE_WP = 5, /* write protected */
	NPTE_TYPE_WB = 6, /* write back */
};

#define __NPTE_NONE	0
#define __NPTE_FULL	(__NPTE_P | __NPTE_R_W | __NPTE_U_S)

#define NPTE_PAGE_MASK	(~((unsigned long)PAGE_SIZE - 1))
#define NPTE_HPAGE_MASK	(~((unsigned long)NANOVM_HPAGE_2M_SIZE - 1))
#define NPTE_FLAGS	((unsigned long)PAGE_SIZE - 1)

#define NPTE_PAGE_TABLE         0 /* 4K */
#define NPTE_PAGE_DIRECTORY     1 /* 2M */
#define NPTE_PAGE_PDPE          2 /* 1G */

#define NPT_PDPE_SIZE   (1UL << 30)

#define npt_align_down(x, a) \
	((unsigned long)(x) & ~(((unsigned long)(a)) - 1))
#define npt_align_up(x, a) \
	((unsigned long)(x + a - 1) & ~(((unsigned long)(a)) - 1))

#define NPTE_CACHE_MASK         (__NPTE_PWT | __NPTE_PCD | __NPTE_PAT)
#define NPTE_SET_CACHE_FLAGS(flags, index)	(((flags) & ~(NPTE_CACHE_MASK)) | ((index & 0x3) << 3) | ((index & 0x4) << 5))

#define VMCB_AVIC_APIC_BAR_MASK		0xFFFFFFFFFF000ULL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
/*
 * Copied from arch/x86/mm/init.c
 */
static uint8_t __pte2cachemode_tbl_npt[8] = {
	[__pte2cm_idx( 0        | 0         | 0        )] = _PAGE_CACHE_MODE_WB,
	[__pte2cm_idx(_PAGE_PWT | 0         | 0        )] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx( 0        | _PAGE_PCD | 0        )] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(_PAGE_PWT | _PAGE_PCD | 0        )] = _PAGE_CACHE_MODE_UC,
	[__pte2cm_idx( 0        | 0         | _PAGE_PAT)] = _PAGE_CACHE_MODE_WB,
	[__pte2cm_idx(_PAGE_PWT | 0         | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(0         | _PAGE_PCD | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(_PAGE_PWT | _PAGE_PCD | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC,
};

static enum page_cache_mode pgprot2cachemode(pgprot_t pgprot)
{
	unsigned long masked;

	masked = pgprot_val(pgprot) & _PAGE_CACHE_MASK;
	if (likely(masked == 0))
		return 0;
	return __pte2cachemode_tbl_npt[__pte2cm_idx(masked)];
}
#endif

static inline uintptr_t npte_addr(npte_t npte)
{
	return (npte & NPTE_PAGE_MASK);
}

static inline uintptr_t npte_page_vaddr(npte_t npte)
{
	return (uintptr_t) __va(npte_addr(npte));
}

static inline npte_t npte_flags(npte_t npte)
{
	return (npte & NPTE_FLAGS);
}

static inline int npte_present(npte_t npte)
{
	return (npte & __NPTE_P);
}

static inline int is_npte_huge(npte_t npte)
{
	return (npte & __NPDPE_PS);
}

static inline npte_t npt_flags(int write, bool pfnmap, unsigned long mtype)
{
	npte_t flags;

	flags = __NPTE_P | __NPTE_U_S |	__NPTE_CACHE_TYPE(mtype);

	if (write)
		flags |= __NPTE_R_W;

	if (pfnmap)
		flags |= __NPTE_PFNMAP;

	if (cpu_has_svm_npt_ad_bits()) {
		flags |= __NPTE_A;
		if (write)
			flags |= __NPTE_D;
	}

	return (flags & NPTE_FLAGS);
}

static inline void npt_mmu_get(struct instance *instp)
{
    atomic_inc(&instp->npt_mmu_users);
}

static inline void npt_mmu_put(struct instance *instp)
{
    atomic_dec(&instp->npt_mmu_users);
}

#define ADDR_INVAL ((unsigned long) -1)

#define ADDR_TO_IDX(la, n) \
	((((unsigned long) (la)) >> (12 + 9 * (n))) & ((1 << 9) - 1))

/* Only used as a IPI handler. */
static void ack_flush(void *_completed)
{
}

static bool npt_flush_remote_tlbs(struct instance *instp, unsigned int req)
{
	bool called = true;
	struct svm_vcpu *vcpu;
	int cpu, me, vcpu_no;
	cpumask_var_t cpus;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);

	me = get_cpu();
	spin_lock(&instp->vcpu_lock);
	for_each_set_bit(vcpu_no, instp->vcpu_bitmap, VM_MAX_VCPUS) {
		vcpu = instp->vcpus[vcpu_no];
		if (!vcpu)
			continue;

		svm_make_request(req, vcpu);
		cpu = vcpu->cpu;

		/* Set ->requests bit before we read ->mode. */
		smp_mb__after_atomic();

		if (cpus != NULL && cpu != -1 && cpu != me &&
			svm_vcpu_exiting_guest_mode(vcpu) != OUTSIDE_GUEST_MODE) {
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

/*
 * Account a present, non-pfnmap NPT leaf as it is installed/torn down, so
 * /proc/slimvm/vm_mem_stat reports 4K/2M page counts on AMD/Hygon the same way
 * the EPT engine does on Intel. The 4k/2m counters are shared instance fields;
 * a given instance only ever uses one engine.
 */
static void npt_trace_mm_stat_map(struct instance *instp, npte_t npte)
{
	if ((npte == __NPTE_NONE) || (npte & __NPTE_PFNMAP))
		return;

	if (is_npte_huge(npte))
		instp->ept_2m_pages++;
	else
		instp->ept_4k_pages++;
}

static void npt_trace_mm_stat_unmap(struct instance *instp, npte_t npte)
{
	if ((npte == __NPTE_NONE) || (npte & __NPTE_PFNMAP))
		return;

	if (is_npte_huge(npte))
		instp->ept_2m_pages--;
	else
		instp->ept_4k_pages--;
}

static int npt_lookup_gpa(struct instance *instp, gpa_t gpa, int level,
	   int create, npte_t **npte_out)
{
	npte_t *dir = (npte_t *) __va(__sme_clr(instp->ept_root));
	int i;

	for (i = NPT_LEVELS - 1; i > level; i--) {
		int idx = ADDR_TO_IDX(gpa, i);

		if (!npte_present(dir[idx])) {
			void *page;

			if (!create)
				return -ENOENT;

			page = (void *) __get_free_page(GFP_ATOMIC);
			if (!page)
				return -ENOMEM;

			memset(page, 0, PAGE_SIZE);
			dir[idx] = npte_addr(__sme_set(virt_to_phys(page))) | __NPTE_FULL;
		}

		if (is_npte_huge(dir[idx]) && i == NPTE_PAGE_DIRECTORY) {
			level = NPTE_PAGE_DIRECTORY;
			break;
		}

		dir = (npte_t *) npte_page_vaddr(__sme_clr(dir[idx]));
	}

	*npte_out = &dir[ADDR_TO_IDX(gpa, level)];

	return 0;
}

static int npt_lookup_hva(struct instance *instp, struct mm_struct *mm,
	   hva_t hva, int level, int create, npte_t **npte_out)
{
	gpa_t gpa;

	gpa = hva_to_gpa(instp, hva);
	if (gpa == ADDR_INVAL)
		return -EINVAL;

	return npt_lookup_gpa(instp, gpa, level, create, npte_out);
}

static void svm_free_npt(npte_t npt_root)
{
	npte_t *pgd = (npte_t *) __va(__sme_clr(npt_root));
	int i, j, k, l;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		npte_t *pud = (npte_t *) npte_page_vaddr(__sme_clr(pgd[i]));
		if (!npte_present(pgd[i]))
			continue;

		for (j = 0; j < PTRS_PER_PUD; j++) {
			npte_t *pmd = (npte_t *) npte_page_vaddr(__sme_clr(pud[j]));
			if (!npte_present(pud[j]))
				continue;

			for (k = 0; k < PTRS_PER_PMD; k++) {
				npte_t *pte = (npte_t *) npte_page_vaddr(__sme_clr(pmd[k]));
				if (!npte_present(pmd[k]))
					continue;
				if (npte_flags(pmd[k]) & __NPDPE_PS) {
					WRITE_ONCE(pmd[i], __NPTE_NONE);
					continue;
				}

				for (l = 0; l < PTRS_PER_PTE; l++) {
					if (!npte_present(pte[l]))
						continue;

					WRITE_ONCE(pte[i], __NPTE_NONE);
				}

				free_page((unsigned long) pte);
			}

			free_page((unsigned long) pmd);
		}

		free_page((unsigned long) pud);
	}

	free_page((unsigned long) pgd);
}

static int npt_clear_npte(struct instance *instp, npte_t *npte)
{
	npte_t npte_value = READ_ONCE(*npte);

	if (npte_value == __NPTE_NONE)
		return 0;

	npt_trace_mm_stat_unmap(instp, npte_value);
	WRITE_ONCE(*npte, __NPTE_NONE);

	return 1;
}

static int npt_follow_pfn(struct instance *instp, int make_write,
		gpa_t gpa, hva_t hva, unsigned long *pfn, unsigned long *mtype)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long type;
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	down_read(&mm->mmap_lock);
#else
	down_read(&mm->mmap_sem);
#endif
	vma = find_vma(mm, hva);
	if (!vma) {
		slimvm_debug("npt: VMA is null");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
		up_read(&mm->mmap_lock);
#else
		up_read(&mm->mmap_sem);
#endif
		return -EFAULT;
	}

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP))) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
		up_read(&mm->mmap_lock);
#else
		up_read(&mm->mmap_sem);
#endif
		slimvm_debug("npt: vm flags 0x%lx, not (VM_IO | VM_PFNMAP)",
			   vma->vm_flags);
		return -EFAULT;
	}

	type = pgprot2cachemode(vma->vm_page_prot);
	if (type == _PAGE_CACHE_MODE_WB)
		*mtype = NPTE_TYPE_WB;
	else if (type == _PAGE_CACHE_MODE_WC)
		*mtype = NPTE_TYPE_WC;
	else
		*mtype = NPTE_TYPE_UC;

	ret = follow_pfn(vma, hva, pfn);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
	up_read(&mm->mmap_lock);
#else
	up_read(&mm->mmap_sem);
#endif

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

static int check_hugepage_consistency(struct instance *instp, gpa_t gpa)
{
	hva_t s, e, size;

	s = gpa_to_hva(instp, gpa & NPTE_HPAGE_MASK);
	e = gpa_to_hva(instp, (gpa + NANOVM_HPAGE_2M_SIZE) & NPTE_HPAGE_MASK);
	size = e - s;

	if (s == ADDR_INVAL || e == ADDR_INVAL)
		return 0;

	return (size == NANOVM_HPAGE_2M_SIZE);
}

static int mapping_level(struct instance *instp, gpa_t gpa)
{
	npte_t *npte;
	int ret;

	if (!check_hugepage_consistency(instp, gpa))
		return NPTE_PAGE_TABLE;

	ret = npt_lookup_gpa(instp, gpa, NPTE_PAGE_DIRECTORY, 0, &npte);
	if (!ret && npte_present(*npte) && !is_npte_huge(*npte))
		return NPTE_PAGE_TABLE;

	return NPTE_PAGE_DIRECTORY;
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
static inline int npt_is_transparent_hugepage(struct page *page)
{
	if (!__is_trans_compoundmap(page))
		return 0;

	return __is_trans_hugepage(compound_head(page));
}

static int npt_pin_user_page(int write, hva_t hva,
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
		npages = get_user_pages_fast_only(hva, 1, FOLL_WRITE, page);
#else
		npages = __get_user_pages_fast(hva, 1, 1, page);
#endif
		if (npages == 1)
			return npages;
	}

	flags |= write ? FOLL_WRITE : 0;
	npages = get_user_pages_unlocked(hva, 1, page, flags);

	return npages;
}

static void release_npte_page(struct page *page, bool pfnmap, int write)
{
	if (unlikely(pfnmap))
		return;

	if (write && !PageReserved(page))
		SetPageDirty(page);

	put_page(page);
}

static int npt_set_npte(struct instance *instp, int make_write,
			gpa_t gpa, hva_t hva)
{
	npte_t *npte, flags;
	struct page *page;
	unsigned long seq, pfn, mtype = NPTE_TYPE_WB;
	int ret, level = NPTE_PAGE_TABLE;
	bool pfnmap = false;

	seq = instp->mmu_notifier_seq;
	ret = npt_pin_user_page(make_write, hva, &page);
	if (ret == 1) {
		pfn = page_to_pfn(page);
	} else {
		if (ret == -ENOMEM)
			return ret;

		if (ret == -ERESTARTSYS || ret == -EBUSY)
			return 0;

		/*
		 * Mostly run on some special region with low frequency, such
		 * as vDSO memory region, or device mmio.
		 */
		ret = npt_follow_pfn(instp, make_write, gpa, hva, &pfn, &mtype);
		if (ret)
			return ret;

		pfnmap = true;
	}

	flags = npt_flags(make_write, pfnmap, mtype);
	spin_lock(&instp->ept_lock);
	if (mmu_notifier_retry(instp, seq))
		goto npt_unlock;

	if (!pfnmap && npt_is_transparent_hugepage(page) &&
	    mapping_level(instp, gpa) == NPTE_PAGE_DIRECTORY) {
		struct page *hpage = compound_head(page);

		WARN_ON((pfn & HPAGE_PFN_MASK) != page_to_pfn(hpage));
		pfn = page_to_pfn(hpage);
		flags |= __NPDPE_PS;
		level = NPTE_PAGE_DIRECTORY;
	}

	ret = npt_lookup_gpa(instp, gpa, level, 1, &npte);
	if (ret)
		goto npt_unlock;

	if (npte_present(*npte)) {
		if (is_npte_huge(*npte) && level != NPTE_PAGE_DIRECTORY)
			goto npt_unlock;
		WARN_ON((*npte >> PAGE_SHIFT) != pfn);
	} else {
		npt_trace_mm_stat_map(instp, (pfn << PAGE_SHIFT) | flags);
	}

	WRITE_ONCE(*npte, __sme_set((pfn << PAGE_SHIFT) | flags));
	release_npte_page(page, pfnmap, make_write);
	spin_unlock(&instp->ept_lock);

	return 0;

npt_unlock:
	spin_unlock(&instp->ept_lock);
	release_npte_page(page, pfnmap, make_write);

	return 0;
}

int svm_do_npt_violation(struct instance *instp, unsigned long gpa,
		unsigned long gva, int fault_flags)
{
	hva_t hva;
	int ret, make_write;

	hva = gpa_to_hva(instp, gpa);
	if (unlikely(hva == ADDR_INVAL))
		return -EINVAL;

	make_write = (fault_flags & SVM_NPT_FAULT_WRITE) ? 1 : 0;
	ret = npt_set_npte(instp, make_write, gpa, hva);

	return ret;
}

/**
 * npt_invalidate_page - removes a page from the NPT
 * @instp: the instance
 * @mm: the process's mm_struct
 * @addr: the address of the page
 *
 * Returns 1 if the page was removed, 0 otherwise
 */
static int npt_invalidate_page(struct instance *instp,
			       struct mm_struct *mm,
			       unsigned long addr)
{
	npte_t *npte;
	int ret;

	spin_lock(&instp->ept_lock);
	ret = npt_lookup_hva(instp, mm, addr, NPTE_PAGE_TABLE, 0, &npte);
	if (ret) {
		spin_unlock(&instp->ept_lock);
		return 0;
	}

	instp->mmu_notifier_seq++;

	/*
	 * This sequence increase will notify the nanovm page fault
	 * that the page that is going to be mapped could have been
	 * freed.
	 */
	smp_wmb();

	ret = npt_clear_npte(instp, npte);
	spin_unlock(&instp->ept_lock);

	if (ret)
		npt_flush_remote_tlbs(instp, SLIMVM_REQ_TLB_FLUSH);

	return ret;
}

/**
 * npt_check_page_mapped - determines if a page is mapped in the npt
 * @instp: the instance
 * @mm: the process's mm_struct
 * @addr: the address of the page
 *
 * Returns 1 if the page is mapped, 0 otherwise
 */
static int npt_check_page_mapped(struct instance *instp,
				 struct mm_struct *mm,
				 unsigned long addr)
{
	npte_t *npte;
	int ret;

	spin_lock(&instp->ept_lock);
	ret = npt_lookup_hva(instp, mm, addr, NPTE_PAGE_TABLE, 0, &npte);
	spin_unlock(&instp->ept_lock);

	return !ret;
}

/**
 * npt_check_page_accessed - determines if a page was accessed using AD bits
 * @instp: the instance
 * @mm: the process's mm_struct
 * @addr: the address of the page
 * @flush: if true, clear the A bit
 *
 * Returns 1 if the page was accessed, 0 otherwise
 */
static int npt_check_page_accessed(struct instance *instp,
				   struct mm_struct *mm,
				   unsigned long addr,
				   bool flush)
{
	npte_t *npte;
	int ret, accessed;

	spin_lock(&instp->ept_lock);
	ret = npt_lookup_hva(instp, mm, addr, NPTE_PAGE_TABLE, 0, &npte);
	if (ret) {
		spin_unlock(&instp->ept_lock);
		return 0;
	}

	accessed = (*npte & __NPTE_A);
	if (flush & accessed)
		*npte = (*npte & ~__NPTE_A);
	spin_unlock(&instp->ept_lock);

	if (flush & accessed)
		npt_flush_remote_tlbs(instp, SLIMVM_REQ_TLB_FLUSH);

	return accessed;
}

static inline struct instance *mmu_notifier_to_instance(struct mmu_notifier *mn)
{
	return container_of(mn, struct instance, mmu_notifier);
}

static inline hva_t pdpe_addr_end(hva_t start, hva_t end)
{
	hva_t boundary = (start + NPT_PDPE_SIZE) & ~(NPT_PDPE_SIZE - 1);

	return ((boundary - 1) < (end - 1)) ? boundary : end;
}

static void npt_clear_page_table(struct instance *instp,
				 struct mm_struct *mm,
				 unsigned long start,
				 unsigned long end)
{
	npte_t *npte;
	hva_t s, e, n;
	int ret;

	s = npte_addr(start);
	e = npte_addr(end + PAGE_SIZE - 1);
	n = pdpe_addr_end(s, e);

	/*
	 * Unmapping part of THP (with munmap() or other way) is not going to
	 * free memory immediately. Instead, we detect that a subpage of THP
	 * is not in use in page_remove_rmap() and queue the THP for splitting
	 * if memory pressure comes. Splitting will free up unused subpages.
	 *
	 * NPT page table is secondary MMU. For unmapping part of THP, clear
	 * NPT entry and put_page to operate in head page's ->_refcount
	 * [increased from get_user_pages_fast]. while sandbox accesses
	 * the used subpages of THP, do NPT violation again to map new NPT
	 * entry.
	 *
	 * Align down the THP page properly. npt_clear_page_directory
	 * would free full mapping of THP page.
	 */
	while (s < e) {
		ret = npt_lookup_hva(instp, mm, s, NPTE_PAGE_TABLE, 0, &npte);
		if (!ret) {
			if (is_npte_huge(*npte)) {
				hva_t down, up;

				down = npt_align_down(s, NANOVM_HPAGE_2M_SIZE);
				up = npt_align_up(s, NANOVM_HPAGE_2M_SIZE);

				if (s > down || e < up)
					npt_clear_npte(instp, npte);

				s = down + NANOVM_HPAGE_2M_SIZE;
			} else {
				s += PAGE_SIZE;
				npt_clear_npte(instp, npte);
			}
		} else {
			s += PAGE_SIZE;
		}

		/*
		 * If the range is too large, release instp->ept_lock
		 * to prevent starvation and lockup detector warnings.
		 */
		if ((s == n) && (s != e)) {
			n = pdpe_addr_end(s, e);
			cond_resched_lock(&instp->ept_lock);
			if (!READ_ONCE(instp->ept_root))
				break;
		}
	}
}

static int npt_clear_dir(struct instance *instp, npte_t *npte)
{
	unsigned long npte_value = READ_ONCE(*npte);
	struct page *page;

	if (npte_value == __NPTE_NONE)
		return 0;

	if (npte_value & __NPTE_PFNMAP) {
		WRITE_ONCE(*npte, __NPTE_NONE);
		return 0;
	}

	npt_trace_mm_stat_unmap(instp, npte_value);
	WRITE_ONCE(*npte, __NPTE_NONE);
	if (!is_npte_huge(npte_value)) {
		page = pfn_to_page(npte_value >> PAGE_SHIFT);
		put_page(page);
	}

	return 1;
}

static void npt_clear_page_directory(struct instance *instp,
				     struct mm_struct *mm,
				     unsigned long start,
				     unsigned long end)
{
	npte_t *npte;
	hva_t s, e;
	int ret;

	if (!READ_ONCE(instp->ept_root))
		return;

	/*
	 * For NPT page directory, only invalidate pages that are contained from
	 * start to end as a best effort.
	 */
	s = npt_align_up(start, NANOVM_HPAGE_2M_SIZE);
	e = npt_align_down(end, NANOVM_HPAGE_2M_SIZE);

	while (s < e) {
		ret = npt_lookup_hva(instp, mm, s,
				NPTE_PAGE_DIRECTORY, 0, &npte);
		if (!ret)
			npt_clear_dir(instp, npte);

		s += NANOVM_HPAGE_2M_SIZE;
	}
}

static int __npt_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						     struct mm_struct *mm,
						     unsigned long start,
						     unsigned long end)
{
	struct instance *instp = mmu_notifier_to_instance(mn);

	npt_mmu_get(instp);
	spin_lock(&instp->ept_lock);
	instp->mmu_notifier_count++;

	npt_clear_page_table(instp, mm, start, end);
	npt_clear_page_directory(instp, mm, start, end);

	instp->ept_invl_count++;
	instp->ept_invl_range += (end - start);
	spin_unlock(&instp->ept_lock);

	npt_flush_remote_tlbs(instp, SLIMVM_REQ_TLB_FLUSH);
	npt_mmu_put(instp);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static int npt_mmu_notifier_invalidate_range_start(struct mmu_notifier *subscription,
						   const struct mmu_notifier_range *range)
{
	return __npt_mmu_notifier_invalidate_range_start(subscription,
							 range->mm,
							 range->start,
							 range->end);
}
#else
static int npt_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						   struct mm_struct *mm,
						   unsigned long start,
						   unsigned long end,
						   bool blockable)
{
	return __npt_mmu_notifier_invalidate_range_start(mn, mm, start, end);
}
#endif

static void __npt_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn)
{
	struct instance *instp = mmu_notifier_to_instance(mn);

	npt_mmu_get(instp);
	spin_lock(&instp->ept_lock);
	instp->mmu_notifier_seq++;

	/*
	 * The above sequence increase must be visible before the
	 * below count decrease.
	 */
	smp_wmb();

	instp->mmu_notifier_count--;
	spin_unlock(&instp->ept_lock);
	npt_mmu_put(instp);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static void npt_mmu_notifier_invalidate_range_end(struct mmu_notifier *subscription,
						  const struct mmu_notifier_range *range)
{
	__npt_mmu_notifier_invalidate_range_end(subscription);
}
#else
static void npt_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
{
	__npt_mmu_notifier_invalidate_range_end(mn);
}
#endif

static void npt_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long address,
					pte_t pte)
{
	struct instance *instp = mmu_notifier_to_instance(mn);

	npt_mmu_get(instp);
	/*
	 * NOTE: Recent linux kernels (seen on 3.7 at least) hold a lock
	 * while calling this notifier, making it impossible to call
	 * get_user_pages_fast(). As a result, we just invalidate the
	 * page so that the mapping can be recreated later during a fault.
	 */
	npt_invalidate_page(instp, mm, address);
	npt_mmu_put(instp);
}

static int npt_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      unsigned long start,
					      unsigned long end)
{
	struct instance *instp = mmu_notifier_to_instance(mn);
	int ret = 0;

	npt_mmu_get(instp);
	if (cpu_has_svm_npt_ad_bits())
		for (; start < end; start += PAGE_SIZE)
			ret |= npt_invalidate_page(instp, mm, start);
	else
		for (; start < end; start += PAGE_SIZE)
			ret |= npt_check_page_accessed(instp, mm, start, true);

	npt_mmu_put(instp);
	return ret;
}

static int npt_mmu_notifier_test_young(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long address)
{
	struct instance *instp = mmu_notifier_to_instance(mn);
	int ret;

	npt_mmu_get(instp);
	if (cpu_has_svm_npt_ad_bits())
		ret = npt_check_page_mapped(instp, mm, address);
	else
		ret = npt_check_page_accessed(instp, mm, address, false);

	npt_mmu_put(instp);
	return ret;
}

static void npt_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	/*
	 * struct instance *instp = mmu_notifier_to_instance(mn);
	 * npt_mmu_get(instp);
	 * ...
	 * npt_mmu_put(instp);
	 */
}

static int npt_mmu_notifier_clear_young(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long start,
					unsigned long end)
{
	/*
	 * struct instance *instp = mmu_notifier_to_instance(mn);
	 * npt_mmu_get(instp);
	 * ...
	 * npt_mmu_put(instp);
	 */
	return 0;
}

static const struct mmu_notifier_ops npt_mmu_notifier_ops = {
	.invalidate_range_start	= npt_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= npt_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= npt_mmu_notifier_clear_flush_young,
	.clear_young		= npt_mmu_notifier_clear_young,
	.test_young		= npt_mmu_notifier_test_young,
	.change_pte		= npt_mmu_notifier_change_pte,
	.release		= npt_mmu_notifier_release,
};

static int npt_register_mmu_notifier(struct instance *instp)
{
	instp->mmu_notifier.ops = &npt_mmu_notifier_ops;
	return mmu_notifier_register(&instp->mmu_notifier, current->mm);
}

int instance_alloc_nptp(struct instance *instp)
{
	void *page;

	page = (void *) get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	instp->ept_root = __sme_pa(page);
	instp->eptp = construct_nptp(instp->ept_root);

	return 0;
}

int instance_init_npt(struct instance *instp)
{
	return npt_register_mmu_notifier(instp);
}

void instance_destroy_npt(struct instance *instp)
{
	unsigned long vmpt_root;

	if (instp->mmu_notifier.ops)
		mmu_notifier_unregister(&instp->mmu_notifier, instp->mm);

	spin_lock(&instp->ept_lock);
	vmpt_root = instp->ept_root;
	/* notify npt_clear_page_*() to exit */
	instp->ept_root = 0;
	spin_unlock(&instp->ept_lock);

	/*
	 * wait until all mmu notifiers exit, otherwise they might use
	 * freed instance pointer(Use-After-Free).
	 */
	while(atomic_read(&instp->npt_mmu_users) != 0) {
		schedule();
	}

	if (vmpt_root)
		svm_free_npt(__sme_clr(vmpt_root));
}
