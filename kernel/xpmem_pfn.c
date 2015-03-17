/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright 2009, 2014 Cray Inc. All Rights Reserved
 */

/*
 * Cross Partition Memory (XPMEM) PFN support.
 */

#include <linux/efi.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <xpmem.h>
#include "xpmem_private.h"

/* #of pages rounded up that vaddr and size occupy */
#undef num_of_pages
#define num_of_pages(v, s) \
		(((offset_in_page(v) + (s)) + (PAGE_SIZE - 1)) >> PAGE_SHIFT)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define PDE_DATA(inode)	((PDE(inode)->data))
#endif

/*
 * Fault in and pin a single page for the specified task and mm.
 */
static int
xpmem_pin_page(struct xpmem_thread_group *tg, struct task_struct *src_task,
		struct mm_struct *src_mm, u64 vaddr)
{
	int ret;
	struct page *page;
	struct vm_area_struct *vma;
	cpumask_t saved_mask = CPU_MASK_NONE;

	vma = find_vma(src_mm, vaddr);
	if (!vma || vma->vm_start > vaddr)
		return -ENOENT;

	/* don't pin pages in address ranges attached from other thread groups */
	if (xpmem_is_vm_ops_set(vma))
		return -ENOENT;

	/*
	 * get_user_pages() may have to allocate pages on behalf of
	 * the source thread group. If so, we want to ensure that pages
	 * are allocated near the source thread group and not the current
	 * thread calling get_user_pages(). Since this does not happen when
	 * the policy is node-local (the most common default policy),
	 * we might have to temporarily switch cpus to get the page
	 * placed where we want it.
	 */
	if (xpmem_vaddr_to_pte_offset(src_mm, vaddr, NULL) == NULL &&
	    cpu_to_node(task_cpu(current)) != cpu_to_node(task_cpu(src_task))) {
		saved_mask = current->cpus_allowed;
		set_cpus_allowed(current, cpumask_of_cpu(task_cpu(src_task)));
	}

	/* get_user_pages() faults and pins the page */
	ret = get_user_pages(src_task, src_mm, vaddr, 1, 1, 1, &page, NULL);

	if (!cpus_empty(saved_mask))
		set_cpus_allowed(current, saved_mask);

	if (ret == 1) {
		atomic_inc(&tg->n_pinned);
		atomic_inc(&xpmem_my_part->n_pinned);
		ret = 0;
	}

	return ret;
}

/*
 * Unpin all pages in the given range for the specified mm.
 */
void
xpmem_unpin_pages(struct xpmem_segment *seg, struct mm_struct *mm,
			u64 vaddr, size_t size)
{
	int n_pgs = num_of_pages(vaddr, size);
	int n_pgs_unpinned = 0;
	struct page *page;
	u64 pfn, vsize = 0;
	pte_t *pte = NULL;

	XPMEM_DEBUG("vaddr=%llx, size=%lx, n_pgs=%d", vaddr, size, n_pgs);

	/* Round down to the nearest page aligned address */
	vaddr &= PAGE_MASK;

	while (n_pgs > 0) {
		pte = xpmem_vaddr_to_pte_size(mm, vaddr, &vsize);

		if (pte) {
			DBUG_ON(!pte_present(*pte));
			pfn = pte_pfn(*pte);
			XPMEM_DEBUG("pfn=%llx, vaddr=%llx, n_pgs=%d",
					pfn, vaddr, n_pgs);
			page = virt_to_page(__va(pfn << PAGE_SHIFT));
			page_cache_release(page);
			n_pgs_unpinned++;
			vaddr += PAGE_SIZE;
			n_pgs--;
		} else {
			/*
			 * vsize holds the memory size we know isn't mapped,
			 * based on which level of the page tables had an
			 * invalid entry. We round up to the nearest address
			 * that could have valid pages and find how many pages
			 * we skipped.
			 */
			vsize = ((vaddr + vsize) & (~(vsize - 1)));
			n_pgs -= (vsize - vaddr)/PAGE_SIZE;
			vaddr = vsize;
		}
	}

	atomic_sub(n_pgs_unpinned, &seg->tg->n_pinned);
	atomic_add(n_pgs_unpinned, &xpmem_my_part->n_unpinned);
}

/*
 * Given a virtual address and XPMEM segment, grab any locks necessary and
 * pin the page.
 */
int
xpmem_ensure_valid_PFN(struct xpmem_segment *seg, u64 vaddr,
			int mmap_sem_prelocked)
{
	int ret = -1, mmap_sem_locked = 0;
	struct xpmem_thread_group *seg_tg = seg->tg;

	/*
	 * If we're faulting a page in our own address space, we don't have to
	 * grab the mmap_sem since we already have it via do_page_fault(). If
	 * we're faulting a page from another address space, there is a
	 * potential for a deadlock on the mmap_sem. If the fault handler
	 * detects this potential, it acquires the two mmap_sems in numeric
	 * order (address-wise).
	 */
	if (seg_tg->mm != current->mm) {
		if (!mmap_sem_prelocked) {
			down_read(&seg_tg->mm->mmap_sem);
			mmap_sem_locked = 1;
		}
	}

	/* the seg may have been marked for destruction while we were down() */
	if (seg->flags & XPMEM_FLAG_DESTROYING) {
		if (mmap_sem_locked)
			up_read(&seg_tg->mm->mmap_sem);
		return -ENOENT;
	}

	/* pin PFN */
	ret = xpmem_pin_page(seg->tg, seg_tg->group_leader,
	                     seg_tg->mm, vaddr);

	if (mmap_sem_locked)
		up_read(&seg_tg->mm->mmap_sem);

	return ret;
}

/*
 * Recall all PFNs belonging to the specified segment that have been
 * accessed by other thread groups.
 */
static void
xpmem_recall_PFNs(struct xpmem_segment *seg)
{
	DBUG_ON(atomic_read(&seg->refcnt) <= 0);
	DBUG_ON(atomic_read(&seg->tg->refcnt) <= 0);

	spin_lock(&seg->lock);
	if (seg->flags & (XPMEM_FLAG_DESTROYING | XPMEM_FLAG_RECALLINGPFNS)) {
		spin_unlock(&seg->lock);

		xpmem_wait_for_seg_destroyed(seg);
		return;
	}
	seg->flags |= XPMEM_FLAG_RECALLINGPFNS;
	spin_unlock(&seg->lock);

	xpmem_seg_down_write(seg);

	/* unpin pages and clear PTEs for each attachment to this segment */
	xpmem_clear_PTEs(seg);

	spin_lock(&seg->lock);
	seg->flags &= ~XPMEM_FLAG_RECALLINGPFNS;
	spin_unlock(&seg->lock);

	xpmem_seg_up_write(seg);
}

/*
 * Recall all PFNs belonging to the specified thread group's XPMEM segments
 * that have been accessed by other thread groups.
 */
static void
xpmem_recall_PFNs_of_tg(struct xpmem_thread_group *seg_tg)
{
	struct xpmem_segment *seg;

	read_lock(&seg_tg->seg_list_lock);
	list_for_each_entry(seg, &seg_tg->seg_list, seg_list) {
		if (!(seg->flags & XPMEM_FLAG_DESTROYING)) {
			xpmem_seg_ref(seg);
			read_unlock(&seg_tg->seg_list_lock);

			xpmem_recall_PFNs(seg);

			read_lock(&seg_tg->seg_list_lock);
			if (list_empty(&seg->seg_list)) {
				/* seg was deleted from seg_tg->seg_list */
				xpmem_seg_deref(seg);
				seg = list_entry(&seg_tg->seg_list,
						 struct xpmem_segment,
						 seg_list);
			} else
				xpmem_seg_deref(seg);
		}
	}
	read_unlock(&seg_tg->seg_list_lock);
}

int
xpmem_block_recall_PFNs(struct xpmem_thread_group *tg, int wait)
{
	int value, returned_value;

	while (1) {
		if (waitqueue_active(&tg->allow_recall_PFNs_wq))
			goto wait;

		value = atomic_read(&tg->n_recall_PFNs);
		while (1) {
			if (unlikely(value > 0))
				break;

			returned_value = atomic_cmpxchg(&tg->n_recall_PFNs,
							value, value - 1);
			if (likely(returned_value == value))
				break;

			value = returned_value;
		}

		if (value <= 0)
			return 0;
wait:
		if (!wait)
			return -EAGAIN;

		wait_event(tg->block_recall_PFNs_wq,
			   (atomic_read(&tg->n_recall_PFNs) <= 0));
	}
}

void
xpmem_unblock_recall_PFNs(struct xpmem_thread_group *tg)
{
	if (atomic_inc_return(&tg->n_recall_PFNs) == 0)
			wake_up(&tg->allow_recall_PFNs_wq);
}

static void
xpmem_disallow_blocking_recall_PFNs(struct xpmem_thread_group *tg)
{
	int value, returned_value;

	while (1) {
		value = atomic_read(&tg->n_recall_PFNs);
		while (1) {
			if (unlikely(value < 0))
				break;
			returned_value = atomic_cmpxchg(&tg->n_recall_PFNs,
							value, value + 1);
			if (likely(returned_value == value))
				break;
			value = returned_value;
		}

		if (value >= 0)
			return;

		wait_event(tg->allow_recall_PFNs_wq,
			  (atomic_read(&tg->n_recall_PFNs) >= 0));
	}
}

static void
xpmem_allow_blocking_recall_PFNs(struct xpmem_thread_group *tg)
{
	if (atomic_dec_return(&tg->n_recall_PFNs) == 0)
		wake_up(&tg->block_recall_PFNs_wq);
}

int
xpmem_fork_begin(void)
{
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(current->tgid);
	if (IS_ERR(tg))
		return PTR_ERR(tg);

	xpmem_disallow_blocking_recall_PFNs(tg);

	mutex_lock(&tg->recall_PFNs_mutex);
	xpmem_recall_PFNs_of_tg(tg);
	mutex_unlock(&tg->recall_PFNs_mutex);

	xpmem_tg_deref(tg);
	return 0;
}

int
xpmem_fork_end(void)
{
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(current->tgid);
	if (IS_ERR(tg))
		return PTR_ERR(tg);

	xpmem_allow_blocking_recall_PFNs(tg);

	xpmem_tg_deref(tg);
	return 0;
}

spinlock_t xpmem_unpin_procfs_lock;
struct proc_dir_entry *xpmem_unpin_procfs_dir;

static int
xpmem_is_thread_group_stopped(struct xpmem_thread_group *tg)
{
	struct task_struct *task = tg->group_leader;

	rcu_read_lock();
	do {
		if (!(task->flags & PF_EXITING) &&
		    task->state != TASK_STOPPED) {
			rcu_read_unlock();
			return 0;
		}
		task = next_thread(task);
	} while (task != tg->group_leader);
	rcu_read_unlock();
	return 1;
}

static ssize_t
xpmem_unpin_procfs_write(struct file *file, const char *buffer,
			 size_t count, loff_t *ppos)
{
	struct seq_file *seq = (struct seq_file *)file->private_data;
	pid_t tgid = (unsigned long)seq->private;
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(tgid);
	if (IS_ERR(tg))
		return -ESRCH;

	if (!xpmem_is_thread_group_stopped(tg)) {
		xpmem_tg_deref(tg);
		return -EPERM;
	}

	xpmem_disallow_blocking_recall_PFNs(tg);

	mutex_lock(&tg->recall_PFNs_mutex);
	xpmem_recall_PFNs_of_tg(tg);
	mutex_unlock(&tg->recall_PFNs_mutex);

	xpmem_allow_blocking_recall_PFNs(tg);

	xpmem_tg_deref(tg);
	return count;
}

static int
xpmem_unpin_procfs_show(struct seq_file *seq, void *offset)
{
	pid_t tgid = (unsigned long)seq->private;
	struct xpmem_thread_group *tg;

	if (tgid == 0) {
		seq_printf(seq, "all pages pinned by XPMEM: %d\n"
				"all pages unpinned by XPMEM: %d\n",
				 atomic_read(&xpmem_my_part->n_pinned),
				 atomic_read(&xpmem_my_part->n_unpinned));
	} else {
		tg = xpmem_tg_ref_by_tgid(tgid);
		if (!IS_ERR(tg)) {
			seq_printf(seq, "pages pinned by XPMEM: %d\n",
				   atomic_read(&tg->n_pinned));
			xpmem_tg_deref(tg);
		}
	}

	return 0;
}

static int
xpmem_unpin_procfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, xpmem_unpin_procfs_show, PDE_DATA(inode));
}

struct file_operations xpmem_unpin_procfs_ops = {
	.owner		= THIS_MODULE,
	.llseek		= seq_lseek,
	.read		= seq_read,
	.write		= xpmem_unpin_procfs_write,
	.open		= xpmem_unpin_procfs_open,
	.release	= single_release,
};
