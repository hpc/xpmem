/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright (c) 2014      Los Alamos National Security, LLC. All rights
 *                         reserved.
 */

/*
 * Cross Partition Memory (XPMEM) PFN support.
 */

#include <linux/efi.h>
#include <linux/pagemap.h>
#include <xpmem.h>
#include "xpmem_private.h"

/* #of pages rounded up that vaddr and size occupy */
#undef num_of_pages
#define num_of_pages(v, s) \
		(((offset_in_page(v) + (s)) + (PAGE_SIZE - 1)) >> PAGE_SHIFT)

/*
 * Fault in and pin all pages in the given range for the specified task and mm.
 */
static int
xpmem_pin_pages(struct xpmem_thread_group *tg, struct task_struct *src_task,
		struct mm_struct *src_mm, u64 vaddr, size_t size, int *pinned)
{
	int ret, malloc = 0, n_pgs = num_of_pages(vaddr, size);
	struct page *pages_array[16], **pages;
	struct vm_area_struct *vma;
	cpumask_t saved_mask = CPU_MASK_NONE;

	*pinned = 0;

	vma = find_vma(src_mm, vaddr);
	if (!vma || vma->vm_start > vaddr)
		return -ENOENT;

	/* don't pin pages in address ranges attached from other thread groups */
	if (xpmem_is_vm_ops_set(vma))
		return -ENOENT;

	if (n_pgs > 16) {
		pages = kzalloc(sizeof(struct page *) * n_pgs, GFP_KERNEL);
		if (pages == NULL)
			return -ENOMEM;

		malloc = 1;
	} else
		pages = pages_array;

	/*
	 * get_user_pages() may have to allocate pages on behalf of
	 * the source thread group. If so, we want to ensure that pages
	 * are allocated near the source thread group and not the current
	 * thread calling get_user_pages(). Since this does not happen when
	 * the policy is node-local (the most common default policy),
	 * we might have to temporarily switch cpus to get the page
	 * placed where we want it.
	 */
	if (xpmem_vaddr_to_pte(src_mm, vaddr) == NULL &&
	    cpu_to_node(task_cpu(current)) != cpu_to_node(task_cpu(src_task))) {
		saved_mask = current->cpus_allowed;
		set_cpus_allowed(current, cpumask_of_cpu(task_cpu(src_task)));
	}

	/* get_user_pages() faults and pins the pages */
	ret = get_user_pages(src_task, src_mm, vaddr, n_pgs, 1, 1, pages, NULL);
	*pinned = 1;

	if (!cpus_empty(saved_mask))
		set_cpus_allowed(current, saved_mask);

	if (malloc)
		kfree(pages);

	DBUG_ON(ret != n_pgs);

	atomic_add(ret, &tg->n_pinned);
	atomic_add(ret, &xpmem_my_part->n_pinned);

	return 0;
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
	u64 pfn;

	XPMEM_DEBUG("vaddr=%llx, size=%lx, n_pgs=%d", vaddr, (unsigned long) size, n_pgs);

	while (n_pgs > 0) {
		pfn = xpmem_vaddr_to_PFN(mm, vaddr);

		/* If the PTE is not present, xpmem_vaddr_to_PFN() returns 0 */
		if (pfn != 0) {
			XPMEM_DEBUG("pfn=%llx, vaddr=%llx, n_pgs=%d",
					pfn, vaddr, n_pgs);
			page = virt_to_page(__va(pfn << PAGE_SHIFT));
			page_cache_release(page);
			n_pgs_unpinned++;
		}

		vaddr += PAGE_SIZE;
		n_pgs--;
	}

	atomic_sub(n_pgs_unpinned, &seg->tg->n_pinned);
	atomic_add(n_pgs_unpinned, &xpmem_my_part->n_unpinned);
}

/*
 * Determine unknown PFNs for a given virtual address range.
 */
static int
xpmem_get_PFNs(struct xpmem_segment *seg, u64 vaddr, size_t size)
{
	struct xpmem_thread_group *seg_tg = seg->tg;
	struct task_struct *src_task = seg_tg->group_leader;
	struct mm_struct *src_mm = seg_tg->mm;
	int ret, pinned;

	/*
	 * We used to look up the source task_struct by tgid, but that
	 * was a performance killer. Instead we stash a pointer to the
	 * thread group leader's task_struct in the xpmem_thread_group structure.
	 * This is safe because we incremented the task_struct's usage count
	 * at the same time we stashed the pointer.
	 */

	/*
	 * Find and pin the pages. xpmem_pin_pages() fails if there are
	 * holes in the vaddr range (which is what we want to happen).
	 */
	ret = xpmem_pin_pages(seg_tg, src_task, src_mm, vaddr, size, &pinned);

	if (ret != 0 && pinned)
		xpmem_unpin_pages(seg, src_mm, vaddr, size);

	return ret;
}

/*
 * Given a virtual address range and XPMEM segment, determine which portions
 * of that range XPMEM needs to fetch PFN information for. As unknown
 * contiguous portions of the virtual address range are determined, other
 * functions are called to do the actual PFN discovery tasks.
 */
int
xpmem_ensure_valid_PFNs(struct xpmem_segment *seg, u64 vaddr, size_t size,
			int mmap_sem_prelocked)
{
	int ret = -1, n_pgs = num_of_pages(vaddr, size), mmap_sem_locked = 0;
	u64 l_vaddr = vaddr + size, t_vaddr = vaddr;
	size_t t_size;
	struct xpmem_thread_group *seg_tg = seg->tg;

	DBUG_ON(n_pgs <= 0);

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
			atomic_inc(&seg_tg->mm->mm_users);
			down_read(&seg_tg->mm->mmap_sem);
			mmap_sem_locked = 1;
		}
	}

	/* the seg may have been marked for destruction while we were down() */
	if (seg->flags & XPMEM_FLAG_DESTROYING) {
		if (mmap_sem_locked) {
			up_read(&seg_tg->mm->mmap_sem);
			atomic_dec(&seg_tg->mm->mm_users);
		}
		return -ENOENT;
	}

	/* pin all PFNs */
	if (n_pgs > 0) {
		t_size = (n_pgs * PAGE_SIZE) - offset_in_page(t_vaddr);
		if (t_vaddr + t_size > l_vaddr)
			t_size = l_vaddr - t_vaddr;

		ret = xpmem_get_PFNs(seg, t_vaddr, t_size);
		if (ret != 0) {
			if (mmap_sem_locked) {
				up_read(&seg_tg->mm->mmap_sem);
				atomic_dec(&seg_tg->mm->mm_users);
			}
			return ret;
		}
	}

	if (mmap_sem_locked) {
		up_read(&seg_tg->mm->mmap_sem);
		atomic_dec(&seg_tg->mm->mm_users);
	}

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

DEFINE_SPINLOCK(xpmem_unpin_procfs_lock);
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

ssize_t
xpmem_unpin_procfs_write(struct file *file, const char *buffer, size_t count,
			 loff_t *pos)
{
	pid_t tgid = (pid_t)(unsigned long) PDE_DATA(file_inode(file));
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

ssize_t
xpmem_unpin_procfs_read(struct file *file, char *buffer, size_t count,
			loff_t *pos)
{
	pid_t tgid = (pid_t)(unsigned long) PDE_DATA(file_inode(file));
	struct xpmem_thread_group *tg;
	int len = 0;

	if (*pos > 0) {
		return 0;
	}

	if (tgid == 0) {
		len = snprintf(buffer, count,
			"all pages pinned by XPMEM: %d\n"
			"all pages unpinned by XPMEM: %d\n",
			atomic_read(&xpmem_my_part->n_pinned),
			atomic_read(&xpmem_my_part->n_unpinned));
	} else {
		tg = xpmem_tg_ref_by_tgid(tgid);
		if (!IS_ERR(tg)) {
			len = snprintf(buffer, count,
				"pages pinned by XPMEM: %d\n",
				atomic_read(&tg->n_pinned));
			xpmem_tg_deref(tg);
		}
	}

	*pos = len;

	return len;
}
