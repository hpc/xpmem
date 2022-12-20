/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright 2010,2012 Cray Inc. All Rights Reserved
 * Copyright (c) 2014-2017 Los Alamos National Security, LLC. All rights
 *                         reserved.
 * Copyright (c) 2019      Google, LLC. All rights reserved.
 * Copyright (c) 2019      Nathan Hjelm. All rights reserved.
 * Copyright (c) 2017-2020 ARM, Inc. All Rights Reserved
 */

/*
 * Cross Partition Memory (XPMEM) attach support.
 */

#include <linux/err.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/file.h>
#include "xpmem_internal.h"
#include "xpmem_private.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

static void
xpmem_open_handler(struct vm_area_struct *vma)
{
	struct xpmem_attachment *att;

	att = (struct xpmem_attachment *)vma->vm_private_data;

	/*
	 * If the new vma is a copy of a vma that has an XPMEM attachment we don't
	 * want the new vma to be associated with the same attachment. This
	 * shouldn't happen in any normal use of XPMEM, but it can happen if the
	 * user calls mremap().
	 */

	if (att && att->at_vma != vma)
		vma->vm_private_data = NULL;
}

/*
 * This function is called whenever a XPMEM address segment is unmapped.
 * We only expect this to occur from a XPMEM detach operation, and if that
 * is the case, there is nothing to do since the detach code takes care of
 * everything. In all other cases, something is tinkering with XPMEM vmas
 * outside of the XPMEM API, so we do the necessary cleanup and kill the
 * current thread group. The vma argument is the portion of the address space
 * that is being unmapped.
 */
static void
xpmem_close_handler(struct vm_area_struct *vma)
{
	struct vm_area_struct *remaining_vma;
	u64 remaining_vaddr;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;

	att = (struct xpmem_attachment *)vma->vm_private_data;
	if (att == NULL) {
		/* can happen if a user tries to mmap /dev/xpmem directly */
		return;
	}

	XPMEM_DEBUG("cleaning up vma with range: 0x%lx - 0x%lx", vma->vm_start, vma->vm_end);

	xpmem_att_ref(att);
	mutex_lock(&att->mutex);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		/* the unmap is being done normally via a detach operation */
		mutex_unlock(&att->mutex);
		xpmem_att_deref(att);
		XPMEM_DEBUG("already cleaned up");
		return;
	}

	/*
	 * See if the entire vma is being unmapped. If so, clean up the
	 * the xpmem_attachment structure and leave the vma to be cleaned up
	 * by the kernel exit path.
	 */
	if (vma->vm_start == att->at_vaddr &&
	    ((vma->vm_end - vma->vm_start) == att->at_size)) {
		att->flags |= XPMEM_FLAG_DESTROYING;

		ap = att->ap;
		xpmem_ap_ref(ap);

		spin_lock(&ap->lock);
		list_del_init(&att->att_list);
		spin_unlock(&ap->lock);

		xpmem_ap_deref(ap);

		xpmem_att_destroyable(att);
		goto out;
	}

	/*
	 * Find the starting vaddr of the vma that will remain after the unmap
	 * has finished. The following if-statement tells whether the kernel
	 * is unmapping the head, tail, or middle of a vma respectively.
	 */
	if (vma->vm_start == att->at_vaddr)
		remaining_vaddr = vma->vm_end;
	else if (vma->vm_end == att->at_vaddr + att->at_size)
		remaining_vaddr = att->at_vaddr;
	else {
		/*
		 * If the unmap occurred in the middle of vma, we have two
		 * remaining vmas to fix up. We first clear out the tail vma
		 * so it gets cleaned up at exit without any ties remaining
		 * to XPMEM.
		 */
		remaining_vaddr = vma->vm_end;
		remaining_vma = find_vma(current->mm, remaining_vaddr);
		BUG_ON(!remaining_vma ||
		       remaining_vma->vm_start > remaining_vaddr ||
		       remaining_vma->vm_private_data != vma->vm_private_data);

		/* this should be safe (we have the mmap_sem/mmap_lock write-locked) */
		remaining_vma->vm_private_data = NULL;
		remaining_vma->vm_ops = NULL;

		/* now set the starting vaddr to point to the head vma */
		remaining_vaddr = att->at_vaddr;
	}

	/*
	 * Find the remaining vma left over by the unmap split and fix
	 * up the corresponding xpmem_attachment structure.
	 */
	remaining_vma = find_vma(current->mm, remaining_vaddr);
	BUG_ON(!remaining_vma ||
	       remaining_vma->vm_start > remaining_vaddr ||
	       remaining_vma->vm_private_data != vma->vm_private_data);

	att->at_vaddr = remaining_vma->vm_start;
	att->at_size = remaining_vma->vm_end - remaining_vma->vm_start;

	/* clear out the private data for the vma being unmapped */
	vma->vm_private_data = NULL;

out:
	mutex_unlock(&att->mutex);
	xpmem_att_deref(att);

	/* cause the demise of the current thread group */
	XPMEM_DEBUG("xpmem_close_handler: unexpected unmap of XPMEM segment at "
	       "[0x%lx - 0x%lx]\n", vma->vm_start, vma->vm_end);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	force_sig(SIGKILL);
#else
	force_sig(SIGKILL, current);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
static vm_fault_t
xpmem_fault_handler(struct vm_fault *vmf)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
int
xpmem_fault_handler(struct vm_fault *vmf)
#else
static int
xpmem_fault_handler(struct vm_area_struct *vma, struct vm_fault *vmf)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	vm_fault_t ret;
#else
	int ret;
#endif
	int att_locked = 0;
	int seg_tg_mmap_sem_locked = 0, vma_verification_needed = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	u64 vaddr = (u64)(uintptr_t) vmf->address;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        struct vm_area_struct *vma = vmf->vma;
#endif
#else
        u64 vaddr = (u64)(uintptr_t) vmf->virtual_address;
#endif
	u64 seg_vaddr;
	unsigned long pfn = 0, old_pfn = 0;
	struct xpmem_thread_group *ap_tg, *seg_tg;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	struct xpmem_segment *seg;

	if (current->flags & PF_DUMPCORE)
		return VM_FAULT_SIGBUS;

	att = (struct xpmem_attachment *)vma->vm_private_data;
	if (att == NULL) {
		/*
		 * Users who effectively bypass xpmem_attach() by opening
		 * and mapping /dev/xpmem will have a NULL finfo and will
		 * be killed here.
		 */
		return VM_FAULT_SIGBUS;
	}
	xpmem_att_ref(att);
	ap = att->ap;
	xpmem_ap_ref(ap);
	ap_tg = ap->tg;
	xpmem_tg_ref(ap_tg);
	if ((ap->flags & XPMEM_FLAG_DESTROYING) ||
	    (ap_tg->flags & XPMEM_FLAG_DESTROYING)) {
		xpmem_att_deref(att);
		xpmem_ap_deref(ap);
		xpmem_tg_deref(ap_tg);
		return VM_FAULT_SIGBUS;
	}
	DBUG_ON(current->tgid != ap_tg->tgid);
	DBUG_ON(ap->mode != XPMEM_RDWR);

	seg = ap->seg;
	xpmem_seg_ref(seg);
	seg_tg = seg->tg;
	xpmem_tg_ref(seg_tg);

	/*
	 * The faulting thread has its mmap_sem/mmap_lock locked on entrance to this
	 * fault handler. In order to supply the missing page we will need
	 * to get access to the segment that has it, as well as lock the
	 * mmap_sem/mmap_lock of the thread group that owns the segment should it be
	 * different from the faulting thread's. Together these provide the
	 * potential for a deadlock, which we attempt to avoid in what follows.
	 */

	ret = xpmem_seg_down_read(seg_tg, seg, 1, 0);
	if (ret == -EAGAIN) {
		/* to avoid possible deadlock drop current->mm->mmap_sem/mmap_lock */
		xpmem_mmap_read_unlock(current->mm);
		ret = xpmem_seg_down_read(seg_tg, seg, 1, 1);
		xpmem_mmap_read_lock(current->mm);
		vma_verification_needed = 1;
	}
	if (ret != 0)
		goto out_1;

	if (seg_tg->mm != current->mm) {
		/*
		 * Lock the seg's thread group's mmap_sem/mmap_lock in a deadlock
		 * safe manner. Get the locks in a consistent order by
		 * getting the smaller address first.
		 */
		if (current->mm < seg_tg->mm) {
			xpmem_mmap_read_lock(seg_tg->mm);
		} else if (!xpmem_mmap_read_trylock(seg_tg->mm)) {
			xpmem_mmap_read_unlock(current->mm);
			xpmem_mmap_read_lock(seg_tg->mm);
			xpmem_mmap_read_lock(current->mm);
			vma_verification_needed = 1;
		}
		seg_tg_mmap_sem_locked = 1;
	}

	/* verify vma hasn't changed due to dropping current->mm->mmap_sem/mmap_lock */
	if (vma_verification_needed) {
		struct vm_area_struct *retry_vma;

		retry_vma = find_vma(current->mm, vaddr);
		if (!retry_vma ||
		    retry_vma->vm_start > vaddr ||
		    !xpmem_is_vm_ops_set(retry_vma) ||
		    retry_vma->vm_private_data != att)
			goto out_2;
	}

	if (mutex_lock_killable(&att->mutex))
		goto out_2;
        att_locked = 1;

	if ((att->flags & XPMEM_FLAG_DESTROYING) ||
	    (ap_tg->flags & XPMEM_FLAG_DESTROYING) ||
	    (seg_tg->flags & XPMEM_FLAG_DESTROYING))
		goto out_2;

	if (vaddr < att->at_vaddr || vaddr + 1 > att->at_vaddr + att->at_size)
		goto out_2;

	/* translate the fault virtual address to the source virtual address */
	seg_vaddr = (att->vaddr & PAGE_MASK) + (vaddr - att->at_vaddr);
	XPMEM_DEBUG("vaddr = %llx, seg_vaddr = %llx", vaddr, seg_vaddr);

        ret = xpmem_ensure_valid_PFN(seg, seg_vaddr, &pfn);
        if (ret != 0)
		goto out_2;

	att->flags |= XPMEM_FLAG_VALIDPTEs;

out_2:
	xpmem_seg_up_read(seg_tg, seg, 1);
out_1:
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);

	ret = VM_FAULT_SIGBUS;

	/*
	 * remap_pfn_range() does not allow racing threads to each insert
	 * the PFN for a given virtual address.  To account for this, we
	 * call remap_pfn_range() with the att->mutex locked and don't
	 * perform the redundant remap_pfn_range() when a PFN already exists.
	 */
        if (pfn && pfn_valid(pfn)) {
		old_pfn = xpmem_vaddr_to_PFN(current->mm, vaddr);
		if (old_pfn) {
			if (old_pfn == pfn) {
				ret = VM_FAULT_NOPAGE;
			} else {
				/* should not be possible, but just in case */
				printk("xpmem_fault_handler: pfn mismatch: "
				       "%ld != %ld\n", old_pfn, pfn);
			}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
			put_page(pfn_to_page(pfn));
#else
			page_cache_release(pfn_to_page(pfn));
#endif
			atomic_dec(&seg->tg->n_pinned);
			atomic_inc(&xpmem_my_part->n_unpinned);
			goto out;
		}

		XPMEM_DEBUG("calling remap_pfn_range() vaddr=%llx, pfn=%lx",
				vaddr, pfn);
		if ((remap_pfn_range(vma, vaddr, pfn, PAGE_SIZE,
				     vma->vm_page_prot)) == 0) {
			ret = VM_FAULT_NOPAGE;
		}
	}
out:
	if (seg_tg_mmap_sem_locked)
		xpmem_mmap_read_unlock(seg_tg->mm);

	if (att_locked)
		mutex_unlock(&att->mutex);

	/* NTH: Cray had this conditional on att_locked but that seems incorrect.
         * Looks like I was correct. Cray fixed this as well. */
        xpmem_tg_deref(seg_tg);
        xpmem_seg_deref(seg);
	xpmem_att_deref(att);

	if (ret == VM_FAULT_SIGBUS) {
		XPMEM_DEBUG("fault returning SIGBUS vaddr=%llx, pfn=%lx", vaddr, pfn);
	}

	return ret;
}

struct vm_operations_struct xpmem_vm_ops = {
	.open = xpmem_open_handler,
	.close = xpmem_close_handler,
	.fault = xpmem_fault_handler
};

/*
 * This function is called via the Linux kernel mmap() code, which is
 * instigated by the call to do_mmap() in xpmem_attach().
 */
int
xpmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	/*
	 * When a mapping is related to a file, the file pointer is typically
	 * stored in vma->vm_file and a fput() is done to it when the VMA is
	 * unmapped. Since file is of no interest in XPMEM's case, we ensure
	 * vm_file is empty and do the fput() here.
	 */
	vma->vm_file = NULL;
	fput(file);

	vma->vm_ops = &xpmem_vm_ops;
	return 0;
}

/*
 * Attach a XPMEM address segment.
 */
int
xpmem_attach(struct file *file, xpmem_apid_t apid, off_t offset, size_t size,
	     u64 vaddr, int fd, int att_flags, u64 *at_vaddr_p)
{
	int ret;
	unsigned long flags, prot_flags = PROT_READ | PROT_WRITE;
	u64 seg_vaddr, at_vaddr;
	struct xpmem_thread_group *ap_tg, *seg_tg;
	struct xpmem_access_permit *ap;
	struct xpmem_segment *seg;
	struct xpmem_attachment *att;
	struct vm_area_struct *vma;

	if (apid <= 0)
		return -EINVAL;

	/* Ensure vaddr is valid */
	if (vaddr && vaddr + PAGE_SIZE - offset_in_page(vaddr) >= TASK_SIZE)
		return -EINVAL;

	/* The start of the attachment must be page aligned */
	if (offset_in_page(vaddr) != 0 || offset_in_page(offset) != 0)
		return -EINVAL;

	/* If the size is not page aligned, fix it */
	if (offset_in_page(size) != 0) 
		size += PAGE_SIZE - offset_in_page(size);

	ap_tg = xpmem_tg_ref_by_apid(apid);
	if (IS_ERR(ap_tg))
		return PTR_ERR(ap_tg);

	ap = xpmem_ap_ref_by_apid(ap_tg, apid);
	if (IS_ERR(ap)) {
		xpmem_tg_deref(ap_tg);
		return PTR_ERR(ap);
	}

	seg = ap->seg;
	xpmem_seg_ref(seg);
	seg_tg = seg->tg;
	xpmem_tg_ref(seg_tg);

	ret = xpmem_seg_down_read(seg_tg, seg, 0, 1);
	if (ret != 0)
		goto out_1;

	ret = xpmem_validate_access(ap, offset, size, XPMEM_RDWR, &seg_vaddr);
	if (ret != 0)
		goto out_2;

	/* size needs to reflect page offset to start of segment */
	size += offset_in_page(seg_vaddr);

	/*
	 * Ensure thread is not attempting to attach its own memory on top
	 * of itself (i.e. ensure the destination vaddr range doesn't overlap
	 * the source vaddr range).
	 */
	seg = ap->seg;
	if (current->tgid == seg_tg->tgid && vaddr) {
		if ((vaddr + size > seg_vaddr) && (vaddr < seg_vaddr + size)) {
			ret = -EINVAL;
			goto out_2;
		}
	}

	/* create new attach structure */
	att = kzalloc(sizeof(struct xpmem_attachment), GFP_KERNEL);
	if (att == NULL) {
		ret = -ENOMEM;
		goto out_2;
	}

	mutex_init(&att->mutex);
	att->vaddr = seg_vaddr;
	att->at_size = size;
	att->ap = ap;
	INIT_LIST_HEAD(&att->att_list);
	att->mm = current->mm;
	mutex_init(&att->invalidate_mutex);

	xpmem_att_not_destroyable(att);
	xpmem_att_ref(att);

	/* must lock mmap_sem/mmap_lock before att's sema to prevent deadlock */
	mutex_lock(&att->mutex);	/* this will never block */

	/* link attach structure to its access permit's att list */
	spin_lock(&ap->lock);
	list_add_tail(&att->att_list, &ap->att_list);
	if (ap->flags & XPMEM_FLAG_DESTROYING) {
		spin_unlock(&ap->lock);
		ret = -ENOENT;
		goto out_3;
	}
	spin_unlock(&ap->lock);

	flags = MAP_SHARED;
	if (vaddr != 0)
		flags |= MAP_FIXED;

	/* check if a segment is already attached in the requested area */
	if (flags & MAP_FIXED) {
		struct vm_area_struct *existing_vma;
		struct vma_iterator vmi;

		xpmem_mmap_read_lock(current->mm);
		vma_iter_init(&vmi, current->mm, vaddr);
		for_each_vma_range(vmi, existing_vma, vaddr + size) {
			if (xpmem_is_vm_ops_set(existing_vma)) {
				xpmem_mmap_read_unlock(current->mm);
				ret = -EINVAL;
				goto out_3;
			}
		}
		xpmem_mmap_read_unlock(current->mm);
	}

	at_vaddr = vm_mmap(file, vaddr, size, prot_flags, flags, offset);
	if (IS_ERR((void *)(uintptr_t) at_vaddr)) {
		ret = at_vaddr;
		goto out_3;
	}
	att->at_vaddr = at_vaddr;

	xpmem_mmap_write_lock(current->mm);
	vma = find_vma(current->mm, at_vaddr);
	xpmem_mmap_write_unlock(current->mm);

	vma->vm_private_data = att;
	vma->vm_flags |=
	    VM_DONTCOPY | VM_DONTDUMP | VM_IO | VM_DONTEXPAND | VM_PFNMAP;
	vma->vm_ops = &xpmem_vm_ops;

	att->at_vma = vma;

	/*
	 * The attach point where we mapped the portion of the segment the
	 * user was interested in is page aligned. But the start of the portion
	 * of the segment may not be, so we adjust the address returned to the
	 * user by that page offset difference so that what they see is what
	 * they expected to see.
	 */
	*at_vaddr_p = at_vaddr + offset_in_page(att->vaddr);

	ret = 0;
out_3:
	if (ret != 0) {
		att->flags |= XPMEM_FLAG_DESTROYING;
		spin_lock(&ap->lock);
		list_del_init(&att->att_list);
		spin_unlock(&ap->lock);
		xpmem_att_destroyable(att);
	}
	mutex_unlock(&att->mutex);
	xpmem_att_deref(att);
out_2:
	xpmem_seg_up_read(seg_tg, seg, 0);
out_1:
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);
	xpmem_seg_deref(seg);
	xpmem_tg_deref(seg_tg);

	return ret;
}

/*
 * Detach an attached XPMEM address segment.
 */
int
xpmem_detach(u64 at_vaddr)
{
	int ret;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	struct vm_area_struct *vma;

	xpmem_mmap_write_lock(current->mm);

	/* find the corresponding vma */
	vma = find_vma(current->mm, at_vaddr);
	if (!vma || vma->vm_start > at_vaddr) {
		xpmem_mmap_write_unlock(current->mm);
		return 0;
	}

	att = (struct xpmem_attachment *)vma->vm_private_data;
	if (!xpmem_is_vm_ops_set(vma) || att == NULL) {
		xpmem_mmap_write_unlock(current->mm);
		return -EINVAL;
	}
	xpmem_att_ref(att);

	if (mutex_lock_killable(&att->mutex)) {
		xpmem_att_deref(att);
		xpmem_mmap_write_unlock(current->mm);
		return -EINTR;
	}

	/* ensure we aren't racing with MMU notifier PTE cleanup */
	mutex_lock(&att->invalidate_mutex);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		mutex_unlock(&att->invalidate_mutex);
		mutex_unlock(&att->mutex);
		xpmem_att_deref(att);
		xpmem_mmap_write_unlock(current->mm);
		return 0;
	}
	att->flags |= XPMEM_FLAG_DESTROYING;

	mutex_unlock(&att->invalidate_mutex);

	ap = att->ap;
	xpmem_ap_ref(ap);

	if (current->tgid != ap->tg->tgid) {
		att->flags &= ~XPMEM_FLAG_DESTROYING;
		xpmem_ap_deref(ap);
		mutex_unlock(&att->mutex);
		xpmem_att_deref(att);
		xpmem_mmap_write_unlock(current->mm);
		return -EACCES;
	}

	xpmem_unpin_pages(ap->seg, current->mm, att->at_vaddr, att->at_size);

	vma->vm_private_data = NULL;

	att->flags &= ~XPMEM_FLAG_VALIDPTEs;

	spin_lock(&ap->lock);
	list_del_init(&att->att_list);
	spin_unlock(&ap->lock);

	mutex_unlock(&att->mutex);


	/* NTH: drop the current mm semaphore before calling vm_munmap (which will
	 * call down_write on the same semaphore) */
	xpmem_mmap_write_unlock(current->mm);
	ret = vm_munmap(vma->vm_start, att->at_size);
	DBUG_ON(ret != 0);

	xpmem_att_destroyable(att);

	xpmem_ap_deref(ap);
	xpmem_att_deref(att);

	return 0;
}

/*
 * Detach an attached XPMEM address segment. This is functionally identical
 * to xpmem_detach(). It is called when ap and att are known.
 *
 * NTH: This function is called either when xpmem_release or when the process
 * closes the xpmem file. In one case the att->mm is the same as current->mm
 * and in the other current->mm is NULL. It should be safe to use vm_munmap
 * instead of the unexported do_munmap if we set current->mm to att->mm when
 * current->mm is NULL.
 */
void
xpmem_detach_att(struct xpmem_access_permit *ap, struct xpmem_attachment *att)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	int ret;


	XPMEM_DEBUG("detaching attr %p. current->mm = %p, att->mm = %p", att,
		    (void *) current->mm, (void *) att->mm);

	mm = current->mm ? current->mm : att->mm;

	/* must lock mmap_sem before att's sema to prevent deadlock */
	xpmem_mmap_write_lock(mm);
	mutex_lock(&att->mutex);

	/* ensure we aren't racing with MMU notifier PTE cleanup */
	mutex_lock(&att->invalidate_mutex);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		mutex_unlock(&att->invalidate_mutex);
		mutex_unlock(&att->mutex);
		xpmem_mmap_write_unlock(mm);
		return;
	}
	att->flags |= XPMEM_FLAG_DESTROYING;

	mutex_unlock(&att->invalidate_mutex);

	/* find the corresponding vma */
	vma = find_vma(mm, att->at_vaddr);
	if (!vma || vma->vm_start > att->at_vaddr) {
		DBUG_ON(1);
		mutex_unlock(&att->mutex);
		xpmem_mmap_write_unlock(mm);
		return;
	}
	DBUG_ON(!xpmem_is_vm_ops_set(vma));
	DBUG_ON((vma->vm_end - vma->vm_start) != att->at_size);
	DBUG_ON(vma->vm_private_data != att);

	xpmem_unpin_pages(ap->seg, mm, att->at_vaddr, att->at_size);

	vma->vm_private_data = NULL;

	att->flags &= ~XPMEM_FLAG_VALIDPTEs;

	spin_lock(&ap->lock);
	list_del_init(&att->att_list);
	spin_unlock(&ap->lock);

	/* NTH: drop the semaphore and attachment lock before calling vm_munmap */
	mutex_unlock(&att->mutex);
	xpmem_mmap_write_unlock(mm);

	/* NTH: if the current task does not have a memory descriptor
	 * then there is nothing more to do. the memory mapping should
	 * go away automatically when the memory descriptor does. */
	if (NULL != current->mm) {
		ret = vm_munmap(vma->vm_start, att->at_size);
		DBUG_ON(ret != 0);
	}

	xpmem_att_destroyable(att);
}

/*
 * Clear all of the PTEs associated with the specified attachment within the
 * range specified by start and end. The last argument needs to be 0 except
 * when called by the mmu notifier.
 */
static void
xpmem_clear_PTEs_of_att(struct xpmem_attachment *att, u64 start, u64 end,
							int from_mmu)
{
	/*
	 * This function should ideally acquire both att->mm->mmap_sem/mmap_lock
	 * and att->mutex.  However, if it is called from a MMU notifier
	 * function, we can not sleep (something both down_read() and
	 * mutex_lock() can do).  For MMU notifier callouts, we try to
	 * acquire the locks once anyway, but if one or both locks were
	 * not acquired, we are technically OK for this function since other
	 * XPMEM functions assure that the vma structure will not be freed
	 * from underneath us, and the prior call to xpmem_att_ref() before
	 * entering the function unsures that att will be valid.
	 *
	 * Must lock mmap_sem/mmap_lock before att's sema to prevent deadlock.
	 */

	if (from_mmu) {
		mutex_lock(&att->invalidate_mutex);
		if (att->flags & XPMEM_FLAG_DESTROYING) {
			mutex_unlock(&att->invalidate_mutex);
			return;
		}
	} else {
		/* Must lock mmap_sem/mmap_lock before att's sema to prevent deadlock. */
		xpmem_mmap_read_lock(att->mm);
		mutex_lock(&att->mutex);
	}

	/*
	 * The att may have been detached before the down() succeeded.
	 * If not, clear kernel PTEs, flush TLBs, etc.
	 */
	if (att->flags & XPMEM_FLAG_VALIDPTEs) {
		struct vm_area_struct *vma;
		u64 invalidate_start, invalidate_end, invalidate_len;
		u64 offset_start, offset_end, unpin_at;
		u64 att_vaddr_end = att->vaddr + att->at_size;

		/* 
		 * SOURCE   [ PG 0 | PG 1 | PG 2 | PG 3 | PG 4 | ... ]
		 *          ^                    ^
		 *          |                    |
		 *  seg->vaddr                 att->vaddr
		 *
		 *          [ attach_info.offset ]
		 *
		 * ------------------------------------------------------
		 *
		 * ATTACH   [ PG 3 | PG 4 | ... ]
		 *          ^                   ^
		 *          |                   |
		 * att->at_vaddr          att_vaddr_end
		 *
		 * The invalidate range (start, end) arguments are originally
		 * in the source address space.
		 *
		 * Convert the attachment address space to the source address
		 * space and find the intersection with (start, end).
		 */
		invalidate_start = max(start, att->vaddr);
		invalidate_end = min(end, att_vaddr_end);
		if (invalidate_start >= att_vaddr_end || invalidate_end <= att->vaddr)
			goto out;

		/* Convert the intersection of vaddr into offsets. */
		offset_start = invalidate_start - att->vaddr;
		offset_end = invalidate_end - att->vaddr;

		/*
		 * Add the starting offset to the attachment's starting vaddr
		 * to get the invalidate range in the attachment address space.
		 */
		unpin_at = att->at_vaddr + offset_start;
		invalidate_len = offset_end - offset_start;
		DBUG_ON(offset_in_page(unpin_at) ||
				offset_in_page(invalidate_len));
		XPMEM_DEBUG("unpin_at = %llx, invalidate_len = %llx\n",
				unpin_at, invalidate_len);

		/* Unpin the pages */
		xpmem_unpin_pages(att->ap->seg, att->mm, unpin_at,
							invalidate_len);

		/*
		 * Clear the PTEs, using the vma out of the att if we
		 * couldn't acquire the mmap_sem/mmap_lock
		 */
		if (from_mmu)
			vma = att->at_vma;
		else
			vma = find_vma(att->mm, att->at_vaddr);

		/* NTH: is this a viable alternative to zap_page_range(). The
		 * benefit of zap_vma_ptes is that it is exported by default. */
		(void) zap_vma_ptes (vma, unpin_at, invalidate_len);

		/* Only clear the flag if all pages were zapped */
		if (offset_start == 0 && att->at_size == invalidate_len)
			att->flags &= ~XPMEM_FLAG_VALIDPTEs;
	}
out:
	if (from_mmu) {
		mutex_unlock(&att->invalidate_mutex);
	} else {
		mutex_unlock(&att->mutex);
		xpmem_mmap_read_unlock(att->mm);
	}
}

/*
 * Clear all of the PTEs associated with all attachments related to the
 * specified access permit within the range specified by start and end.
 * The last argument needs to be 0 except when called by the mmu notifier.
 */
static void
xpmem_clear_PTEs_of_ap(struct xpmem_access_permit *ap, u64 start, u64 end,
							int from_mmu)
{
	struct xpmem_attachment *att;

	spin_lock(&ap->lock);
	list_for_each_entry(att, &ap->att_list, att_list) {
		if (!(att->flags & XPMEM_FLAG_VALIDPTEs))
			continue;

		xpmem_att_ref(att);  /* don't care if XPMEM_FLAG_DESTROYING */
		spin_unlock(&ap->lock);

		xpmem_clear_PTEs_of_att(att, start, end, from_mmu);

		spin_lock(&ap->lock);
		if (list_empty(&att->att_list)) {
			/* att was deleted from ap->att_list, start over */
			xpmem_att_deref(att);
			att = list_entry(&ap->att_list, struct xpmem_attachment,
					 att_list);
		} else
			xpmem_att_deref(att);
	}
	spin_unlock(&ap->lock);
}

/*
 * Clear all of the PTEs associated with all attaches to the specified segment
 * within the range specified by start and end. The last argument needs to be
 * 0 except when called by the mmu notifier.
 */
void
xpmem_clear_PTEs_range(struct xpmem_segment *seg, u64 start, u64 end,
								int from_mmu)
{
	struct xpmem_access_permit *ap;

	spin_lock(&seg->lock);
	list_for_each_entry(ap, &seg->ap_list, ap_list) {
		xpmem_ap_ref(ap);  /* don't care if XPMEM_FLAG_DESTROYING */
		spin_unlock(&seg->lock);

		xpmem_clear_PTEs_of_ap(ap, start, end, from_mmu);

		spin_lock(&seg->lock);
		if (list_empty(&ap->ap_list)) {
			/* ap was deleted from seg->ap_list, start over */
			xpmem_ap_deref(ap);
			ap = list_entry(&seg->ap_list,
					 struct xpmem_access_permit, ap_list);
		} else
			xpmem_ap_deref(ap);
	}
	spin_unlock(&seg->lock);
}

/*
 * Wrapper for xpmem_clear_PTEs_range() that uses the max range
 */
void xpmem_clear_PTEs(struct xpmem_segment *seg)
{
	xpmem_clear_PTEs_range(seg, seg->vaddr, seg->vaddr + seg->size, 0);
}
