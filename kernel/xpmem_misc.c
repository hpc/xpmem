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
 * Cross Partition Memory (XPMEM) miscellaneous functions.
 */

#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <xpmem.h>
#include "xpmem_private.h"

uint32_t xpmem_debug_on = 0;

/*
 * xpmem_tg_ref() - see xpmem_private.h for inline definition
 */

/*
 * Return a pointer to the xpmem_thread_group structure that corresponds to the
 * specified tgid. Increment the refcnt as well if found.
 */
struct xpmem_thread_group *
xpmem_tg_ref_by_tgid(pid_t tgid)
{
	int index;
	struct xpmem_thread_group *tg;

	index = xpmem_tg_hashtable_index(tgid);
	read_lock(&xpmem_my_part->tg_hashtable[index].lock);

	list_for_each_entry(tg, &xpmem_my_part->tg_hashtable[index].list,
								tg_hashlist) {
		if (tg->tgid == tgid) {
			if (tg->flags & XPMEM_FLAG_DESTROYING)
				continue;  /* could be others with this tgid */

			xpmem_tg_ref(tg);
			read_unlock(&xpmem_my_part->tg_hashtable[index].lock);
			return tg;
		}
	}

	read_unlock(&xpmem_my_part->tg_hashtable[index].lock);
	return ERR_PTR(-ENOENT);
}

/*
 * Return a pointer to the xpmem_thread_group structure that corresponds to the
 * specified segid. Increment the refcnt as well if found.
 */
struct xpmem_thread_group *
xpmem_tg_ref_by_segid(xpmem_segid_t segid)
{
	return xpmem_tg_ref_by_tgid(xpmem_segid_to_tgid(segid));
}

/*
 * Return a pointer to the xpmem_thread_group structure that corresponds to the
 * specified apid. Increment the refcnt as well if found.
 */
struct xpmem_thread_group *
xpmem_tg_ref_by_apid(xpmem_apid_t apid)
{
	return xpmem_tg_ref_by_tgid(xpmem_apid_to_tgid(apid));
}

/*
 * Decrement the refcnt for a xpmem_thread_group structure previously
 * referenced via xpmem_tg_ref(), xpmem_tg_ref_by_tgid(), or
 * xpmem_tg_ref_by_segid().
 */
void
xpmem_tg_deref(struct xpmem_thread_group *tg)
{
	char tgid_string[XPMEM_TGID_STRING_LEN];

	DBUG_ON(atomic_read(&tg->refcnt) <= 0);
	if (atomic_dec_return(&tg->refcnt) != 0)
		return;

	/*
	 * Process has been removed from lookup lists and is no
	 * longer being referenced, so it is safe to remove it.
	 */
	DBUG_ON(!(tg->flags & XPMEM_FLAG_DESTROYING));
	DBUG_ON(!list_empty(&tg->seg_list));

	snprintf(tgid_string, XPMEM_TGID_STRING_LEN, "%d", tg->tgid);
	spin_lock(&xpmem_unpin_procfs_lock);
	remove_proc_entry(tgid_string, xpmem_unpin_procfs_dir);
	spin_unlock(&xpmem_unpin_procfs_lock);

	kfree(tg->ap_hashtable);

	kfree(tg);
}

/*
 * xpmem_seg_ref - see xpmem_private.h for inline definition
 */

/*
 * Return a pointer to the xpmem_segment structure that corresponds to the
 * given segid. Increment the refcnt as well.
 */
struct xpmem_segment *
xpmem_seg_ref_by_segid(struct xpmem_thread_group *seg_tg, xpmem_segid_t segid)
{
	struct xpmem_segment *seg;

	read_lock(&seg_tg->seg_list_lock);

	list_for_each_entry(seg, &seg_tg->seg_list, seg_list) {
		if (seg->segid == segid) {
			if (seg->flags & XPMEM_FLAG_DESTROYING)
				continue; /* could be others with this segid */

			xpmem_seg_ref(seg);
			read_unlock(&seg_tg->seg_list_lock);
			return seg;
		}
	}

	read_unlock(&seg_tg->seg_list_lock);
	return ERR_PTR(-ENOENT);
}

/*
 * Decrement the refcnt for a xpmem_segment structure previously referenced via
 * xpmem_seg_ref() or xpmem_seg_ref_by_segid().
 */
void
xpmem_seg_deref(struct xpmem_segment *seg)
{
	DBUG_ON(atomic_read(&seg->refcnt) <= 0);
	if (atomic_dec_return(&seg->refcnt) != 0)
		return;

	/*
	 * Segment has been removed from lookup lists and is no
	 * longer being referenced so it is safe to free it.
	 */
	DBUG_ON(!(seg->flags & XPMEM_FLAG_DESTROYING));

	kfree(seg);
}

/*
 * xpmem_ap_ref() - see xpmem_private.h for inline definition
 */

/*
 * Return a pointer to the xpmem_access_permit structure that corresponds to
 * the given apid. Increment the refcnt as well.
 */
struct xpmem_access_permit *
xpmem_ap_ref_by_apid(struct xpmem_thread_group *ap_tg, xpmem_apid_t apid)
{
	int index;
	struct xpmem_access_permit *ap;

	index = xpmem_ap_hashtable_index(apid);
	read_lock(&ap_tg->ap_hashtable[index].lock);

	list_for_each_entry(ap, &ap_tg->ap_hashtable[index].list,
			    ap_hashlist) {
		if (ap->apid == apid) {
			if (ap->flags & XPMEM_FLAG_DESTROYING)
				break;	/* can't be others with this apid */

			xpmem_ap_ref(ap);
			read_unlock(&ap_tg->ap_hashtable[index].lock);
			return ap;
		}
	}

	read_unlock(&ap_tg->ap_hashtable[index].lock);
	return ERR_PTR(-ENOENT);
}

/*
 * Decrement the refcnt for a xpmem_access_permit structure previously
 * referenced via xpmem_ap_ref() or xpmem_ap_ref_by_apid().
 */
void
xpmem_ap_deref(struct xpmem_access_permit *ap)
{
	DBUG_ON(atomic_read(&ap->refcnt) <= 0);
	if (atomic_dec_return(&ap->refcnt) == 0) {
		/*
		 * Access has been removed from lookup lists and is no
		 * longer being referenced so it is safe to remove it.
		 */
		DBUG_ON(!(ap->flags & XPMEM_FLAG_DESTROYING));
		kfree(ap);
	}
}

/*
 * xpmem_att_ref() - see xpmem_private.h for inline definition
 */

/*
 * Decrement the refcnt for a xpmem_attachment structure previously referenced
 * via xpmem_att_ref().
 */
void
xpmem_att_deref(struct xpmem_attachment *att)
{
	DBUG_ON(atomic_read(&att->refcnt) <= 0);
	if (atomic_dec_return(&att->refcnt) == 0) {
		/*
		 * Attach has been removed from lookup lists and is no
		 * longer being referenced so it is safe to remove it.
		 */
		DBUG_ON(!(att->flags & XPMEM_FLAG_DESTROYING));
		kfree(att);
	}
}

/*
 * Acquire read access to a xpmem_segment structure.
 */
int
xpmem_seg_down_read(struct xpmem_thread_group *seg_tg,
		    struct xpmem_segment *seg, int block_recall_PFNs, int wait)
{
	int ret;

	if (block_recall_PFNs) {
		ret = xpmem_block_recall_PFNs(seg_tg, wait);
		if (ret != 0)
			return ret;
	}

	if (!down_read_trylock(&seg->sema)) {
		if (!wait) {
			if (block_recall_PFNs)
				xpmem_unblock_recall_PFNs(seg_tg);
			return -EAGAIN;
		}
		down_read(&seg->sema);
	}

	if ((seg->flags & XPMEM_FLAG_DESTROYING) ||
	    (seg_tg->flags & XPMEM_FLAG_DESTROYING)) {
		up_read(&seg->sema);
		if (block_recall_PFNs)
			xpmem_unblock_recall_PFNs(seg_tg);
		return -ENOENT;
	}
	return 0;
}

/*
 * Ensure that a user is correctly accessing a segment for a copy or an attach.
 */
int
xpmem_validate_access(struct xpmem_access_permit *ap, off_t offset,
		      size_t size, int mode, u64 *vaddr)
{
	/* ensure that this thread has permission to access segment */
	if (current->tgid != ap->tg->tgid ||
	    (mode == XPMEM_RDWR && ap->mode == XPMEM_RDONLY))
		return -EACCES;

	if (offset < 0 || size == 0 || offset + size > ap->seg->size)
		return -EINVAL;

	*vaddr = ap->seg->vaddr + offset;
	return 0;
}

/*
 * Only allow through SIGTERM or SIGKILL if they will be fatal to the
 * current thread.
 */
void
xpmem_block_nonfatal_signals(sigset_t *oldset)
{
	unsigned long flags;
	sigset_t new_blocked_signals;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	*oldset = current->blocked;
	sigfillset(&new_blocked_signals);
	sigdelset(&new_blocked_signals, SIGTERM);
	if (current->sighand->action[SIGKILL - 1].sa.sa_handler == SIG_DFL)
		sigdelset(&new_blocked_signals, SIGKILL);

	current->blocked = new_blocked_signals;
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}

/*
 * Return blocked signal mask to default.
 */
void
xpmem_unblock_nonfatal_signals(sigset_t *oldset)
{
	unsigned long flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	current->blocked = *oldset;
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}

/*
 * XPMEM printk debugging via procfs
 */
ssize_t
xpmem_debug_printk_procfs_write(struct file *file, const char *buffer,
				size_t count, loff_t *pos)
{
	char buf;
	
	if(copy_from_user(&buf, buffer, 1))
		return -EFAULT;

	if (buf == '0') 
		xpmem_debug_on = 0;
	else if (buf == '1')
		xpmem_debug_on = 1;

	return count;
}

ssize_t
xpmem_debug_printk_procfs_read(struct file *file, char *buffer,
			       size_t count, loff_t *pos)
{
	int len;
	if (*pos > 0) {
		return 0;
	}
	len = snprintf(buffer, count, "%d\n", xpmem_debug_on);

	*pos = len;

	return len;
}
