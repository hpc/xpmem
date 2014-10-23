/*
 * xpmem_proc2: thread two of various XPMEM tests
 *
 * Copyright (c) 2010 Cray, Inc.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <xpmem.h>
#include <xpmem_test.h>

/**
 * test_base - a simple test to share and attach
 * Description:
 *      Creates a share (initialized to a random value), calls a second process
 *	to attach to the shared address and increment its value.
 * Return Values:
 *	Success: 0
 *	Failure: -2
 */
int test_base(test_args *xpmem_args)
{
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	int i, ret=0, *data;

	segid = strtol(xpmem_args->share, NULL, 16);
	data = attach_segid(segid, &apid);
	if (data == (void *)-1) {
		perror("xpmem_attach");
		return -2;
	}

	printf("xpmem_proc2: mypid = %d\n", getpid());
	printf("xpmem_proc2: segid = %llx\n", segid);
	printf("xpmem_proc2: attached at %p\n", data);

	printf("xpmem_proc2: adding 1 to all elems\n\n");
	for (i = 0; i < SHARE_INT_SIZE; i++) {
		if (*(data + i) != i) {
			printf("xpmem_proc2: ***mismatch at %d: expected %d "
				"got %d\n", i, i, *(data + i));
			ret = -2;
		}
		*(data + i) += 1;
	}

	xpmem_detach(data);
	xpmem_release(apid);

	return ret;
}

/**
 * test_two_attach - same as test_base, but with two consumers
 * Description:
 *	Attach to the same apid twice.
 * Return Values:
 *	Success: 0
 *	Failure: -2
 */
int test_two_attach(test_args *xpmem_args)
{
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	int i, ret=0, *data[2];

	segid = strtol(xpmem_args->share, NULL, 16);
	data[0] = attach_segid(segid, &apid);
	data[1] = attach_segid(segid, &apid);
	if (data[0] == (void *)-1 || data[1] == (void *)-1) {
		perror("xpmem_attach");
		return -2;
	}

	printf("xpmem_proc2: mypid = %d\n", getpid());
	printf("xpmem_proc2: segid = %llx\n", segid);
	printf("xpmem_proc2: attached at %p\n", data[0]);
	printf("xpmem_proc2: attached at %p\n", data[1]);

	printf("xpmem_proc2: adding 1 to all elems using %p\n", data[0]);
	printf("xpmem_proc2: adding 1 to all elems using %p\n\n", data[1]);
	for (i = 0; i < SHARE_INT_SIZE; i++) {
		if (*(data[0] + i) != i) {
			printf("xpmem_proc2: ***mismatch at %d: expected %d "
				"got %d\n", i, i, *(data[0] + i));
			ret = -2;
		}
		*(data[0] + i) += 1;
		*(data[1] + i) += 1;
	}
	
	xpmem_detach(data[0]);
	xpmem_detach(data[1]);

	xpmem_release(apid);

	return ret;
}

/**
 * test_two_shares - same as test_base, but with two sources and two consumers
 * Description:
 *	Two consumers of two different apids.
 * Return Values:
 *	Success: 0
 *	Failure: -2
 */
int test_two_shares(test_args *xpmem_args)
{
	xpmem_segid_t segid[2];
	xpmem_apid_t apid[2];
	int i, ret=0, *data[2];
	char *tmp;
	
	tmp = xpmem_args->share;
	segid[0] = strtol(tmp, NULL, 16);
	tmp += strlen(tmp) + 1;
	segid[1] = strtol(tmp, NULL, 16);
	data[0] = attach_segid(segid[0], &apid[0]);
	data[1] = attach_segid(segid[1], &apid[1]);
	if (data[0] == (void *)-1 || data[1] == (void *)-1) {
		perror("xpmem_attach");
		return -2;
	}

	printf("xpmem_proc2: mypid = %d\n", getpid());
	printf("xpmem_proc2: segid[0] = %llx\n", segid[0]);
	printf("xpmem_proc2: segid[1] = %llx\n", segid[1]);
	printf("xpmem_proc2: data[0] attached at %p\n", data[0]);
	printf("xpmem_proc2: data[1] attached at %p\n", data[1]);

	printf("xpmem_proc2: adding 1 to all elems using %p\n", data[0]);
	printf("xpmem_proc2: adding 1 to all elems using %p\n\n", data[1]);
	for (i = 0; i < SHARE_INT_SIZE; i++) {
		if (*(data[0] + i) != i) {
			printf("xpmem_proc2: ***mismatch at %d: expected %d "
				"got %d\n", i, i, *(data[0] + i));
			ret = -2;
		}
		if (*(data[1] + i) != i) {
			printf("xpmem_proc2: ***mismatch at %d: expected %d "
				"got %d\n", i, i, *(data[1] + i));
			ret = -2;
		}
		*(data[0] + i) += 1;
		*(data[1] + i) += 1;
	}

	xpmem_detach(data[0]);
	xpmem_detach(data[1]);

	xpmem_release(apid[0]);
	xpmem_release(apid[1]);

	return ret;
}

/**
 * test_fork - test if forks are handled properly
 * Description:
 *	Called by xpmem_master, but do nothing. xpmem_proc1 does the fork.
 * Return Values:
 *	Success: 0
 *	Failure: -2
 */
int test_fork(test_args *xpmem_args)
{
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	struct xpmem_addr addr;
	int i, ret=0, *data;

	segid = strtol(xpmem_args->share, NULL, 16);
	apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
	
	addr.apid = apid;
	addr.offset = PAGE_SIZE;
	data = (int *)xpmem_attach(addr, PAGE_SIZE, NULL);
	if (data == (void *)-1) {
		perror("xpmem_attach");
		return -2;
	}
	
	printf("xpmem_proc2: mypid = %d\n", getpid());
	printf("xpmem_proc2: segid = %llx\n", segid);
	printf("xpmem_proc2: attached at %p\n", data);

	printf("xpmem_proc2: reading to pin pages\n");
	for (i = 0; i < PAGE_INT_SIZE; i++) {
		if (*(data + i) != PAGE_INT_SIZE + i) {
			printf("xpmem_proc2: ***mismatch at %d: expected %lu "
				"got %d\n", i, PAGE_INT_SIZE + i, *(data + i));
			ret = -2;
		}
	}
	
	/* Now wait for xpmem_proc1 to invoke COW */
	printf("xpmem_proc2: waiting for COW...\n\n");
	while (xpmem_args->share[COW_LOCK_INDEX] == 0) {
		xpmem_args->share[COW_LOCK_INDEX] = 1;
	}
	sleep(1);

	printf("xpmem_proc2: adding 1 to all elems\n\n");
	for (i = 0; i < PAGE_INT_SIZE; i++)
		*(data + i) += 1;

	xpmem_detach(data);
	xpmem_release(apid);

	return ret;
}

int main(int argc, char **argv)
{
	test_args xpmem_args;
	int test_nr;

	if (argc < 2) {
		printf("Usage: %s <test number>\n", argv[0]);
		return -2;
	}
	test_nr = atoi(argv[1]);

	if ((xpmem_args.fd = open("/tmp/xpmem.share", O_RDWR)) == -1) {
		perror("open");
		return -2;
	}
	xpmem_args.share = mmap(0, TMP_SHARE_SIZE, PROT_READ|PROT_WRITE,
			MAP_SHARED, xpmem_args.fd, 0);
	if (xpmem_args.share == MAP_FAILED) {
		perror("mmap");
		return -2;
	}

	return (*xpmem_test[test_nr].function)(&xpmem_args);
}
