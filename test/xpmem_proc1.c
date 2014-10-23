/*
 * xpmem_proc1: process one capable of running various XPMEM tests
 *
 * Copyright (c) 2010 Cray, Inc.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <xpmem.h>
#include <xpmem_test.h>

/**
 * test_base - a simple test to share and attach
 * Description:
 *      Creates a share (initialized to a random value), calls a second process
 *	to attach to the shared address and increment its value.
 * Return Values:
 *	Success: 0
 *	Failure: -1
 */
int test_base(test_args *xpmem_args)
{
	int i, ret=0, *data, expected;
	xpmem_segid_t segid;

	segid = make_share(&data, SHARE_SIZE);
	if (segid == -1) {
		perror("xpmem_make");
		xpmem_args->share[LOCK_INDEX] = 1;
		return -1;
	}

	printf("xpmem_proc1: mypid = %d\n", getpid());
	printf("xpmem_proc1: sharing %ld bytes\n", SHARE_SIZE);
	printf("xpmem_proc1: segid = %llx at %p\n\n", segid, data);

	/* Copy data to mmap share */
	sprintf(xpmem_args->share, "%llx", segid);

	/* Give control back to xpmem_master */
	xpmem_args->share[LOCK_INDEX] = 1;

	/* Wait for xpmem_proc2 to finish */
	lockf(xpmem_args->lock, F_LOCK, 0);
	lockf(xpmem_args->lock, F_ULOCK, 0);

	printf("xpmem_proc1: verifying data...");
	expected = (xpmem_args->add == 2 ? 2 : 1); /* Slightly hackish */
	for (i = 0; i < SHARE_INT_SIZE; i++) {
		if (*(data + i) != i + expected) {
			printf("xpmem_proc1: ***mismatch at %d: expected %d "
				"got %d\n", i, i + expected, *(data + i));
			ret = -1;
		}
	}
	printf("done\n");

	unmake_share(segid, data, SHARE_SIZE);

	return ret;
}

/**
 * test_two_attach - same as test_base, but with two consumers
 * Description:
 *	Difference in implemention is in xpmem_proc2.c
 * Return Values:
 *	Success: Average value incremented
 *	Failure: -1
 */
int test_two_attach(test_args *xpmem_args)
{
	xpmem_args->add = 2;
	return test_base(xpmem_args);
}

/**
 * test_two_shares - same as test_base, but with two sources and two consumers
 * Description:
 *	See test_base.
 * Return Values:
 *	Success: 0
 *	Failure: -1
 */
int test_two_shares(test_args *xpmem_args)
{
	int i, ret=0, *data[2];
	xpmem_segid_t segid[2];
	char *tmp;

	segid[0] = make_share(&data[0], SHARE_SIZE);
	segid[1] = make_share(&data[1], SHARE_SIZE);
	if (segid[0] == -1 || segid[1] == -1) {
		perror("xpmem_make");
		xpmem_args->share[LOCK_INDEX] = 1;
		return 1;
	}

	printf("xpmem_proc1: mypid = %d\n", getpid());
	printf("xpmem_proc1: sharing 2 segments, %ld bytes each\n", SHARE_SIZE);
	printf("xpmem_proc1: segid[0] = %llx at %p\n", segid[0], data[0]);
	printf("xpmem_proc1: segid[1] = %llx at %p\n\n", segid[1], data[1]);

	/* Copy data to mmap share */
	tmp = xpmem_args->share;
	sprintf(tmp, "%llx", segid[0]);
	tmp += strlen(tmp) + 1;
	sprintf(tmp, "%llx", segid[1]);

	/* Give control back to xpmem_master */
	xpmem_args->share[LOCK_INDEX] = 1;

	/* Wait for xpmem_proc2 to finish */
	lockf(xpmem_args->lock, F_LOCK, 0);
	lockf(xpmem_args->lock, F_ULOCK, 0);

	printf("xpmem_proc1: verifying data...");
	for (i = 0; i < SHARE_INT_SIZE; i++) {
		if (*(data[0] + i) != i + 1) {
			printf("xpmem_proc1: ***mismatch at %d with segment 0: "
				"expected %d got %d\n", i, i+1, *(data[0]+i));
			ret = -1;
		}
		if (*(data[1] + i) != i + 1) {
			printf("xpmem_proc1: ***mismatch at %d with segment 1: "
				"expected %d got %d\n", i, i+1, *(data[1]+i));
			ret = -1;
		}
	}
	printf("done\n");

	unmake_share(segid[0], data[0], SHARE_SIZE);
	unmake_share(segid[1], data[1], SHARE_SIZE);

	return ret;
}

/**
 * test_fork - test if copy-on-write is handled properly
 * Description:
 *	Creates a share, calls a second process to attach. Wait for second
 *	process to pin the second page, then write to this page to induce
 *	copy-on-write.
 * Return Values:
 *      Success: 0
 *      Failure: -1
 */
int test_fork(test_args *xpmem_args)
{
	int i, ret=0, *data, expected;
	xpmem_segid_t segid;
	pid_t p1_child;

	segid = make_share(&data, SHARE_SIZE);
	if (segid == -1) {
		perror("xpmem_make");
		xpmem_args->share[LOCK_INDEX] = 1;
		return 1;
	}

	printf("xpmem_proc1: mypid = %d\n", getpid());
	printf("xpmem_proc1: sharing %ld bytes\n", SHARE_SIZE);
	printf("xpmem_proc1: segid = %llx at %p\n\n", segid, data);

	/* Copy data to mmap share */
	sprintf(xpmem_args->share, "%llx", segid);

	/* Give control back to xpmem_master */
	xpmem_args->share[LOCK_INDEX] = 1;

	/* Wait for xpmem_proc2 to attach and pin */
	while (xpmem_args->share[COW_LOCK_INDEX] == 0) { usleep(1000); }

	printf("xpmem_proc1: forking a child\n");
	p1_child = fork();

	if (p1_child == -1) {
		perror("fork");
		return -1;
	} else if (p1_child == 0) {
		printf("\nxpmem_child: hello from pid %d\n\n", getpid());
		sleep(3);
		return 0;
	} else {
		printf("xpmem_proc1: adding 1 to all elems to induce COW\n");
		for (i = 0; i < SHARE_INT_SIZE; i++)
			*(data + i) += 1;

		printf("xpmem_proc1: give control back to xpmem_proc2\n\n");
		lockf(xpmem_args->lock, F_LOCK, 0);
		lockf(xpmem_args->lock, F_ULOCK, 0);

		printf("xpmem_proc1: verifying data...");
		for (i = 0; i < SHARE_INT_SIZE; i++) {
			/* xpmem_proc2 attached to second page and added 1 */
			if (i >= PAGE_INT_SIZE && i < 2*PAGE_INT_SIZE)
				expected = 2;
			else
				expected = 1;
			if (*(data + i) != i + expected) {
				printf("xpmem_proc1: ***mismatch at %d: "
					"expected %d got %d\n", i, i + expected,
					*(data + i));
				ret = -1;
			}
		}
		printf("done\n");

		unmake_share(segid, data, SHARE_SIZE);

		return ret;
	}
}

int main(int argc, char **argv)
{
	test_args xpmem_args;
	int test_nr;

	if (argc < 2) {
		printf("Usage: %s <test number>\n", argv[0]);
		return -1;
	}
	test_nr = atoi(argv[1]);

	if ((xpmem_args.fd = open("/tmp/xpmem.share", O_RDWR)) == -1) {
		perror("open xpmem.share");
		return -1;
	}
	if ((xpmem_args.lock = open("/tmp/xpmem.lock", O_RDWR)) == -1) {
		perror("open xpmem.lock");
		return -1;
	}
	xpmem_args.share = mmap(0, TMP_SHARE_SIZE, PROT_READ|PROT_WRITE,
			MAP_SHARED, xpmem_args.fd, 0);
	if (xpmem_args.share == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	return (*xpmem_test[test_nr].function)(&xpmem_args);
}
