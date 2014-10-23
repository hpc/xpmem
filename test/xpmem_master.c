/*
 * xpmem_master: controller thread for various XPMEM tests
 *
 * Copyright (c) 2010 Cray, Inc.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <xpmem.h>
#include <xpmem_test.h>

#define test_result(name, val1, val2) (((val1) == (val2)) ?	\
		printf("==== %s PASSED ====\n\n", (name)) :	\
		printf("==== %s FAILED ====\n\n", (name)))

int test_base(test_args* t) { return 0; }
int test_two_attach(test_args* t) { return 0; }
int test_two_shares(test_args* t) { return 0; }
int test_fork(test_args* t) { return 0; }

int main(int argc, char** argv)
{
	pid_t p1, p2;
	int i, fd, lock, status[2];
	char *share, test_nr[4];

	printf("XPMEM version = %x\n\n", xpmem_version());

	if ((fd = open("/tmp/xpmem.share", O_RDWR)) == -1) {
		perror("open xpmem.share");
		return -1;
	}
	if ((lock = open("/tmp/xpmem.lock", O_RDWR)) == -1) {
		perror("open xpmem.lock");
		return -1;
	}

	share = mmap(0, TMP_SHARE_SIZE, PROT_READ|PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (share == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	/* Loop over all tests */
	for (i=0; xpmem_test[i].name != NULL; ++i) {
		printf("==== %s STARTS ====\n", xpmem_test[i].name);
		sprintf(test_nr, "%d", i);
		memset(share, '\0', TMP_SHARE_SIZE);
		lockf(lock, F_LOCK, 0);

		p1 = fork();
		if (p1 == -1) {
			perror("fork p1");
			return -1;
		}
		else if (p1 == 0) {
			if (execl("./xpmem_proc1", "xpmem_proc1", test_nr,
					NULL) == -1) {
				perror("execl p1");
				return -1;
			}
		}

		/* Wait for xpmem_proc1 to finish processing */
		while (share[LOCK_INDEX] == 0) { usleep(1000); }

		p2 = fork();
		if (p2 == -1) {
			perror("fork p2");
			return -1;
		}
		else if (p2 == 0) {
			if (execl("./xpmem_proc2", "xpmem_proc2", test_nr,
					NULL) == -1) {
				perror("execl p2");
				return -1;
			}
		}
		waitpid(p2, &status[1], 0);
		status[1] = WEXITSTATUS(status[1]);

		/* Release lock so xpmem_proc1 can exit */
		lockf(lock, F_ULOCK, 0);
		waitpid(p1, &status[0], 0);
		status[0] = WEXITSTATUS(status[0]);

		test_result(xpmem_test[i].name, status[0], status[1]);
	}

	munmap(share, TMP_SHARE_SIZE);
	return 0;
}
