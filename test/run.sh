#!/usr/bin/env bash

test -e /tmp/xpmem.share && rm -f /tmp/xpmem.share
test -e /tmp/xpmem.lock && rm -f /tmp/xpmem.lock

# create TMP_SHARE_SIZE bytes defined in xpmem_test.h
for i in `seq 0 31` ; do
	echo -n 0 >> /tmp/xpmem.share
done
echo 0 > /tmp/xpmem.lock

# Run the main test app
$PWD/xpmem_master

# Tests complete -- now check for memory leaks
echo "==== test_mem_leak STARTS ===="
PINNED=$(grep "pages pinned" /proc/xpmem/* | sed -e 's/^.*: //')
UNPINNED=$(grep "pages unpinned" /proc/xpmem/* | sed -e 's/^.*: //')
echo "all pinned pages = $PINNED"
echo "all unpinned pages = $UNPINNED"
if [ "$PINNED" -eq "$UNPINNED" ]; then
	echo "==== test_mem_leak PASSED ===="
else
	echo "==== test_mem_leak FAILED ===="
fi

if [ -e "/tmp/xpmem.share" ]; then
	rm /tmp/xpmem.share
fi
if [ -e "/tmp/xpmem.lock" ]; then
	rm /tmp/xpmem.lock
fi
