// SPDX-License-Identifier: GPL-2.0

/* x86 MKTME Encrypt API Tests */

/* Address & length parameters to encrypt_mprotect() must be page aligned */
void test_param_alignment(void)
{
	size_t datalen = PAGE_SIZE * 2;
	key_serial_t key;
	int ret, i;
	char *buf;

	key = add_key("mktme", "keyname", options_CPU_long,
		      strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);

	if (key == -1) {
		perror("test_param_alignment");
		return;
	}
	buf = (char *)mmap(NULL, datalen, PROT_NONE,
			   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	/* Fail if addr is not page aligned */
	ret = syscall(sys_encrypt_mprotect, buf + 100, datalen / 2, PROT_NONE,
		      key);
	if (!ret)
		fprintf(stderr, "Error: addr is not page aligned\n");

	/* Fail if len is not page aligned */
	ret = syscall(sys_encrypt_mprotect, buf, 9, PROT_NONE, key);
	if (!ret)
		fprintf(stderr, "Error: len is not page aligned.");

	/* Fail if both addr and len are not page aligned */
	ret = syscall(sys_encrypt_mprotect, buf + 100, datalen + 100,
		      PROT_READ | PROT_WRITE, key);
	if (!ret)
		fprintf(stderr, "Error: addr and len are not page aligned\n");

	/* Success if both addr and len are page aligned */
	ret = syscall(sys_encrypt_mprotect, buf, datalen,
		      PROT_READ | PROT_WRITE, key);

	if (ret)
		fprintf(stderr, "Fail: addr and len are both page aligned\n");

	ret = munmap(buf, datalen);

	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Error: invalidate failed on key [%d]\n", key);
}

/*
 * Do encrypt_mprotect and follow with classic mprotects.
 * KeyID should remain unchanged.
 */
void test_change_protections(void)
{
	unsigned int keyid, check_keyid;
	key_serial_t key;
	void *ptra;
	int ret, i;

	const int prots[] = {
		PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC,
		PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC,
	};

	key = add_key("mktme", "testkey", options_CPU_long,
		      strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);
	if (key == -1) {
		perror(__func__);
		return;
	}
	ptra = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE,
		    -1, 0);
	if (!ptra) {
		fprintf(stderr, "Error: mmap failed.");
		goto revoke_key;
	}
	/* Encrypt Memory */
	ret = syscall(sys_encrypt_mprotect, ptra, PAGE_SIZE, PROT_NONE, key);
	if (ret)
		fprintf(stderr, "Error: encrypt_mprotect [%d]\n", ret);

	/* Remember the assigned KeyID */
	keyid = find_smaps_keyid((unsigned long)ptra);

	/* Classic mprotects()  should not change KeyID. */
	for (i = 0; i < ARRAY_SIZE(prots); i++) {
		ret = mprotect(ptra, PAGE_SIZE, prots[i]);
		if (ret)
			fprintf(stderr, "Error: encrypt_mprotect [%d]\n", ret);

		check_keyid = find_smaps_keyid((unsigned long)ptra);
		if (keyid != check_keyid)
			fprintf(stderr, "Error: keyid change not expected\n");
	};
free_memory:
	ret = munmap(ptra, PAGE_SIZE);
revoke_key:
	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Error: invalidate failed. [%d]\n", key);
}

/*
 * Make one mapping and create a bunch of keys.
 * Encrypt that one mapping repeatedly with different keys.
 * Verify the KeyID changes in smaps.
 */
void test_key_swap(void)
{
	unsigned int prev_keyid, next_keyid;
	int maxswaps = max_keyids / 2;		/* Not too many swaps */
	key_serial_t key[maxswaps];
	long size = PAGE_SIZE;
	int keys_available = 0;
	char name[12];
	void *ptra;
	int i, ret;

	for (i = 0; i < maxswaps; i++) {
		sprintf(name, "mk_swap_%d", i);
		key[i] = add_key("mktme", name, options_CPU_long,
				 strlen(options_CPU_long),
				 KEY_SPEC_THREAD_KEYRING);
		if (key[i] == -1) {
			perror(__func__);
			goto free_keys;
		} else {
			keys_available++;
		}
	}

	printf("     Info: created %d keys\n", keys_available);
	ptra = mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!ptra) {
		perror("mmap");
		goto free_keys;
	}
	prev_keyid = 0;

	for (i = 0; i < keys_available; i++) {
		ret = syscall(sys_encrypt_mprotect, ptra, size,
			      PROT_NONE, key[i]);
		if (ret) {
			perror("encrypt_mprotect");
			goto free_memory;
		}

		next_keyid = find_smaps_keyid((unsigned long)ptra);
		if (prev_keyid == next_keyid)
			fprintf(stderr, "Error %s: expected new keyid\n",
				__func__);
		prev_keyid = next_keyid;
	}
free_memory:
	ret = munmap(ptra, size);

free_keys:
	for (i = 0; i < keys_available; i++) {
		if (keyctl(KEYCTL_INVALIDATE, key[i]) == -1)
			perror(__func__);
	}
}

/*
 * These may not be doing as orig planned. Need to check that key is
 * invalidated and then gets destroyed when last map is removed.
 */
void test_counters_same(void)
{
	key_serial_t key;
	int count = 4;
	void *ptr[count];
	int ret, i;

	/* Get 4 pieces of memory */
	i = count;
	while (i--) {
		ptr[i] = mmap(NULL, PAGE_SIZE, PROT_NONE,
			      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (!ptr[i])
			perror("mmap");
	}
	/* Protect with same key */
	key = add_key("mktme", "mk_same", options_USER, strlen(options_USER),
		      KEY_SPEC_THREAD_KEYRING);

	if (key == -1) {
		perror("add_key");
		goto free_mem;
	}
	i = count;
	while (i--) {
		ret = syscall(sys_encrypt_mprotect, ptr[i], PAGE_SIZE,
			      PROT_NONE, key);
		if (ret)
			perror("encrypt_mprotect");
	}
	/* Discard Key & Unmap Memory (order irrelevant) */
	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Error: invalidate failed.\n");
free_mem:
	i = count;
	while (i--)
		ret = munmap(ptr[i], PAGE_SIZE);
}

void test_counters_diff(void)
{
	int prot = PROT_READ | PROT_WRITE;
	long size = PAGE_SIZE;
	int ret, i;
	int loop = 4;
	char name[12];
	void *ptr[loop];
	key_serial_t diffkey[loop];

	i = loop;
	while (i--)
		ptr[i] = mmap(NULL, size, prot, MAP_ANONYMOUS | MAP_PRIVATE,
			      -1, 0);
	i = loop;
	while (i--) {
		sprintf(name, "cheese_%d", i);
		diffkey[i] = add_key("mktme", name, options_USER,
				     strlen(options_USER),
				     KEY_SPEC_THREAD_KEYRING);
		ret = syscall(sys_encrypt_mprotect, ptr[i], size, prot,
			      diffkey[i]);
		if (ret)
			perror("encrypt_mprotect");
	}

	i = loop;
	while (i--)
		ret = munmap(ptr[i], PAGE_SIZE);

	i = loop;
	while (i--) {
		if (keyctl(KEYCTL_INVALIDATE, diffkey[i]) == -1)
			fprintf(stderr, "Error: invalidate failed key:%d\n",
				diffkey[i]);
	}
}

void test_counters_holes(void)
{
	int prot = PROT_READ | PROT_WRITE;
	long size = PAGE_SIZE;
	int ret, i;
	int loop = 6;
	void *ptr[loop];
	key_serial_t samekey;

	samekey = add_key("mktme", "gouda", options_CPU_long,
			  strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);

	i = loop;
	while (i--) {
		ptr[i] = mmap(NULL, size, prot, MAP_ANONYMOUS | MAP_PRIVATE,
			      -1, 0);
		if (i % 2) {
			ret = syscall(sys_encrypt_mprotect, ptr[i], size, prot,
				      samekey);
			if (ret)
				perror("mprotect error");
		}
	}

	i = loop;
	while (i--)
		ret = munmap(ptr[i], size);

	if (keyctl(KEYCTL_INVALIDATE, samekey) == -1)
		fprintf(stderr, "Error: invalidate failed\n");
}

/*
 * Try on SIMICs. See is SIMICs 'a1a1' thing does the trick.
 * May need real hardware.
 * One buffer  -> encrypt entirety w one key
 * Same buffer -> encrypt in pieces w different keys
 */
void test_split(void)
{
	int prot = PROT_READ | PROT_WRITE;
	int ret, i;
	int pieces = 10;
	size_t len = PAGE_SIZE;
	char name[12];
	char *buf;
	key_serial_t firstkey;
	key_serial_t diffkey[pieces];

	/* get one piece of memory, protect it, memset it */
	buf = (char *)mmap(NULL, len, PROT_NONE,
			   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	firstkey = add_key("mktme", "firstkey", options_CPU_long,
			   strlen(options_CPU_long),
			   KEY_SPEC_THREAD_KEYRING);

	ret = syscall(sys_encrypt_mprotect, buf, len, PROT_READ | PROT_WRITE,
		      firstkey);

	if (ret) {
		printf("firstkey mprotect error:%d\n", ret);
		goto free_mem;
	}

	memset(buf, 9, len);
	/*
	 * Encrypt pieces of buf with different encryption keys.
	 * Expect to see the data in those pieces zero'd
	 */
	for (i = 0; i < pieces; i++) {
		sprintf(name, "cheese_%d", i);
		diffkey[i] = add_key("mktme", name, options_CPU_long,
				     strlen(options_CPU_long),
				     KEY_SPEC_THREAD_KEYRING);
		ret = syscall(sys_encrypt_mprotect, (buf + (i * len)), len,
			      PROT_READ | PROT_WRITE, diffkey[i]);
		if (ret)
			printf("diff key mprotect error:%d\n", ret);
		else
			printf("done protecting w i:%d key[%d]\n", i,
			       diffkey[i]);
	}
	printf("SIMICs - this should NOT be all 'f's.\n");
	for (i = 0; i < len; i++)
		printf("-%x", buf[i]);
	printf("\n");

	getchar();
	i = pieces;
	for (i = 0; i < pieces; i++) {
		if (keyctl(KEYCTL_INVALIDATE, diffkey[i]) == -1)
			fprintf(stderr, "invalidate failed key:%d\n",
				diffkey[i]);
	}
	if (keyctl(KEYCTL_INVALIDATE, firstkey) == -1)
		fprintf(stderr, "invalidate failed on key:%d\n", firstkey);
free_mem:
	ret = munmap(buf, len);
}

void test_well_suited(void)
{
	int prot;
	long size = PAGE_SIZE;
	int ret, i;
	int loop = 6;
	void *ptr[loop];
	key_serial_t key;
	void *addr, *first;

	/* mmap alternating protections so that we get loop# of vma's  */
	i = loop;
	/* map the first one */
	first = mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	addr = first + PAGE_SIZE;
	i--;
	while (i--)  {
		prot = (i % 2) ? PROT_READ : PROT_WRITE;
		ptr[i] = mmap(addr, size, prot, MAP_ANONYMOUS | MAP_PRIVATE,
			      -1, 0);
		addr = addr + PAGE_SIZE;
	}
	/* Protect with same key */
	key = add_key("mktme", "mk_suited954", options_USER,
		      strlen(options_USER), KEY_SPEC_THREAD_KEYRING);

	/* Changing FLAGS and adding KEY */
	ret = syscall(sys_encrypt_mprotect, ptr[0], (loop * PAGE_SIZE),
		      PROT_EXEC, key);
	if (ret)
		fprintf(stderr, "Error: encrypt_mprotect [%d]\n", ret);

	i = loop;
	while (i--)
		ret = munmap(ptr[i], size);

	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Error: invalidate failed\n");
}

void test_not_suited(int argc, char *argv[])
{
	int prot;
	int protA = PROT_READ;
	int protB = PROT_WRITE;
	int flagsA = MAP_ANONYMOUS | MAP_PRIVATE;
	int flagsB = MAP_SHARED | MAP_ANONYMOUS;
	int flags;
	int ret, i;
	int loop = 6;
	void *ptr[loop];
	key_serial_t key;

	printf("loop count [%d]\n", loop);

	/* mmap alternating protections so that we get loop# of vma's  */
	i = loop;
	while (i--)  {
		prot = (i % 2) ? PROT_READ : PROT_WRITE;
		if (i == 2)
			flags = flagsB;
		else
			flags = flagsA;
		ptr[i] = mmap(NULL, PAGE_SIZE, prot, flags, -1, 0);
	}

	/* protect with same key */
	key = add_key("mktme", "mk_notsuited", options_CPU_long,
		      strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);

	/* Changing FLAGS and adding KEY */
	ret = syscall(sys_encrypt_mprotect, ptr[0], (loop * PAGE_SIZE),
		      PROT_EXEC, key);
	if (!ret)
		fprintf(stderr, "Error: expected encrypt_mprotect to fail.\n");

	i = loop;
	while (i--)
		ret = munmap(ptr[i], PAGE_SIZE);

	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Error: invalidate failed.\n");
}

