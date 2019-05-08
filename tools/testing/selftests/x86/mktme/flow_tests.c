// SPDX-License-Identifier: GPL-2.0

/*
 * x86 MKTME:  API Tests
 *
 * Flow Tests either
 *	1) Validate some interaction between the 2 API's: Key & Encrypt
 *	2) or, Validate code flows, scenarios, known/fixed issues.
 */

/*
 * Userspace Keys with outstanding memory mappings can be discarded,
 * (discarded == revoke, invalidate, expire, unlink)
 * The paired KeyID will not be freed for reuse until the last memory
 * mapping is unmapped.
 */
void test_discard_in_use_key(void)
{
	key_serial_t key;
	void *ptra;
	int ret;

	key = add_key("mktme", "discard-test", options_CPU_long,
		      strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);

	if (key == -1) {
		perror("add key");
		return;
	}
	ptra = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE,
		    -1, 0);
	if (!ptra) {
		fprintf(stderr, "Error: mmap failed. ");
		if (keyctl(KEYCTL_INVALIDATE, key) == -1)
			fprintf(stderr, "Error: invalidate failed. Key:%d\n",
				key);
		return;
	}
	ret = syscall(sys_encrypt_mprotect, ptra, PAGE_SIZE, PROT_NONE, key);
	if (ret) {
		fprintf(stderr, "Error: encrypt_mprotect: %d\n", ret);
		goto free_memory;
	}
	if (keyctl(KEYCTL_INVALIDATE, key) != 0)
		fprintf(stderr, "Error: test_revoke_in_use_key\n");
free_memory:
	ret = munmap(ptra, PAGE_SIZE);
}

/* TODO: Can this be made useful? Used to reproduce a trace in Kai's setup. */
void test_kai_madvise(void)
{
	key_serial_t key;
	void *ptra;
	int ret;

	key = add_key("mktme", "testkey", options_USER, strlen(options_USER),
		      KEY_SPEC_THREAD_KEYRING);

	if (key == -1) {
		perror("add_key");
		return;
	}

	/* TODO wanted MAP_FIXED here - but kept failing to mmap */
	ptra = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ptra) {
		perror("failed to mmap");
		goto revoke_key;
	}

	ret = madvise(ptra, PAGE_SIZE, MADV_MERGEABLE);
	if (ret)
		perror("madvise err mergeable");

	if ((madvise(ptra, PAGE_SIZE, MADV_HUGEPAGE)) != 0)
		perror("madvise err hugepage");

	if ((madvise(ptra, PAGE_SIZE, MADV_DONTFORK)) != 0)
		perror("madvise err dontfork");

	ret = syscall(sys_encrypt_mprotect, ptra, PAGE_SIZE, PROT_NONE, key);
	if (ret)
		perror("mprotect error");

	ret = munmap(ptra, PAGE_SIZE);
revoke_key:
	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "invalidate failed on key [%d]\n", key);
}

void test_one_simple_round_trip(void)
{
	long size = PAGE_SIZE * 10;
	key_serial_t key;
	void *ptra;
	int ret;

	key = add_key("mktme", "testkey", options_USER, strlen(options_USER),
		      KEY_SPEC_THREAD_KEYRING);

	if (key == -1) {
		perror("add_key");
		return;
	}

	ptra = mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!ptra) {
		perror("failed to mmap");
		goto revoke_key;
	}

	ret = syscall(sys_encrypt_mprotect, ptra, size, PROT_NONE, key);
	if (ret)
		perror("mprotect error");

	ret = munmap(ptra, size);
revoke_key:
	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "revoke failed on key [%d]\n", key);
}

void test_switch_key_no_data(void)
{
	key_serial_t keyA, keyB;
	int ret, i;
	void *buf;

	/*
	 * Program 2 keys: Protect with one, protect with other
	 */
	keyA = add_key("mktme", "keyA", options_USER, strlen(options_USER),
		       KEY_SPEC_THREAD_KEYRING);
	if (keyA == -1) {
		perror("add_key");
		return;
	}
	keyB = add_key("mktme", "keyB", options_CPU_long,
		       strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);
	if (keyB == -1) {
		perror("add_key");
		return;
	}
	buf = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE,
		   -1, 0);
	if (!buf) {
		perror("mmap error");
		goto revoke_key;
	}
	ret = syscall(sys_encrypt_mprotect, buf, PAGE_SIZE, PROT_NONE, keyA);
	if (ret)
		perror("mprotect error");

	ret = syscall(sys_encrypt_mprotect, buf, PAGE_SIZE, PROT_NONE, keyB);
	if (ret)
		perror("mprotect error");

free_memory:
	ret = munmap(buf, PAGE_SIZE);
revoke_key:
	if (keyctl(KEYCTL_INVALIDATE, keyA) == -1)
		printf("revoke failed on key [%d]\n", keyA);
	if (keyctl(KEYCTL_INVALIDATE, keyB) == -1)
		printf("revoke failed on key [%d]\n", keyB);
}

void test_switch_key_mult_vmas(void)
{
	int prot = PROT_READ | PROT_WRITE;
	long size = PAGE_SIZE;
	int ret, i;
	int loop = 12;
	void *ptr[loop];
	key_serial_t firstkey;
	key_serial_t nextkey;

	firstkey = add_key("mktme", "gouda", options_CPU_long,
			   strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);
	nextkey = add_key("mktme", "ricotta", options_CPU_long,
			  strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);

	i = loop;
	while (i--) {
		ptr[i] = mmap(NULL, size, PROT_NONE,
			      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (i % 2) {
			ret = syscall(sys_encrypt_mprotect, ptr[i],
				      size, prot, firstkey);
			if (ret)
				perror("mprotect error");
		}
	}
	i = loop;
	while (i--) {
		if (i % 2) {
			ret = syscall(sys_encrypt_mprotect, ptr[i], size, prot,
				      nextkey);
			if (ret)
				perror("mprotect error");
		}
	}
	i = loop;
	while (i--)
		ret = munmap(ptr[i], size);

	if (keyctl(KEYCTL_INVALIDATE, nextkey) == -1)
		fprintf(stderr, "invalidate failed key %d\n", nextkey);
	if (keyctl(KEYCTL_INVALIDATE, firstkey) == -1)
		fprintf(stderr, "invalidate failed key %d\n", firstkey);
}

/* Write to buf with no encrypt key, then encrypt buf */
void test_switch_key0_to_key(void)
{
	key_serial_t key;
	size_t datalen = PAGE_SIZE;
	char *buf_1, *buf_2;
	int ret, i;

	key = add_key("mktme", "keyA", options_USER, strlen(options_USER),
		      KEY_SPEC_THREAD_KEYRING);
	if (key == -1) {
		perror("add_key");
		return;
	}
	buf_1 = (char *)mmap(NULL, datalen, PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!buf_1) {
		perror("failed to mmap");
		goto inval_key;
	}
	buf_2 = (char *)mmap(NULL, datalen, PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!buf_2) {
		perror("failed to mmap");
		goto inval_key;
	}
	memset(buf_1, 9, datalen);
	memset(buf_2, 9, datalen);

	ret = syscall(sys_encrypt_mprotect, buf_1, datalen,
		      PROT_READ | PROT_WRITE, key);
	if (ret)
		perror("mprotect error");

	if (!memcmp(buf_1, buf_2, sizeof(buf_1)))
		fprintf(stderr, "Error: bufs should not have matched\n");

free_memory:
	ret = munmap(buf_1, datalen);
	ret = munmap(buf_2, datalen);
inval_key:
	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "invalidate failed on key [%d]\n", key);
}

void test_zero_page(void)
{
	/*
	 * write access to the zero page, gets replaced with a newly
	 * allocated page.
	 * Can this be seen in smaps?
	 */
}

