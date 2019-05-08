// SPDX-License-Identifier: GPL-2.0

/*
 *  Testing payload options
 *
 *  Invalid options should return -EINVAL, not a Key.
 *  TODO This is just checking for the Key.
 *       Add a check for the actual -EINVAL return.
 *
 *  Invalid option cases are grouped based on why they are invalid.
 *  Valid option cases are one large array of expected goodness
 *
 */
const char *bad_type_tail = "algorithm=aes-xts-128 key=12345678123456781234567812345678 tweak=12345678123456781234567812345678";
const char *bad_type[] = {
	"type=",			/* missing */
	"type=cpu, type=cpu",		/* duplicate good */
	"type=cpu, type=user",
	"type=user, type=user",
	"type=user, type=cpu",
	"type=cp",			/* spelling */
	"type=cpus",
	"type=pu",
	"type=cpucpu",
	"type=useruser",
	"type=use",
	"type=users",
	"type=used",
	"type=User",			/* case */
	"type=USER",
	"type=UsEr",
	"type=CPU",
	"type=Cpu",
};

const char *bad_alg_tail = "type=cpu";
const char *bad_algorithm[] = {
	"algorithm=",
	"algorithm=aes-xts-12",
	"algorithm=aes-xts-128aes-xts-128",
	"algorithm=es-xts-128",
	"algorithm=bad",
	"algorithm=aes-xts-128-xxxx",
	"algorithm=xxx-aes-xts-128",
};

const char *bad_key_tail = "type=cpu algorithm=aes-xts-128 tweak=12345678123456781234567812345678";
const char *bad_key[] = {
	"key=",
	"key=0",
	"key=ababababababab",
	"key=blah",
	"key=0123333456789abcdef",
	"key=abracadabra",
	"key=-1",
};

const char *bad_tweak_tail = "type=cpu algorithm=aes-xts-128 key=12345678123456781234567812345678";
const char *bad_tweak[] = {
	"tweak=",
	"tweak=ab",
	"tweak=bad",
	"tweak=-1",
	"tweak=000000000000000",
};

/* Bad, missing, repeating tokens and bad overall payload length */
const char *bad_other[] = {
	"",
	" ",
	"a ",
	"algorithm= tweak= type= key=",
	"key=aaaaaaaaaaaaaaaa tweak=aaaaaaaaaaaaaaaa type=cpu",
	"algorithm=aes-xts-128 tweak=0000000000000000 tweak=aaaaaaaaaaaaaaaa key=0000000000000000  type=cpu",
	"algorithm=aes-xts-128 tweak=0000000000000000 key=0000000000000000 key=0000000000000000 type=cpu",
	"algorithm=aes-xts-128 tweak=0000000000000000 key=0000000000000000  type=cpu type=cpu",
	"algorithm=aes-xts-128 tweak=0000000000000000 key=0000000000000000  type=cpu type=user",
	"tweak=0000000000000000011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
};

void test_invalid_options(const char *bad_options[], unsigned int size,
			  const char *good_tail, char *descrip)
{
	key_serial_t key[size];
	char options[512];
	char name[15];
	int i, ret;

	for (i = 0; i < size; i++) {
		sprintf(name, "mk_inv_%d", i);
		sprintf(options, "%s %s", bad_options[i], good_tail);

		key[i] = add_key("mktme", name, options,
				 strlen(options),
				 KEY_SPEC_THREAD_KEYRING);
		if (key[i] > 0)
			fprintf(stderr, "Error %s: [%s] accepted.\n",
				descrip, bad_options[i]);
	}
	for (i = 0; i < size; i++) {
		if (key[i] > 0) {
			ret = keyctl(KEYCTL_INVALIDATE, key[i]);
			if (ret == -1)
				fprintf(stderr, "Key invalidate failed: [%d]\n",
					key[i]);
		}
	}
}

void test_keys_invalid_options(void)
{
	test_invalid_options(bad_type, ARRAY_SIZE(bad_type),
			     bad_type_tail, "Invalid Type Option");
	test_invalid_options(bad_algorithm, ARRAY_SIZE(bad_algorithm),
			     bad_alg_tail, "Invalid Algorithm Option");
	test_invalid_options(bad_key, ARRAY_SIZE(bad_key),
			     bad_key_tail, "Invalid Key Option");
	test_invalid_options(bad_tweak, ARRAY_SIZE(bad_tweak),
			     bad_tweak_tail, "Invalid Tweak Option");
	test_invalid_options(bad_other, ARRAY_SIZE(bad_other),
			     NULL, "Invalid Option");
}

const char *valid_options[] = {
	"algorithm=aes-xts-128 type=user key=0123456789abcdef0123456789abcdef tweak=abababababababababababababababab",
	"algorithm=aes-xts-128 type=user tweak=0123456789abcdef0123456789abcdef key=abababababababababababababababab",
	"algorithm=aes-xts-128 type=user key=01010101010101010101010101010101 tweak=0123456789abcdef0123456789abcdef",
	"algorithm=aes-xts-128 tweak=01010101010101010101010101010101 type=user key=0123456789abcdef0123456789abcdef",
	"algorithm=aes-xts-128 key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa tweak=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa type=user",
	"algorithm=aes-xts-128 tweak=aaaaaaaaaaaaaaaa0000000000000000 key=aaaaaaaaaaaaaaaa0000000000000000  type=user",
	"algorithm=aes-xts-128 type=cpu key=aaaaaaaaaaaaaaaa0123456789abcdef tweak=abababaaaaaaaaaaaaaaaaababababab",
	"algorithm=aes-xts-128 type=cpu tweak=0123456aaaaaaaaaaaaaaaa789abcdef key=abababaaaaaaaaaaaaaaaaababababab",
	"algorithm=aes-xts-128 type=cpu key=010101aaaaaaaaaaaaaaaa0101010101 tweak=01234567aaaaaaaaaaaaaaaa89abcdef",
	"algorithm=aes-xts-128 tweak=01010101aaaaaaaaaaaaaaaa01010101 type=cpu key=012345aaaaaaaaaaaaaaaa6789abcdef",
	"algorithm=aes-xts-128 key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa tweak=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa type=cpu",
	"algorithm=aes-xts-128 tweak=00000000000000000000000000000000 type=cpu",
	"algorithm=aes-xts-128 key=00000000000000000000000000000000 type=cpu",
	"algorithm=aes-xts-128 type=cpu",
	"algorithm=aes-xts-128 tweak=00000000000000000000000000000000 key=00000000000000000000000000000000 type=cpu",
	"algorithm=aes-xts-128 tweak=00000000000000000000000000000000 key=00000000000000000000000000000000 type=cpu",
};

void test_keys_valid_options(void)
{
	char name[15];
	int i, ret;
	key_serial_t key[ARRAY_SIZE(valid_options)];

	for (i = 0; i < ARRAY_SIZE(valid_options); i++) {
		sprintf(name, "mk_val_%d", i);
		key[i] = add_key("mktme", name, valid_options[i],
				 strlen(valid_options[i]),
				 KEY_SPEC_THREAD_KEYRING);
		if (key[i] <= 0)
			fprintf(stderr, "Fail valid option: [%s]\n",
				valid_options[i]);
	}
	for (i = 0; i < ARRAY_SIZE(valid_options); i++) {
		if (key[i] > 0) {
			ret = keyctl(KEYCTL_INVALIDATE, key[i]);
			if (ret)
				fprintf(stderr, "Invalidate failed key[%d]\n",
					key[i]);
		}
	}
}

/*
 *  key_serial_t add_key(const char *type, const char *description,
 *			 const void *payload, size_t plen,
 *			 key_serial_t keyring);
 *
 *  The Kernel Key Service should validate this. But, let's validate
 *  some basic syntax. MKTME Keys does NOT propose a description based
 *  on type and payload if no description is provided. (Some other key
 *  types do make that 'proposal'.)
 */

void test_keys_descriptor(void)
{
	key_serial_t key;

	key = add_key("mktme", NULL, options_CPU_long, strlen(options_CPU_long),
		      KEY_SPEC_THREAD_KEYRING);

	if (errno != EINVAL)
		fprintf(stderr, "Fail: expected EINVAL with NULL descriptor\n");

	if (key > 0)
		if (keyctl(KEYCTL_INVALIDATE, key) == -1)
			fprintf(stderr, "Key invalidate failed: %s\n",
				strerror(errno));

	key = add_key("mktme", "", options_CPU_long, strlen(options_CPU_long),
		      KEY_SPEC_THREAD_KEYRING);

	if (errno != EINVAL)
		fprintf(stderr,
			"Fail: expected EINVAL with empty descriptor\n");

	if (key > 0)
		if (keyctl(KEYCTL_INVALIDATE, key) == -1)
			fprintf(stderr, "Key invalidate failed: %s\n",
				strerror(errno));
}

/*
 * Test: Add multiple keys with with same descriptor
 *
 * Expect that the same Key Handle (key_serial_t) will be returned
 * on each subsequent request for the same key. This is treated like
 * a key update.
 */

void test_keys_add_mult_same(void)
{
	int i, inval, num_keys = 5;
	key_serial_t key[num_keys];

	for (i = 1; i <= num_keys; i++) {
		key[i] = add_key("mktme", "multiple_keys",
				 options_USER,
				 strlen(options_USER),
				 KEY_SPEC_THREAD_KEYRING);

		if (i > 1)
			if (key[i] != key[i - 1]) {
				fprintf(stderr, "Fail: expected same key.\n");
				inval = i;    /* maybe i keys to invalidate */
				goto out;
			}
	}
	inval = 1;    /* if all works correctly, only 1 key to invalidate */
out:
	for (i = 1; i <= inval; i++) {
		if (keyctl(KEYCTL_INVALIDATE, key[i]) == -1)
			fprintf(stderr, "Key invalidate failed: %s\n",
				strerror(errno));
	}
}

/*
 * Add two keys with the same descriptor but different payloads.
 * The result should be one key with the payload from the second
 * add_key() request. Key Service recognizes the duplicate
 * descriptor and allows the payload to be updated.
 *
 * mktme key type chooses not to support the keyctl read command.
 * This means we cannot read the key payloads back to compare.
 * That piece can only be verified in debug mode.
 */
void test_keys_change_payload(void)
{
	key_serial_t key_a, key_b;

	key_a = add_key("mktme", "changepay", options_USER,
			strlen(options_USER), KEY_SPEC_THREAD_KEYRING);
	if (key_a == -1) {
		fprintf(stderr, "Failed to add test key_a: %s\n",
			strerror(errno));
		return;
	}
	key_b = add_key("mktme", "changepay", options_CPU_long,
			strlen(options_CPU_long), KEY_SPEC_THREAD_KEYRING);
	if (key_b == -1) {
		fprintf(stderr, "Failed to add test key_b: %s\n",
			strerror(errno));
		goto out;
	}
	if (key_a != key_b) {
		fprintf(stderr, "Fail: expected same key, got new key.\n");
		if (keyctl(KEYCTL_INVALIDATE, key_b) == -1)
			fprintf(stderr, "Key invalidate failed: %s\n",
				strerror(errno));
	}
out:
	if (keyctl(KEYCTL_INVALIDATE, key_a) == -1)
		fprintf(stderr, "Key invalidate failed: %s\n", strerror(errno));
}

/*  Add a key, then discard via method parameter: revoke or invalidate */
void test_keys_add_discard(int method)
{
	key_serial_t key;
	int i;

	key = add_key("mktme", "mtest_add_discard", options_USER,
		      strlen(options_USER), KEY_SPEC_THREAD_KEYRING);
	if (key < 0)
		perror("add_key");

	if (keyctl(method, key) == -1)
		fprintf(stderr, "Key %s failed: %s\n",
			((method == KEYCTL_INVALIDATE) ? "invalidate"
			: "revoke"), strerror(errno));
}

void test_keys_add_invalidate(void)
{
	test_keys_add_discard(KEYCTL_INVALIDATE);
}

void test_keys_add_revoke(void)
{
	if (remove_gc_delay()) {
		fprintf(stderr, "Skipping REVOKE test. Cannot set gc_delay.\n");
		return;
	}
	test_keys_add_discard(KEYCTL_REVOKE);
	restore_gc_delay();
}

void test_keys_describe(void)
{
	key_serial_t key;
	char buf[256];
	int ret;

	key = add_key("mktme", "describe_this_key", options_USER,
		      strlen(options_USER), KEY_SPEC_THREAD_KEYRING);

	if (key == -1) {
		fprintf(stderr, "Add_key failed.\n");
		return;
	}
	if (keyctl(KEYCTL_DESCRIBE, key, buf, sizeof(buf)) == -1) {
		fprintf(stderr, "%s: KEYCTL_DESCRIBE failed\n", __func__);
		goto revoke_key;
	}
	if (strncmp(buf, "mktme", 5))
		fprintf(stderr, "Error: mktme descriptor missing.\n");

revoke_key:
	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Key invalidate failed: %s\n", strerror(errno));
}

void test_keys_update_explicit(void)
{
	key_serial_t key;

	key = add_key("mktme", "testkey", options_USER, strlen(options_USER),
		      KEY_SPEC_SESSION_KEYRING);

	if (key == -1) {
		perror("add_key");
		return;
	}
	if (keyctl(KEYCTL_UPDATE, key, options_CPU_long,
		   strlen(options_CPU_long)) == -1)
		fprintf(stderr, "Error: Update key failed\n");

	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Key invalidate failed: %s\n", strerror(errno));
}

void test_keys_update_clear(void)
{
	key_serial_t key;

	key = add_key("mktme", "testkey", options_USER, strlen(options_USER),
		      KEY_SPEC_SESSION_KEYRING);

	if (keyctl(KEYCTL_UPDATE, key, options_CLEAR,
		   strlen(options_CLEAR)) == -1)
		fprintf(stderr, "update: clear key failed\n");

	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Key invalidate failed: %s\n", strerror(errno));
}

void test_keys_no_encrypt(void)
{
	key_serial_t key;

	key = add_key("mktme", "no_encrypt_key", options_NOENCRYPT,
		      strlen(options_USER), KEY_SPEC_SESSION_KEYRING);

	if (key == -1) {
		fprintf(stderr, "Error: add_key type=no_encrypt failed.\n");
		return;
	}
	if (keyctl(KEYCTL_INVALIDATE, key) == -1)
		fprintf(stderr, "Key invalidate failed: %s\n", strerror(errno));
}

void test_keys_unique_keyid(void)
{
	/*
	 * exists[] array must be of mktme_nr_keyids + 1 size, else the
	 * uniqueness test will fail. OK for max_keyids under test to be
	 * less than mktme_nr_keyids.
	 */
	unsigned int exists[max_keyids + 1];
	unsigned int keyids[max_keyids + 1];
	key_serial_t key[max_keyids + 1];
	void *ptr[max_keyids + 1];
	int keys_available = 0;
	char name[12];
	int i, ret;

	/* Get as many keys as possible */
	for (i = 1; i <= max_keyids; i++) {
		sprintf(name, "mk_unique_%d", i);
		key[i] = add_key("mktme", name, options_CPU_short,
				 strlen(options_CPU_short),
				 KEY_SPEC_THREAD_KEYRING);
		if (key[i] > 0)
			keys_available++;
	}
	/* Create mappings, encrypt them, and find the assigned KeyIDs */
	for (i = 1; i <= keys_available; i++) {
		ptr[i] = mmap(NULL, PAGE_SIZE, PROT_NONE,
			      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		ret = syscall(sys_encrypt_mprotect, ptr[i], PAGE_SIZE,
			      PROT_NONE, key[i]);
		keyids[i] = find_smaps_keyid((unsigned long)ptr[i]);
	}
	/* Verify the KeyID's are unique */
	memset(exists, 0, sizeof(exists));
	for (i = 1; i <= keys_available; i++) {
		if (exists[keyids[i]])
			fprintf(stderr, "Error: duplicate keyid %d\n",
				keyids[i]);
		exists[keyids[i]] = 1;
	}

	/* Clean up */
	for (i = 1; i <= keys_available; i++) {
		ret = munmap(ptr[i], PAGE_SIZE);
		if (keyctl(KEYCTL_INVALIDATE, key[i]) == -1)
			fprintf(stderr, "Invalidate failed Serial:%d\n",
				key[i]);
	}
	sleep(1);  /* Rest a bit while keys get freed. */
}

void test_keys_get_max_keyids(void)
{
	key_serial_t key[max_keyids + 1];
	int keys_available = 0;
	char name[12];
	int i, ret;

	for (i = 1; i <= max_keyids; i++) {
		sprintf(name, "mk_get63_%d", i);
		key[i] = add_key("mktme", name, options_CPU_short,
				 strlen(options_CPU_short),
				 KEY_SPEC_THREAD_KEYRING);
		if (key[i] > 0)
			keys_available++;
	}

	fprintf(stderr, "     Info: got %d of %d system keys\n",
		keys_available, max_keyids);

	for (i = 1; i <= keys_available; i++) {
		if (keyctl(KEYCTL_INVALIDATE, key[i]) == -1)
			fprintf(stderr, "Invalidate failed Serial:%d\n",
				key[i]);
	}
	sleep(1);  /* Rest a bit while keys get freed. */
}

/*
 * TODO: Run out of keys, release 1, grab it, repeat
 * This test in not completed and is not in the run list.
 */
void test_keys_max_out(void)
{
	key_serial_t key[max_keyids + 1];
	int keys_available;
	char name[12];
	int i, ret;

	/* Get all the keys or as many as possible: keys_available */
	for (i = 1; i <= max_keyids; i++) {
		sprintf(name, "mk_max_%d", i);
		key[i] = add_key("mktme", name, options_CPU_short,
				 strlen(options_CPU_short),
				 KEY_SPEC_THREAD_KEYRING);
		if (key[i] < 0) {
			fprintf(stderr, "failed to get key[%d]\n", i);
			continue;
		}
	}
	keys_available = i - 1;
	if (keys_available < max_keyids)
		printf("Error: only got %d keys, expected %d\n",
		       keys_available, max_keyids);

	for (i = 1; i <= keys_available; i++) {
		if (keyctl(KEYCTL_INVALIDATE, key[i]) == -1)
			fprintf(stderr, "Invalidate failed key:%d\n", key[i]);
	}
}

/* Add each type of key */
void test_keys_add_each_type(void)
{
	key_serial_t key;
	int i;

	const char *options[] = {
		options_CPU_short, options_CPU_long, options_USER,
		options_CLEAR, options_NOENCRYPT
	};
	static const char *opt_name[] = {
		"add_key cpu_short", "add_key cpu_long", "add_key user",
		"add_key clear", "add_key no-encrypt"
	};

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		key = add_key("mktme", opt_name[i], options[i],
			      strlen(options[i]), KEY_SPEC_SESSION_KEYRING);

		if (key == -1) {
			perror(opt_name[i]);
		} else {
			perror(opt_name[i]);
			if (keyctl(KEYCTL_INVALIDATE, key) == -1)
				fprintf(stderr, "Key invalidate failed: %d\n",
					key);
		}
	}
}
