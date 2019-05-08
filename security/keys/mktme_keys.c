// SPDX-License-Identifier: GPL-3.0

/* Documentation/x86/mktme_keys.rst */

#include <linux/cred.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/mm.h>
#include <linux/parser.h>
#include <linux/percpu-refcount.h>
#include <linux/random.h>
#include <linux/string.h>
#include <asm/intel_pconfig.h>
#include <keys/mktme-type.h>
#include <keys/user-type.h>

#include "internal.h"

static DEFINE_SPINLOCK(mktme_lock);
struct kmem_cache *mktme_prog_cache;	/* Hardware programming cache */
unsigned long *mktme_target_map;	/* Pconfig programming targets */
cpumask_var_t mktme_leadcpus;		/* One lead CPU per pconfig target */

/* 1:1 Mapping between Userspace Keys (struct key) and Hardware KeyIDs */
struct mktme_mapping {
	unsigned int	mapped_keyids;
	struct key	*key[];
};

struct mktme_mapping *mktme_map;

static inline long mktme_map_size(void)
{
	long size = 0;

	size += sizeof(*mktme_map);
	size += sizeof(mktme_map->key[0]) * (mktme_nr_keyids + 1);
	return size;
}

int mktme_map_alloc(void)
{
	mktme_map = kvzalloc(mktme_map_size(), GFP_KERNEL);
	if (!mktme_map)
		return -ENOMEM;
	return 0;
}

int mktme_reserve_keyid(struct key *key)
{
	int i;

	if (mktme_map->mapped_keyids == mktme_nr_keyids)
		return 0;

	for (i = 1; i <= mktme_nr_keyids; i++) {
		if (mktme_map->key[i] == 0) {
			mktme_map->key[i] = key;
			mktme_map->mapped_keyids++;
			return i;
		}
	}
	return 0;
}

void mktme_release_keyid(int keyid)
{
	mktme_map->key[keyid] = 0;
	mktme_map->mapped_keyids--;
}

int mktme_keyid_from_key(struct key *key)
{
	int i;

	for (i = 1; i <= mktme_nr_keyids; i++) {
		if (mktme_map->key[i] == key)
			return i;
	}
	return 0;
}

struct percpu_ref *encrypt_count;
void mktme_percpu_ref_release(struct percpu_ref *ref)
{
	unsigned long flags;
	int keyid;

	for (keyid = 1; keyid <= mktme_nr_keyids; keyid++) {
		if (&encrypt_count[keyid] == ref)
			break;
	}
	if (&encrypt_count[keyid] != ref) {
		pr_debug("%s: invalid ref counter\n", __func__);
		return;
	}
	percpu_ref_exit(ref);
	spin_lock_irqsave(&mktme_map_lock, flags);
	mktme_release_keyid(keyid);
	spin_unlock_irqrestore(&mktme_map_lock, flags);
}

enum mktme_opt_id {
	OPT_ERROR,
	OPT_TYPE,
	OPT_KEY,
	OPT_TWEAK,
	OPT_ALGORITHM,
};

static const match_table_t mktme_token = {
	{OPT_TYPE, "type=%s"},
	{OPT_KEY, "key=%s"},
	{OPT_TWEAK, "tweak=%s"},
	{OPT_ALGORITHM, "algorithm=%s"},
	{OPT_ERROR, NULL}
};

struct mktme_payload {
	u32		keyid_ctrl;	/* Command & Encryption Algorithm */
	u8		data_key[MKTME_AES_XTS_SIZE];
	u8		tweak_key[MKTME_AES_XTS_SIZE];
};

struct mktme_hw_program_info {
	struct mktme_key_program *key_program;
	int *status;
};

struct mktme_err_table {
	const char *msg;
	bool retry;
};

static const struct mktme_err_table mktme_error[] = {
/* MKTME_PROG_SUCCESS     */ {"KeyID was successfully programmed",   false},
/* MKTME_INVALID_PROG_CMD */ {"Invalid KeyID programming command",   false},
/* MKTME_ENTROPY_ERROR    */ {"Insufficient entropy",		      true},
/* MKTME_INVALID_KEYID    */ {"KeyID not valid",		     false},
/* MKTME_INVALID_ENC_ALG  */ {"Invalid encryption algorithm chosen", false},
/* MKTME_DEVICE_BUSY      */ {"Failure to access key table",	      true},
};

static int mktme_parse_program_status(int status[])
{
	int cpu, sum = 0;

	/* Success: all CPU(s) programmed all key table(s) */
	for_each_cpu(cpu, mktme_leadcpus)
		sum += status[cpu];
	if (!sum)
		return MKTME_PROG_SUCCESS;

	/* Invalid Parameters: log the error and return the error. */
	for_each_cpu(cpu, mktme_leadcpus) {
		switch (status[cpu]) {
		case MKTME_INVALID_KEYID:
		case MKTME_INVALID_PROG_CMD:
		case MKTME_INVALID_ENC_ALG:
			pr_err("mktme: %s\n", mktme_error[status[cpu]].msg);
			return status[cpu];

		default:
			break;
		}
	}
	/*
	 * Device Busy or Insufficient Entropy: do not log the
	 * error. These will be retried and if retries (time or
	 * count runs out) caller will log the error.
	 */
	for_each_cpu(cpu, mktme_leadcpus) {
		if (status[cpu] == MKTME_DEVICE_BUSY)
			return status[cpu];
	}
	return MKTME_ENTROPY_ERROR;
}

/* Program a single key using one CPU. */
static void mktme_do_program(void *hw_program_info)
{
	struct mktme_hw_program_info *info = hw_program_info;
	int cpu;

	cpu = smp_processor_id();
	info->status[cpu] = mktme_key_program(info->key_program);
}

static int mktme_program_all_keytables(struct mktme_key_program *key_program)
{
	struct mktme_hw_program_info info;
	int err, retries = 10; /* Maybe users should handle retries */

	info.key_program = key_program;
	info.status = kcalloc(num_possible_cpus(), sizeof(info.status[0]),
			      GFP_KERNEL);

	while (retries--) {
		get_online_cpus();
		on_each_cpu_mask(mktme_leadcpus, mktme_do_program,
				 &info, 1);
		put_online_cpus();

		err = mktme_parse_program_status(info.status);
		if (!err)			   /* Success */
			return err;
		else if (!mktme_error[err].retry)  /* Error no retry */
			return -ENOKEY;
	}
	/* Ran out of retries */
	pr_err("mktme: %s\n", mktme_error[err].msg);
	return err;
}

/* Copy the payload to the HW programming structure and program this KeyID */
static int mktme_program_keyid(int keyid, struct mktme_payload *payload)
{
	struct mktme_key_program *kprog = NULL;
	u8 kern_entropy[MKTME_AES_XTS_SIZE];
	int ret, i;

	kprog = kmem_cache_zalloc(mktme_prog_cache, GFP_ATOMIC);
	if (!kprog)
		return -ENOMEM;

	/* Hardware programming requires cached aligned struct */
	kprog->keyid = keyid;
	kprog->keyid_ctrl = payload->keyid_ctrl;
	memcpy(kprog->key_field_1, payload->data_key, MKTME_AES_XTS_SIZE);
	memcpy(kprog->key_field_2, payload->tweak_key, MKTME_AES_XTS_SIZE);

	/* Strengthen the entropy fields for CPU generated keys */
	if ((payload->keyid_ctrl & 0xff) == MKTME_KEYID_SET_KEY_RANDOM) {
		get_random_bytes(&kern_entropy, sizeof(kern_entropy));
		for (i = 0; i < (MKTME_AES_XTS_SIZE); i++) {
			kprog->key_field_1[i] ^= kern_entropy[i];
			kprog->key_field_2[i] ^= kern_entropy[i];
		}
	}
	ret = mktme_program_all_keytables(kprog);
	kmem_cache_free(mktme_prog_cache, kprog);
	return ret;
}

/* Key Service Method called when a Userspace Key is garbage collected. */
static void mktme_destroy_key(struct key *key)
{
	int keyid = mktme_keyid_from_key(key);

	mktme_map->key[keyid] = (void *)-1;
	percpu_ref_kill(&encrypt_count[keyid]);
}

/* Key Service Method to create a new key. Payload is preparsed. */
int mktme_instantiate_key(struct key *key, struct key_preparsed_payload *prep)
{
	struct mktme_payload *payload = prep->payload.data[0];
	unsigned long flags;
	int keyid;

	spin_lock_irqsave(&mktme_lock, flags);
	keyid = mktme_reserve_keyid(key);
	spin_unlock_irqrestore(&mktme_lock, flags);
	if (!keyid)
		return -ENOKEY;

	if (percpu_ref_init(&encrypt_count[keyid], mktme_percpu_ref_release,
			    0, GFP_KERNEL))
		goto err_out;

	if (!mktme_program_keyid(keyid, payload))
		return MKTME_PROG_SUCCESS;

	percpu_ref_exit(&encrypt_count[keyid]);
err_out:
	spin_lock_irqsave(&mktme_lock, flags);
	mktme_release_keyid(keyid);
	spin_unlock_irqrestore(&mktme_lock, flags);
	return -ENOKEY;
}

/* Make sure arguments are correct for the TYPE of key requested */
static int mktme_check_options(struct mktme_payload *payload,
			       unsigned long token_mask, enum mktme_type type)
{
	if (!token_mask)
		return -EINVAL;

	switch (type) {
	case MKTME_TYPE_USER:
		if (test_bit(OPT_ALGORITHM, &token_mask))
			payload->keyid_ctrl |= MKTME_AES_XTS_128;
		else
			return -EINVAL;

		if ((test_bit(OPT_KEY, &token_mask)) &&
		    (test_bit(OPT_TWEAK, &token_mask)))
			payload->keyid_ctrl |= MKTME_KEYID_SET_KEY_DIRECT;
		else
			return -EINVAL;
		break;

	case MKTME_TYPE_CPU:
		if (test_bit(OPT_ALGORITHM, &token_mask))
			payload->keyid_ctrl |= MKTME_AES_XTS_128;
		else
			return -EINVAL;

		payload->keyid_ctrl |= MKTME_KEYID_SET_KEY_RANDOM;
		break;

	case MKTME_TYPE_NO_ENCRYPT:
		payload->keyid_ctrl |= MKTME_KEYID_NO_ENCRYPT;
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

/* Parse the options and store the key programming data in the payload. */
static int mktme_get_options(char *options, struct mktme_payload *payload)
{
	enum mktme_type type = MKTME_TYPE_ERROR;
	substring_t args[MAX_OPT_ARGS];
	unsigned long token_mask = 0;
	char *p = options;
	int ret, token;

	while ((p = strsep(&options, " \t"))) {
		if (*p == '\0' || *p == ' ' || *p == '\t')
			continue;
		token = match_token(p, mktme_token, args);
		if (token == OPT_ERROR)
			return -EINVAL;
		if (test_and_set_bit(token, &token_mask))
			return -EINVAL;

		switch (token) {
		case OPT_KEY:
			ret = hex2bin(payload->data_key, args[0].from,
				      MKTME_AES_XTS_SIZE);
			if (ret < 0)
				return -EINVAL;
			break;

		case OPT_TWEAK:
			ret = hex2bin(payload->tweak_key, args[0].from,
				      MKTME_AES_XTS_SIZE);
			if (ret < 0)
				return -EINVAL;
			break;

		case OPT_TYPE:
			type = match_string(mktme_type_names,
					    ARRAY_SIZE(mktme_type_names),
					    args[0].from);
			if (type < 0)
				return -EINVAL;
			break;

		case OPT_ALGORITHM:
			ret = match_string(mktme_alg_names,
					   ARRAY_SIZE(mktme_alg_names),
					   args[0].from);
			if (ret < 0)
				return -EINVAL;
			break;

		default:
			return -EINVAL;
		}
	}
	return mktme_check_options(payload, token_mask, type);
}

void mktme_free_preparsed_payload(struct key_preparsed_payload *prep)
{
	kzfree(prep->payload.data[0]);
}

/*
 * Key Service Method to preparse a payload before a key is created.
 * Check permissions and the options. Load the proposed key field
 * data into the payload for use by the instantiate method.
 */
int mktme_preparse_payload(struct key_preparsed_payload *prep)
{
	struct mktme_payload *mktme_payload;
	size_t datalen = prep->datalen;
	char *options;
	int ret;

	if (!capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (datalen <= 0 || datalen > 1024 || !prep->data)
		return -EINVAL;

	options = kmemdup_nul(prep->data, datalen, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	mktme_payload = kzalloc(sizeof(*mktme_payload), GFP_KERNEL);
	if (!mktme_payload) {
		ret = -ENOMEM;
		goto out;
	}
	ret = mktme_get_options(options, mktme_payload);
	if (ret < 0) {
		kzfree(mktme_payload);
		goto out;
	}
	prep->quotalen = sizeof(mktme_payload);
	prep->payload.data[0] = mktme_payload;
out:
	kzfree(options);
	return ret;
}

struct key_type key_type_mktme = {
	.name		= "mktme",
	.preparse	= mktme_preparse_payload,
	.free_preparse	= mktme_free_preparsed_payload,
	.instantiate	= mktme_instantiate_key,
	.describe	= user_describe,
	.destroy	= mktme_destroy_key,
};

static void mktme_update_pconfig_targets(void)
{
	int cpu, target_id;

	cpumask_clear(mktme_leadcpus);
	bitmap_clear(mktme_target_map, 0, sizeof(mktme_target_map));

	for_each_online_cpu(cpu) {
		target_id = topology_physical_package_id(cpu);
		if (!__test_and_set_bit(target_id, mktme_target_map))
			__cpumask_set_cpu(cpu, mktme_leadcpus);
	}
}

static int mktme_alloc_pconfig_targets(void)
{
	if (!alloc_cpumask_var(&mktme_leadcpus, GFP_KERNEL))
		return -ENOMEM;

	mktme_target_map = bitmap_alloc(topology_max_packages(), GFP_KERNEL);
	if (!mktme_target_map) {
		free_cpumask_var(mktme_leadcpus);
		return -ENOMEM;
	}
	return 0;
}

static int __init init_mktme(void)
{
	int ret;

	/* Verify keys are present */
	if (mktme_nr_keyids < 1)
		return 0;

	/* Mapping of Userspace Keys to Hardware KeyIDs */
	if (mktme_map_alloc())
		return -ENOMEM;

	/* Used to program the hardware key tables */
	mktme_prog_cache = KMEM_CACHE(mktme_key_program, SLAB_PANIC);
	if (!mktme_prog_cache)
		goto free_map;

	/* Hardware programming targets */
	if (mktme_alloc_pconfig_targets())
		goto free_cache;

	/* Initialize first programming targets */
	mktme_update_pconfig_targets();

	/* Reference counters to protect in use KeyIDs */
	encrypt_count = kvcalloc(mktme_nr_keyids + 1, sizeof(encrypt_count[0]),
				 GFP_KERNEL);
	if (!encrypt_count)
		goto free_targets;

	ret = register_key_type(&key_type_mktme);
	if (!ret)
		return ret;			/* SUCCESS */

	kvfree(encrypt_count);
free_targets:
	free_cpumask_var(mktme_leadcpus);
	bitmap_free(mktme_target_map);
free_cache:
	kmem_cache_destroy(mktme_prog_cache);
free_map:
	kvfree(mktme_map);

	return -ENOMEM;
}

late_initcall(init_mktme);
