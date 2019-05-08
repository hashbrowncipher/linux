// SPDX-License-Identifier: GPL-3.0

/* Documentation/x86/mktme_keys.rst */

#include <linux/init.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/mm.h>
#include <keys/user-type.h>

#include "internal.h"

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

struct key_type key_type_mktme = {
	.name		= "mktme",
	.describe	= user_describe,
};

static int __init init_mktme(void)
{
	int ret;

	/* Verify keys are present */
	if (mktme_nr_keyids < 1)
		return 0;

	/* Mapping of Userspace Keys to Hardware KeyIDs */
	if (mktme_map_alloc())
		return -ENOMEM;

	ret = register_key_type(&key_type_mktme);
	if (!ret)
		return ret;			/* SUCCESS */

	kvfree(mktme_map);

	return -ENOMEM;
}

late_initcall(init_mktme);
