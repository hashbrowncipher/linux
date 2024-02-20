/* SPDX-License-Identifier: GPL-2.0 */

/* Key service for Multi-KEY Total Memory Encryption */

#ifndef _KEYS_MKTME_TYPE_H
#define _KEYS_MKTME_TYPE_H

#include <linux/key.h>

/*
 * The AES-XTS 128 encryption algorithm requires 128 bits for each
 * user supplied data key and tweak key.
 */
#define MKTME_AES_XTS_SIZE	16	/* 16 bytes, 128 bits */

enum mktme_alg {
	MKTME_ALG_AES_XTS_128,
};

const char *const mktme_alg_names[] = {
	[MKTME_ALG_AES_XTS_128]	= "aes-xts-128",
};

enum mktme_type {
	MKTME_TYPE_ERROR = -1,
	MKTME_TYPE_USER,
	MKTME_TYPE_CPU,
	MKTME_TYPE_NO_ENCRYPT,
};

const char *const mktme_type_names[] = {
	[MKTME_TYPE_USER]	= "user",
	[MKTME_TYPE_CPU]	= "cpu",
	[MKTME_TYPE_NO_ENCRYPT]	= "no-encrypt",
};

extern struct key_type key_type_mktme;

#endif /* _KEYS_MKTME_TYPE_H */
