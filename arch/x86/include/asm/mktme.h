#ifndef	_ASM_X86_MKTME_H
#define	_ASM_X86_MKTME_H

#include <linux/types.h>

#ifdef CONFIG_X86_INTEL_MKTME
extern phys_addr_t mktme_keyid_mask;
extern int mktme_nr_keyids;
extern int mktme_keyid_shift;
#else
#define mktme_keyid_mask	((phys_addr_t)0)
#define mktme_nr_keyids		0
#define mktme_keyid_shift	0
#endif

#endif
