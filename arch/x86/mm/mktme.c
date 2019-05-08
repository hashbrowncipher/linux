#include <asm/mktme.h>

/* Mask to extract KeyID from physical address. */
phys_addr_t mktme_keyid_mask;
/*
 * Number of KeyIDs available for MKTME.
 * Excludes KeyID-0 which used by TME. MKTME KeyIDs start from 1.
 */
int mktme_nr_keyids;
/* Shift of KeyID within physical address. */
int mktme_keyid_shift;

DEFINE_STATIC_KEY_FALSE(mktme_enabled_key);
EXPORT_SYMBOL_GPL(mktme_enabled_key);

static bool need_page_mktme(void)
{
	/* Make sure keyid doesn't collide with extended page flags */
	BUILD_BUG_ON(__NR_PAGE_EXT_FLAGS > 16);

	return !!mktme_nr_keyids;
}

static void init_page_mktme(void)
{
	static_branch_enable(&mktme_enabled_key);
}

struct page_ext_operations page_mktme_ops = {
	.need = need_page_mktme,
	.init = init_page_mktme,
};
