#include <linux/mm.h>
#include <linux/highmem.h>
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

int __vma_keyid(struct vm_area_struct *vma)
{
	pgprotval_t prot = pgprot_val(vma->vm_page_prot);
	return (prot & mktme_keyid_mask) >> mktme_keyid_shift;
}

/* Prepare page to be used for encryption. Called from page allocator. */
void __prep_encrypted_page(struct page *page, int order, int keyid, bool zero)
{
	int i;

	/*
	 * The hardware/CPU does not enforce coherency between mappings
	 * of the same physical page with different KeyIDs or
	 * encryption keys. We are responsible for cache management.
	 */
	clflush_cache_range(page_address(page), PAGE_SIZE * (1UL << order));

	for (i = 0; i < (1 << order); i++) {
		/* All pages coming out of the allocator should have KeyID 0 */
		WARN_ON_ONCE(lookup_page_ext(page)->keyid);
		lookup_page_ext(page)->keyid = keyid;

		/* Clear the page after the KeyID is set. */
		if (zero)
			clear_highpage(page);

		page++;
	}
}

/*
 * Handles freeing of encrypted page.
 * Called from page allocator on freeing encrypted page.
 */
void free_encrypted_page(struct page *page, int order)
{
	int i;

	/*
	 * The hardware/CPU does not enforce coherency between mappings
	 * of the same physical page with different KeyIDs or
	 * encryption keys. We are responsible for cache management.
	 */
	clflush_cache_range(page_address(page), PAGE_SIZE * (1UL << order));

	for (i = 0; i < (1 << order); i++) {
		/* Check if the page has reasonable KeyID */
		WARN_ON_ONCE(lookup_page_ext(page)->keyid > mktme_nr_keyids);
		lookup_page_ext(page)->keyid = 0;
		page++;
	}
}
