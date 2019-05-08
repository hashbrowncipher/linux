#include <linux/mm.h>
#include <asm/mem_encrypt.h>
#include <asm/mktme.h>

/*
 * Encryption bits need to be set and cleared for both Intel MKTME and
 * AMD SME when converting between DMA address and physical address.
 */
dma_addr_t __mem_encrypt_dma_set(dma_addr_t daddr, phys_addr_t paddr)
{
	unsigned long keyid;

	if (sme_active())
		return __sme_set(daddr);
	keyid = page_keyid(pfn_to_page(__phys_to_pfn(paddr)));

	return (daddr & ~mktme_keyid_mask) | (keyid << mktme_keyid_shift);
}
EXPORT_SYMBOL_GPL(__mem_encrypt_dma_set);

phys_addr_t __mem_encrypt_dma_clear(phys_addr_t paddr)
{
	if (sme_active())
		return __sme_clr(paddr);

	return paddr & ~mktme_keyid_mask;
}
EXPORT_SYMBOL_GPL(__mem_encrypt_dma_clear);
