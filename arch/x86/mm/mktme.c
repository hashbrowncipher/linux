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
