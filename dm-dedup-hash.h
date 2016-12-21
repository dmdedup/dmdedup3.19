/*
 * Copyright (C) 2012-2014 Vasily Tarasov
 * Copyright (C) 2012-2014 Geoff Kuenning
 * Copyright (C) 2012-2014 Sonam Mandal
 * Copyright (C) 2012-2014 Karthikeyani Palanisami
 * Copyright (C) 2012-2014 Philip Shilane
 * Copyright (C) 2012-2014 Sagar Trehan
 * Copyright (C) 2012-2014 Erez Zadok
 *
 * This file is released under the GPL.
 */

#ifndef DM_DEDUP_HASH_H
#define DM_DEDUP_HASH_H

#include <linux/version.h>

#define DEDUP_HASH_DESC_COUNT 128

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0) //4.6.0-rc1
#define SHASH 1
#define crypto_alloc_hash crypto_alloc_shash
#define crypto_hash_final crypto_shash_final
#define crypto_hash_init crypto_shash_init
#define crypto_hash_update crypto_shash_update
#define crypto_hash_digestsize crypto_shash_digestsize
#define crypto_free_hash crypto_free_shash
#define hash_desc shash_desc
#endif

static inline int crypto_has_hash(const char *alg_name, u32 type, u32 mask)
{
        type &= ~CRYPTO_ALG_TYPE_MASK;
        mask &= ~CRYPTO_ALG_TYPE_MASK;
        type |= CRYPTO_ALG_TYPE_SHASH;
        mask |= CRYPTO_ALG_TYPE_HASH_MASK;

        return crypto_has_alg(alg_name, type, mask);
}

struct hash_desc_table {
#if SHASH
	union{
		/*Made as pointer from array to extra data allocation for context/state*/
		struct shash_desc *shd;//[DEDUP_HASH_DESC_COUNT];
		/*Added void pointer for better access, to increment byte wise*/
		void *desc;
	};
	uint32_t desc_state_size;
#else
	struct hash_desc desc[DEDUP_HASH_DESC_COUNT];
#endif
	bool free_bitmap[DEDUP_HASH_DESC_COUNT];
	atomic_long_t slot_counter;
} /*desc_table*/;

extern void desc_table_deinit(struct hash_desc_table *desc_table);
extern struct hash_desc_table *desc_table_init(char *crypt_alg);
extern int compute_hash_bio(struct hash_desc_table *desc_table,
				struct bio *bio, char *hash);
extern unsigned int get_hash_digestsize(struct hash_desc_table *desc_table);

#endif /* DM_DEDUP_HASH_H */
