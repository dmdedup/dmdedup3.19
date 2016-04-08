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

#define DEDUP_HASH_DESC_COUNT 128

struct hash_desc_table {
	struct hash_desc desc[DEDUP_HASH_DESC_COUNT];
	bool free_bitmap[DEDUP_HASH_DESC_COUNT];
	atomic_long_t slot_counter;
} /*desc_table*/;

extern void desc_table_deinit(struct hash_desc_table *desc_table);
extern struct hash_desc_table *desc_table_init(char *crypt_alg);
extern int compute_hash_bio(struct hash_desc_table *desc_table,
				struct bio *bio, char *hash);
extern unsigned int get_hash_digestsize(struct hash_desc_table *desc_table);

#endif /* DM_DEDUP_HASH_H */
