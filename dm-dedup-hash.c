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

#include "dm-dedup-target.h"
#include "dm-dedup-hash.h"
#include <linux/atomic.h>
#include <linux/blk_types.h>

/*
 * We are declaring and initalizaing global hash_desc, because
 * we need to do hash computation in endio function, and this
 * function is called in softirq context. Hence we are not
 * allowed to perform any operation on that path which can sleep.
 * And tfm allocation in hash_desc, at one point, tries to take
 * semaphore and hence tries to sleep. And because of this we get
 * BUG, which complains "Scheduling while atomic". Hence to avoid
 * this scenario, we moved the declaration and initialization out
 * of critical path.
 */
static struct hash_desc *slot_to_desc(struct hash_desc_table *desc_table,
							unsigned long slot)
{
	BUG_ON(slot >= DEDUP_HASH_DESC_COUNT);
	return &(desc_table->desc[slot]);
}

struct hash_desc_table *desc_table_init(char *hash_alg)
{
	int i = 0;
	struct hash_desc *desc;
	struct hash_desc_table *desc_table;

	desc_table = kmalloc(sizeof(struct hash_desc_table), GFP_NOIO);
	if (!desc_table)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < DEDUP_HASH_DESC_COUNT; i++) {
		desc_table->free_bitmap[i] = true;
		desc = &desc_table->desc[i];
		desc->flags = 0;
		desc->tfm = crypto_alloc_hash(hash_alg, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(desc->tfm))
			return (struct hash_desc_table *)desc->tfm;
	}

	atomic_long_set(&(desc_table->slot_counter), 0);

	return desc_table;
}

void desc_table_deinit(struct hash_desc_table *desc_table)
{
	int i = 0;
	struct hash_desc *desc;

	for (i = 0; i < DEDUP_HASH_DESC_COUNT; i++) {
		desc = desc_table->desc + i;
		crypto_free_hash(desc->tfm);
	}

	kfree(desc_table);
	desc_table = NULL;
}

static int get_next_slot(struct hash_desc_table *desc_table)
{
	unsigned long num = 0;
	int count = 0;

	do {
		if (count == DEDUP_HASH_DESC_COUNT)
			return -EBUSY;

		count++;
		num = atomic_long_inc_return(&(desc_table->slot_counter));
		num = num % DEDUP_HASH_DESC_COUNT;

	} while (!desc_table->free_bitmap[num]);

	/* XXX: Possibility of race condition here. As checking of bitmap
	 *	and its setting is not happening in same step. But it will
	 *	work for now, as we declare atleast twice more hash_desc
	 *	then number of threads.
	 */
	desc_table->free_bitmap[num] = false;

	return num;
}

static void put_slot(struct hash_desc_table *desc_table, unsigned long slot)
{
	BUG_ON(slot >= DEDUP_HASH_DESC_COUNT);
	BUG_ON(desc_table->free_bitmap[slot]);
	desc_table->free_bitmap[slot] = true;
}

unsigned int get_hash_digestsize(struct hash_desc_table *desc_table)
{
	unsigned long slot;
	struct hash_desc *desc;

	slot = get_next_slot(desc_table);
	desc = slot_to_desc(desc_table, slot);

	return crypto_hash_digestsize(desc->tfm);
}

int compute_hash_bio(struct hash_desc_table *desc_table,
				struct bio *bio, char *hash)
{
	struct scatterlist sg;
	int ret = 0;
	unsigned long slot;
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct hash_desc *desc;

	slot = get_next_slot(desc_table);
	desc = slot_to_desc(desc_table, slot);

	ret = crypto_hash_init(desc);
	if (ret)
		goto out;

	sg_init_table(&sg, 1);
	__bio_for_each_segment(bvec, bio, iter, bio->bi_iter) {
		sg_set_page(&sg, bvec.bv_page, bvec.bv_len,
			    bvec.bv_offset);
		crypto_hash_update(desc, &sg, sg.length);
	}

	crypto_hash_final(desc, hash);
out:
	put_slot(desc_table, slot);
	return ret;
}
