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

#include <linux/vmalloc.h>
#include <linux/errno.h>

#include "dm-dedup-kvstore.h"
#include "dm-dedup-ram.h"
#include "dm-dedup-backend.h"

#define EMPTY_ENTRY -5
#define DELETED_ENTRY -6

#define UINT32_MAX	(4294967295U)
#define HASHTABLE_OVERPROV	(10)

struct metadata {
	/* Space Map */
	uint32_t *smap;
	uint64_t smax;
	uint64_t allocptr;

	/*
	 * XXX: Currently we support only one linear and one sparse KVS.
	 */
	struct kvstore_inram *kvs_linear;
	struct kvstore_inram *kvs_sparse;
};

struct kvstore_inram {
	struct kvstore ckvs;
	uint32_t kmax;
	char *store;
};

static struct metadata *init_meta_inram(void *init_param, bool *unformatted)
{
	uint64_t smap_size, tmp;
	struct metadata *md;
	struct init_param_inram *p = (struct init_param_inram *)init_param;

	DMINFO("Initializing INRAM backend");

	*unformatted = true;

	md = kmalloc(sizeof(*md), GFP_NOIO);
	if (!md)
		return ERR_PTR(-ENOMEM);

	smap_size = p->blocks * sizeof(uint32_t);

	md->smap = vmalloc(smap_size);
	if (!md->smap) {
		kfree(md);
		return ERR_PTR(-ENOMEM);
	}

	tmp = smap_size;
	(void) do_div(tmp, (1024 * 1024));
	DMINFO("Space allocated for pbn reference count map: %llu.%06llu MB\n",
	       tmp, smap_size - (tmp * (1024 * 1024)));

	memset(md->smap, 0, smap_size);

	md->smax = p->blocks;
	md->allocptr = 0;
	md->kvs_linear = NULL;
	md->kvs_sparse = NULL;

	return md;
}

static void exit_meta_inram(struct metadata *md)
{
	if (md->smap)
		vfree(md->smap);

	if (md->kvs_linear) {
		if (md->kvs_linear->store)
			vfree(md->kvs_linear->store);
		kfree(md->kvs_linear);
	}

	if (md->kvs_sparse) {
		if (md->kvs_sparse->store)
			vfree(md->kvs_sparse->store);
		kfree(md->kvs_sparse);
	}

	kfree(md);
}


static int flush_meta_inram(struct metadata *md)
{
	return 0;
}

/********************************************************
 *		Space Management Functions		*
 ********************************************************/

static uint64_t next_head(uint64_t current_head, uint64_t smax)
{
	current_head += 1;
	return dm_sector_div64(current_head, smax);
}

static int alloc_data_block_inram(struct metadata *md, uint64_t *blockn)
{
	uint64_t head, tail;

	head = tail = md->allocptr;

	do {
		if (!md->smap[head]) {
			md->smap[head] = 1;
			*blockn = head;
			md->allocptr = next_head(head, md->smax);
			return 0;
		}

		head = next_head(head, md->smax);

	} while (head != tail);

	return -ENOSPC;
}

static int inc_refcount_inram(struct metadata *md, uint64_t blockn)
{
	if (blockn >= md->smax)
		return -ERANGE;

	if (md->smap[blockn] != UINT32_MAX)
		md->smap[blockn]++;
	else
		return -E2BIG;

	return 0;
}

static int dec_refcount_inram(struct metadata *md, uint64_t blockn)
{
	if (blockn >= md->smax)
		return -ERANGE;

	if (md->smap[blockn])
		md->smap[blockn]--;
	else
		return -EFAULT;

	return 0;
}

static int get_refcount_inram(struct metadata *md, uint64_t blockn)
{
	if (blockn >= md->smax)
		return -ERANGE;

	return md->smap[blockn];
}

/********************************************************
 *		General KVS Functions			*
 ********************************************************/

static int is_empty(char *ptr, int length)
{
	int i = 0;

	while ((i < length) && (ptr[i] == EMPTY_ENTRY))
		i++;

	return i == length;
}

static int is_deleted(char *ptr, int length)
{
	int i = 0;

	while ((i < length) && (ptr[i] == DELETED_ENTRY))
		i++;

	return i == length;
}

/*********************************************************
 *		Linear KVS Functions			 *
 *********************************************************/

static int kvs_delete_linear_inram(struct kvstore *kvs,
					void *key, int32_t ksize)
{
	uint64_t idx;
	char *ptr;
	struct kvstore_inram *kvinram = NULL;

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	idx = *((uint64_t *)key);

	if (idx > kvinram->kmax)
		return -ERANGE;

	ptr = kvinram->store + kvs->vsize * idx;

	if (is_empty(ptr, kvs->vsize))
		return -ENODEV;

	memset(ptr, EMPTY_ENTRY, kvs->vsize);

	return 0;
}

/*
 * 0 - not found
 * 1 - found
 * < 0 - error on lookup
 */
static int kvs_lookup_linear_inram(struct kvstore *kvs, void *key,
			int32_t ksize, void *value, int32_t *vsize)
{
	uint64_t idx;
	char *ptr;
	struct kvstore_inram *kvinram = NULL;

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	idx = *((uint64_t *)key);

	if (idx > kvinram->kmax)
		return -ERANGE;

	ptr = kvinram->store + kvs->vsize * idx;

	if (is_empty(ptr, kvs->vsize))
		return 0;

	memcpy(value, ptr, kvs->vsize);
	*vsize = kvs->vsize;

	return 1;
}

static int kvs_insert_linear_inram(struct kvstore *kvs, void *key,
				int32_t ksize, void *value,
				int32_t vsize)
{
	uint64_t idx;
	char *ptr;
	struct kvstore_inram *kvinram = NULL;

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	if (vsize != kvs->vsize)
		return -EINVAL;

	idx = *((uint64_t *)key);

	if (idx > kvinram->kmax)
		return -ERANGE;

	ptr = kvinram->store + kvs->vsize * idx;

	memcpy(ptr, value, kvs->vsize);

	return 0;
}

/*
 * NOTE: if iteration_action() is a deletion/cleanup function,
 *	Make sure that the store is implemented such that
 *	deletion in-place is safe while iterating.
 */
static int kvs_iterate_linear_inram(struct kvstore *kvs,
		int (*iteration_action)(void *key, int32_t ksize,
		void *value, int32_t vsize, void *data), void *data)
{
	int ret = 0;
	uint64_t i = 0;
	char *ptr = NULL;
	struct kvstore_inram *kvinram = NULL;

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	for (i = 0; i < kvinram->kmax; i++) {
		ptr = kvinram->store + (i * kvs->vsize);

		ret = is_empty(ptr, kvs->vsize);

		if (!ret) {
			ret = iteration_action((void *)&i, kvs->ksize,
					(void *)ptr, kvs->vsize, data);
			if (ret < 0)
				goto out;
		}
	}

out:
	return ret;
}

static struct kvstore *kvs_create_linear_inram(struct metadata *md,
			uint32_t ksize, uint32_t vsize, uint32_t kmax,
			bool unformatted)
{
	struct kvstore_inram *kvs;
	uint64_t kvstore_size, tmp;

	if (!vsize || !ksize || !kmax)
		return ERR_PTR(-ENOTSUPP);

	/* Currently only 64bit keys are supported */
	if (ksize != 8)
		return ERR_PTR(-ENOTSUPP);

	/* We do not support two or more KVSs at the moment */
	if (md->kvs_linear)
		return ERR_PTR(-EBUSY);

	kvs = kmalloc(sizeof(*kvs), GFP_NOIO);
	if (!kvs)
		return ERR_PTR(-ENOMEM);

	kvstore_size = (kmax + 1) * vsize;
	kvs->store = vmalloc(kvstore_size);
	if (!kvs->store) {
		kfree(kvs);
		return ERR_PTR(-ENOMEM);
	}

	tmp = kvstore_size;
	(void) do_div(tmp, (1024 * 1024));
	DMINFO("Space allocated for linear key value store: %llu.%06llu MB\n",
	       tmp, kvstore_size - (tmp * (1024 * 1024)));

	memset(kvs->store, EMPTY_ENTRY, kvstore_size);

	kvs->ckvs.vsize = vsize;
	kvs->ckvs.ksize = ksize;
	kvs->kmax = kmax;

	kvs->ckvs.kvs_insert = kvs_insert_linear_inram;
	kvs->ckvs.kvs_lookup = kvs_lookup_linear_inram;
	kvs->ckvs.kvs_delete = kvs_delete_linear_inram;
	kvs->ckvs.kvs_iterate = kvs_iterate_linear_inram;
	md->kvs_linear = kvs;

	return &(kvs->ckvs);
}

/********************************************************
 *		Sparse KVS Functions			*
 ********************************************************/

static int kvs_delete_sparse_inram(struct kvstore *kvs,
				   void *key, int32_t ksize)
{
	uint64_t idxhead = *((uint64_t *)key);
	uint32_t entry_size, head, tail;
	char *ptr;
	struct kvstore_inram *kvinram = NULL;

	if (ksize != kvs->ksize)
		return -EINVAL;

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	entry_size = kvs->vsize + kvs->ksize;
	head = do_div(idxhead, kvinram->kmax);
	tail = head;

	do {
		ptr = kvinram->store + entry_size * head;

		if (is_empty(ptr, entry_size))
			goto doesnotexist;

		if (memcmp(ptr, key, kvs->ksize))
			head = next_head(head, kvinram->kmax);
		else {
			memset(ptr, DELETED_ENTRY, entry_size);
			return 0;
		}
	} while (head != tail);

doesnotexist:
	return -ENODEV;
}

/*
 * 0 - not found
 * 1 - found
 * < 0 - error on lookup
 */
static int kvs_lookup_sparse_inram(struct kvstore *kvs, void *key,
				   int32_t ksize, void *value, int32_t *vsize)
{
	uint64_t idxhead = *((uint64_t *)key);
	uint32_t entry_size, head, tail;
	char *ptr;
	struct kvstore_inram *kvinram = NULL;

	if (ksize != kvs->ksize)
		return -EINVAL;

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	entry_size = kvs->vsize + kvs->ksize;
	head = do_div(idxhead, kvinram->kmax);
	tail = head;

	do {
		ptr = kvinram->store + entry_size * head;

		if (is_empty(ptr, entry_size))
			return 0;

		if (memcmp(ptr, key, kvs->ksize))
			head = next_head(head, kvinram->kmax);
		else {
			memcpy(value, ptr + kvs->ksize, kvs->vsize);
			return 1;
		}

	} while (head != tail);

	return 0;
}

static int kvs_insert_sparse_inram(struct kvstore *kvs, void *key,
				   int32_t ksize, void *value, int32_t vsize)
{
	uint64_t idxhead = *((uint64_t *)key);
	uint32_t entry_size, head, tail;
	char *ptr;
	struct kvstore_inram *kvinram = NULL;

	BUG_ON(!kvs);

	if (ksize > kvs->ksize)
		return -EINVAL;

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	entry_size = kvs->vsize + kvs->ksize;
	head = do_div(idxhead, kvinram->kmax);
	tail = head;

	do {
		ptr = kvinram->store + entry_size * head;

		if (is_empty(ptr, entry_size) || is_deleted(ptr, entry_size)) {
			memcpy(ptr, key, kvs->ksize);
			memcpy(ptr + kvs->ksize, value, kvs->vsize);
			return 0;
		}

		head = next_head(head, kvinram->kmax);

	} while (head != tail);

	return -ENOSPC;
}

/*
 *
 * NOTE: if iteration_action() is a deletion/cleanup function,
 *	 Make sure that the store is implemented such that
 *	 deletion in-place is safe while iterating.
 */
static int kvs_iterate_sparse_inram(struct kvstore *kvs,
		int (*iteration_action)(void *key, int32_t ksize,
		void *value, int32_t vsize, void *data), void *data)
{
	int err = 0;
	uint32_t kvalue_size, head = 0;
	char *ptr = NULL;
	struct kvstore_inram *kvinram = NULL;

	BUG_ON(!kvs);

	kvinram = container_of(kvs, struct kvstore_inram, ckvs);

	kvalue_size = kvs->vsize + kvs->ksize;

	do {
		ptr = kvinram->store + (head * kvalue_size);

		if (!is_empty(ptr, kvalue_size) &&
			!is_deleted(ptr, kvalue_size)) {
			err = iteration_action((void *)ptr, kvs->ksize,
					(void *)(ptr + kvs->ksize),
					kvs->vsize, data);

			if (err < 0)
				goto out;
		}

		head = next_head(head, kvinram->kmax);
	} while (head);

out:
	return err;
}

static struct kvstore *kvs_create_sparse_inram(struct metadata *md,
			uint32_t ksize, uint32_t vsize, uint32_t knummax,
			bool unformatted)
{
	struct kvstore_inram *kvs;
	uint64_t kvstore_size, tmp;

	if (!vsize || !ksize || !knummax)
		return ERR_PTR(-ENOTSUPP);

	/* We do not support two or more KVSs at the moment */
	if (md->kvs_sparse)
		return ERR_PTR(-EBUSY);

	kvs = kmalloc(sizeof(*kvs), GFP_NOIO);
	if (!kvs)
		return ERR_PTR(-ENOMEM);

	knummax += (knummax * HASHTABLE_OVERPROV) / 100;

	kvstore_size = (knummax * (vsize + ksize));

	kvs->store = vmalloc(kvstore_size);
	if (!kvs->store) {
		kfree(kvs);
		return ERR_PTR(-ENOMEM);
	}

	tmp = kvstore_size;
	(void) do_div(tmp, (1024 * 1024));
	DMINFO("Space allocated for sparse key value store: %llu.%06llu MB\n",
	       tmp, kvstore_size - (tmp * (1024 * 1024)));

	memset(kvs->store, EMPTY_ENTRY, kvstore_size);

	kvs->ckvs.vsize = vsize;
	kvs->ckvs.ksize = ksize;
	kvs->kmax = knummax;

	kvs->ckvs.kvs_insert = kvs_insert_sparse_inram;
	kvs->ckvs.kvs_lookup = kvs_lookup_sparse_inram;
	kvs->ckvs.kvs_delete = kvs_delete_sparse_inram;
	kvs->ckvs.kvs_iterate = kvs_iterate_sparse_inram;

	md->kvs_sparse = kvs;

	return &(kvs->ckvs);
}

struct metadata_ops metadata_ops_inram = {
	.init_meta = init_meta_inram,
	.exit_meta = exit_meta_inram,
	.kvs_create_linear = kvs_create_linear_inram,
	.kvs_create_sparse = kvs_create_sparse_inram,

	.alloc_data_block = alloc_data_block_inram,
	.inc_refcount = inc_refcount_inram,
	.dec_refcount = dec_refcount_inram,
	.get_refcount = get_refcount_inram,

	.flush_meta = flush_meta_inram,

	.flush_bufio_cache = NULL,
};
