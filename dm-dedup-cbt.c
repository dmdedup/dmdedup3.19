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

#include <linux/errno.h>
#include "persistent-data/dm-btree.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-disk.h"
#include "persistent-data/dm-block-manager.h"
#include "persistent-data/dm-transaction-manager.h"

#include "dm-dedup-cbt.h"
#include "dm-dedup-backend.h"
#include "dm-dedup-kvstore.h"

#define EMPTY_ENTRY -5
#define DELETED_ENTRY -6

#define UINT32_MAX	(4294967295U)

#define METADATA_BSIZE 4096
#define METADATA_CACHESIZE 64  /* currently block manager ignores this value */
#define METADATA_MAXLOCKS 5
#define METADATA_SUPERBLOCK_LOCATION 0

struct metadata {
	struct dm_block_manager *meta_bm;
	struct dm_transaction_manager *tm;
	struct dm_space_map *data_sm;
	struct dm_space_map *meta_sm;

	/*
	 * XXX: Currently we support only one linear and one sparse KVS.
	 */
	struct kvstore_cbt *kvs_linear;
	struct kvstore_cbt *kvs_sparse;
};

struct kvstore_cbt {
	struct kvstore ckvs;
	uint32_t entry_size;	/* for sparse only */

	struct dm_btree_info info;
	uint64_t root;
};

#define SPACE_MAP_ROOT_SIZE 128

struct metadata_superblock {
	__le32 csum; /* Checksum of superblock except for this field. */
	__le32 flags; /* General purpose flags. Not used. */
	__le64 blocknr;	/* This block number, dm_block_t. */
	__u8 uuid[16]; /* UUID of device (Not used) */
	__le64 magic; /* Magic number to check against */
	__le32 version;	/* Metadata root version */
	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];/* Metadata space
							     map */
	__u8 data_space_map_root[SPACE_MAP_ROOT_SIZE]; /* Data space map */
	__le64 lbn_pbn_root; /* lbn pbn btree root. */
	__le64 hash_pbn_root; /* hash pbn btree root. */
	__le32 data_block_size;	/* In bytes */
	__le32 metadata_block_size; /* In bytes */
	__le64 metadata_nr_blocks;/* Number of metadata blocks used. */
} __packed;

static int __begin_transaction(struct metadata *md)
{
	int r;
	struct metadata_superblock *disk_super;
	struct dm_block *sblock;

	r = dm_bm_read_lock(md->meta_bm, METADATA_SUPERBLOCK_LOCATION,
			    NULL, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);

	if (md->kvs_linear)
		md->kvs_linear->root = le64_to_cpu(disk_super->lbn_pbn_root);

	if (md->kvs_sparse)
		md->kvs_sparse->root = le64_to_cpu(disk_super->hash_pbn_root);

	dm_bm_unlock(sblock);

	return r;
}

static int __commit_transaction(struct metadata *md)
{
	int r = 0;
	size_t metadata_len, data_len;
	struct metadata_superblock *disk_super;
	struct dm_block *sblock;

	BUILD_BUG_ON(sizeof(struct metadata_superblock) > 512);

	r = dm_sm_commit(md->data_sm);
	if (r < 0)
		goto out;

	r = dm_tm_pre_commit(md->tm);
	if (r < 0)
		goto out;

	r = dm_sm_root_size(md->meta_sm, &metadata_len);
	if (r < 0)
		goto out;

	r = dm_sm_root_size(md->data_sm, &data_len);
	if (r < 0)
		goto out;

	r = dm_bm_write_lock(md->meta_bm, METADATA_SUPERBLOCK_LOCATION,
			     NULL, &sblock);
	if (r)
		goto out;

	disk_super = dm_block_data(sblock);

	if (md->kvs_linear)
		disk_super->lbn_pbn_root = cpu_to_le64(md->kvs_linear->root);

	if (md->kvs_sparse)
		disk_super->hash_pbn_root = cpu_to_le64(md->kvs_sparse->root);

	r = dm_sm_copy_root(md->meta_sm,
			    &disk_super->metadata_space_map_root, metadata_len);
	if (r < 0)
		goto out_locked;

	r = dm_sm_copy_root(md->data_sm, &disk_super->data_space_map_root,
			    data_len);
	if (r < 0)
		goto out_locked;

	r = dm_tm_commit(md->tm, sblock);

out:
	return r;

out_locked:
	dm_bm_unlock(sblock);
	return r;
}

static int write_initial_superblock(struct metadata *md)
{
	int r;
	size_t meta_len, data_len;
	struct dm_block *sblock;
	struct metadata_superblock *disk_super;

	r = dm_sm_root_size(md->meta_sm, &meta_len);
	if (r < 0)
		return r;

	r = dm_sm_root_size(md->data_sm, &data_len);
	if (r < 0)
		return r;

	r = dm_sm_commit(md->data_sm);
	if (r < 0)
		return r;

	r = dm_tm_pre_commit(md->tm);
	if (r < 0)
		return r;

	r = dm_bm_write_lock_zero(md->meta_bm, METADATA_SUPERBLOCK_LOCATION,
				  NULL, &sblock);
	if (r < 0)
		return r;

	disk_super = dm_block_data(sblock);

	r = dm_sm_copy_root(md->meta_sm, &disk_super->metadata_space_map_root,
			    meta_len);
	if (r < 0)
		goto bad_locked;

	r = dm_sm_copy_root(md->data_sm, &disk_super->data_space_map_root,
			    data_len);
	if (r < 0)
		goto bad_locked;

	return dm_tm_commit(md->tm, sblock);

bad_locked:
	dm_bm_unlock(sblock);
	return r;
}

static int superblock_all_zeroes(struct dm_block_manager *bm, bool *result)
{
	int r;
	unsigned i;
	struct dm_block *b;
	__le64 *data_le, zero = cpu_to_le64(0);
	unsigned sb_block_size = dm_bm_block_size(bm) / sizeof(__le64);

	/*
	 * We can't use a validator here - it may be all zeroes.
	 */
	r = dm_bm_read_lock(bm, METADATA_SUPERBLOCK_LOCATION, NULL, &b);
	if (r)
		return r;

	data_le = dm_block_data(b);
	*result = true;
	for (i = 0; i < sb_block_size; i++) {
		if (data_le[i] != zero) {
			*result = false;
			break;
		}
	}

	return dm_bm_unlock(b);
}

static struct metadata *init_meta_cowbtree(void *input_param, bool *unformatted)
{
	int ret;
	struct metadata *md;
	struct dm_block_manager *meta_bm;
	struct dm_space_map *meta_sm;
	struct dm_space_map *data_sm = NULL;
	struct dm_transaction_manager *tm;
	struct init_param_cowbtree *p =
				(struct init_param_cowbtree *)input_param;

	DMINFO("Initializing COWBTREE backend");

	md = kzalloc(sizeof(*md), GFP_NOIO);
	if (!md)
		return ERR_PTR(-ENOMEM);

	meta_bm = dm_block_manager_create(p->metadata_bdev, METADATA_BSIZE,
					  METADATA_CACHESIZE, METADATA_MAXLOCKS);
	if (IS_ERR(meta_bm)) {
		md = (struct metadata *)meta_bm;
		goto badbm;
	}

	ret = superblock_all_zeroes(meta_bm, unformatted);
	if (ret) {
		md = ERR_PTR(ret);
		goto badtm;
	}

	if (!*unformatted) {
		struct dm_block *sblock;
		struct metadata_superblock *disk_super;

		md->meta_bm = meta_bm;

		ret = dm_bm_read_lock(meta_bm, METADATA_SUPERBLOCK_LOCATION,
				      NULL, &sblock);
		if (ret < 0) {
			DMERR("could not read_lock superblock");
			/* XXX: handle error */
		}

		disk_super = dm_block_data(sblock);

		ret = dm_tm_open_with_sm(meta_bm, METADATA_SUPERBLOCK_LOCATION,
					 disk_super->metadata_space_map_root,
					 sizeof(disk_super->metadata_space_map_root),
					 &md->tm, &md->meta_sm);
		if (ret < 0) {
			DMERR("could not open_with_sm superblock");
			/* XXX: handle error */
		}


		md->data_sm = dm_sm_disk_open(md->tm, disk_super->data_space_map_root,
					      sizeof(disk_super->data_space_map_root));
		if (IS_ERR(md->data_sm)) {
			DMERR("dm_disk_open failed");
			/*XXX: handle error */
		}

		dm_bm_unlock(sblock);

		goto begin_trans;
	}

	ret = dm_tm_create_with_sm(meta_bm, METADATA_SUPERBLOCK_LOCATION,
				   &tm, &meta_sm);
	if (ret < 0) {
		md = ERR_PTR(ret);
		goto badtm;
	}

	data_sm = dm_sm_disk_create(tm, p->blocks);
	if (IS_ERR(data_sm)) {
		md = (struct metadata *)data_sm;
		goto badsm;
	}

	md->meta_bm = meta_bm;
	md->tm = tm;
	md->meta_sm = meta_sm;
	md->data_sm = data_sm;

	ret = write_initial_superblock(md);
	if (ret < 0) {
		md = ERR_PTR(ret);
		goto badwritesuper;
	}

begin_trans:
	ret = __begin_transaction(md);
	if (ret < 0) {
		md = ERR_PTR(ret);
		goto badwritesuper;
	}

	md->kvs_linear = NULL;
	md->kvs_sparse = NULL;

	return md;

badwritesuper:
	dm_sm_destroy(data_sm);
badsm:
	dm_tm_destroy(tm);
	dm_sm_destroy(meta_sm);
badtm:
	dm_block_manager_destroy(meta_bm);
badbm:
	kfree(md);
	return md;
}

static void exit_meta_cowbtree(struct metadata *md)
{
	int ret;

	ret = __commit_transaction(md);
	if (ret < 0)
		DMWARN("%s: __commit_transaction() failed, error = %d.",
			__func__, ret);

	dm_sm_destroy(md->data_sm);
	dm_tm_destroy(md->tm);
	dm_sm_destroy(md->meta_sm);
	dm_block_manager_destroy(md->meta_bm);

	kfree(md->kvs_linear);
	kfree(md->kvs_sparse);

	kfree(md);
}

static int flush_meta_cowbtree(struct metadata *md)
{
	int r;

	r = __commit_transaction(md);
	if (r < 0)
		return r;

	r = __begin_transaction(md);

	return r;
}

/********************************************************
 *		Space Management Functions		*
 ********************************************************/

static int alloc_data_block_cowbtree(struct metadata *md, uint64_t *blockn)
{

	return dm_sm_new_block(md->data_sm, blockn);
}

static int inc_refcount_cowbtree(struct metadata *md, uint64_t blockn)
{
	return dm_sm_inc_block(md->data_sm, blockn);
}

static int dec_refcount_cowbtree(struct metadata *md, uint64_t blockn)
{
	return dm_sm_dec_block(md->data_sm, blockn);
}

static int get_refcount_cowbtree(struct metadata *md, uint64_t blockn)
{
	uint32_t refcount;
	int r;

	r = dm_sm_get_count(md->data_sm, blockn, &refcount);
	if (r < 0)
		return r;

	return (int)refcount;
}

/*********************************************************
 *		Linear KVS Functions			 *
 *********************************************************/

static int kvs_delete_linear_cowbtree(struct kvstore *kvs,
				      void *key, int32_t ksize)
{
	int r;
	struct kvstore_cbt *kvcbt = NULL;

	kvcbt = container_of(kvs, struct kvstore_cbt, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	r = dm_btree_remove(&(kvcbt->info), kvcbt->root, key, &(kvcbt->root));

	if (r == -ENODATA)
		return -ENODEV;
	else if (r >= 0)
		return 0;

	return r;
}

/*
 * 0 - not found
 * 1 - found
 * < 0 - error on lookup
 */
static int kvs_lookup_linear_cowbtree(struct kvstore *kvs, void *key,
				      int32_t ksize, void *value, int32_t *vsize)
{
	int r;
	struct kvstore_cbt *kvcbt = NULL;

	kvcbt = container_of(kvs, struct kvstore_cbt, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	r = dm_btree_lookup(&(kvcbt->info), kvcbt->root, key, value);

	if (r == -ENODATA)
		return 0;
	else if (r >= 0)
		return 1;
	else
		return r;
}

static int kvs_insert_linear_cowbtree(struct kvstore *kvs, void *key,
				      int32_t ksize, void *value,
				      int32_t vsize)
{
	int inserted;
	struct kvstore_cbt *kvcbt = NULL;

	kvcbt = container_of(kvs, struct kvstore_cbt, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	if (vsize != kvs->vsize)
		return -EINVAL;

	__dm_bless_for_disk(value);
	return dm_btree_insert_notify(&(kvcbt->info), kvcbt->root, key,
				      value, &(kvcbt->root), &inserted);

}

static struct kvstore * kvs_create_linear_cowbtree(struct metadata *md,
			uint32_t ksize, uint32_t vsize, uint32_t kmax,
			bool unformatted)
{
	struct kvstore_cbt *kvs;
	int r;

	if (!vsize || !ksize)
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

	kvs->ckvs.ksize = ksize;
	kvs->ckvs.vsize = vsize;

	kvs->info.tm = md->tm;
	kvs->info.levels = 1;
	kvs->info.value_type.context = NULL;
	kvs->info.value_type.size = vsize;
	kvs->info.value_type.inc = NULL;
	kvs->info.value_type.dec = NULL;
	kvs->info.value_type.equal = NULL;

	if (!unformatted) {
		kvs->ckvs.kvs_insert = kvs_insert_linear_cowbtree;
		kvs->ckvs.kvs_lookup = kvs_lookup_linear_cowbtree;
		kvs->ckvs.kvs_delete = kvs_delete_linear_cowbtree;
		kvs->ckvs.kvs_iterate = NULL;

		md->kvs_linear = kvs;
		__begin_transaction(md);
	} else {
		r = dm_btree_empty(&(kvs->info), &(kvs->root));
		if (r < 0) {
			kvs = ERR_PTR(r);
			goto badtree;
		}

		/* I think this should be moved below the 4 lines below */
		flush_meta_cowbtree(md);

		kvs->ckvs.kvs_insert = kvs_insert_linear_cowbtree;
		kvs->ckvs.kvs_lookup = kvs_lookup_linear_cowbtree;
		kvs->ckvs.kvs_delete = kvs_delete_linear_cowbtree;
		kvs->ckvs.kvs_iterate = NULL;

		md->kvs_linear = kvs;
	}

	return &(kvs->ckvs);

badtree:
	kfree(kvs);
	return (struct kvstore *) kvs;
}

/********************************************************
 *		Sparse KVS Functions			*
 ********************************************************/

static int kvs_delete_sparse_cowbtree(struct kvstore *kvs,
				      void *key, int32_t ksize)
{
	char *entry;
	uint64_t key_val;
	int r;
	struct kvstore_cbt *kvcbt = NULL;

	kvcbt = container_of(kvs, struct kvstore_cbt, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	entry = kmalloc(kvcbt->entry_size, GFP_NOIO);
	if (!entry)
		return -ENOMEM;

	key_val = (*(uint64_t *)key);

repeat:

	r = dm_btree_lookup(&(kvcbt->info), kvcbt->root, &key_val, entry);
	if (r == -ENODATA)
		return -ENODEV;
	else if (r >= 0) {
		if (!memcmp(entry, key, ksize)) {
			r = dm_btree_remove(&(kvcbt->info),
				kvcbt->root, &key_val, &(kvcbt->root));
			kfree(entry);
			return r;
		}
		key_val++;
		goto repeat;
	} else {
		kfree(entry);
		return r;
	}
}

/*
 * 0 - not found
 * 1 - found
 * < 0 - error on lookup
 */
static int kvs_lookup_sparse_cowbtree(struct kvstore *kvs, void *key,
				      int32_t ksize, void *value, int32_t *vsize)
{
	char *entry;
	uint64_t key_val;
	int r;
	struct kvstore_cbt *kvcbt = NULL;

	kvcbt = container_of(kvs, struct kvstore_cbt, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	entry = kmalloc(kvcbt->entry_size, GFP_NOIO);
	if (!entry)
		return -ENOMEM;

	key_val = (*(uint64_t *)key);

repeat:

	r = dm_btree_lookup(&(kvcbt->info), kvcbt->root, &key_val, entry);
	if (r == -ENODATA) {
		kfree(entry);
		return 0;
	} else if (r >= 0) {
		if (!memcmp(entry, key, ksize)) {
			memcpy(value, entry + ksize, kvs->vsize);
			kfree(entry);
			return 1;
		}
		key_val++;
		goto repeat;
	} else {
		kfree(entry);
		return r;
	}
}

static int kvs_insert_sparse_cowbtree(struct kvstore *kvs, void *key,
				      int32_t ksize, void *value,
				      int32_t vsize)
{
	char *entry;
	uint64_t key_val;
	int r;
	struct kvstore_cbt *kvcbt = NULL;

	kvcbt = container_of(kvs, struct kvstore_cbt, ckvs);

	if (ksize != kvs->ksize)
		return -EINVAL;

	if (vsize != kvs->vsize)
		return -EINVAL;

	entry = kmalloc(kvcbt->entry_size, GFP_NOIO);
	if (!entry)
		return -ENOMEM;

	key_val = (*(uint64_t *)key);


repeat:

	r = dm_btree_lookup(&(kvcbt->info), kvcbt->root, &key_val, entry);
	if (r == -ENODATA) {
		memcpy(entry, key, ksize);
		memcpy(entry + ksize, value, vsize);
		__dm_bless_for_disk(&key_val);
		r = dm_btree_insert(&(kvcbt->info), kvcbt->root, &key_val,
				    entry, &(kvcbt->root));
		kfree(entry);
		return r;
	} else if (r >= 0) {
		key_val++;
		goto repeat;
	} else {
		kfree(entry);
		return r;
	}
}

static struct kvstore *kvs_create_sparse_cowbtree(struct metadata *md,
			uint32_t ksize, uint32_t vsize, uint32_t knummax,
			bool unformatted)
{
	struct kvstore_cbt *kvs;
	int r;

	if (!vsize || !ksize)
		return ERR_PTR(-ENOTSUPP);

	/* We do not support two or more KVSs at the moment */
	if (md->kvs_sparse)
		return ERR_PTR(-EBUSY);

	kvs = kmalloc(sizeof(*kvs), GFP_NOIO);
	if (!kvs)
		return ERR_PTR(-ENOMEM);

	kvs->ckvs.vsize = vsize;
	kvs->ckvs.ksize = ksize;
	kvs->entry_size = vsize + ksize;

	kvs->info.tm = md->tm;
	kvs->info.levels = 1;
	kvs->info.value_type.context = NULL;
	kvs->info.value_type.size = kvs->entry_size;
	kvs->info.value_type.inc = NULL;
	kvs->info.value_type.dec = NULL;
	kvs->info.value_type.equal = NULL;

	if (!unformatted) {
		kvs->ckvs.kvs_insert = kvs_insert_sparse_cowbtree;
		kvs->ckvs.kvs_lookup = kvs_lookup_sparse_cowbtree;
		kvs->ckvs.kvs_delete = kvs_delete_sparse_cowbtree;
		kvs->ckvs.kvs_iterate = NULL;

		md->kvs_sparse = kvs;
		__begin_transaction(md);
	} else {
		r = dm_btree_empty(&(kvs->info), &(kvs->root));
		if (r < 0) {
			kvs = ERR_PTR(r);
			goto badtree;
		}

		/* I think this should be moved below the 4 lines below */
		flush_meta_cowbtree(md);

		kvs->ckvs.kvs_insert = kvs_insert_sparse_cowbtree;
		kvs->ckvs.kvs_lookup = kvs_lookup_sparse_cowbtree;
		kvs->ckvs.kvs_delete = kvs_delete_sparse_cowbtree;
		kvs->ckvs.kvs_iterate = NULL;

		md->kvs_sparse = kvs;
	}

	return &(kvs->ckvs);

badtree:
	kfree(kvs);
	return (struct kvstore *) kvs;
}

struct metadata_ops metadata_ops_cowbtree = {
	.init_meta = init_meta_cowbtree,
	.exit_meta = exit_meta_cowbtree,
	.kvs_create_linear = kvs_create_linear_cowbtree,
	.kvs_create_sparse = kvs_create_sparse_cowbtree,

	.alloc_data_block = alloc_data_block_cowbtree,
	.inc_refcount = inc_refcount_cowbtree,
	.dec_refcount = dec_refcount_cowbtree,
	.get_refcount = get_refcount_cowbtree,

	.flush_meta = flush_meta_cowbtree,

	.flush_bufio_cache = NULL,
};
