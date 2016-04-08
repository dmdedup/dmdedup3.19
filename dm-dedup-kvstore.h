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

#ifndef KVSTORE_H
#define KVSTORE_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/list.h>
#include <linux/err.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/gfp.h>

#include <linux/scatterlist.h>
#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/algapi.h>

#include "dm-dedup-target.h"

struct kvstore {
	uint32_t vsize;
	uint32_t ksize;

	int (*kvs_delete)(struct kvstore *kvs, void *key, int32_t ksize);
	int (*kvs_lookup)(struct kvstore *kvs, void *key, int32_t ksize,
				void *value, int32_t *vsize);
	int (*kvs_insert)(struct kvstore *kvs, void *key, int32_t ksize,
				void *value, int32_t vsize);
	int (*kvs_iterate)(struct kvstore *kvs, int (*itr_action)
				(void *key, int32_t ksize, void *value,
				 int32_t vsize, void *data), void *data);
};

#endif /* KVSTORE_H */
