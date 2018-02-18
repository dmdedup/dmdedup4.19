/*
 * Copyright (C) 2012-2017 Vasily Tarasov
 * Copyright (C) 2012-2014 Geoff Kuenning
 * Copyright (C) 2012-2014 Sonam Mandal
 * Copyright (C) 2012-2014 Karthikeyani Palanisami
 * Copyright (C) 2012-2014 Philip Shilane
 * Copyright (C) 2012-2014 Sagar Trehan
 * Copyright (C) 2012-2017 Erez Zadok
 * Copyright (c) 2016-2017 Vinothkumar Raja
 * Copyright (c) 2017-2017 Nidhi Panpalia
 * Copyright (c) 2012-2017 Stony Brook University
 * Copyright (c) 2012-2017 The Research Foundation for SUNY
 * This file is released under the GPL.
 */

#ifndef DM_DEDUP_H
#define DM_DEDUP_H

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
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/parser.h>
#include <linux/blk_types.h>
#include <linux/mempool.h>

#include <linux/scatterlist.h>
#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <crypto/algapi.h>

#define DM_MSG_PREFIX "dedup-mod"

#define CRYPTO_ALG_NAME_LEN     16
#define MAX_DIGEST_SIZE	SHA256_DIGEST_SIZE

#define MAX_BACKEND_NAME_LEN (64)

#define MIN_DEDUP_WORK_IO	16

/* Per target instance structure */
struct dedup_config {
	struct dm_dev *data_dev;
	struct dm_dev *metadata_dev;

	u32 block_size;	/* in bytes */
	u32 sectors_per_block;

	u32 pblocks;	/* physical blocks */
	u32 lblocks;	/* logical blocks */

	struct workqueue_struct *workqueue;

	struct bio_set *bs;
	struct hash_desc_table *desc_table;

	u64 logical_block_counter;	/* Total number of used LBNs */
	u64 physical_block_counter;/* Total number of allocated PBNs */
	u64 gc_counter; /*Total number of garbage collected blocks */

	u64	writes;		/* total number of writes */
	u64	dupwrites;
	u64	uniqwrites;
	u64	reads_on_writes;
	u64	overwrites;	/* writes to a prev. written offset */
	u64	newwrites;	/* writes to never written offsets */

	/* flag to check for data corruption */
	bool	check_corruption;
	bool	fec;		/* flag to fix block corruption */
	u64	fec_fixed;	/* number of corruptions fixed */
	/* Total number of corruptions encountered */
	u64	corrupted_blocks;

	/* used for read-on-write of misaligned requests */
	struct dm_io_client *io_client;

	char backend_str[MAX_BACKEND_NAME_LEN];
	struct metadata_ops *mdops;
	struct metadata *bmd;
	struct kvstore *kvs_hash_pbn;
	struct kvstore *kvs_lbn_pbn;

	char crypto_alg[CRYPTO_ALG_NAME_LEN];
	int crypto_key_size;

	u32 flushrq;		/* after how many writes call flush */
	u64 writes_after_flush;	/* # of writes after the last flush */

	mempool_t *dedup_work_pool;	/* Dedup work pool */
	mempool_t *check_work_pool;	/* Corruption check work pool */
};

/* Value of the HASH-PBN key-value store */
struct hash_pbn_value {
	u64 pbn;	/* in blocks */
};

/* Value of the LBN-PBN key-value store */
struct lbn_pbn_value {
	u64 pbn;	/* in blocks */
};

#endif /* DM_DEDUP_H */
