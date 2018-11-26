/*
 * Copyright (C) 2012-2017 Vasily Tarasov
 * Copyright (C) 2012-2014 Geoff Kuenning
 * Copyright (C) 2012-2014 Sonam Mandal
 * Copyright (C) 2012-2014 Karthikeyani Palanisami
 * Copyright (C) 2012-2014 Philip Shilane
 * Copyright (C) 2012-2014 Sagar Trehan
 * Copyright (C) 2012-2017 Erez Zadok
 * Copyright (c) 2012-2017 Stony Brook University
 * Copyright (c) 2012-2017 The Research Foundation for SUNY
 * This file is released under the GPL.
 */

#ifndef COWBTREE_BACKEND_H
#define COWBTREE_BACKEND_H

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

#define MAX_LINEAR_PROBING_LIMIT 5

#define __INJ_ERR_ALLOC_BLK__ 0x01
#define __INJ_ERR_KVS_INS_LINEAR_BTREE__ 0x02
#define __INJ_ERR_KVS_DEL_LINEAR_BTREE__ 0x04
#define __INJ_ERR_KVS_INS_SPARSE_BTREE__ 0x08
#define __INJ_ERR_KVS_DEL_SPARSE_BTREE__ 0x10
#define __INJ_ERR_INC_REFCNT__ 0x20
#define __INJ_ERR_DEC_REFCNT__ 0x40

extern struct metadata_ops metadata_ops_cowbtree;

extern uint32_t err_inject_bitmap;
extern bool err_inject_on;
struct init_param_cowbtree {
	struct block_device *metadata_bdev;
	u64 blocks;
};

#endif /* COWBTREE_BACKEND_H */
