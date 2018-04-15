#include <linux/vmalloc.h>
#include <linux/kdev_t.h>

#include "dm-dedup-target.h"
#include "dm-dedup-rw.h"
#include "dm-dedup-hash.h"
#include "dm-dedup-backend.h"
#include "dm-dedup-ram.h"
#include "dm-dedup-cbt.h"
#include "dm-dedup-kvstore.h"
#include "dm-dedup-check.h"
#include "dm-dedup-test-handlewrite.h"
#include "dm-dedup-ut-handlewrite.h"

/*
 * This bitmap decides which error to inject. If no error to be injected
 * then keep value to 0 or else keep value equal to the specific error
 * want to inject.
 */
static uint32_t inj_err_bitmap=0x02;

/*
 * Inject error for allocate_block method if bit is set of alloc_block in
 * bitmap. Inject error only for first allocate block otherwise call
 * original allocate_block method.
 */
int inj_err_allocate_block(struct dedup_config *dc, uint64_t *pbn_new) {
	static bool injected = false;
	if ((inj_err_bitmap & __INJ_ERR_ALLOC_BLK__) && !injected) {
		DMWARN("Injected alloc block called");
		injected = true;
		return -ENOMEM;
	} else {
		return allocate_block(dc, pbn_new);
	}
}

/*
 * Inject error for every 5th insertion of entry in lbn mapping if it's
 * bit is set in above bitmap. Otherwise call normal kvs_insert function.
 */
int inj_err_kvs_insert_linear_cowbtree(struct kvstore *kvs, void *key,
				       s32 ksize, void *value,
				       int32_t vsize) {
	static int err_cnt = 0;
	if ((inj_err_bitmap & __INJ_ERR_KVS_INS_LINEAR_BTREE__) &&
		(err_cnt++ % 5 == 0)) {
		DMWARN("Injected insert linear called");
		return -EINVAL;
	} else {
		return kvs_insert_linear_cowbtree(kvs, key, ksize, value, vsize);
	}
}

/*
 * Inject error for every 5th deletion of entry in lbn mapping if it's
 * bit is set in above bitmap. Otherwise call normal kvs_delete function.
 */
int inj_err_kvs_delete_linear_cowbtree(struct kvstore *kvs, void *key,
				       int32_t ksize) {
	static int err_cnt = 0;
	if ((inj_err_bitmap & __INJ_ERR_KVS_DEL_LINEAR_BTREE__) &&
		(err_cnt++ % 5 == 0)) {
		DMWARN("Injected delete linear called");
		return -EINVAL;
	} else {
		return kvs_delete_linear_cowbtree(kvs, key, ksize);
	}
}

/*
 * Inject error for every 5th insertion of entry in ash mapping if it's
 * bit is set in above bitmap. Otherwise call normal kvs_insert function.
 */
int inj_err_kvs_insert_sparse_cowbtree(struct kvstore *kvs, void *key,
				       s32 ksize, void *value,
				       int32_t vsize) {
	static int err_cnt = 0;
	if ((inj_err_bitmap & __INJ_ERR_KVS_INS_SPARSE_BTREE__) &&
		(err_cnt++ % 5 == 0)){
		DMWARN("Injected insert sparse called");
		return -EINVAL;
	} else {
		return kvs_insert_sparse_cowbtree(kvs, key, ksize, value, vsize);
	}
}

/*
 * Inject error for every 5th deletion of entry in hash mapping if it's
 * bit is set in above bitmap. Otherwise call normal kvs_delete function.
 */
int inj_err_kvs_delete_sparse_cowbtree(struct kvstore *kvs, void *key,
				       int32_t ksize) {
	static int err_cnt = 0;
	if ((inj_err_bitmap & __INJ_ERR_KVS_DEL_SPARSE_BTREE__) &&
		(err_cnt++ % 5 == 0)){
		DMWARN("Injected delete sparse called");
		return -EINVAL;
	} else {
		return kvs_delete_sparse_cowbtree(kvs, key, ksize);
	}
}

/*
 * Inject error for incrementing ref count if it's bit is set in bitmap.
 * Otherwise call original inc_refcount function.
 */
int inj_err_inc_refcount_cowbtree(struct metadata *md, uint64_t blockn) {
	if (inj_err_bitmap & __INJ_ERR_INC_REFCNT__) {
		DMWARN("Injected inc refcount called");
		return -EINVAL;
	} else {
		return inc_refcount_cowbtree(md, blockn);
	}
}

/*
 * Inject error for decrementing ref count if it's bit is set in bitmap.
 * Otherwise call original dec_refcount function.
 */
int inj_err_dec_refcount_cowbtree(struct metadata *md, uint64_t blockn) {
	if (inj_err_bitmap & __INJ_ERR_DEC_REFCNT__) {
		DMWARN("Injected dec refcount called");
		return -EINVAL;
	} else {
		return dec_refcount_cowbtree(md, blockn);
	}
}

