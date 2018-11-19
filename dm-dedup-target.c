/*
 * Copyright (C) 2012-2018 Vasily Tarasov
 * Copyright (C) 2012-2014 Geoff Kuenning
 * Copyright (C) 2012-2014 Sonam Mandal
 * Copyright (C) 2012-2014 Karthikeyani Palanisami
 * Copyright (C) 2012-2014 Philip Shilane
 * Copyright (C) 2012-2014 Sagar Trehan
 * Copyright (C) 2012-2018 Erez Zadok
 * Copyright (c) 2016-2017 Vinothkumar Raja
 * Copyright (c) 2017-2017 Nidhi Panpalia
 * Copyright (c) 2017-2018 Noopur Maheshwari
 * Copyright (c) 2018-2018 Rahul Rane
 * Copyright (c) 2012-2018 Stony Brook University
 * Copyright (c) 2012-2018 The Research Foundation for SUNY
 * This file is released under the GPL.
 */

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

#define MAX_DEV_NAME_LEN (64)

#define MIN_IOS 64

#define MIN_DATA_DEV_BLOCK_SIZE (4 * 1024)
#define MAX_DATA_DEV_BLOCK_SIZE (1024 * 1024)

struct on_disk_stats {
	u64 physical_block_counter;
	u64 logical_block_counter;
};

/*
 * All incoming requests are packed in the dedup_work structure
 * for further processing by the workqueue thread.
 */
struct dedup_work {
	struct work_struct worker;
	struct dedup_config *config;
	struct bio *bio;
};

enum backend {
	BKND_INRAM,
	BKND_COWBTREE
};

/* Initializes bio. */
static void bio_zero_endio(struct bio *bio)
{
	zero_fill_bio(bio);
	bio->bi_status = BLK_STS_OK;
	bio_endio(bio);
}

/* Returns the logical block number for the bio. */
static uint64_t bio_lbn(struct dedup_config *dc, struct bio *bio)
{
	sector_t lbn = bio->bi_iter.bi_sector;

	sector_div(lbn, dc->sectors_per_block);

	return lbn;
}

/* Entry point to the generic block layer. */
static void do_io_remap_device(struct dedup_config *dc, struct bio *bio)
{
	bio->bi_bdev = dc->data_dev->bdev;
	generic_make_request(bio);
}

/*
 * Updates the sector indice, given the pbn and offset calculation, and
 * enters the generic block layer.
 */
static void do_io(struct dedup_config *dc, struct bio *bio, uint64_t pbn)
{
	int offset;

	offset = sector_div(bio->bi_iter.bi_sector, dc->sectors_per_block);
	bio->bi_iter.bi_sector = (sector_t)pbn * dc->sectors_per_block + offset;

	do_io_remap_device(dc, bio);
}

/*
 * Gets the pbn from the LBN->PBN entry and performs io request.
 * If corruption check is enabled, it prepares the check_io
 * structure for FEC and then performs io request.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int handle_read(struct dedup_config *dc, struct bio *bio)
{
	u64 lbn;
	u32 vsize;
	struct lbn_pbn_value lbnpbn_value;
	struct check_io *io;
	struct bio *clone;
	int r;

	lbn = bio_lbn(dc, bio);

	/* get the pbn in LBN->PBN store for incoming lbn */
	r = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
			sizeof(lbn), (void *)&lbnpbn_value, &vsize);

	if (r == -ENODATA) {
		/* unable to find the entry in LBN->PBN store */
		bio_zero_endio(bio);
	} else if (r == 0) {
		/* entry found in the LBN->PBN store */

		/* if corruption check not enabled directly do io request */
		if (!dc->check_corruption) {
			clone = bio;
			goto read_no_fec;
		}

		/* Prepare check_io structure to be later used for FEC */
		io = kmalloc(sizeof(struct check_io), GFP_NOIO);
		io->dc = dc;
		io->pbn = lbnpbn_value.pbn;
		io->lbn = lbn;
		io->base_bio = bio;

		/*
		 * Prepare bio clone to handle disk read
		 * clone is created so that we can have our own endio
		 * where we call bio_endio on original bio
		 * after corruption checks are done
		 */
		clone = bio_clone_fast(bio, GFP_NOIO, dc->bs);
		if (!clone) {
			r = -ENOMEM;
			goto out_clone_fail;
		}

		/*
		 * Store the check_io structure in bio's private field
		 * used as indirect argument when disk read is finished
		 */
		clone->bi_end_io = dedup_check_endio;
		clone->bi_private = io;

read_no_fec:
		do_io(dc, clone, lbnpbn_value.pbn);
	} else {
		goto out;
	}

	r = 0;
	goto out;

out_clone_fail:
	kfree(io);

out:
	return r;

}

/*
 * Allocates pbn_new and increments the logical and physical block
 * counters. Note that it also increments refcount internally.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
int allocate_block(struct dedup_config *dc, uint64_t *pbn_new)
{
	int r;

	r = dc->mdops->alloc_data_block(dc->bmd, pbn_new);

	if (!r) {
		dc->logical_block_counter++;
		dc->physical_block_counter++;
	}

	return r;
}

/*
 * Allocates pbn_new and performs write io.
 * Inserts the new LBN->PBN entry.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int alloc_pbnblk_and_insert_lbn_pbn(struct dedup_config *dc,
					   u64 *pbn_new,
					   struct bio *bio, uint64_t lbn)
{
	int r = 0;
	struct lbn_pbn_value lbnpbn_value;

	r = allocate_block(dc, pbn_new);
	if (r < 0) {
		r = -EIO;
		return r;
	}

	lbnpbn_value.pbn = *pbn_new;
	do_io(dc, bio, *pbn_new);

	r = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn, (void *)&lbn,
					sizeof(lbn), (void *)&lbnpbn_value,
					sizeof(lbnpbn_value));
	if (r < 0)
		dc->mdops->dec_refcount(dc->bmd, *pbn_new);

	return r;
}

/*
 * Internal function to handle write when lbn-pbn entry is not
 * present. It creates a new lbn-pbn mapping and insert given
 * hash for this new pbn in hash-pbn mapping. Then increments
 * refcount for this new pbn.
 *
 * Returns -ERR code on failure.
 * Returns 0 on success.
 */
static int __handle_no_lbn_pbn(struct dedup_config *dc,
			       struct bio *bio, uint64_t lbn, u8 *hash)
{
	int r, ret;
	u64 pbn_new;
	struct hash_pbn_value hashpbn_value;

	/* Create a new lbn-pbn mapping for given lbn */
	r = alloc_pbnblk_and_insert_lbn_pbn(dc, &pbn_new, bio, lbn);
	if (r < 0)
		goto out;

	/* Inserts new hash-pbn mapping for given hash. */
	hashpbn_value.pbn = pbn_new;
	r = dc->kvs_hash_pbn->kvs_insert(dc->kvs_hash_pbn, (void *)hash,
					 dc->crypto_key_size,
					 (void *)&hashpbn_value,
					 sizeof(hashpbn_value));
	if (r < 0)
		goto kvs_insert_err;

	/* Increments refcount for new pbn entry created. */
	r = dc->mdops->inc_refcount(dc->bmd, pbn_new);
	if (r < 0)
		goto inc_refcount_err;

	/* On all successful steps increment new write count. */
	dc->newwrites++;
	goto out;

/* Error handling code path */
inc_refcount_err:
	/* Undo actions taken in hash-pbn kvs insert. */
	ret = dc->kvs_hash_pbn->kvs_delete(dc->kvs_hash_pbn,
					   (void *)hash, dc->crypto_key_size);
	if (ret < 0)
		DMERR("Error in deleting previously created hash pbn entry.");
kvs_insert_err:
	/* Undo actions taken in alloc_pbnblk_and_insert_lbn_pbn. */
	ret = dc->kvs_lbn_pbn->kvs_delete(dc->kvs_lbn_pbn,
					  (void *)&lbn, sizeof(lbn));
	if (ret < 0)
		DMERR("Error in deleting previously created lbn pbn entry.");
	ret = dc->mdops->dec_refcount(dc->bmd, pbn_new);
	if (ret < 0)
		DMERR("ERROR in decrementing previously incremented refcount.");
out:
	return r;
}

/*
 * Internal function to handle write when lbn-pbn mapping is present.
 * It creates a block for new pbn and inserts lbn-pbn(new) mapping.
 * Decrements old pbn refcount and inserts new hash-pbn entry followed
 * by incrementing refcount of new pbn.
 *
 * Returns -ERR code on failure.
 * Returns 0 on success.
 */
static int __handle_has_lbn_pbn(struct dedup_config *dc,
				struct bio *bio, uint64_t lbn, u8 *hash,
				u64 pbn_old)
{
	int r, ret;
	u64 pbn_new;
	struct hash_pbn_value hashpbn_value;

	/* Allocates a new block for new pbn and inserts lbn-pbn lapping. */
	r = alloc_pbnblk_and_insert_lbn_pbn(dc, &pbn_new, bio, lbn);
	if (r < 0)
		goto out;

	/* Inserts new hash-pbn entry for given hash. */
	hashpbn_value.pbn = pbn_new;
	r = dc->kvs_hash_pbn->kvs_insert(dc->kvs_hash_pbn, (void *)hash,
					 dc->crypto_key_size,
					 (void *)&hashpbn_value,
					 sizeof(hashpbn_value));
	if (r < 0)
		goto kvs_insert_err;

	/* Increments refcount of new pbn. */
	r = dc->mdops->inc_refcount(dc->bmd, pbn_new);
	if (r < 0)
		goto inc_refcount_err;

	/* Decrements refcount for old pbn and decrement logical block cnt. */
	r = dc->mdops->dec_refcount(dc->bmd, pbn_old);
	if (r < 0)
		goto dec_refcount_err;
	dc->logical_block_counter--;

	/* On all successful steps increment overwrite count. */
	dc->overwrites++;
	goto out;

/* Error handling code path. */
dec_refcount_err:
	/* Undo actions taken while incrementing refcount of new pbn. */
	ret = dc->mdops->dec_refcount(dc->bmd, pbn_new);
	if (ret < 0)
		DMERR("Error in decrementing previously incremented refcount.");

inc_refcount_err:
	ret = dc->kvs_hash_pbn->kvs_delete(dc->kvs_hash_pbn, (void *)hash,
					   dc->crypto_key_size);
	if (ret < 0)
		DMERR("Error in deleting previously inserted hash pbn entry");

kvs_insert_err:
	/* Undo actions taken in alloc_pbnblk_and_insert_lbn_pbn. */
	ret = dc->kvs_lbn_pbn->kvs_delete(dc->kvs_lbn_pbn, (void *)&lbn,
					  sizeof(lbn));
	if (ret < 0)
		DMERR("Error in deleting previously created lbn pbn entry");

	ret = dc->mdops->dec_refcount(dc->bmd, pbn_new);
	if (ret < 0)
		DMERR("ERROR in decrementing previously incremented refcount.");
out:
	return r;
}

/*
 * Handles write io when Hash->PBN entry is not found.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int handle_write_no_hash(struct dedup_config *dc,
				struct bio *bio, uint64_t lbn, u8 *hash)
{
	int r;
	u32 vsize;
	struct lbn_pbn_value lbnpbn_value;

	r = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
					sizeof(lbn), (void *)&lbnpbn_value,
					&vsize);
	if (r == -ENODATA) {
		/* No LBN->PBN mapping entry */
		r = __handle_no_lbn_pbn(dc, bio, lbn, hash);
	} else if (r == 0) {
		/* LBN->PBN mappings exist */
		r = __handle_has_lbn_pbn(dc, bio, lbn, hash, lbnpbn_value.pbn);
	}
	if (r == 0)
		dc->uniqwrites++;
	return r;
}

/*
 * Internal function to handle write when hash-pbn entry is present,
 * but lbn-pbn entry is not present.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int __handle_no_lbn_pbn_with_hash(struct dedup_config *dc,
					 struct bio *bio, uint64_t lbn,
					 u64 pbn_this,
					 struct lbn_pbn_value lbnpbn_value)
{
	int r = 0, ret;

	/* Increments refcount of this passed pbn */
	r = dc->mdops->inc_refcount(dc->bmd, pbn_this);
	if (r < 0)
		goto out;

	lbnpbn_value.pbn = pbn_this;

	/* Insert lbn->pbn_this entry */
	r = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn, (void *)&lbn,
					sizeof(lbn), (void *)&lbnpbn_value,
					sizeof(lbnpbn_value));
	if (r < 0)
		goto kvs_insert_error;

	dc->logical_block_counter++;

	bio->bi_status = BLK_STS_OK;
	bio_endio(bio);
	dc->newwrites++;
	goto out;

kvs_insert_error:
	/* Undo actions taken while incrementing refcount of this pbn. */
	ret = dc->mdops->dec_refcount(dc->bmd, pbn_this);
	if (ret < 0)
		DMERR("Error in decrementing previously incremented refcount.");
out:
	return r;
}

/*
 * Internal function to handle write when both hash-pbn entry and lbn-pbn
 * entry is present.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int __handle_has_lbn_pbn_with_hash(struct dedup_config *dc,
					  struct bio *bio, uint64_t lbn,
					  u64 pbn_this,
					  struct lbn_pbn_value lbnpbn_value)
{
	int r = 0, ret;
	struct lbn_pbn_value this_lbnpbn_value;
	u64 pbn_old;

	pbn_old = lbnpbn_value.pbn;

	/* special case, overwrite same LBN/PBN with same data */
	if (pbn_this == pbn_old)
		goto out;

	/* Increments refcount of this passed pbn */
	r = dc->mdops->inc_refcount(dc->bmd, pbn_this);
	if (r < 0)
		goto out;

	this_lbnpbn_value.pbn = pbn_this;

	/* Insert lbn->pbn_this entry */
	r = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn, (void *)&lbn,
					sizeof(lbn),
					(void *)&this_lbnpbn_value,
					sizeof(this_lbnpbn_value));
	if (r < 0)
		goto kvs_insert_err;

	/* Decrement refcount of old pbn */
	r = dc->mdops->dec_refcount(dc->bmd, pbn_old);
	if (r < 0)
		goto dec_refcount_err;

	goto out;	/* all OK */

dec_refcount_err:
	/* Undo actions taken while decrementing refcount of old pbn */
	/* Overwrite lbn->pbn_this entry with lbn->pbn_old entry */
	ret = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn, (void *)&lbn,
				    	  sizeof(lbn), (void *)&lbnpbn_value,
					  sizeof(lbnpbn_value));
	if (ret < 0)
		DMERR("Error in overwriting lbn->pbn_this [%llu] with"
		      " lbn-pbn_old entry [%llu].", this_lbnpbn_value.pbn,
		      lbnpbn_value.pbn);

kvs_insert_err:
	ret = dc->mdops->dec_refcount(dc->bmd, pbn_this);
	if (ret < 0)
		DMERR("Error in decrementing previously incremented refcount.");
out:
	if (r == 0) {
		bio->bi_status = BLK_STS_OK;
		bio_endio(bio);
		dc->overwrites++;
	}

	return r;
}

/*
 * Handles write io when Hash->PBN entry is found.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int handle_write_with_hash(struct dedup_config *dc, struct bio *bio,
				  u64 lbn, u8 *final_hash,
				  struct hash_pbn_value hashpbn_value)
{
	int r;
	u32 vsize;
	struct lbn_pbn_value lbnpbn_value;
	u64 pbn_this;

	pbn_this = hashpbn_value.pbn;
	r = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
					sizeof(lbn), (void *)&lbnpbn_value, &vsize);

	if (r == -ENODATA) {
		/* No LBN->PBN mapping entry */
		r = __handle_no_lbn_pbn_with_hash(dc, bio, lbn, pbn_this,
						  lbnpbn_value);
	} else if (r == 0) {
		/* LBN->PBN mapping entry exists */
		r = __handle_has_lbn_pbn_with_hash(dc, bio, lbn, pbn_this,
						   lbnpbn_value);
	}
	if (r == 0)
		dc->dupwrites++;
	return r;
}

/*
 * Performs a lookup for Hash->PBN entry.
 * If entry is not found, it invokes handle_write_no_hash.
 * If entry is found, it invokes handle_write_with_hash.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int handle_write(struct dedup_config *dc, struct bio *bio)
{
	u64 lbn;
	u8 hash[MAX_DIGEST_SIZE];
	struct hash_pbn_value hashpbn_value;
	u32 vsize;
	struct bio *new_bio = NULL;
	int r;

	/* If there is a data corruption make the device read-only */
	if (dc->corrupted_blocks > dc->fec_fixed)
		return -EIO;

	dc->writes++;

	/* Read-on-write handling */
	if (bio->bi_iter.bi_size < dc->block_size) {
		dc->reads_on_writes++;
		new_bio = prepare_bio_on_write(dc, bio);
		if (!new_bio || IS_ERR(new_bio))
			return -ENOMEM;
		bio = new_bio;
	}

	lbn = bio_lbn(dc, bio);

	r = compute_hash_bio(dc->desc_table, bio, hash);
	if (r)
		return r;

	r = dc->kvs_hash_pbn->kvs_lookup(dc->kvs_hash_pbn, hash,
					 dc->crypto_key_size,
					 &hashpbn_value, &vsize);

	if (r == -ENODATA)
		r = handle_write_no_hash(dc, bio, lbn, hash);
	else if (r == 0)
		r = handle_write_with_hash(dc, bio, lbn, hash,
					   hashpbn_value);

	if (r < 0)
		return r;

	dc->writes_after_flush++;
	if ((dc->flushrq && dc->writes_after_flush >= dc->flushrq) ||
	    (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA))) {
		r = dc->mdops->flush_meta(dc->bmd);
		if (r < 0)
			return r;
		dc->writes_after_flush = 0;
	}

	return 0;
}

/*
 * Handles discard request by clearing LBN-PBN mapping and
 * decrementing refcount of pbn. If refcount reaches one that
 * means only hash-pbn mapping is present which will be cleaned
 * up at garbage collection time.
 *
 * Returns -ERR on failure
 * Returns 0 on success
 */
static int handle_discard(struct dedup_config *dc, struct bio *bio)
{
	u64 lbn, pbn_val;
	u32 vsize;
	struct lbn_pbn_value lbnpbn_value;
	int r, ret;

	lbn = bio_lbn(dc, bio);
	DMWARN("Discard request received for LBN :%llu", lbn);

	/* Get the pbn from LBN->PBN store for requested LBN. */
	r = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
					sizeof(lbn), (void *)&lbnpbn_value,
					&vsize);
	if (r == -ENODATA) {
		/*
 		 * Entry not present in LBN->PBN store hence need to forward
 		 * the discard request to underlying block layer without
 		 * remapping with pbn.
 		 */
		DMWARN("Discard request received for lbn [%llu] whose LBN-PBN entry"
		" is not present.", lbn);
		do_io_remap_device(dc, bio);
		goto out;
	}
	if (r < 0)
		goto out;

	/* Entry found in the LBN->PBN store */
	pbn_val = lbnpbn_value.pbn;

	/*
	 * Decrement pbn's refcount. If the refcount reaches one then forward discard
	 * request to underlying block device.
	 */
	if (dc->mdops->get_refcount(dc->bmd, pbn_val) > 1) {
		r = dc->kvs_lbn_pbn->kvs_delete(dc->kvs_lbn_pbn,
						(void *)&lbn,
						sizeof(lbn));
		if (r < 0) {
			DMERR("Failed to delete LBN-PBN entry for pbn_val :%llu",
				pbn_val);
			goto out;
		}
		r = dc->mdops->dec_refcount(dc->bmd, pbn_val);
		if (r < 0) {
			/*
 			 * If could not decrement refcount then need to revert
 			 * above deletion of lbn-pbn mapping.
 			 */
			ret = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn,
							(void *)&lbn,
							sizeof(lbn),
							(void *)&lbnpbn_value,
							sizeof(lbnpbn_value));
			goto out;
		}

		dc->physical_block_counter -= 1;
	}
	/*
 	 * If refcount reaches 1 then forward discard request to underlying
 	 * block layer else end bio request.
 	 */
	if (dc->mdops->get_refcount(dc->bmd, pbn_val) == 1) {
		do_io(dc, bio, pbn_val);
	} else {
		bio->bi_status = BLK_STS_OK;
		bio_endio(bio);
	}
out:
	return r;
}

/*
 * Processes block io requests and propagates negative error
 * code to block io status (BLK_STS_*).
 */
static void process_bio(struct dedup_config *dc, struct bio *bio)
{
	int r;

	if (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA) && !bio_sectors(bio)) {
		r = dc->mdops->flush_meta(dc->bmd);
		if (r == 0)
			dc->writes_after_flush = 0;
		do_io_remap_device(dc, bio);
		return;
	}
	if (bio_op(bio) == REQ_OP_DISCARD) {
		r = handle_discard(dc, bio);
		return;
	}

	switch (bio_data_dir(bio)) {
	case READ:
		r = handle_read(dc, bio);
		break;
	case WRITE:
		r = handle_write(dc, bio);
	}

	if (r < 0) {
		switch (r) {
		case -EWOULDBLOCK:
			bio->bi_status = BLK_STS_AGAIN;
			break;
		case -EINVAL:
		case -EIO:
			bio->bi_status = BLK_STS_IOERR;
			break;
		case -ENODATA:
			bio->bi_status = BLK_STS_MEDIUM;
			break;
		case -ENOMEM:
			bio->bi_status = BLK_STS_RESOURCE;
			break;
		case -EPERM:
			bio->bi_status = BLK_STS_PROTECTION;
			break;
		}
		bio_endio(bio);
	}
}

/*
 * Main function for all work pool threads that process the block io
 * operation.
 */
static void do_work(struct work_struct *ws)
{
	struct dedup_work *data = container_of(ws, struct dedup_work, worker);
	struct dedup_config *dc = (struct dedup_config *)data->config;
	struct bio *bio = (struct bio *)data->bio;

	mempool_free(data, dc->dedup_work_pool);

	process_bio(dc, bio);
}

/*
 * Defers block io operations by enqueuing them in the work pool
 * queue.
 */
static void dedup_defer_bio(struct dedup_config *dc, struct bio *bio)
{
	struct dedup_work *data;

	data = mempool_alloc(dc->dedup_work_pool, GFP_NOIO);
	if (!data) {
		bio->bi_status = BLK_STS_RESOURCE;
		bio_endio(bio);
		return;
	}

	data->bio = bio;
	data->config = dc;

	INIT_WORK(&(data->worker), do_work);

	queue_work(dc->workqueue, &(data->worker));
}

/*
 * Wrapper function for dedup_defer_bio.
 *
 * Returns DM_MAPIO_SUBMITTED.
 */
static int dm_dedup_map(struct dm_target *ti, struct bio *bio)
{
	dedup_defer_bio(ti->private, bio);

	return DM_MAPIO_SUBMITTED;
}

struct dedup_args {
	struct dm_target *ti;

	struct dm_dev *meta_dev;

	struct dm_dev *data_dev;
	u64 data_size;

	u32 block_size;

	char hash_algo[CRYPTO_ALG_NAME_LEN];

	enum backend backend;
	char backend_str[MAX_BACKEND_NAME_LEN];

	u32 flushrq;

	bool corruption_flag;
};

/*
 * Parses metadata device.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int parse_meta_dev(struct dedup_args *da, struct dm_arg_set *as,
			  char **err)
{
	int r;

	r = dm_get_device(da->ti, dm_shift_arg(as),
			  dm_table_get_mode(da->ti->table), &da->meta_dev);
	if (r)
		*err = "Error opening metadata device";

	return r;
}

/*
 * Parses data device.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int parse_data_dev(struct dedup_args *da, struct dm_arg_set *as,
			  char **err)
{
	int r;

	r = dm_get_device(da->ti, dm_shift_arg(as),
			  dm_table_get_mode(da->ti->table), &da->data_dev);
	if (r)
		*err = "Error opening data device";
	else
		da->data_size = i_size_read(da->data_dev->bdev->bd_inode);

	return r;
}

/*
 * Parses block size.
 *
 * Returns -EINVAL in failure.
 * Returns 0 on success.
 */
static int parse_block_size(struct dedup_args *da, struct dm_arg_set *as,
			    char **err)
{
	u32 block_size;

	if (kstrtou32(dm_shift_arg(as), 10, &block_size) ||
	    !block_size ||
		block_size < MIN_DATA_DEV_BLOCK_SIZE ||
		block_size > MAX_DATA_DEV_BLOCK_SIZE ||
		!is_power_of_2(block_size)) {
		*err = "Invalid data block size";
		return -EINVAL;
	}

	if (block_size > da->data_size) {
		*err = "Data block size is larger than the data device";
		return -EINVAL;
	}

	da->block_size = block_size;

	return 0;
}

/*
 * Checks for a recognized hash algorithm.
 *
 * Returns -EINVAL in failure.
 * Returns 0 on success.
 */
static int parse_hash_algo(struct dedup_args *da, struct dm_arg_set *as,
			   char **err)
{
	strlcpy(da->hash_algo, dm_shift_arg(as), CRYPTO_ALG_NAME_LEN);

	if (!crypto_has_alg(da->hash_algo, 0, CRYPTO_ALG_ASYNC)) {
		*err = "Unrecognized hash algorithm";
		return -EINVAL;
	}

	return 0;
}

/*
 * Checks for a supported metadata backend.
 *
 * Returns -EINVAL in failure.
 * Returns 0 on success.
 */
static int parse_backend(struct dedup_args *da, struct dm_arg_set *as,
			 char **err)
{
	char backend[MAX_BACKEND_NAME_LEN];

	strlcpy(backend, dm_shift_arg(as), MAX_BACKEND_NAME_LEN);

	if (!strcmp(backend, "inram")) {
		da->backend = BKND_INRAM;
	} else if (!strcmp(backend, "cowbtree")) {
		da->backend = BKND_COWBTREE;
	} else {
		*err = "Unsupported metadata backend";
		return -EINVAL;
	}

	strlcpy(da->backend_str, backend, MAX_BACKEND_NAME_LEN);

	return 0;
}

/*
 * Checks for a valid flushrq value.
 *
 * Returns -EINVAL in failure.
 * Returns 0 on success.
 */
static int parse_flushrq(struct dedup_args *da, struct dm_arg_set *as,
			 char **err)
{
	if (kstrtou32(dm_shift_arg(as), 10, &da->flushrq)) {
		*err = "Invalid flushrq value";
		return -EINVAL;
	}

	return 0;
}

/*
 * Checks for a valid corruption flag value.
 *
 * Returns -EINVAL in failure.
 * Returns 0 on success.
 */
static int parse_corruption_flag(struct dedup_args *da, struct dm_arg_set *as,
			 char **err)
{
	bool corruption_flag;

        if (kstrtobool(dm_shift_arg(as), &corruption_flag)) {
                *err = "Invalid corruption flag value";
                return -EINVAL;
        }

        da->corruption_flag = corruption_flag;

        return 0;

}

/*
 * Wrapper function for all parse functions.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int parse_dedup_args(struct dedup_args *da, int argc,
			    char **argv, char **err)
{
	struct dm_arg_set as;
	int r;

	if (argc < 7) {
		*err = "Insufficient args";
		return -EINVAL;
	}

	if (argc > 7) {
		*err = "Too many args";
		return -EINVAL;
	}

	as.argc = argc;
	as.argv = argv;

	r = parse_meta_dev(da, &as, err);
	if (r)
		return r;

	r = parse_data_dev(da, &as, err);
	if (r)
		return r;

	r = parse_block_size(da, &as, err);
	if (r)
		return r;

	r = parse_hash_algo(da, &as, err);
	if (r)
		return r;

	r = parse_backend(da, &as, err);
	if (r)
		return r;

	r = parse_flushrq(da, &as, err);
	if (r)
		return r;

	r = parse_corruption_flag(da, &as, err);
	if (r)
		return r;

	return 0;
}

/*
 * Decrements metadata and data device's use count
 * and removes them if necessary.
 */
static void destroy_dedup_args(struct dedup_args *da)
{
	if (da->meta_dev)
		dm_put_device(da->ti, da->meta_dev);

	if (da->data_dev)
		dm_put_device(da->ti, da->data_dev);
}

/*
 * Dmdedup constructor.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int dm_dedup_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dedup_args da;
	struct dedup_config *dc;
	struct workqueue_struct *wq;

	struct init_param_inram iparam_inram;
	struct init_param_cowbtree iparam_cowbtree;
	void *iparam = NULL;
	struct metadata *md = NULL;

	sector_t data_size;
	int r;
	int crypto_key_size;

	struct on_disk_stats d;
	struct on_disk_stats *data = &d;
	u64 logical_block_counter = 0;
	u64 physical_block_counter = 0;

	mempool_t *dedup_work_pool = NULL;
	mempool_t *check_work_pool = NULL;

	bool unformatted;

	memset(&da, 0, sizeof(struct dedup_args));
	da.ti = ti;

	r = parse_dedup_args(&da, argc, argv, &ti->error);
	if (r)
		goto out;

	dc = kzalloc(sizeof(*dc), GFP_KERNEL);
	if (!dc) {
		ti->error = "Error allocating memory for dedup config";
		r = -ENOMEM;
		goto out;
	}

	/* Do we need to add BIOSET_NEED_RESCURE in the flags passed in bioset_create as well? */
	dc->bs = bioset_create(MIN_IOS, 0, BIOSET_NEED_BVECS);
	if (!dc->bs) {
		ti->error = "failed to create bioset";
		r = -ENOMEM;
		goto bad_bs;
	}

	wq = create_singlethread_workqueue("dm-dedup");
	if (!wq) {
		ti->error = "failed to create workqueue";
		r = -ENOMEM;
		goto bad_wq;
	}

	dedup_work_pool = mempool_create_kmalloc_pool(MIN_DEDUP_WORK_IO,
						      sizeof(struct dedup_work));
	if (!dedup_work_pool) {
		ti->error = "failed to create dedup mempool";
		r = -ENOMEM;
		goto bad_dedup_mempool;
	}

	check_work_pool = mempool_create_kmalloc_pool(MIN_DEDUP_WORK_IO,
						sizeof(struct check_work));
	if (!check_work_pool) {
		ti->error = "failed to create fec mempool";
		r = -ENOMEM;
		goto bad_check_mempool;
	}


	dc->io_client = dm_io_client_create();
	if (IS_ERR(dc->io_client)) {
		ti->error = "failed to create dm_io_client";
		r = PTR_ERR(dc->io_client);
		goto bad_io_client;
	}

	dc->block_size = da.block_size;
	dc->sectors_per_block = to_sector(da.block_size);
	data_size = ti->len;
	(void)sector_div(data_size, dc->sectors_per_block);
	dc->lblocks = data_size;

	data_size = i_size_read(da.data_dev->bdev->bd_inode) >> SECTOR_SHIFT;
	(void)sector_div(data_size, dc->sectors_per_block);
	dc->pblocks = data_size;

	/* Meta-data backend specific part */
	switch (da.backend) {
	case BKND_INRAM:
		dc->mdops = &metadata_ops_inram;
		iparam_inram.blocks = dc->pblocks;
		iparam = &iparam_inram;
		break;
	case BKND_COWBTREE:
		dc->mdops = &metadata_ops_cowbtree;
		iparam_cowbtree.blocks = dc->pblocks;
		iparam_cowbtree.metadata_bdev = da.meta_dev->bdev;
		iparam = &iparam_cowbtree;
	}

	strcpy(dc->backend_str, da.backend_str);

	md = dc->mdops->init_meta(iparam, &unformatted);
	if (IS_ERR(md)) {
		ti->error = "failed to initialize backend metadata";
		r = PTR_ERR(md);
		goto bad_metadata_init;
	}

	dc->desc_table = desc_table_init(da.hash_algo);
	if (IS_ERR(dc->desc_table)) {
		ti->error = "failed to initialize crypto API";
		r = PTR_ERR(dc->desc_table);
		goto bad_metadata_init;
	}

	crypto_key_size = get_hash_digestsize(dc->desc_table);

	dc->kvs_hash_pbn = dc->mdops->kvs_create_sparse(md, crypto_key_size,
				sizeof(struct hash_pbn_value),
				dc->pblocks, unformatted);
	if (IS_ERR(dc->kvs_hash_pbn)) {
		ti->error = "failed to create sparse KVS";
		r = PTR_ERR(dc->kvs_hash_pbn);
		goto bad_kvstore_init;
	}

	dc->kvs_lbn_pbn = dc->mdops->kvs_create_linear(md, 8,
			sizeof(struct lbn_pbn_value), dc->lblocks, unformatted);
	if (IS_ERR(dc->kvs_lbn_pbn)) {
		ti->error = "failed to create linear KVS";
		r = PTR_ERR(dc->kvs_lbn_pbn);
		goto bad_kvstore_init;
	}

	r = dc->mdops->flush_meta(md);
	if (r < 0) {
		ti->error = "failed to flush metadata";
		goto bad_kvstore_init;
	}

	if (!unformatted && dc->mdops->get_private_data) {
		r = dc->mdops->get_private_data(md, (void **)&data,
				sizeof(struct on_disk_stats));
		if (r < 0) {
			ti->error = "failed to get private data from superblock";
			goto bad_kvstore_init;
		}

		logical_block_counter = data->logical_block_counter;
		physical_block_counter = data->physical_block_counter;
	}

	dc->data_dev = da.data_dev;
	dc->metadata_dev = da.meta_dev;

	dc->workqueue = wq;
	dc->dedup_work_pool = dedup_work_pool;
	dc->check_work_pool = check_work_pool;
	dc->bmd = md;

	dc->logical_block_counter = logical_block_counter;
	dc->physical_block_counter = physical_block_counter;

	dc->gc_counter = 0;
	dc->writes = 0;
	dc->dupwrites = 0;
	dc->uniqwrites = 0;
	dc->reads_on_writes = 0;
	dc->overwrites = 0;
	dc->newwrites = 0;

	dc->check_corruption = da.corruption_flag;
	dc->fec = false;
	dc->fec_fixed = 0;
	dc->corrupted_blocks = 0;

	strcpy(dc->crypto_alg, da.hash_algo);
	dc->crypto_key_size = crypto_key_size;

	dc->flushrq = da.flushrq;
	dc->writes_after_flush = 0;

	r = dm_set_target_max_io_len(ti, dc->sectors_per_block);
	if (r)
		goto bad_kvstore_init;

	ti->num_flush_bios = 1;
	ti->flush_supported = true;
	ti->discards_supported = true;
	ti->num_discard_bios = 1;
	ti->private = dc;
	return 0;

bad_kvstore_init:
	desc_table_deinit(dc->desc_table);
bad_metadata_init:
	if (md && !IS_ERR(md))
		dc->mdops->exit_meta(md);
	dm_io_client_destroy(dc->io_client);
bad_io_client:
	mempool_destroy(check_work_pool);
bad_check_mempool:
	mempool_destroy(dedup_work_pool);
bad_dedup_mempool:
	destroy_workqueue(wq);
bad_wq:
	kfree(dc->bs);
bad_bs:
	kfree(dc);
out:
	destroy_dedup_args(&da);
	return r;
}


/* Dmdedup destructor. */
static void dm_dedup_dtr(struct dm_target *ti)
{
	struct dedup_config *dc = ti->private;
	struct on_disk_stats data;
	int ret;

	if (dc->mdops->set_private_data) {
		data.physical_block_counter = dc->physical_block_counter;
		data.logical_block_counter = dc->logical_block_counter;

		ret = dc->mdops->set_private_data(dc->bmd, &data,
				sizeof(struct on_disk_stats));
		if (ret < 0)
			DMERR("Failed to set the private data in superblock.");
	}

	ret = dc->mdops->flush_meta(dc->bmd);
	if (ret < 0)
		DMERR("Failed to flush the metadata to disk.");

	flush_workqueue(dc->workqueue);
	destroy_workqueue(dc->workqueue);

	mempool_destroy(dc->dedup_work_pool);

	dc->mdops->exit_meta(dc->bmd);

	dm_io_client_destroy(dc->io_client);

	dm_put_device(ti, dc->data_dev);
	dm_put_device(ti, dc->metadata_dev);
	desc_table_deinit(dc->desc_table);

	kfree(dc);
}

/* Gives Dmdedup status. */
static void dm_dedup_status(struct dm_target *ti, status_type_t status_type,
			    unsigned int status_flags, char *result, unsigned int maxlen)
{
	struct dedup_config *dc = ti->private;
	u64 data_total_block_count;
	u64 data_used_block_count;
	u64 data_free_block_count;
	u64 data_actual_block_count;
	int sz = 0;

	switch (status_type) {
	case STATUSTYPE_INFO:
		data_used_block_count = dc->physical_block_counter;
		data_actual_block_count = dc->logical_block_counter;
		data_total_block_count = dc->pblocks;

		data_free_block_count =
			data_total_block_count - data_used_block_count;

		DMEMIT("%llu %llu %llu %llu ",
		       data_total_block_count, data_free_block_count,
			data_used_block_count, data_actual_block_count);

		DMEMIT("%d %d:%d %d:%d ",
		       dc->block_size,
			MAJOR(dc->data_dev->bdev->bd_dev),
			MINOR(dc->data_dev->bdev->bd_dev),
			MAJOR(dc->metadata_dev->bdev->bd_dev),
			MINOR(dc->metadata_dev->bdev->bd_dev));

		DMEMIT("%llu %llu %llu %llu %llu %llu %llu",
		       dc->writes, dc->uniqwrites, dc->dupwrites,
			dc->reads_on_writes, dc->overwrites, dc->newwrites, dc->gc_counter);
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%s %s %u %s %s %u",
		       dc->metadata_dev->name, dc->data_dev->name, dc->block_size,
			dc->crypto_alg, dc->backend_str, dc->flushrq);
	}
}

/*
 * Cleans up Hash->PBN entry.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int cleanup_hash_pbn(void *key, int32_t ksize, void *value,
			    s32 vsize, void *data)
{
	int r = 0;
	u64 pbn_val = 0;
	struct hash_pbn_value hashpbn_value = *((struct hash_pbn_value *)value);
	struct dedup_config *dc = (struct dedup_config *)data;

	BUG_ON(!data);

	pbn_val = hashpbn_value.pbn;

	if (dc->mdops->get_refcount(dc->bmd, pbn_val) == 1) {
		r = dc->kvs_hash_pbn->kvs_delete(dc->kvs_hash_pbn,
							key, ksize);
		if (r < 0)
			goto out;
		r = dc->mdops->dec_refcount(dc->bmd, pbn_val);
		if (r < 0)
			goto out_dec_refcount;

		dc->physical_block_counter -= 1;
		dc->gc_counter++;
	}

	goto out;

out_dec_refcount:
	dc->kvs_hash_pbn->kvs_insert(dc->kvs_hash_pbn, key,
			ksize, (void *)&hashpbn_value,
			sizeof(hashpbn_value));
out:
	return r;
}

/*
 * Performs garbage collection.
 * Iterates over all Hash->PBN entries and cleans up
 * hashes if the refcount of block is 1.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int garbage_collect(struct dedup_config *dc)
{
	int err = 0;

	BUG_ON(!dc);

	/* Cleanup hashes if the refcount of block == 1 */
	err = dc->kvs_hash_pbn->kvs_iterate(dc->kvs_hash_pbn,
			&cleanup_hash_pbn, (void *)dc);

	return err;
}

/*
 * Gives Debug messages for garbage collection.
 * Also, enables and disables corruption check and
 * FEC flags.
 *
 * Returns -ERR code in failure.
 * Returns 0 on success.
 */
static int dm_dedup_message(struct dm_target *ti,
			    unsigned int argc, char **argv)
{
	int r = 0;

	struct dedup_config *dc = ti->private;
	BUG_ON(!dc);

	if (!strcasecmp(argv[0], "garbage_collect")) {
		r = garbage_collect(dc);
		if (r < 0)
			DMERR("Error in performing garbage_collect: %d.", r);
	} else if (!strcasecmp(argv[0], "drop_bufio_cache")) {
		if (dc->mdops->flush_bufio_cache)
			dc->mdops->flush_bufio_cache(dc->bmd);
		else
			r = -ENOTSUPP;
	} else if (!strcasecmp(argv[0], "corruption")) {
                if (argc != 2) {
                        DMINFO("Incomplete message: Usage corruption <0,1,2>:"
				"0 - disable all corruption check flags, "
				"1 - Enable corruption check, "
				"2 - Enable FEC flag  (also enable corruption check if disabled)");
                        r = -EINVAL;
                } else if (!strcasecmp(argv[1], "1")) {
                        dc->check_corruption = true;
                        dc->fec = false;
                } else if (!strcasecmp(argv[1], "2")) {
                        dc->check_corruption = true;
                        dc->fec = true;
                } else if (!strcasecmp(argv[1], "0")) {
                        dc->fec = false;
                        dc->check_corruption = false;
                } else {
                        r = -EINVAL;
                }
	} else {
		r = -EINVAL;
	}

	return r;
}

static struct target_type dm_dedup_target = {
	.name = "dedup",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = dm_dedup_ctr,
	.dtr = dm_dedup_dtr,
	.map = dm_dedup_map,
	.message = dm_dedup_message,
	.status = dm_dedup_status,
};

static int __init dm_dedup_init(void)
{
	return dm_register_target(&dm_dedup_target);
}

static void __exit dm_dedup_exit(void)
{
	dm_unregister_target(&dm_dedup_target);
}

module_init(dm_dedup_init);
module_exit(dm_dedup_exit);

MODULE_DESCRIPTION(DM_NAME " target for data deduplication");
MODULE_LICENSE("GPL");
