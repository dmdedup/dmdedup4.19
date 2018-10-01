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

#include "dm-dedup-target.h"
#include "dm-dedup-check.h"
#include "dm-dedup-hash.h"
#include "dm-dedup-backend.h"
#include "dm-dedup-kvstore.h"

/*
 * bio - contains the data read from the disk
 * io  - contains pbn, lbn information obtained from LBN->PBN mapping
 *
 * Hash is calculated for the data inside bio, and
 * checked against HASH->PBN structure. If PBN from both the
 * mappings doesn't match, then the function tries to correct
 * the error
 *
 * The refcount for old pbn is reduced so that it gets taken care
 * by the garbage collection engine when it reaches 1
 */
static void check_endio(struct bio *bio, struct check_io *io)
{
	int r;
	struct dedup_config *dc;
	u8 hash[MAX_DIGEST_SIZE];
	struct hash_pbn_value hashpbn_value;
	struct lbn_pbn_value lbnpbn_value;
	u32 vsize;

	if (bio->bi_status)
		goto out;

	dc = io->dc;

	BUG_ON(!dc->check_corruption);

	/* calculate hash for the data read from the disk */
	r = compute_hash_bio(dc->desc_table, bio, hash);

	/* if hash calculation fails, return silently */
	if (r)
		goto out;

	/* retrieve the pbn from HASH->PBN mapping if any */
	r = dc->kvs_hash_pbn->kvs_lookup(dc->kvs_hash_pbn, hash,
			dc->crypto_key_size, &hashpbn_value, &vsize);

	/* HASH->PBN lookup failed */
	if (r < 0)
		goto out;

	if (r == 0)
		goto no_hash_pbn_entry;

	/* HASH->PBN lookup return a valid entry */
	/* Lookup successful, Comparing LBN-PBN with HASH-PBN */
	if (io->pbn == hashpbn_value.pbn)
		goto out;

	/* if fec is not enabled, only report corruption */
	if (!dc->fec)
		goto no_fec;

	/* if PBNs don't match, remove the old LBN->PBN entry */
	r = dc->kvs_lbn_pbn->kvs_delete(dc->kvs_lbn_pbn,
					(void *)&(io->lbn), sizeof(io->lbn));
	if (r < 0)
		goto out_fec_fail;

	/* decrement the refcount for old PBN */
	dc->mdops->dec_refcount(dc->bmd, io->pbn);

	lbnpbn_value.pbn = hashpbn_value.pbn;

	/* increment the refcount for new PBN */
	r = dc->mdops->inc_refcount(dc->bmd, lbnpbn_value.pbn);
	if (r < 0)
		goto out_fec_fail;

	/* insert the new mapping in LBN->PBN mapping */
	r = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn,
					(void *)&(io->lbn), sizeof(io->lbn),
					(void *)&lbnpbn_value,
					sizeof(lbnpbn_value));
	if (r < 0) {
		dc->mdops->dec_refcount(dc->bmd, lbnpbn_value.pbn);
		goto out_fec_fail;
	}

	goto out_fec_pass;

no_hash_pbn_entry:
	/* No matching entry found in HASH->PBN lookup */

	/* if fec is not enabled, only report corruption */
	if (!dc->fec)
		goto no_fec;

	/*
	 * No matching entry found in HASH->PBN lookup
	 * Insert a new HASH->PBN mapping
	 * XXX: Leaves an extra entry in HASH->PBN for the
		old data.
	 */
	hashpbn_value.pbn = io->pbn;
	r = dc->kvs_hash_pbn->kvs_insert(dc->kvs_hash_pbn,
				(void *)hash, dc->crypto_key_size,
				(void *)&hashpbn_value, sizeof(hashpbn_value));
	if (r < 0)
		goto out_fec_fail;

out_fec_pass:
	dc->fec_fixed++;
	goto out_corruption;

no_fec:
out_fec_fail:
	bio->bi_status = BLK_STS_IOERR;

out_corruption:
	dc->corrupted_blocks++;

out:
	kfree(io);
	bio_endio(bio);
}

/* Calls worker function with data in worker. */
static void issue_work(struct work_struct *ws)
{
	struct check_work *data = container_of(ws, struct check_work, worker);
	struct check_io *io = (struct check_io *)data->io;

	mempool_free(data, io->dc->check_work_pool);

	check_endio(io->base_bio, io);
}

/* Allocates and initializes workqueue and regsiters function for work. */
void dedup_check_endio(struct bio *clone)
{
	struct check_work *data;
	struct check_io *io;

	io = clone->bi_private;

	/* deallocate clone created before disk read */
	bio_put(clone);

	/*
	 * initialize a worker for handling the FEC.
	 * Directly calling check_work would panic
	 */
	data = mempool_alloc(io->dc->check_work_pool, GFP_NOIO);
	if (!data) {
		/*
		 * XXX: Decide whether to fail or silently pass
		 *	if unable to do corruption check
		 *	and set the corresponding error flags
		 */
		bio_endio(io->base_bio);
		kfree(io);
		return;
	}

	data->io = io;

	INIT_WORK(&(data->worker), issue_work);

	queue_work(io->dc->workqueue, &(data->worker));
}
