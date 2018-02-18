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
static struct shash_desc *slot_to_desc(struct hash_desc_table *desc_table,
							unsigned long slot)
{
	BUG_ON(slot >= DEDUP_HASH_DESC_COUNT);
       return desc_table->desc[slot];
}

struct hash_desc_table *desc_table_init(char *hash_alg)
{
	int i = 0;
       struct hash_desc_table *desc_table, *out;
       struct crypto_shash *item;

	desc_table = kmalloc(sizeof(struct hash_desc_table), GFP_NOIO);
	if (!desc_table)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < DEDUP_HASH_DESC_COUNT; i++) {
		desc_table->free_bitmap[i] = true;
               item = crypto_alloc_shash(hash_alg, 0, 0);
               if (IS_ERR(item)) {
                       i--;
                       out = (struct hash_desc_table *)item;
                       goto error;
               }
               desc_table->desc[i] = kmalloc(sizeof(struct shash_desc)
                                             + crypto_shash_descsize(item),
                                             GFP_NOIO);
               if (!desc_table->desc[i]) {
                       i--;
                       crypto_free_shash(item);
                       out = ERR_PTR(-ENOMEM);
                       goto error;
               }
               desc_table->desc[i]->tfm = item;
	}

	atomic_long_set(&(desc_table->slot_counter), 0);

	return desc_table;
error:
       for ( ; i >= 0; i--) {
               crypto_free_shash(desc_table->desc[i]->tfm);
               kfree(desc_table->desc[i]);
       }
       kfree(desc_table);
       return out;
}

void desc_table_deinit(struct hash_desc_table *desc_table)
{
	int i = 0;

	for (i = 0; i < DEDUP_HASH_DESC_COUNT; i++) {
               crypto_free_shash(desc_table->desc[i]->tfm);
               kfree(desc_table->desc[i]);
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
       struct shash_desc *desc;
       unsigned int ret;

	slot = get_next_slot(desc_table);
	desc = slot_to_desc(desc_table, slot);

       ret = crypto_shash_digestsize(desc->tfm);
       put_slot(desc_table, slot);
       return ret;
}

int compute_hash_bio(struct hash_desc_table *desc_table,
		     struct bio *bio, char *hash)
{
	int ret = 0;
	unsigned long slot;
	struct bio_vec bvec;
	struct bvec_iter iter;
       struct shash_desc *desc;

	slot = get_next_slot(desc_table);
	desc = slot_to_desc(desc_table, slot);

       ret = crypto_shash_init(desc);
	if (ret)
		goto out;
	__bio_for_each_segment(bvec, bio, iter, bio->bi_iter) {
               crypto_shash_update(desc,
                                   page_address(bvec.bv_page)+bvec.bv_offset,
                                   bvec.bv_len);
	}

       crypto_shash_final(desc, hash);
out:
	put_slot(desc_table, slot);
	return ret;
}
