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

#ifndef BACKEND_H
#define BACKEND_H

struct metadata;		/* metadata store identifier */
struct kvstore;			/* key-value store identifier */

#define BF_NEGATIVE -1
#define BF_POSITIVE 0

struct metadata_ops {
	/*
	 * It initializes backend for cowbtree and inram. In case of cowbtree
	 * either new metadata device is created or it is reconstructed from
	 * existing metadata device. For in-ram backend new linked list is
	 * initialized.
	 *
	 * Returns ERR_PTR(*) on error.
	 * Valid pointer on success.
	 */
	struct metadata * (*init_meta)(void *init_param, bool *unformatted);

	void (*exit_meta)(struct metadata *md);

	/*
	 * Creates linear key-value store. Ksize and vsize in bytes.
	 * If ksize or vsize are equal to zero, it means that keys
	 * and values will be of a variable size. kmax is the
	 * maximum _value_ of the key. If kmax is equal to zero,
	 * then maximum is not known by the caller.
	 *
	 * Returns ERR_PTR(*) on error.
	 * Valid pointer on success.
	 */
	struct kvstore * (*kvs_create_linear)(struct metadata *md,
					      u32 ksize, uint32_t vsize,
					      u32 kmax, bool unformatted);
	/*
	 * Creates sparse key-value store. Ksize and vsize in bytes.
	 * If ksize or vsize are equal to zero, it means that keys
	 * and values will be of a variable size. knummax is the
	 * maximum _number_ of the keys. If keymax is equal to zero,
	 * then maximum is not known by the caller.
	 *
	 * Returns ERR_PTR(*) on error.
	 * Valid pointer on success.
	 */
	struct kvstore * (*kvs_create_sparse)(struct metadata *md,
					      u32 ksize, uint32_t vsize,
					      u32 knummax, bool unformatted);

	/*
	 * Returns -ERR code on error.
	 * Returns 0 on success. In this case, "blockn" contains a newly
	 * allocated block number.
	 */
	int (*alloc_data_block)(struct metadata *md, uint64_t *blockn);

	/*
	 * Returns -ERR code on error.
	 * Returns 0 on success.
	 */
	int (*inc_refcount)(struct metadata *md, uint64_t blockn);

	/*
	 * Returns -ERR code on error.
	 * Returns 0 on success.
	 */
	int (*dec_refcount)(struct metadata *md, uint64_t blockn);

	/*
	 * Returns -ERR code on error.
	 * Returns refcount on success.
	 */
	int (*get_refcount)(struct metadata *md, uint64_t blockn);

	/*
	 * Returns -ERR code on error.
	 * Return 0 on success.
	 */
	int (*flush_meta)(struct metadata *md);

	/*
	 * It stores the private data stored in the metadata into
	 * the data pointer provided.
	 *
	 * Returns -ERR code on error.
	 * Returns 0 on success.
	 */
	int (*get_private_data)(struct metadata *md, void **data,
				uint32_t size);

	/*
	 * Fills in private data stored in the metadata.
	 *
	 * Returns -ERR code on error.
	 * Returns 0 on success.
	 */
	int (*set_private_data)(struct metadata *md, void *data, uint32_t size);

	/*
	 * This is a hack to drop cache. In future we want to implement
	 * proper message passing interface, to accomplish this and other
	 * tasks.
	 */
	void (*flush_bufio_cache)(struct metadata *md);
};

#endif /* BACKEND_H */
