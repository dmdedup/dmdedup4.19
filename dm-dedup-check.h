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

#ifndef DM_DEDUP_CHECK_CORRUPTION_H
#define DM_DEDUP_CHECK_CORRUPTION_H

/*
 * Check_io struct is used to pass arguments through
 * struct bio, to be used later in the callback function
 */
struct check_io {
	struct dedup_config *dc;
	u64 pbn;
	u64 lbn;
	struct bio *base_bio;
};

/*
 * check_work struct is used to initialize a dedicated
 * workqueue only for doing Forward error correction
 */
struct check_work {
	struct work_struct worker;
	struct check_io *io;
};

extern void dedup_check_endio(struct bio *clone);

#endif /* DM_DEDUP_CHECK_CORRUPTION_H */
