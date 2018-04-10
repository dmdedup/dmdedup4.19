/*
 * Copyright (C) 2012-2018 Vasily Tarasov
 * Copyright (C) 2012-2018 Erez Zadok
 * Copyright (C) 2018-2018 Rahul Rane
 * Copyright (C) 2017-2018 Noopur Maheshwari
 * Copyright (c) 2012-2018 Stony Brook University
 * Copyright (c) 2012-2018 The Research Foundation for SUNY
 * This file is released under the GPL.
 */

#ifndef DM_DEDUP_TEST_HANDLEWRITE_H
#define DM_DEDUP_TEST_HANDLEWRITE_H

/*
 * Handle_write_no_hash testing. Injecting error at different
 * stages and testing code path. Macros are defined to inject
 * error at different stages. If value of macro is set to 1
 * then error will be injected at that stage. We can inject
 * multiple errors at same time or single error at a time.
 */
#define EINJECTERR	1
#if 0
#define __INJECT_ERR_ALLOC_PBNBLK__
#define __INJECT_ERR_ALLOC_PBNBLK_LBNPBN_INSERT__
/*
 * To test codepath of handle_write_no_hash when no lbn-pbn
 * mapping is present.
 */
#define __INJECT_ERR_HANDLE_NO_LBNPBN_KVS_INSERT__
#define __INJECT_ERR_HANDLE_NO_LBNPBN_INC_REFCNT__
#define __INJECT_ERR_HANDLE_NO_LBNPBN_KVS_DELETE_ERRPATH_1__
#define __INJECT_ERR_HANDLE_NO_LBNPBN_KVS_DELETE_ERRPATH_2__
#define __INJECT_ERR_HANDLE_NO_LBNPBN_DEC_REFCNT_ERRPATH__

/*
 * To test codepath of handle_write_no_hash when lbn-pbn mapping
 * is present.
 */
#define __INJECT_ERR_HANDLE_HAS_LBNPBN_KVS_INSERT__
#define __INJECT_ERR_HANDLE_HAS_LBNPBN_INC_REFCNT__
#define __INJECT_ERR_HANDLE_HAS_LBNPBN_DEC_REFCNT__
#define __INJECT_ERR_HANDLE_HAS_LBNPBN_DEC_REFCNT_ERRPATH_1__
#define __INJECT_ERR_HANDLE_HAS_LBNPBN_KVS_DELETE_ERRPATH_1__
#define __INJECT_ERR_HANDLE_HAS_LBNPBN_KVS_DELETE_ERRPATH_2__
#define __INJECT_ERR_HANDLE_HAS_LBNPBN_DEC_REFCNT_ERRPATH_2__
#endif
#endif /* DM_DEDUP_TEST_HANDLEWRITE_H */
