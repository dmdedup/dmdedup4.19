//#define __INJECT_ERROR_HANDLE_WRITE__

/*
 * If __INJECT_ERROR_HANDLE_WRITE__ macro is defined
 * then "inj_err" string will be appended to functions
 * otherwise normal function will be called.
 */
#ifdef __INJECT_ERROR_HANDLE_WRITE__
#define INJECT_ERR_STR inj_err_
#else
#define INJECT_ERR_STR
#endif

#define GLUE_HELPER(x, y) x##y
#define GLUE(x, y) GLUE_HELPER(x, y)

#define __INJ_ERR_ALLOC_BLK__ 0x01
#define __INJ_ERR_KVS_INS_LINEAR_BTREE__ 0x02
#define __INJ_ERR_KVS_DEL_LINEAR_BTREE__ 0x04
#define __INJ_ERR_KVS_INS_SPARSE_BTREE__ 0x08
#define __INJ_ERR_KVS_DEL_SPARSE_BTREE__ 0x10
#define __INJ_ERR_INC_REFCNT__ 0x20
#define __INJ_ERR_DEC_REFCNT__ 0x40

extern int allocate_block(struct dedup_config *dc, uint64_t *pbn_new);
int inj_err_allocate_block(struct dedup_config *dc, uint64_t *pbn_new);

extern int kvs_insert_linear_cowbtree(struct kvstore *kvs, void *key,
				      s32 ksize, void *value,
				      int32_t vsize);
int inj_err_kvs_insert_linear_cowbtree(struct kvstore *kvs, void *key,
				       s32 ksize, void *value,
				       int32_t vsize);

extern int kvs_delete_linear_cowbtree(struct kvstore *kvs, void *key,
				      int32_t ksize);
int inj_err_kvs_delete_linear_cowbtree(struct kvstore *kvs, void *key,
				       int32_t ksize);

extern int kvs_insert_sparse_cowbtree(struct kvstore *kvs, void *key,
				      s32 ksize, void *value,
				      int32_t vsize);
int inj_err_kvs_insert_sparse_cowbtree(struct kvstore *kvs, void *key,
				       s32 ksize, void *value,
				       int32_t vsize);

extern int kvs_delete_sparse_cowbtree(struct kvstore *kvs, void *key,
				      int32_t ksize);
int inj_err_kvs_delete_sparse_cowbtree(struct kvstore *kvs, void *key,
				       int32_t ksize);

extern int inc_refcount_cowbtree(struct metadata *md, uint64_t blockn);
int inj_err_inc_refcount_cowbtree(struct metadata *md, uint64_t blockn);

extern int dec_refcount_cowbtree(struct metadata *md, uint64_t blockn);
int inj_err_dec_refcount_cowbtree(struct metadata *md, uint64_t blockn);
