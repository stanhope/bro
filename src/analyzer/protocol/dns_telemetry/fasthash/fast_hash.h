#ifndef _fast_hash_h
#define _fast_hash_h

#include <stdint.h>
#include "fast_hash_common.h"

/******************************************************************************* 
 *      Interface                                                              *
 *                                                                             *
 * fast_hash_init() must be called first                                       *
 * then fast_hash_add_hash() must be called for each length that will be used  *
 * then fast_hash_insert() and fixed_len_hash_lookup() can be called.          *
 * then fast_hash_destroy() will clean up                                      *
 *******************************************************************************/ 

/***********************************************************************
 * fast_hash_init(max_keylen)                                          *
 *                                                                     *
 * Prepare a structure to handle hashes up to a given key length.      *
 *                                                                     *
 * Returns a pointer to be used with our other functions               *
 ***********************************************************************/
struct fast_hash* 
	fast_hash_init(uint32_t max_keylen);

/***********************************************************************
 * fast_hash_add_hash(fast_hash,key_len,val_len,count)                 *
 *                                                                     *
 * Set up a hash for a given key + value length.                       *
 * Count is the estimated number of items this length will have.       *
 * This is not an automatically resizing hash, so inserts will fail as *
 * the hash exceeds ~98% full (and performance will drop somewhat).    *
 *                                                                     *
 * Value length must be invariant for a given key length.              *
 ***********************************************************************/
void 
	fast_hash_add_hash(struct fast_hash *hashes, 
                            uint32_t key_len,
                            uint32_t val_len,
                            uint32_t count);

/***********************************************************************
 * fast_hash_insert(fast_hash,key,key_len,value)                       *
 *                                                                     *
 * Add entry to hash if space remains. Key and value data is copied.   *
 * The value pointer must be a valid pointer to a value at least as    *
 * wide as was configured when fast_hash_add_hash() was called for     *
 * this key_len.                                                       *
 *                                                                     *
 * Returns NULL on failure to insert.                                  *
 ***********************************************************************/
void*
	fast_hash_insert(struct fast_hash *hashes,
                          void *key,
                          uint32_t key_len,
                          void *value);
/***********************************************************************
 * fast_hash_lookup(fast_hash,key,key_len)                             *
 *                                                                     *
 * Add entry to hash if space remains. Key and value data is copied.   *
 * The value pointer must be a valid pointer to a value at least as    *
 * wide as was configured when fast_hash_add_hash() was called for     *
 * this key_len.                                                       *
 *                                                                     *
 * Returns pointer to value or NULL                                    *
 ***********************************************************************/
inline void* 
	fast_hash_lookup(struct fast_hash *hashes,
                          const void *key, 
                          uint32_t key_len) 
{
	if (hashes->h[key_len]) 
	  return fixed_len_hash_lookup(hashes->h[key_len], (const char*)key); 
	else 
		return NULL;
}

/***********************************************************************
 * fast_hash_destroy()                                                 *
 *                                                                     *
 * Free all associated resources.                                      *
 ***********************************************************************/
void 
	fast_hash_destroy(struct fast_hash *hashes);

#endif
