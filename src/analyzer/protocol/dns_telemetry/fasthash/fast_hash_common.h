#ifndef _fast_hash_common_h
#define _fast_hash_common_h

#include <stdint.h>

struct fixed_len_hash {
	uint32_t counts;
	char     *record;
	char     *last_record;
	uint32_t key_len;
	uint32_t val_len;
	uint32_t rec_len;
	void     *records;
};

void*
    fixed_len_hash_lookup(struct fixed_len_hash* self, const char*key);

struct fast_hash {
	uint32_t max_keylen;
	struct fixed_len_hash *h[];
};

#endif
