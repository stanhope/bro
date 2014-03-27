#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <math.h>
#include "fast_hash_common.h"

inline int memcmp_fast(const void *a, const void *b, uint32_t len) {
	uint32_t chunks, remainder;
	if (len >= 8) {
		chunks    = len / 8;
		remainder = len % 8;
	} else {
		chunks    = 0;
		remainder = len;
	}
	while (chunks--) {
		if (*(uint64_t*)a != *(uint64_t*)b) return 1;
		a += 8;
		b += 8;
	}
	switch (remainder) {
		case 7:
			if (*(uint8_t*)a != *(uint8_t*)b) return 1;
			a += 1;
			b += 1;
		case 6:
			if (*(uint16_t*)a != *(uint16_t*)b) return 1;
			a += 2;
			b += 2;
			return (*(uint32_t*)a != *(uint32_t*)b);
		case 5:
			if (*(uint8_t*)a != *(uint8_t*)b) return 1;
			a += 1;
			b += 1;
		case 4:
			return (*(uint32_t*)a != *(uint32_t*)b);
		case 3:
			if (*(uint8_t*)a != *(uint8_t*)b) return 1;
			a += 1;
			b += 1;
		case 2:
			return (*(uint16_t*)a != *(uint16_t*)b);
		case 1:
			return (*(uint8_t*)a != *(uint8_t*)b);
		default:
			return 0;
	}
}

struct fixed_len_hash* 
fixed_len_hash_init(uint32_t key_len, uint32_t val_len, int count)
{
  struct fixed_len_hash *self = (struct fixed_len_hash*)calloc(sizeof(struct fixed_len_hash),1);
	self->key_len = key_len;
	self->val_len = val_len;
	self->rec_len = key_len + val_len;
	self->counts = (1.3 * count); 
	uint32_t records  = self->counts + 256; //TODO More optimal choice of tailing overflow count 
	// printf("Allocated %u slots for %u items (%f%%) @ key length %u\n",records,count,(double)count/records,key_len);
	self->record      = (char*)calloc(self->rec_len,records);
	self->last_record = &self->record[self->rec_len*(records-1)];
	return self;
}

void
fixed_len_hash_destroy(struct fixed_len_hash* self)
{
	free(self->record);
	free(self);
}


// Really dumb "hash" function demonstrates significant cost of FNV1 (25-50% of total time!)
uint32_t _fixed_len_hash_hash(const char *key, uint32_t len) {
	if (len >= 12) {
		return *(uint32_t*)key * *(uint32_t*)(key+4) * *(uint32_t*)(key+8);
	} else if (len >= 8) {
		return *(uint32_t*)key * *(uint32_t*)(key+4);
	} else {
		return *(uint32_t*)key;
	}
}

/*
// FNV1 - rather slow
uint32_t _fixed_len_hash_hash(const char *key, uint32_t len) {
	uint32_t hash = 2166136261;
	uint32_t i;
	for (i=0; i<len; i++)
		hash = (16777619 * hash) ^ key[i];
	return hash;
}
*/

inline char* 
  _fixed_len_hash_addr(struct fixed_len_hash* self, const char *key) 
{
	return &self->record[
		self->rec_len
		* (_fixed_len_hash_hash(key, self->key_len) % self->counts)
	];
}

void*
fixed_len_hash_lookup(struct fixed_len_hash* self, const char *key)
{
	char *record = _fixed_len_hash_addr(self, key);
	do {
	  if (memcmp_fast(record, key, self->key_len) == 0) 
	    return (void*)record + self->key_len;
	  record += self->rec_len;
	} while (*record != 0);
	return NULL;
}

void* 
fixed_len_hash_insert(struct fixed_len_hash* self, void *key, void *value)
{
  char *record = _fixed_len_hash_addr(self, (const char*)key);
	while (*record != 0) {
		if (record < self->last_record) {
			record += self->rec_len;
		} else {
			return NULL; // Out of space!
		}
	}
	memcpy(record                , key  , self->key_len);
	memcpy(record + self->key_len, value, self->val_len);
	return (void*)record;
}

struct fast_hash*
fast_hash_init(uint32_t max_keylen)
{
  struct fast_hash *h = (fast_hash*)calloc(   sizeof(struct fast_hash) 
	                             + (sizeof(struct fixed_len_hash)*(max_keylen+1))
	                            ,1);
	if (h) h->max_keylen = max_keylen;
	return h;
};

void
fast_hash_destroy(struct fast_hash *hashes)
{
	uint32_t i;
	for (i=0;i<=hashes->max_keylen;i++) {
		if (hashes->h[i]) fixed_len_hash_destroy(hashes->h[i]);
	}
}

void
fast_hash_add_hash(struct fast_hash *hashes, uint32_t key_len, uint32_t val_len, uint32_t count) {
	hashes->h[key_len] = fixed_len_hash_init(key_len,val_len,count);
}

void*
fast_hash_insert(struct fast_hash *hashes, void *key, uint32_t key_len, void *value) {
	return fixed_len_hash_insert(hashes->h[key_len], key, value);
}
