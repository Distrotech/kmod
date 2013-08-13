/*
 * libkmod - interface to kernel module operations
 *
 * Copyright (C) 2011-2013  ProFUSION embedded systems
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "libkmod.h"
#include "libkmod-hash.h"

#include "libkmod-util.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static _always_inline_ unsigned long long native_read_tsc(void)
{
    unsigned hi, lo;
    asm volatile ("lfence;\n"
		  "rdtsc;\n"
		  : "=a"(lo), "=d"(hi));
    return (unsigned long long)((lo) | ((uint64_t)(hi) << 32));
}

static inline unsigned long long get_cycles(unsigned long long last)
{
	unsigned long long ret;

	ret = native_read_tsc();

	return ret - last;
}

struct hash_entry {
	const char *key;
	const void *value;
};

struct hash_bucket {
	struct hash_entry *entries;
	unsigned int used;
	unsigned int total;
};

struct hash {
	unsigned int count;
	unsigned int step;
	unsigned int n_buckets;
	void (*free_value)(void *value);
	struct hash_bucket buckets[];
};

struct hash *hash_new(unsigned int n_buckets,
					void (*free_value)(void *value))
{
	struct hash *hash;

	n_buckets = ALIGN_POWER2(n_buckets);
	hash = calloc(1, sizeof(struct hash) +
		      n_buckets * sizeof(struct hash_bucket));
	if (hash == NULL)
		return NULL;
	hash->n_buckets = n_buckets;
	hash->free_value = free_value;
	hash->step = n_buckets / 32;
	if (hash->step == 0)
		hash->step = 4;
	else if (hash->step > 64)
		hash->step = 64;
	return hash;
}

void hash_free(struct hash *hash)
{
	struct hash_bucket *bucket, *bucket_end;

	if (hash == NULL)
		return;

	bucket = hash->buckets;
	bucket_end = bucket + hash->n_buckets;
	for (; bucket < bucket_end; bucket++) {
		if (hash->free_value) {
			struct hash_entry *entry, *entry_end;
			entry = bucket->entries;
			entry_end = entry + bucket->used;
			for (; entry < entry_end; entry++)
				hash->free_value((void *)entry->value);
		}
		free(bucket->entries);
	}
	free(hash);
}

static _always_inline_ uint32_t rotl32 ( uint32_t x, int8_t r )
{
  return (x << r) | (x >> (32 - r));
}

#define	ROTL32(x,y)	rotl32(x,y)

static _always_inline_ uint32_t getblock32 ( const uint32_t * p, int i )
{
  return p[i];
}

static inline unsigned int MurmurHash3_x86_32(const void * key, unsigned int len)
{
  const uint8_t * data = (const uint8_t*)key;
  const int nblocks = len / 4;

  uint32_t h1 = 0;

  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  const uint8_t * tail;
  uint32_t k1;

  //----------
  // body

  const uint32_t * blocks = (const uint32_t *)(data + nblocks*4);

  for(int i = -nblocks; i; i++)
  {
    k1 = getblock32(blocks,i);

    k1 *= c1;
    k1 = ROTL32(k1,15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1,13);
    h1 = h1*5+0xe6546b64;
  }

  //----------
  // tail

  tail = (const uint8_t*)(data + nblocks*4);

  k1 = 0;

  switch(len & 3)
  {
  case 3: k1 ^= tail[2] << 16;
  case 2: k1 ^= tail[1] << 8;
  case 1: k1 ^= tail[0];
          k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
  };

  //----------
  // finalization

  h1 ^= len;

  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}

static inline unsigned int hash_crc32c_hw(const void *key, unsigned int len)
{
    const char* p_buf = (const char*) key;
    unsigned int crc = 0;
    unsigned int i;

    for (i = 0; i < len / sizeof(uint64_t); i++) {
	    crc = __builtin_ia32_crc32di(crc, *(uint64_t*) p_buf);
	    p_buf += sizeof(uint64_t);
    }

    len &= sizeof(uint64_t) - 1;

    switch (len) {
    case 7:
	    crc = __builtin_ia32_crc32qi(crc, *p_buf++);
    case 6:
	    crc = __builtin_ia32_crc32hi(crc, *(uint16_t*) p_buf);
	    p_buf += 2;
	    // case 5 is below: 4 + 1
    case 4:
	    crc = __builtin_ia32_crc32si(crc, *(uint32_t*) p_buf);
	    break;
    case 3:
	    crc = __builtin_ia32_crc32qi(crc, *p_buf++);
    case 2:
	    crc = __builtin_ia32_crc32hi(crc, *(uint16_t*) p_buf);
	    break;
    case 5:
	    crc = __builtin_ia32_crc32si(crc, *(uint32_t*) p_buf);
	    p_buf += 4;
    case 1:
	    crc = __builtin_ia32_crc32qi(crc, *p_buf);
	    break;
    case 0:
	    break;
    }

    return crc;

}

static inline unsigned int MurmurHash3_x86_32(const void *key, unsigned int len)
{
	unsigned hash = 5381;
	const signed char *c;

	/* DJB's hash function */

	for (c = key; *c; c++)
		hash = (hash << 5) + hash + (unsigned) *c;

	return hash;
}

static inline unsigned int hash_paul(const char *key, unsigned int len)
{
	/* Paul Hsieh (http://www.azillionmonkeys.com/qed/hash.html)
	 * used by WebCore (http://webkit.org/blog/8/hashtables-part-2/)
	 * EFL's eina and possible others.
	 */
	unsigned int tmp, hash = len, rem = len & 3;

	len /= 4;

	/* Main loop */
	for (; len > 0; len--) {
		hash += get_unaligned((uint16_t *) key);
		tmp = (get_unaligned((uint16_t *)(key + 2)) << 11) ^ hash;
		hash = (hash << 16) ^ tmp;
		key += 4;
		hash += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
	case 3:
		hash += get_unaligned((uint16_t *) key);
		hash ^= hash << 16;
		hash ^= key[2] << 18;
		hash += hash >> 11;
		break;

	case 2:
		hash += get_unaligned((uint16_t *) key);
		hash ^= hash << 11;
		hash += hash >> 17;
		break;

	case 1:
		hash += *key;
		hash ^= hash << 10;
		hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

/*
 * add or replace key in hash map.
 *
 * none of key or value are copied, just references are remembered as is,
 * make sure they are live while pair exists in hash!
 */
int hash_add(struct hash *hash, const char *key, const void *value)
{
	unsigned int keylen = strlen(key);
	unsigned int hashval = hash_superfast(key, keylen);
	unsigned int pos = hashval & (hash->n_buckets - 1);
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	if (bucket->used + 1 >= bucket->total) {
		unsigned new_total = bucket->total + hash->step;
		size_t size = new_total * sizeof(struct hash_entry);
		struct hash_entry *tmp = realloc(bucket->entries, size);
		if (tmp == NULL)
			return -errno;
		bucket->entries = tmp;
		bucket->total = new_total;
	}

	entry = bucket->entries;
	entry_end = entry + bucket->used;
	for (; entry < entry_end; entry++) {
		int c = strcmp(key, entry->key);
		if (c == 0) {
			if (hash->free_value)
				hash->free_value((void *)entry->value);
			entry->value = value;
			return 0;
		} else if (c < 0) {
			memmove(entry + 1, entry,
				(entry_end - entry) * sizeof(struct hash_entry));
			break;
		}
	}

	entry->key = key;
	entry->value = value;
	bucket->used++;
	hash->count++;
	return 0;
}

void hash_dump(struct hash *hash)
{
	unsigned int i _unused_;

	fprintf(stderr, "#####\n");
	fprintf(stderr, "%p %d %u\n", hash, hash->count, hash->n_buckets);
	fprintf(stderr, "#####\n");
	for (i = 0; i < hash->n_buckets; i++) {
		struct hash_bucket *bucket = hash->buckets + i;
		fprintf(stderr, "%u %d\n", i, bucket->used);
	}
	fprintf(stderr, "#####\n");
	hash_dump_keys(hash);
	fprintf(stderr, "#####\n");
}

void hash_dump_keys(struct hash *hash)
{
	unsigned int i;

	for (i = 0; i < hash->n_buckets; i++) {
		struct hash_bucket *bucket = hash->buckets + i;
		struct hash_entry *entry, *entry_end;

		entry = bucket->entries;
		entry_end = entry + bucket->used;
		for (; entry < entry_end; entry++)
			fprintf(stderr, "%s\n", entry->key);
	}
}

/* similar to hash_add(), but fails if key already exists */
int hash_add_unique(struct hash *hash, const char *key, const void *value)
{
	unsigned int keylen = strlen(key);
	unsigned int hashval = hash_superfast(key, keylen);
	unsigned int pos = hashval & (hash->n_buckets - 1);
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	if (bucket->used + 1 >= bucket->total) {
		unsigned new_total = bucket->total + hash->step;
		size_t size = new_total * sizeof(struct hash_entry);
		struct hash_entry *tmp = realloc(bucket->entries, size);
		if (tmp == NULL)
			return -errno;
		bucket->entries = tmp;
		bucket->total = new_total;
	}

	entry = bucket->entries;
	entry_end = entry + bucket->used;
	for (; entry < entry_end; entry++) {
		int c = strcmp(key, entry->key);
		if (c == 0)
			return -EEXIST;
		else if (c < 0) {
			memmove(entry + 1, entry,
				(entry_end - entry) * sizeof(struct hash_entry));
			break;
		}
	}

	entry->key = key;
	entry->value = value;
	bucket->used++;
	hash->count++;
	return 0;
}

static int hash_entry_cmp(const void *pa, const void *pb)
{
	const struct hash_entry *a = pa;
	const struct hash_entry *b = pb;
	return strcmp(a->key, b->key);
}

void *hash_find(const struct hash *hash, const char *key)
{
	unsigned int keylen = strlen(key);
	unsigned int hashval = hash_superfast(key, keylen);
	unsigned int pos = hashval & (hash->n_buckets - 1);
	const struct hash_bucket *bucket = hash->buckets + pos;
	const struct hash_entry se = {
		.key = key,
		.value = NULL
	};
	const struct hash_entry *entry = bsearch(
		&se, bucket->entries, bucket->used,
		sizeof(struct hash_entry), hash_entry_cmp);
	if (entry == NULL)
		return NULL;
	return (void *)entry->value;
}

int hash_del(struct hash *hash, const char *key)
{
	unsigned int keylen = strlen(key);
	unsigned int hashval = hash_superfast(key, keylen);
	unsigned int pos = hashval & (hash->n_buckets - 1);
	unsigned int steps_used, steps_total;
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;
	const struct hash_entry se = {
		.key = key,
		.value = NULL
	};

	entry = bsearch(&se, bucket->entries, bucket->used,
		sizeof(struct hash_entry), hash_entry_cmp);
	if (entry == NULL)
		return -ENOENT;

	if (hash->free_value)
		hash->free_value((void *)entry->value);

	entry_end = bucket->entries + bucket->used;
	memmove(entry, entry + 1,
		(entry_end - entry) * sizeof(struct hash_entry));

	bucket->used--;
	hash->count--;

	steps_used = bucket->used / hash->step;
	steps_total = bucket->total / hash->step;
	if (steps_used + 1 < steps_total) {
		size_t size = (steps_used + 1) *
			hash->step * sizeof(struct hash_entry);
		struct hash_entry *tmp = realloc(bucket->entries, size);
		if (tmp) {
			bucket->entries = tmp;
			bucket->total = (steps_used + 1) * hash->step;
		}
	}

	return 0;
}

unsigned int hash_get_count(const struct hash *hash)
{
	return hash->count;
}

void hash_iter_init(const struct hash *hash, struct hash_iter *iter)
{
	iter->hash = hash;
	iter->bucket = 0;
	iter->entry = -1;
}

bool hash_iter_next(struct hash_iter *iter, const char **key,
							const void **value)
{
	const struct hash_bucket *b = iter->hash->buckets + iter->bucket;
	const struct hash_entry *e;

	iter->entry++;

	if (iter->entry >= b->used) {
		iter->entry = 0;

		for (iter->bucket++; iter->bucket < iter->hash->n_buckets;
							iter->bucket++) {
			b = iter->hash->buckets + iter->bucket;

			if (b->used > 0)
				break;
		}

		if (iter->bucket >= iter->hash->n_buckets)
			return false;
	}

	e = b->entries + iter->entry;

	if (value != NULL)
		*value = e->value;
	if (key != NULL)
		*key = e->key;

	return true;
}
