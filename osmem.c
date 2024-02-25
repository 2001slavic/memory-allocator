// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define META_SIZE sizeof(struct block_meta)

#define MMAP_THRESHOLD	(128 * 1024)
#define ALLOC_ERROR ((void *) -1)

#define ALLOC_MODE_MALLOC 0
#define ALLOC_MODE_CALLOC 1

#define BLOCK_NOT_FOUND ((void *) -1)

#define MIN(a, b)	((a) > (b) ? (b) : (a))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

#define TRUE 1
#define FALSE 0

// Base of linked-list.
struct block_meta *global_base = (struct block_meta *)NULL;

// Search for block in list and return its previous.
struct block_meta *get_block(struct block_meta *block)
{
	struct block_meta *prev = BLOCK_NOT_FOUND;

	if (!global_base)
		return BLOCK_NOT_FOUND;
	if (block == global_base)
		return NULL;

	struct block_meta *p = global_base;

	for (; p; prev = p, p = p->next) {
		if (p == block)
			return prev;
	}

	return BLOCK_NOT_FOUND;
}

// Remove a block from linked-list.
void remove_block(struct block_meta *block)
{
	struct block_meta *prev = get_block(block);

	if (prev == BLOCK_NOT_FOUND)
		return;
	if (prev == NULL) {
		global_base = NULL;
		return;
	}

	prev->next = block->next;
}

// Get last block. If param is TRUE -- returns last block from heap.
struct block_meta *get_last(int last_from_heap)
{
	struct block_meta *p = global_base;
	struct block_meta *res = NULL;

	for (; p; p = p->next) {
		if ((last_from_heap && p->status != STATUS_MAPPED) || !last_from_heap)
			res = p;
	}
	return res;
}

// Append block to linked-list.
void append_block(struct block_meta *block)
{
	block->next = NULL;
	struct block_meta *last = get_last(FALSE);

	if (last)
		last->next = block;
	else
		global_base = block;
}

// Attempt to split a block. size_t size -- the desired size of allocated block.
void split(struct block_meta *block, size_t size)
{
	block->status = STATUS_ALLOC;
	// Check if enough space for at least one byte of payload after split.
	int size_diff = block->size - size - ALIGN(META_SIZE) - ALIGN(1);

	if (size_diff < 0)
		return;

	// The free block.
	struct block_meta *block2 = (void *)block + size;

	block2->next = block->next;
	block2->size = block->size - size;
	block2->status = STATUS_FREE;

	block->next = block2;
	block->size = size;
	block->status = STATUS_ALLOC;
}

// Attempt to perform memory preallocation.
struct block_meta *prealloc(size_t size)
{
	// Check if prealloc was already performed.
	static int first_time = 1;

	if (!first_time)
		return NULL;
	struct block_meta *block = sbrk(MMAP_THRESHOLD);

	if (block == ALLOC_ERROR)
		return NULL;
	append_block(block);
	block->size = MMAP_THRESHOLD;
	split(block, size);

	first_time = 0;
	return block;
}

// (void *) to (struct block_meta *)
struct block_meta *get_block_ptr(void *ptr)
{
	return (struct block_meta *)ptr - 1;
}

// Find best-fit free block of at least size_t size.
struct block_meta *find_free_block(size_t size)
{
	struct block_meta *res = NULL;
	int size_diff = __INT_MAX__;

	for (struct block_meta *p = global_base; p; p = p->next) {
		int curr_diff = p->size - size;

		if (p->status == STATUS_FREE && curr_diff >= 0 && curr_diff < size_diff) {
			res = p;
			size_diff = curr_diff;
		}
	}
	return res;
}

/*
 *	Attempt to expand memory.
 *	If alloc_new == TRUE, allocate new block of memory if expand not possible.
 */
struct block_meta *expand(size_t size, int alloc_new)
{
	struct block_meta *last = get_last(TRUE);

	// Allocate new memory, if needed.
	if ((!last || last->status != STATUS_FREE) && alloc_new) {
		struct block_meta *block = sbrk(size);

		if (block == ALLOC_ERROR)
			return NULL;
		append_block(block);
		block->size = size;
		block->status = STATUS_ALLOC;
		return block;
	}

	void *ret = sbrk(size - last->size);

	if (ret == ALLOC_ERROR)
		return NULL;
	last->size = size;
	last->status = STATUS_ALLOC;

	return last;
}

// Attempt coalescing free blocks.
void coalesce(void)
{
	struct block_meta *first = global_base;

	if (!first)
		return;
	struct block_meta *second = global_base->next;

	if (!second)
		return;

	while (second) {
		if (first->status == STATUS_FREE && second->status == STATUS_FREE) {
			first->next = second->next;
			first->size += second->size;
			second = first->next;
		} else {
			first = first->next;
			second = second->next;
		}
	}
}

/*
 *	os_malloc() + os_calloc().
 *	int mode -- sets malloc or calloc mode
 */
void *alloc(size_t size, int mode)
{
	if (size <= 0)
		return NULL;

	struct block_meta *block;
	const size_t total_size = ALIGN(size) + ALIGN(META_SIZE);

	size_t threshold;

	if (mode == ALLOC_MODE_MALLOC)
		threshold = MMAP_THRESHOLD;
	else if (mode == ALLOC_MODE_CALLOC)
		threshold = getpagesize();

	if (total_size > threshold) {
		block = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (block == ALLOC_ERROR)
			return NULL;

		append_block(block);
		block->size = total_size;
		block->status = STATUS_MAPPED;
		return (block + 1);
	}

	coalesce();

	block = find_free_block(total_size);
	if (block) {
		split(block, total_size);
		return (block + 1);
	}

	block = prealloc(total_size);
	if (!block) {
		block = expand(total_size, TRUE);
		if (!block)
			return NULL;
	}
	return (block + 1);
}

void *os_malloc(size_t size)
{
	return alloc(size, ALLOC_MODE_MALLOC);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;
	struct block_meta *block = get_block_ptr(ptr);

	if (block->status != STATUS_ALLOC && block->status != STATUS_MAPPED)
		return;
	if (block->status == STATUS_MAPPED) {
		remove_block(block);
		munmap(block, block->size);
		return;
	}

	block->status = STATUS_FREE;
}

void *os_calloc(size_t nmemb, size_t size)
{
	void *ret = alloc(nmemb * size, ALLOC_MODE_CALLOC);

	if (!ret)
		return NULL;
	memset(ret, 0, nmemb * size);
	return ret;
}

// Expand function, more specific for realloc() needs.
int realloc_expand(struct block_meta *block, size_t size)
{
	struct block_meta *next = block->next;

	if (next && next->status == STATUS_FREE) {
		block->size += next->size;
		remove_block(next);
		if (block->size >= size) {
			split(block, size);
			return 1;
		}
	}

	struct block_meta *last = get_last(TRUE);

	if (block == last) {
		block = expand(size, FALSE);
		return 1;
	}

	return 0;
}

// What should realloc normally do.
void *realloc_new_block(struct block_meta *block, size_t size)
{
	struct block_meta *new_block = get_block_ptr(os_malloc(size));

	memcpy((void *)new_block + ALIGN(META_SIZE), (void *)block + ALIGN(META_SIZE), MIN(block->size, size));
	os_free(block + 1);
	return (new_block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);
	if (get_block_ptr(ptr)->status == STATUS_FREE)
		return NULL;
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	size_t total_size = ALIGN(size) + ALIGN(META_SIZE);
	struct block_meta *block = get_block_ptr(ptr);

	if (get_block(block) == BLOCK_NOT_FOUND)
		return NULL;

	if (block->status == STATUS_MAPPED)
		return realloc_new_block(block, size);

	if (block->size >= total_size) {
		split(block, total_size);
		return (block + 1);
	}
	if (total_size < MMAP_THRESHOLD) {
		coalesce();
		int ret = realloc_expand(block, total_size);

		if (ret == 0)
			return realloc_new_block(block, size);
	} else {
		return realloc_new_block(block, size);
	}

	return (block + 1);
}
