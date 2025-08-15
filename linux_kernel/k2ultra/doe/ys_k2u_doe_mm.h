/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YS_K2U_DOE_MM_H
#define __YS_K2U_DOE_MM_H
#include <linux/types.h>

#define MM_NAME_SIZE		16

#undef pr_debug
#define pr_debug pr_info

struct mm_region {
	u64 address;
	u64 size;
	struct mm_region *next;
};

struct ys_k2u_doe_mm {
	struct device *dev;
	const char *name;
	u64 base_address;
	u64 total_size;
	u32 align_mask;
	dma_addr_t dma_base;
	void *mem_ptr;
	bool use_host_mem;
	struct mm_region *used_list;
	struct mm_region *free_list;
};

static inline void ys_k2u_doe_mm_dump(struct ys_k2u_doe_mm *ymm) {}

struct ys_k2u_doe_mm *ys_k2u_doe_mm_init(struct device *dev, u64 base, u64 size,
					 bool use_host_mem, u32 align_mask, const char *name);
void ys_k2u_doe_mm_uninit(struct ys_k2u_doe_mm *ymm);
/**
 * ys_k2u_doe_malloc() - alloc memory from user mm_pool
 *
 * @ymm: memory poll
 * @size: size of the memory region to be requested
 *
 * Return:
 * % -ENOMEM:	- Fail to alloc.
 * % >=0:	- Address of the memory region
 */
int64_t ys_k2u_doe_malloc(struct ys_k2u_doe_mm *ymm, u64 size);
void ys_k2u_doe_free(struct ys_k2u_doe_mm *ymm, u64 address);

void ys_k2u_doe_mm_sort(struct ys_k2u_doe_mm **ymm_list, u32 list_total);
int ys_k2u_doe_mm_merge(struct ys_k2u_doe_mm **merge_to,
			struct ys_k2u_doe_mm **merge_from, u32 from_list_total);
int ys_k2u_doe_mm_move(struct ys_k2u_doe_mm *move_to, struct ys_k2u_doe_mm *move_from);
#endif /* __YS_K2U_DOE_MM_H */
