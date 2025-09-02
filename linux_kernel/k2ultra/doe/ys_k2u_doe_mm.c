// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include "ys_k2u_doe_mm.h"

struct ys_k2u_doe_mm *ys_k2u_doe_mm_init(struct device *dev, u64 base, u64 size,
					 bool use_host_mem, u32 align_mask, const char *name)
{
	struct ys_k2u_doe_mm	*ymm;

	ymm = kzalloc(sizeof(*ymm), GFP_KERNEL);
	if (!ymm)
		return ERR_PTR(-ENOMEM);

	ymm->dev = dev;
	ymm->base_address = base;
	ymm->total_size = size;
	ymm->align_mask = align_mask;
	ymm->name = name;
	ymm->used_list = NULL;

	/* init the head of free_list with total size */
	ymm->free_list = kzalloc(sizeof(*ymm->free_list), GFP_KERNEL);
	if (!ymm->free_list) {
		kfree(ymm);
		return ERR_PTR(-ENOMEM);
	}
	ymm->free_list->address = base;
	ymm->free_list->size = size;
	ymm->free_list->next = NULL;

	ymm->use_host_mem = use_host_mem;
	if (use_host_mem) {
		ymm->mem_ptr = dma_alloc_coherent(dev, size, &ymm->dma_base, GFP_KERNEL);
		if (ymm->mem_ptr) {
			memset(ymm->mem_ptr, 0, size);
		} else {
			kfree(ymm->free_list);
			kfree(ymm);
			return ERR_PTR(-ENOMEM);
		}
	}

	return ymm;
}

void ys_k2u_doe_mm_uninit(struct ys_k2u_doe_mm *ymm)
{
	struct mm_region *mr, *prev;

	if (!ymm)
		return;

	/* traverse to free used_list node */
	mr = ymm->used_list;
	while (mr) {
		prev = mr;
		mr = prev->next;
		kfree(prev);
	}

	/* traverse to free free_list node */
	mr = ymm->free_list;
	while (mr) {
		prev = mr;
		mr = prev->next;
		kfree(prev);
	}

	if (ymm->use_host_mem && ymm->mem_ptr)
		dma_free_coherent(ymm->dev, ymm->total_size, ymm->mem_ptr, ymm->dma_base);

	kfree(ymm);
}

void ys_k2u_doe_mm_sort(struct ys_k2u_doe_mm **ymm_list, u32 list_total)
{
	struct ys_k2u_doe_mm *ymm_base = NULL;
	u32 ymm_min = 0;
	u32 i = 0;
	u32 j = 0;

	for (i = 0; i < list_total; i++) {
		for (j = i, ymm_min = i; j < list_total; j++) {
			if (ymm_list[j]->dma_base < ymm_list[ymm_min]->dma_base)
				ymm_min = j;
		}
		ymm_base = ymm_list[i];
		ymm_list[i] = ymm_list[ymm_min];
		ymm_list[ymm_min] = ymm_base;
	}
}

int ys_k2u_doe_mm_merge(struct ys_k2u_doe_mm **merge_to,
			struct ys_k2u_doe_mm **merge_from, u32 from_list_total)
{
	struct ys_k2u_doe_mm *ymm_prev = NULL;
	struct ys_k2u_doe_mm *ymm_next = NULL;
	struct ys_k2u_doe_mm *ymm_merge = NULL;
	u32 from_i = 0;
	u32 to_i = 0;
	u32 total_size = 0;

	ymm_prev = merge_from[0];
	total_size = ymm_prev->total_size;
	for (from_i = 1; from_i < from_list_total; from_i++) {
		ymm_next = merge_from[from_i];
		if (ymm_prev->dma_base + total_size == ymm_next->dma_base) {
			total_size += ymm_next->total_size;
		} else {
			ymm_merge = ys_k2u_doe_mm_init(NULL, ymm_prev->dma_base, total_size,
						       false, 64, "host_manage");
			if (IS_ERR(ymm_merge))
				return -ENOMEM;

			merge_to[to_i++] = ymm_merge;
			ymm_prev = ymm_next;
			total_size = ymm_next->total_size;
		}
	}

	merge_to[to_i] = ys_k2u_doe_mm_init(NULL, ymm_prev->dma_base,
					    total_size, false, 64, "host_manage");
	if (IS_ERR(merge_to[to_i]))
		return -ENOMEM;

	return 0;
}

int ys_k2u_doe_mm_move(struct ys_k2u_doe_mm *move_to, struct ys_k2u_doe_mm *move_from)
{
	if (!move_to || !move_from)
		return 0;

	kfree(move_to->free_list);
	move_to->free_list = move_from->free_list;
	move_to->used_list = move_from->used_list;
	move_from->free_list = NULL;
	move_from->used_list = NULL;

	if (move_from->use_host_mem && move_from->mem_ptr)
		memcpy(move_to->mem_ptr, move_from->mem_ptr, move_from->total_size);

	return 0;
}

int64_t ys_k2u_doe_malloc(struct ys_k2u_doe_mm *ymm, u64 size)
{
	struct mm_region *mr, *new_mr = NULL, *prev = NULL;

	if (!ymm || !ymm->free_list)
		return -ENOMEM;

	/* let the region size align */
	size = (size + ymm->align_mask) & ~ymm->align_mask;

	/* traverse free_list to find enough space */
	mr = ymm->free_list;
	while (mr) {
		if (mr->size == size) {
			/* change the head node if first MR is used */
			if (!prev)
				ymm->free_list = mr->next;
			else
				prev->next = mr->next;

			new_mr = mr;
			break;
		} else if (mr->size > size) {
			/* alloc new MR node for allocation */
			new_mr = kzalloc(sizeof(*new_mr), GFP_KERNEL);
			if (!new_mr)
				return -ENOMEM;
			new_mr->size = size;
			new_mr->address = mr->address;

			/* decrease the size of free MR */
			mr->size -= size;
			mr->address += size;
			break;
		}

		prev = mr;
		mr = mr->next;
	}

	if (!new_mr)
		return -ENOMEM;

	/* add node to the head of used_list */
	new_mr->next = ymm->used_list;
	ymm->used_list = new_mr;

	ys_k2u_doe_mm_dump(ymm);

	return new_mr->address;
}

/* Insert memory region in address order */
static int ys_k2u_doe_try_insert(struct ys_k2u_doe_mm *ymm, struct mm_region *prev,
				 struct mm_region *new_mr, struct mm_region *mr)
{
	/* find the previous MR less than new_mr */
	if (prev && new_mr->address < prev->address)
		return -1;

	/* find the current MR bigger than new_mr */
	if (mr && new_mr->address > mr->address)
		return -1;

	/* now find the place to insert */
	new_mr->next = mr;

	/* maybe can merge with next_mr */
	if (mr && (new_mr->address + new_mr->size == mr->address)) {
		new_mr->size += mr->size;
		new_mr->next = mr->next;
		kfree(mr);
	}

	if (prev) {
		/* maybe can merge to prev_mr */
		if (prev->address + prev->size == new_mr->address) {
			prev->size += new_mr->size;
			prev->next = new_mr->next;
			kfree(new_mr);
		} else {
			prev->next = new_mr;
		}
	} else {
		/* insert as the head of free_list */
		ymm->free_list = new_mr;
	}

	return 0;
}

void ys_k2u_doe_free(struct ys_k2u_doe_mm *ymm, u64 address)
{
	struct mm_region *mr, *new_mr = NULL, *prev = NULL;

	if (!ymm)
		return;

	/* traverse used_list to find the target MR */
	new_mr = ymm->used_list;
	while (new_mr) {
		if (new_mr->address == address)
			break;
		prev = new_mr;
		new_mr = new_mr->next;
	}
	if (!new_mr) {
		pr_warn("Unknowned address:0x%llx to free\n", address);
		return;
	}

	/* delete new_mr from used list */
	if (!prev)
		ymm->used_list = new_mr->next;
	else
		prev->next = new_mr->next;

	/* traverse free_list to insert the new free_MR */
	prev = NULL;
	if (!ymm->free_list) {
		ymm->free_list = new_mr;
		new_mr->next = NULL;
	} else {
		mr = ymm->free_list;
		while (ys_k2u_doe_try_insert(ymm, prev, new_mr, mr)) {
			prev = mr;
			mr = mr->next;
		}
	}

	ys_k2u_doe_mm_dump(ymm);
}

