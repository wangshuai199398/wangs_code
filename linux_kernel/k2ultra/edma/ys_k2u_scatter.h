/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YS_K2U_SCATTER_H__
#define __YS_K2U_SCATTER_H__

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/dma-mapping.h>
#include <linux/types.h>

#include "ys_k2u_new_base.h"

struct ys_k2u_scatterlist {
	dma_addr_t addr;
	u32 len;
	u16 freeid;
};

struct ys_k2u_sctfrag {
	u16 seg_start;
	u16 seg_num;
	bool tso_fp;
	bool tso_lp;
	bool tso_valid;
	u8 mss_num;
};

struct ys_k2u_sctseg {
	dma_addr_t addr;
	u32 len;
	bool fp;
	bool lp;
	bool unmap;
	u16 sctlidx;
};

struct ys_k2u_scatter {
	u16 sctlist_num;
	struct ys_k2u_scatterlist sctlist[YS_K2U_N_MAX_SCTLIST];
	struct ys_k2u_sctfrag frags[YS_K2U_N_MAX_SCTFRAGS];
	struct ys_k2u_sctseg segs[YS_K2U_N_MAX_SCTSEGS];
	struct sk_buff *skb;
};

struct ys_k2u_scatter_iter {
	u8 frag_idx;
	u8 seg_idx;
	u8 seg_num;
	bool unmap;
	struct ys_k2u_sctfrag *frag;
	struct ys_k2u_sctseg *seg;
	struct ys_k2u_scatterlist *sctl;
};

static inline void
ys_k2u_scatter_iter_start(struct ys_k2u_scatter *scatter,
			  struct ys_k2u_scatter_iter *iter)
{
	iter->frag_idx = 0;
	iter->seg_idx = 0;
	iter->seg_num = scatter->frags[0].seg_num;
	iter->frag = scatter->frags;
	iter->seg = scatter->segs;
	iter->unmap = iter->seg->unmap;
	if (iter->unmap)
		iter->sctl = &scatter->sctlist[iter->seg->sctlidx];
	else
		iter->sctl = NULL;
}

static inline bool
ys_k2u_scatter_iter_cond(struct ys_k2u_scatter *scatter,
			 struct ys_k2u_scatter_iter *iter)
{
	u8 seg_start;
	u8 seg_num;

	seg_start = scatter->frags[iter->frag_idx].seg_start;
	seg_num = scatter->frags[iter->frag_idx].seg_num;
	if (!seg_num)
		return false;
	if (iter->seg_idx >= seg_start + seg_num)
		return false;
	return true;
}

static inline void
ys_k2u_scatter_iter_next(struct ys_k2u_scatter *scatter,
			 struct ys_k2u_scatter_iter *iter)
{
	u8 seg_start;
	u8 seg_num;

	seg_start = scatter->frags[iter->frag_idx].seg_start;
	seg_num = scatter->frags[iter->frag_idx].seg_num;
	iter->seg_idx++;
	if (iter->seg_idx >= seg_start + seg_num)
		iter->frag_idx++;
	iter->seg_num = scatter->frags[iter->frag_idx].seg_num;
	iter->frag = &scatter->frags[iter->frag_idx];
	iter->seg = &scatter->segs[iter->seg_idx];
	iter->unmap = iter->seg->unmap;
	if (iter->unmap)
		iter->sctl = &scatter->sctlist[iter->seg->sctlidx];
	else
		iter->sctl = NULL;
}

int
ys_k2u_scatter_construct(struct ys_k2u_scatter *scatter, struct device *dev,
			 struct sk_buff *skb, u16 fragsize);
void ys_k2u_scatter_destruct(struct ys_k2u_scatter *scatter, struct device *dev);

#endif /* __YS_K2U_SCATTER_H__ */
