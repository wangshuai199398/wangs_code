/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_DMAMAP_H__
#define __YS_DMAMAP_H__

struct ys_dmamap_table;

typedef void (*ys_dmamap_opaque_cb)(void *opaque);
struct ys_dmamap_table *ys_dmamap_table_create(struct device *dev);
void ys_dmamap_table_destroy(struct ys_dmamap_table *tbl);
int ys_dmamap_map(struct ys_dmamap_table *tbl, u64 iova, size_t size,
		  u64 pa, void *opaque);
void ys_dmamap_unmap(struct ys_dmamap_table *tbl, u64 iova, size_t size,
		     ys_dmamap_opaque_cb cb);

#endif /* __YS_DMAMAP_H__ */
