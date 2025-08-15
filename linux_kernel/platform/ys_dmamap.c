// SPDX-License-Identifier: GPL-2.0
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interval_tree_generic.h>
#include <linux/rbtree.h>
#include <linux/iommu.h>

#include "ys_dmamap.h"

struct ys_dmamap_node {
	struct rb_node rb;
	u64 start;	/* Start of interval */
	u64 end;	/* end location _in_ interval */
	u64 pa;
	u64 __subtree_last;
	void *opaque;
};

struct ys_dmamap_table {
#ifdef RB_ROOT_CACHED
	struct rb_root_cached root;
#else
	struct rb_root root;
#endif
	struct mutex mlock;;       //protect root
	struct list_head node;
	atomic_t refcnt;
	struct iommu_domain *domain;
	struct device *dev;
	struct iommu_group *group;
};

struct ys_dmamap_table_head {
	struct list_head head;
	struct mutex mlock;	//protect list
};

typedef void (*ys_dmamap_cb)(struct ys_dmamap_table *tbl, struct ys_dmamap_node *node,
			     ys_dmamap_opaque_cb cb);

static struct ys_dmamap_table_head ys_dmamap_tlb_head = {
	.head = LIST_HEAD_INIT(ys_dmamap_tlb_head.head),
	.mlock = __MUTEX_INITIALIZER(ys_dmamap_tlb_head.mlock),
};

#define START(node) ((node)->start)
#define LAST(node) ((node)->end)
INTERVAL_TREE_DEFINE(struct ys_dmamap_node,
		     rb, u64, __subtree_last,
		     START, LAST, static inline, ys_dmamap_node);

static void ys_dmamap_flush(struct ys_dmamap_table *tbl);

struct ys_dmamap_table *ys_dmamap_table_create(struct device *dev)
{
	struct ys_dmamap_table_head *head = &ys_dmamap_tlb_head;
	struct ys_dmamap_table *tbl;
	struct iommu_group *group;

	group = iommu_group_get(dev);
	if (!group)
		return NULL;

	mutex_lock(&head->mlock);
	list_for_each_entry(tbl, &head->head, node) {
		if (tbl->dev == dev || tbl->group == group) {
			iommu_group_put(group);
			atomic_inc(&tbl->refcnt);
			mutex_unlock(&head->mlock);
			return tbl;
		}
	}
	mutex_unlock(&head->mlock);

	tbl = kzalloc(sizeof(*tbl), GFP_KERNEL);
	if (!tbl) {
		iommu_group_put(group);
		return NULL;
	}
#ifdef RB_ROOT_CACHED
	tbl->root = RB_ROOT_CACHED;
#else
	tbl->root = RB_ROOT;
#endif
	INIT_LIST_HEAD(&tbl->node);
	atomic_set(&tbl->refcnt, 1);
	tbl->dev = dev;

	tbl->domain = iommu_get_domain_for_dev(dev);
	if (!tbl->domain)
		goto out_free_domain;

	tbl->group = group;

	list_add_tail(&tbl->node, &head->head);

	return tbl;

out_free_domain:
	kfree(tbl);
	iommu_group_put(group);
	return NULL;
}

void ys_dmamap_table_destroy(struct ys_dmamap_table *tbl)
{
	struct ys_dmamap_table_head *head = &ys_dmamap_tlb_head;

	if (!atomic_dec_and_test(&tbl->refcnt))
		return;

	mutex_lock(&head->mlock);
	list_del(&tbl->node);
	mutex_unlock(&head->mlock);

	ys_dmamap_flush(tbl);

	iommu_group_put(tbl->group);

	kfree(tbl);
}

static int ys_dmamap_add(struct ys_dmamap_table *tbl, u64 start, u64 end,
			 u64 pa, void *opaque)
{
	struct ys_dmamap_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->start = start;
	node->end = end;
	node->pa = pa;
	node->opaque = opaque;

	ys_dmamap_node_insert(node, &tbl->root);

	return 0;
}

static void ys_dmamap_del_cb(struct ys_dmamap_table *tbl, struct ys_dmamap_node *node,
			     ys_dmamap_opaque_cb cb)
{
	ys_dmamap_node_remove(node, &tbl->root);
	kfree(node);
}

static void ys_dmamap_del_cb_2(struct ys_dmamap_table *tbl, struct ys_dmamap_node *node,
			       ys_dmamap_opaque_cb cb)
{
	u64 iova = node->start;
	size_t size = node->end - node->start + 1;
	struct page *page = node->opaque;

	iommu_unmap(tbl->domain, iova, size);

	unpin_user_pages(&page, 1);

	ys_dmamap_node_remove(node, &tbl->root);
	kfree(node);
}

static void ys_dmamap_iter(struct ys_dmamap_table *tbl, u64 start, u64 end,
			   ys_dmamap_cb cb, ys_dmamap_opaque_cb ocb)
{
	struct ys_dmamap_node *node;

	while ((node = ys_dmamap_node_iter_first(&tbl->root, start, end)) != NULL)
		cb(tbl, node, ocb);
}

static void ys_dmamap_del(struct ys_dmamap_table *tbl, u64 start, u64 end)
{
	ys_dmamap_iter(tbl, start, end, ys_dmamap_del_cb_2, NULL);
}

static void ys_dmamap_flush(struct ys_dmamap_table *tbl)
{
	ys_dmamap_del(tbl, 0ULL, 0ULL - 1);
}

static bool ys_dmamap_exist(struct ys_dmamap_table *tbl, u64 start, u64 end)
{
	struct ys_dmamap_node *node;

	mutex_lock(&tbl->mlock);
	node = ys_dmamap_node_iter_first(&tbl->root, start, end);
	mutex_unlock(&tbl->mlock);

	return !!node;
}

int ys_dmamap_map(struct ys_dmamap_table *tbl, u64 iova, size_t size,
		  u64 pa, void *opaque)
{
	int ret;
	int prot =  (IOMMU_WRITE | IOMMU_READ);

	if (ys_dmamap_exist(tbl, iova, iova + size - 1))
		return -EEXIST;

	mutex_lock(&tbl->mlock);
	ret = iommu_map(tbl->domain, iova, pa, size, prot);
	if (ret) {
		mutex_unlock(&tbl->mlock);
		return ret;
	}

	ret = ys_dmamap_add(tbl, iova, iova + size - 1, pa, opaque);
	mutex_unlock(&tbl->mlock);

	return 0;
}

static void ys_dmamap_unmap_cb(struct ys_dmamap_table *tbl, struct ys_dmamap_node *node,
			       ys_dmamap_opaque_cb cb)
{
	u64 iova = node->start;
	size_t size = node->end - node->start + 1;

	if (cb)
		cb(node->opaque);
	iommu_unmap(tbl->domain, iova, size);
	ys_dmamap_del_cb(tbl, node, NULL);
}

void ys_dmamap_unmap(struct ys_dmamap_table *tbl, u64 iova, size_t size,
		     ys_dmamap_opaque_cb cb)
{
	mutex_lock(&tbl->mlock);
	ys_dmamap_iter(tbl, iova, iova + size - 1, ys_dmamap_unmap_cb, cb);
	mutex_unlock(&tbl->mlock);
}
