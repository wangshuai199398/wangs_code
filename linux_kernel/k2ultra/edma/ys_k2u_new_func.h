/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _YS_K2U_NEW_FUNC_H
#define _YS_K2U_NEW_FUNC_H

#include "ys_k2u_new_base.h"

struct ys_k2u_funcbase {
	u16 top;
	u16 base;
};

struct ys_k2u_func_pf {
	struct ys_k2u_funcbase pfx_fbase[YS_K2U_N_MAX_PF];
	struct ys_k2u_queuebase pfx_qbase[YS_K2U_N_MAX_PF];
	struct ys_k2u_queuebase funcx_p_qbase[YS_K2U_N_PF_MAX_FUNC];
	struct ys_k2u_queuebase funcx_g_qbase[YS_K2U_N_PF_MAX_FUNC];
	u16 funcx_irqnum[YS_K2U_N_PF_MAX_FUNC];
};

struct ys_k2u_new_func {
	struct pci_dev *pdev;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *hw_addr;
	void __iomem *hw_dma_addr;

	u32 dma_id;
	u32 dma_inst;
	u32 dma_qmaxnum;
	u32 dma_max_qsetnum;

	u16 dma_qset_offset;
	u16 dma_qset_qmaxnum;

	u16 dma_irq_maxnum;

	u16 func_irqnum;
	struct ys_k2u_queuebase func_l_qbase;
	struct ys_k2u_queuebase func_f_qbase;
	struct ys_k2u_queuebase func_p_qbase;
	struct ys_k2u_queuebase func_g_qbase;

	struct dentry *debugfs_root;
	struct dentry *debugfs_info_file;

	void *vfsf_priv;

	struct ys_k2u_func_pf func_pf[];
};

static inline void __iomem *ys_k2u_func_get_hwaddr(struct ys_pdev_priv *pdev_priv)
{
	return ((struct ys_k2u_new_func *)(pdev_priv->padp_priv))->hw_addr;
}

static inline struct ys_k2u_new_func *
ys_k2u_func_get_priv(struct ys_pdev_priv *pdev_priv)
{
	return (struct ys_k2u_new_func *)(pdev_priv->padp_priv);
}

int ys_k2u_pdev_func_init(struct ys_pdev_priv *pdev_priv);
void ys_k2u_pdev_func_uninit(struct ys_pdev_priv *pdev_priv);

struct ys_k2u_queuebase
ys_k2u_func_get_qbase(struct ys_pdev_priv *pdev_priv, enum ys_k2u_queue_type type);
void ys_k2u_func_set_qbase(struct ys_pdev_priv *pdev_priv, enum ys_k2u_queue_type type,
			   struct ys_k2u_queuebase qbase);
void ys_k2u_func_change_qnum(struct ys_pdev_priv *pdev_priv, u16 qnum, bool is_add);

struct ys_k2u_queuebase
ys_k2u_func_get_funcx_qbase(struct ys_pdev_priv *pdev_priv, u16 func_id,
			    enum ys_k2u_queue_type type);

void ys_k2u_func_set_funcx_qbase(struct ys_pdev_priv *pdev_priv, u16 func_id,
				 enum ys_k2u_queue_type type, struct ys_k2u_queuebase qbase);
void ys_k2u_func_change_funcx_qnum(struct ys_pdev_priv *pdev_priv, u16 func_id,
				   u16 qnum, bool is_add);

u16 ys_k2u_func_get_irqnum(struct ys_pdev_priv *pdev_priv);
void ys_k2u_func_set_irqnum(struct ys_pdev_priv *pdev_priv, u16 irqnum);
void ys_k2u_func_change_irqnum(struct ys_pdev_priv *pdev_priv, u16 irqnum, bool is_add);

u16 ys_k2u_func_get_funcx_irqnum(struct ys_pdev_priv *pdev_priv, u16 func_id);
void ys_k2u_func_set_funcx_irqnum(struct ys_pdev_priv *pdev_priv, u16 func_id, u16 irqnum);
void ys_k2u_func_change_funcx_irqnum(struct ys_pdev_priv *pdev_priv, u16 func_id,
				     u16 irqnum, bool is_add);

int ys_k2u_pdev_get_init_qbase(struct pci_dev *pdev);
int ys_k2u_pdev_get_init_qnum(struct pci_dev *pdev);

u16 ys_k2u_func_get_vfnum(struct ys_pdev_priv *pdev_priv);

#endif /* _YS_K2U_NEW_FUNC_H */
