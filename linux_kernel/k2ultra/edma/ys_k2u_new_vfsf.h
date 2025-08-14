/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_NEW_VFSF_H__
#define __YS_K2U_NEW_VFSF_H__

#include "ys_k2u_new_base.h"

int ys_k2u_pdev_vfsf_init(struct ys_pdev_priv *pdev_priv);
void ys_k2u_pdev_vfsf_uninit(struct ys_pdev_priv *pdev_priv);

int ys_k2u_sriov_enable(struct pci_dev *pdev, u32 num_vfs);
int ys_k2u_sriov_config_change(struct pci_dev *pdev);
int ys_k2u_sriov_disable(struct pci_dev *pdev);

u16 ys_k2u_vfsf_get_irq_maxnum(struct ys_pdev_priv *pdev_priv);
void ys_k2u_vfsf_set_qsetid(struct ys_pdev_priv *pdev_priv, u16 vf_idx, u16 qsetid);
u16 ys_k2u_vfsf_get_qsetid(struct ys_pdev_priv *pdev_priv, u16 vf_idx);
u16 ys_k2u_vfsf_get_maxqnum(struct ys_pdev_priv *pdev_priv, enum ys_k2u_ndev_type type);
u16 ys_k2u_vfsf_get_minqnum(struct ys_pdev_priv *pdev_priv, enum ys_k2u_ndev_type type);
#endif /* __YS_K2U_VFSF_H__ */
