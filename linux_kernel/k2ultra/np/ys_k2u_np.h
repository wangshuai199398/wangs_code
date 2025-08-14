/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_NP_H_
#define __YS_K2U_NP_H_

#include <linux/types.h>

#include "../../platform/ys_auxiliary.h"
#include "../../platform/ys_pdev.h"

int ys_k2u_np_aux_probe(struct auxiliary_device *auxdev);

void ys_k2u_np_aux_remove(struct auxiliary_device *auxdev);

int ys_np_set_tbl_ready(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_doe_protect(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_fcs_err_drop(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_tm_trust_pri(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_LRO(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_ignore_PPP(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_trust_PPP(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_bypass_offload(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_ign_tnl_v4_id(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_ign_frag_l4_port(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_tbl_cache_miss(struct ys_pdev_priv *pdev_priv, bool val);

int ys_np_set_MA_dispatch_policy(struct ys_pdev_priv *pdev_priv, u16 val);

struct ys_np_sw *ys_get_np_by_bus_id(int bus_id);

int ys_k2u_np_ops_set_cfg(struct pci_dev *pdev, u16 type, u16 val);

int ys_k2u_np_set_lag_cfg(struct pci_dev *pdev, u8 bond_id, bool enable, u32 val);
int ys_k2u_np_set_lag_linkstatus_cfg(struct pci_dev *pdev, u16 port_id, bool enable);
#endif /* __YS_K2U_NP_H_ */
