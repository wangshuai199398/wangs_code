/* SPDX-License-Identifier: GPL-2.0 */

#ifndef YS_K2U_NEW_CORE_H
#define YS_K2U_NEW_CORE_H

#include "ys_k2u_new_base.h"

extern bool smart_nic;
extern bool dpu_soc;
extern bool dpu_host;

int ys_k2u_pdev_init(struct ys_pdev_priv *pdev_priv);
void ys_k2u_pdev_uninit(struct ys_pdev_priv *pdev_priv);
int ys_k2u_pdev_fix_mode(struct ys_pdev_priv *pdev_priv);
void ys_k2u_pdev_unfix_mode(struct ys_pdev_priv *pdev_priv);

#endif /* YS_K2U_NEW_CORE_H */
