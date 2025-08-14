/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_NEW_QSET_H__
#define __YS_K2U_NEW_QSET_H__

#include "ys_k2u_new_base.h"

struct ys_k2u_qset {
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv;
	u16 id;
};

struct ys_k2u_qset *
ys_k2u_qset_alloc(struct ys_pdev_priv *pdev_priv, struct ys_ndev_priv *ndev_priv);
void ys_k2u_qset_free(struct ys_k2u_qset *qset);
int ys_k2u_qset_start(struct ys_k2u_qset *qset, u16 txqnum, u16 rxqnum);
void ys_k2u_qset_stop(struct ys_k2u_qset *qset);

int ys_k2u_pdev_qset_init(struct ys_pdev_priv *pdev_priv);
void ys_k2u_pdev_qset_uninit(struct ys_pdev_priv *pdev_priv);

int ys_k2u_qsetid_alloc(struct ys_pdev_priv *pdev_priv, enum ys_k2u_ndev_type type,
			u16 *qsetid, u16 num);
void ys_k2u_qsetid_free(struct ys_pdev_priv *pdev_priv, u16 *qsetid, u16 num);

void ys_k2u_qset_set_qset2q(struct ys_pdev_priv *pdev_priv, u16 qset_id,
			    struct ys_k2u_queuebase *qbase);
void ys_k2u_qset_set_q2qset(struct ys_pdev_priv *pdev_priv, u16 qset_id,
			    struct ys_k2u_queuebase *qbase);

#endif /* __YS_K2U_NEW_QSET_H__ */
