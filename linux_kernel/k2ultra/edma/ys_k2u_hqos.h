/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_HQOS_H__
#define __YS_K2U_HQOS_H__

int ys_k2u_set_vf_rate(struct net_device *ndev, int vf, int min_tx_rate, int max_tx_rate);

#endif /* __YS_K2U_HQOS_H__ */
