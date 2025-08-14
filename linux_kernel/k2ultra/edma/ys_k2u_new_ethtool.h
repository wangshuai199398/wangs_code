/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _YS_K2U_NEW_ETHTOOL_H_
#define _YS_K2U_NEW_ETHTOOL_H_

#include "ys_k2u_new_base.h"

int ys_k2u_et_set_channels(struct net_device *ndev, struct ethtool_channels *ch);
void ys_k2u_et_get_ringparam(struct net_device *dev, struct ethtool_ringparam *param);
int ys_k2u_et_ringparam_check(struct net_device *dev, struct ethtool_ringparam *param);
int ys_k2u_et_set_ringparam(struct net_device *dev, struct ethtool_ringparam *param);
void ys_k2u_et_get_stats(struct net_device *ndev, u64 *data);
void ys_k2u_et_get_stats_strings(struct net_device *ndev, u8 *data);
int ys_k2u_et_get_stats_count(struct net_device *ndev);
u32 ys_k2u_get_rxfh_key_size(struct net_device *ndev);
u32 ys_k2u_get_rxfh_indir_size(struct net_device *ndev);
int ys_k2u_get_rxfh(struct net_device *ndev, u32 *indir, u8 *key, u8 *hfunc);
int ys_k2u_set_rxfh(struct net_device *ndev, const u32 *indir, const u8 *key, const u8 hfunc);

#define YS_K2U_ETHTOOL_FUNC(func) \
	do {								\
		typeof(func) func_tmp = func;		\
		func_tmp->ys_set_channels = ys_k2u_et_set_channels;	\
		func_tmp->ys_get_ringparam = ys_k2u_et_get_ringparam;	\
		func_tmp->ys_ringparam_check = ys_k2u_et_ringparam_check; \
		func_tmp->ys_set_ringparam = ys_k2u_et_set_ringparam;	\
		func_tmp->ys_get_rxfh_indir_size = ys_k2u_get_rxfh_indir_size;	\
		func_tmp->ys_get_rxfh_key_size = ys_k2u_get_rxfh_key_size;	\
		func_tmp->ys_get_rxfh = ys_k2u_get_rxfh;	\
		func_tmp->ys_set_rxfh = ys_k2u_set_rxfh;	\
	} while (0)

#endif /* _YS_K2U_NEW_ETHTOOL_H_ */
