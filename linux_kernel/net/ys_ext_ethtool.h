/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_EXT_ETHTOOL_H
#define __YS_EXT_ETHTOOL_H
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include "../user_include/ys_ext_ethtool_cmd.h"
#include "../lib/kernel_compat.h"

#define YS_IOCG_EXTETHTOOL (SIOCDEVPRIVATE + 6)

#ifdef YS_HAVE_KERNEL_RING
struct kernel_ethtool_ringparam;
#endif /* YS_HAVE_KERNEL_RING */
#ifdef YS_HAVE_ETHTOOL_MAC_STATS
struct ethtool_eth_mac_stats;
#endif /* YS_HAVE_ETHTOOL_MAC_STATS */
#ifdef YS_HAVE_ETHTOOL_COALESCE_CQE
struct netlink_ext_ack;
struct kernel_ethtool_coalesce;
#endif
struct ys_ext_ethtool_ops {
#ifdef ETHTOOL_COALESCE_USECS
	u32     supported_coalesce_params;
#endif /* ETHTOOL_COALESCE_USECS */
	int	(*get_settings)(struct net_device *ndev, struct ethtool_cmd *cmd);
	int	(*set_settings)(struct net_device *ndev, struct ethtool_cmd *cmd);
	void    (*get_drvinfo)(struct net_device *ndev, struct ethtool_drvinfo *info);
	int     (*get_regs_len)(struct net_device *ndev);
	void    (*get_regs)(struct net_device *ndev, struct ethtool_regs *reg, void *data);
	u32     (*get_link)(struct net_device *ndev);
	int     (*get_eeprom_len)(struct net_device *ndev);
	int     (*get_eeprom)(struct net_device *ndev, struct ethtool_eeprom *e, u8 *d);
	int     (*set_eeprom)(struct net_device *ndev, struct ethtool_eeprom *e, u8 *d);
#ifdef YS_HAVE_ETHTOOL_COALESCE_CQE
	int     (*get_coalesce)(struct net_device *ndev, struct ethtool_coalesce *ec,
				struct kernel_ethtool_coalesce *kec, struct netlink_ext_ack *nea);
	int     (*set_coalesce)(struct net_device *ndev, struct ethtool_coalesce *ec,
				struct kernel_ethtool_coalesce *kec, struct netlink_ext_ack *nea);
#else
	int	(*get_coalesce)(struct net_device *ndev, struct ethtool_coalesce *ec);
	int	(*set_coalesce)(struct net_device *ndev, struct ethtool_coalesce *ec);
#endif /* YS_HAVE_ETHTOOL_COALESCE_CQE */
#ifdef YS_HAVE_KERNEL_RING
	void    (*get_ringparam)(struct net_device *ndev, struct ethtool_ringparam *ringp,
				 struct kernel_ethtool_ringparam *rp, struct netlink_ext_ack *nea);
#else
	void	(*get_ringparam)(struct net_device *ndev, struct ethtool_ringparam *ring);
#endif
#ifdef YS_HAVE_KERNEL_RING
	int     (*set_ringparam)(struct net_device *ndev, struct ethtool_ringparam *ringp,
				 struct kernel_ethtool_ringparam *rp, struct netlink_ext_ack *nea);
#else
	int     (*set_ringparam)(struct net_device *ndev, struct ethtool_ringparam *ringp);
#endif
	void    (*self_test)(struct net_device *ndev, struct ethtool_test *test, u64 *d);
	void    (*get_strings)(struct net_device *ndev, u32 stringset, u8 *d);
	int     (*set_phys_id)(struct net_device *ndev, enum ethtool_phys_id_state);
	void    (*get_ethtool_stats)(struct net_device *ndev, struct ethtool_stats *s, u64 *d);
	int     (*begin)(struct net_device *ndev);
	void    (*complete)(struct net_device *ndev);
	u32     (*get_priv_flags)(struct net_device *ndev);
	int     (*set_priv_flags)(struct net_device *ndev, u32 data);
	int     (*get_sset_count)(struct net_device *ndev, int sid);
	int     (*get_rxnfc)(struct net_device *ndev, struct ethtool_rxnfc *nfc, u32 *rule_locs);
	int     (*set_rxnfc)(struct net_device *ndev, struct ethtool_rxnfc *nfc);
	u32     (*get_rxfh_key_size)(struct net_device *ndev);
	u32     (*get_rxfh_indir_size)(struct net_device *ndev);
	int	(*get_rxfh)(struct net_device *ndev, u32 *indir, u8 *key, u8 *hfunc);
	int	(*set_rxfh)(struct net_device *ndev, const u32 *indir,
			    const u8 *key, const u8 hfunc);
	int	(*get_rxfh_context)(struct net_device *ndev, u32 *indir, u8 *key,
				    u8 *hfunc, u32 rss_context);
	int	(*set_rxfh_context)(struct net_device *ndev, const u32 *indir, const u8 *key,
				    const u8 hfunc, u32 *rss_context, bool delete);
	void    (*get_channels)(struct net_device *ndev, struct ethtool_channels *chann);
	int     (*set_channels)(struct net_device *ndev, struct ethtool_channels *chann);
	int     (*get_ts_info)(struct net_device *ndev, struct ethtool_ts_info *info);
	int     (*get_module_info)(struct net_device *ndev, struct ethtool_modinfo *info);
	int     (*get_module_eeprom)(struct net_device *ndev, struct ethtool_eeprom *e, u8 *d);
	int     (*get_link_ksettings)(struct net_device *ndev, struct ethtool_link_ksettings *set);
	int     (*set_link_ksettings)(struct net_device *ndev,
				      const struct ethtool_link_ksettings *set);
	int     (*get_fecparam)(struct net_device *ndev, struct ethtool_fecparam *fecp);
	int     (*set_fecparam)(struct net_device *ndev, struct ethtool_fecparam *fecp);
	void    (*get_eth_mac_stats)(struct net_device *ndev,
				     struct ethtool_eth_mac_stats *mac_stats);
};

extern struct ys_ext_ethtool_ops exttool_ops;
int ys_ext_ethtool(struct net_device *ndev, struct ifreq *ifr);
#endif /* __YS_EXT_ETHTOOL_H */
