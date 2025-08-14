/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_CMAC_H_
#define __YS_CMAC_H_

#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/netdevice.h>

#include "ys_platform.h"
#include "ys_adapter.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"

#include "ys_cmac_register.h"

#define CMAC_ID 0
#define CMAC_LINK_STATUS 0x02
#define CMAC_CORE_VERSION 0x00000301
#define CMAC_RESET_WAIT_MS 1

enum { REG_TEST, EEPROM_TEST, LOOPBACK_TEST, LINK_TEST, INT_TEST };

enum { CMAC_PRIV_FLAG,
};

#ifdef YS_HAVE_ETHTOOL_MAC_STATS
#define get_mac_stats(cmac) ((cmac)->et_get_mac_stats = ys_cmac_get_mac_stats)
#else
#define get_mac_stats(cmac) \
	do {                \
	} while (0)
#endif

int ys_cmac_eth_init(struct net_device *ndev);
int ys_cmac_ndev_init(struct net_device *ndev);

void ys_cmac_get_self_strings(struct net_device *ndev, u8 *data);
void ys_cmac_get_priv_strings(struct net_device *ndev, u8 *data);
int ys_cmac_get_self_count(struct net_device *ndev);
int ys_cmac_get_priv_count(struct net_device *ndev);
void ys_cmac_self_offline_test(struct net_device *ndev,
			       struct ethtool_test *eth_test, u64 *data);
void ys_cmac_self_online_test(struct net_device *ndev,
			      struct ethtool_test *eth_test, u64 *data);

void ys_cmac_netdev_check_link(struct net_device *ndev);
void ys_cmac_get_supported_advertising(struct net_device *ndev,
				       struct ys_ethtool_ksetting *cmd);
u32 ys_cmac_get_link_speed(struct net_device *ndev);
u32 ys_cmac_get_link_duplex(struct net_device *ndev);
u8 ys_cmac_get_link_autoneg(struct net_device *ndev);
u32 ys_cmac_get_link_port_type(struct net_device *ndev);
u32 ys_cmac_get_priv_flags(struct net_device *ndev);
u32 ys_cmac_set_priv_flags(struct net_device *ndev, u32 falg);
#ifdef YS_HAVE_ETHTOOL_COALESCE_CQE
int ys_cmac_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec,
			 struct kernel_ethtool_coalesce *kec,
			 struct netlink_ext_ack *ack);
int ys_cmac_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec,
			 struct kernel_ethtool_coalesce *kec,
			 struct netlink_ext_ack *ack);
#else
int ys_cmac_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec);
int ys_cmac_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec);
#endif /* YS_HAVE_ETHTOOL_COALESCE_CQE */
int ys_cmac_get_fec_mode(struct net_device *ndev, struct ethtool_fecparam *fp);
int ys_cmac_set_fec_mode(struct net_device *ndev, u32 fec);
#ifdef YS_HAVE_ETHTOOL_MAC_STATS
void ys_cmac_get_mac_stats(struct net_device *ndev,
			   struct ethtool_eth_mac_stats *mac_stats);
#endif /* YS_HAVE_ETHTOOL_MAC_STATS */
int ys_cmac_enable(struct net_device *ndev);

#define CMAC_ETH_FUNC(cmac)                                              \
	do {								\
		typeof(cmac) _cmac_temp = (cmac);				\
		_cmac_temp->et_get_self_strings = ys_cmac_get_self_strings;   \
		_cmac_temp->et_get_priv_strings = ys_cmac_get_priv_strings;   \
		_cmac_temp->et_get_self_count = ys_cmac_get_self_count;       \
		_cmac_temp->et_get_priv_count = ys_cmac_get_priv_count;       \
		_cmac_temp->et_check_link = ys_cmac_netdev_check_link;        \
		_cmac_temp->et_get_supported_advertising =                    \
			ys_cmac_get_supported_advertising;              \
		_cmac_temp->et_get_link_speed = ys_cmac_get_link_speed;       \
		_cmac_temp->et_get_link_duplex = ys_cmac_get_link_duplex;     \
		_cmac_temp->et_get_link_autoneg = ys_cmac_get_link_autoneg;   \
		_cmac_temp->et_get_link_port_type = ys_cmac_get_link_port_type;   \
		_cmac_temp->et_get_priv_flags = ys_cmac_get_priv_flags;       \
		_cmac_temp->et_set_priv_flags = ys_cmac_set_priv_flags;       \
		_cmac_temp->et_get_fec_mode = ys_cmac_get_fec_mode;           \
		_cmac_temp->et_set_fec_mode = ys_cmac_set_fec_mode;           \
		_cmac_temp->enable_mac = ys_cmac_enable;                      \
		get_mac_stats(_cmac_temp);                                    \
	} while (0)
#define CMAC_NDEV_FUNC(cmac)

#endif /* __YS_CMAC_H_ */
