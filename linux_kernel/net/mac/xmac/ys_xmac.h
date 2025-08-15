/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_XMAC_H_
#define __YS_XMAC_H_

#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/netdevice.h>

#include "ys_platform.h"
#include "ys_adapter.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"

#include "ys_xmac_register.h"

#define get_xmac_stats(xmac) ((xmac)->et_get_mac_stats = ys_xmac_get_mac_stats)

enum ys_xmac_state_statistics {
	XMAC_STATUS_CYCLE_COUNT,
	XMAC_STAT_RX_FRAMING_ERR,
	XMAC_STAT_RX_BAD_CODE,
	XMAC_STAT_RX_ERROR,
	XMAC_STAT_RX_RSFEC_CORRECTED_CW_INC,
	XMAC_STAT_RX_RSFEC_UNCORRECTED_CW_INC,
	XMAC_STAT_RX_RSFEC_ERR_COUNT0_INC,

	XMAC_STAT_TX_FRAMING_ERROR,
	XMAC_STAT_TX_TOTAL_PACKETS,
	XMAC_STAT_TX_TOTAL_GOOD_PACKETS,
	XMAC_STAT_TX_TOTAL_BYTES,
	XMAC_STAT_TX_TOTAL_GOOD_BYTES,
	XMAC_STAT_TX_PACKET_64_BYTES,
	XMAC_STAT_TX_PACKET_65_127_BYTES,
	XMAC_STAT_TX_PACKET_128_255_BYTES,
	XMAC_STAT_TX_PACKET_256_511_BYTES,
	XMAC_STAT_TX_PACKET_512_1023_BYTES,
	XMAC_STAT_TX_PACKET_1024_1518_BYTES,
	XMAC_STAT_TX_PACKET_1519_1522_BYTES,
	XMAC_STAT_TX_PACKET_1523_1548_BYTES,
	XMAC_STAT_TX_PACKET_1549_2047_BYTES,
	XMAC_STAT_TX_PACKET_2048_4095_BYTES,
	XMAC_STAT_TX_PACKET_4096_8191_BYTES,
	XMAC_STAT_TX_PACKET_8192_9215_BYTES,
	XMAC_STAT_TX_PACKET_LARGE,
	XMAC_STAT_TX_PACKET_SMALL,
	XMAC_STAT_TX_BAD_FCS,
	XMAC_STAT_TX_UNICAST,
	XMAC_STAT_TX_MULTICAST,
	XMAC_STAT_TX_BROADCAST,
	XMAC_STAT_TX_VLAN,
	XMAC_STAT_TX_PAUSE,
	XMAC_STAT_TX_USER_PAUSE,

	XMAC_STAT_RX_TOTAL_PACKETS,
	XMAC_STAT_RX_TOTAL_GOOD_PACKETS,
	XMAC_STAT_RX_TOTAL_BYTES,
	XMAC_STAT_RX_TOTAL_GOOD_BYTES,
	XMAC_STAT_RX_PACKET_64_BYTES,
	XMAC_STAT_RX_PACKET_65_127_BYTES,
	XMAC_STAT_RX_PACKET_128_255_BYTES,
	XMAC_STAT_RX_PACKET_256_511_BYTES,
	XMAC_STAT_RX_PACKET_512_1023_BYTES,
	XMAC_STAT_RX_PACKET_1024_1518_BYTES,
	XMAC_STAT_RX_PACKET_1519_1022_BYTES,
	XMAC_STAT_RX_PACKET_1523_1548_BYTES,
	XMAC_STAT_RX_PACKET_1549_2047_BYTES,
	XMAC_STAT_RX_PACKET_2048_4095_BYTES,
	XMAC_STAT_RX_PACKET_4096_8191_BYTES,
	XMAC_STAT_RX_PACKET_8192_9215_BYTES,
	XMAC_STAT_RX_PACKET_LARGE,
	XMAC_STAT_RX_PACKET_SMALL,

	XMAC_STAT_RX_UNDERSIZE,
	XMAC_STAT_RX_FRAGMENT,
	XMAC_STAT_RX_OVERSIZE,
	XMAC_STAT_RX_TOOLONG,
	XMAC_STAT_RX_JABBER,
	XMAC_STAT_RX_BAD_FCS,
	XMAC_STAT_RX_PACKET_BAD_FCS,
	XMAC_STAT_RX_STOMPED_BAD_FCS,
	XMAC_STAT_RX_UNICAST,
	XMAC_STAT_RX_MULTICAST,
	XMAC_STAT_RX_BROADCAST,
	XMAC_STAT_RX_VLAN,
	XMAC_STAT_RX_PAUSE,
	XMAC_STAT_RX_USER_PAUSE,

	XMAC_STAT_RX_INRANGEERR,
	XMAC_STAT_RX_TRUNCATED,
	XMAC_STAT_RX_TEST_PATTERN_MISMATCH,
	XMAC_STAT_FEC_INC_CORRECT_COUNT,
	XMAC_STAT_FEC_INC_CANT_CORRECT_COUNT,
};

int ys_xmac_init(struct auxiliary_device *auxdev);
void ys_xmac_uninit(struct auxiliary_device *auxdev);
int ys_xmac_eth_init(struct net_device *ndev);
int ys_xmac_ndev_init(struct net_device *ndev);
void ys_xmac_ndev_uninit(struct net_device *ndev);
int ys_xmac_enable(struct net_device *ndev);
void ys_xmac_netdev_check_link(struct net_device *ndev);
void ys_xmac_get_supported_advertising(struct net_device *ndev,
				       struct ys_ethtool_ksetting *cmd);
u32 ys_xmac_get_link_speed(struct net_device *ndev);
u32 ys_xmac_get_link_duplex(struct net_device *ndev);
u32 ys_xmac_get_link_port_type(struct net_device *ndev);
u8 ys_xmac_get_link_autoneg(struct net_device *ndev);
int ys_xmac_set_link_autoneg(struct net_device *ndev, bool autoneg);
int ys_xmac_get_fec_mode(struct net_device *ndev,
			 struct ethtool_fecparam *fp);
int ys_xmac_set_fec_mode(struct net_device *ndev, u32 fec);
void ys_xmac_get_stats(struct net_device *ndev, u64 *data);
void ys_xmac_get_stats_strings(struct net_device *ndev, u8 *data);
int ys_xmac_get_stats_count(struct net_device *ndev);

#define XMAC_ETH_FUNC(xmac)					\
	do {							\
		typeof(xmac) _xmac_temp = (xmac);		\
		_xmac_temp->enable_mac = ys_xmac_enable;	\
		_xmac_temp->et_check_link = ys_xmac_netdev_check_link;		\
		_xmac_temp->et_get_supported_advertising = ys_xmac_get_supported_advertising; \
		_xmac_temp->et_get_link_speed = ys_xmac_get_link_speed;		\
		_xmac_temp->et_set_link_speed = ys_xmac_set_link_speed;		\
		_xmac_temp->et_get_link_duplex = ys_xmac_get_link_duplex;	\
		_xmac_temp->et_set_link_duplex_mode = ys_xmac_set_link_duplex;	\
		_xmac_temp->et_get_link_port_type = ys_xmac_get_link_port_type;	\
		_xmac_temp->et_get_link_autoneg = ys_xmac_get_link_autoneg;	\
		_xmac_temp->et_set_link_autoneg = ys_xmac_set_link_autoneg;	\
		_xmac_temp->et_get_fec_mode = ys_xmac_get_fec_mode;		\
		_xmac_temp->et_set_fec_mode = ys_xmac_set_fec_mode;		\
		get_xmac_stats(_xmac_temp);						\
	} while (0)
#define XMAC_NDEV_FUNC(xmac)	{}

#endif /* __YS_XMAC_H_ */
