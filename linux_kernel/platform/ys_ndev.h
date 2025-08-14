/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_NETDEV_H_
#define __YS_NETDEV_H_

#include <linux/netdevice.h>
#include <linux/types.h>

#include "ys_pdev.h"

#include "ys_utils.h"

#include "../net/ys_ethtool_ops.h"
#include "../net/ys_ndev_ops.h"

#include "ysnic.h"

#define YS_MTU 1500
#define YS_MAX_MTU 9600
#ifdef CONFIG_YSHW_K2ULTRA
#define YS_NP_MAX_MTU 9600
#else
#define YS_NP_MAX_MTU 9000
#endif

#define YS_ADEV_TYPE_ETH_BASE 0
#define YS_ADEV_TYPE_SF_BASE 0x100
#define YS_ADEV_TYPE_REP_BASE 0x10

/* according to YS_K2U_SMARTNIC_REP_ID_PF / YSK2_SMARTNIC_REP_ID_PF */
#define YS_REP_ADEV_IDX_PF	0
/* according to YS_K2U_SMARTNIC_REP_ID_UPLINK / YSK2_SMARTNIC_REP_ID_UPLINK */
#define YS_REP_ADEV_IDX_UPLINK	0x200

#define YS_FLOW_HASH_INDIR_TABLE_SIZE	0x80
enum {
	LAN_STATS_TX64_BYTES_CNT,
	LAN_STATS_TX65_128_BYTES_CNT,
	LAN_STATS_TX129_256_BYTES_CNT,
	LAN_STATS_TX257_512_BYTES_CNT,
	LAN_STATS_TX513_1024_BYTES_CNT,
	LAN_STATS_TX1025_1514_BYTES_CNT,
	LAN_STATS_TX1515_2048_BYTES_CNT,
	LAN_STATS_TX2049_4096_BYTES_CNT,
	LAN_STATS_TX4097_8192_BYTES_CNT,
	LAN_STATS_TX8193_9600_BYTES_CNT,
	LAN_STATS_TX9600_PLUS_BYTES_CNT,
	LAN_STATS_TX_SHORT_60_BYTES_CNT,
	LAN_STATS_TX_OVER_9600_BYTES_CNT,
	LAN_STATS_TX_OTHER_BYTES_CNT,
	LAN_STATS_TX_IPV4_CNT,
	LAN_STATS_TX_IPV6_CNT,
	LAN_STATS_TX_IPV4_VLAN_CNT,
	LAN_STATS_TX_IPV6_VLAN_CNT,
	LAN_STATS_TX_UNICAST_CNT,
	LAN_STATS_TX_BROADCAST_CNT,
	LAN_STATS_TX_MULTICAST_IPV4_CNT,
	LAN_STATS_TX_MULTICAST_IPV6_CNT,
	LAN_STATS_TX_LOSS_PKT_CNT,
	LAN_STATS_TX_CHECKSUM_ERROR_CNT,
	LAN_STATS_TX_FCS_ERROR_CNT,
	LAN_STATS_RX64_BYTES_CNT,
	LAN_STATS_RX65_128_BYTES_CNT,
	LAN_STATS_RX129_256_BYTES_CNT,
	LAN_STATS_RX257_512_BYTES_CNT,
	LAN_STATS_RX513_1024_BYTES_CNT,
	LAN_STATS_RX1025_1514_BYTES_CNT,
	LAN_STATS_RX1515_2048_BYTES_CNT,
	LAN_STATS_RX2049_4096_BYTES_CNT,
	LAN_STATS_RX4097_8192_BYTES_CNT,
	LAN_STATS_RX8193_9600_BYTES_CNT,
	LAN_STATS_RX9600_PLUS_BYTES_CNT,
	LAN_STATS_RX_SHORT_60_BYTES_CNT,
	LAN_STATS_RX_OVER_9600_BYTES_CNT,
	LAN_STATS_RX_OTHER_BYTES_CNT,
	LAN_STATS_RX_IPV4_CNT,
	LAN_STATS_RX_IPV6_CNT,
	LAN_STATS_RX_IPV4_VLAN_CNT,
	LAN_STATS_RX_IPV6_VLAN_CNT,
	LAN_STATS_RX_UNICAST_CNT,
	LAN_STATS_RX_BROADCAST_CNT,
	LAN_STATS_RX_MULTICAST_IPV4_CNT,
	LAN_STATS_RX_MULTICAST_IPV6_CNT,
	LAN_STATS_RX_LOSS_PKT_CNT,
	LAN_STATS_RX_CHECKSUM_ERROR_CNT,
	LAN_STATS_RX_FCS_ERROR_CNT,
	LAN_STATS_INFO_LEN,
	MAX_STATS_INFO_LEN,
};

struct ys_priv_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stats_offset;
};

#define _STAT(_name, _size, _stats)                         \
	{                                                   \
		.stat_string = _name, .sizeof_stat = _size, \
		.stats_offset = _stats,                     \
	}

struct ys_stats {
	u64 tx_pkt_64_bytes;
	u64 tx_pkt_65_128_bytes;
	u64 tx_pkt_129_256_bytes;
	u64 tx_pkt_257_512_bytes;
	u64 tx_pkt_513_1024_bytes;
	u64 tx_pkt_1025_1514_bytes;
	u64 tx_pkt_1515_2048_bytes;
	u64 tx_pkt_2049_4096_bytes;
	u64 tx_pkt_4097_8192_bytes;
	u64 tx_pkt_8193_9600_bytes;
	u64 tx_pkt_9600_plus_bytes;
	u64 tx_pkt_short_than_60_bytes;
	u64 tx_pkt_over_than_9600_bytes;
	u64 tx_pkt_other_bytes;
	u64 tx_ipv4;
	u64 tx_ipv6;
	u64 tx_ipv4_vlan;
	u64 tx_ipv6_vlan;
	u64 tx_unicast;
	u64 tx_broadcast;
	u64 tx_multicast_ipv4;
	u64 tx_multicast_ipv6;
	u64 tx_loss_packet;
	u64 tx_checksum_error;
	u64 tx_fcs_error;
	u64 rx_pkt_64_bytes;
	u64 rx_pkt_65_128_bytes;
	u64 rx_pkt_129_256_bytes;
	u64 rx_pkt_257_512_bytes;
	u64 rx_pkt_513_1024_bytes;
	u64 rx_pkt_1025_1514_bytes;
	u64 rx_pkt_1515_2048_bytes;
	u64 rx_pkt_2049_4096_bytes;
	u64 rx_pkt_4097_8192_bytes;
	u64 rx_pkt_8193_9600_bytes;
	u64 rx_pkt_9600_plus_bytes;
	u64 rx_pkt_short_than_60_bytes;
	u64 rx_pkt_over_than_9600_bytes;
	u64 rx_pkt_other_bytes;
	u64 rx_ipv4;
	u64 rx_ipv6;
	u64 rx_ipv4_vlan;
	u64 rx_ipv6_vlan;
	u64 rx_unicast;
	u64 rx_broadcast;
	u64 rx_multicast_ipv4;
	u64 rx_multicast_ipv6;
	u64 rx_loss_packet;
	u64 rx_checksum_error;
	u64 rx_fcs_error;
};

struct ys_napi {
	u16 qid;
	struct napi_struct napi;
	void *priv_data;
};

enum port_flags {
	YS_PORT_FLAG_FORCE_BASER_FEC = 0x2,
	YS_PORT_FLAG_FORCE_RS_FEC = 0x4,
	YS_PORT_FLAG_AUTONEG_ENABLE = 0x08,
	YS_PORT_FLAG_LOOPBACK = 0x10
};

enum {
	YS_LINK_STATR_AUTO = 0,
	YS_LINK_STATR_ENABLE = 1,
	YS_LINK_STATR_DISABLE = 2,
};

enum {
	YS_REP_TYPE_NONE = 0,
	YS_REP_TYPE_UPLINK = 1,
	YS_REP_TYPE_PF = 2,
	YS_REP_TYPE_VF = 3,
};

struct q_depth_param {
	u32 rxq_depth;
	u32 txq_depth;
};

struct ys_hash_field {
	u8 ipv4_tcp_hash_mode;
	u8 ipv6_tcp_hash_mode;
	u8 ipv4_udp_hash_mode;
	u8 ipv6_udp_hash_mode;
};

struct ys_vlan {
	u32 vlan_id;
	struct list_head list;
};

struct ys_ndev_priv {
	void *tc_priv;
	struct pci_dev *pdev;
	struct net_device *ndev;
	/* statistics lock, when get statistics of net_device */
	spinlock_t statistics_lock;
	/* state lock, when related to state of net_device */
	struct mutex state_lock;
	/* open lock, when open or rmmod net_device */
	struct mutex open_lock;
	/* mac table operating lock */
	spinlock_t mac_tbl_lock;
	/* record user resource to recycle */
	struct list_head qres;

	void *adp_priv;
	u32 adev_type;
	u32 rep_type;

	struct ys_queue_params qi;

	struct timer_list link_timer;
	struct delayed_work update_stats_work;

	int fec_cfg;
	u32 link_state;
	struct ys_ethtool_hw_ops *ys_eth_hw;

	struct ys_ndev_hw_ops *ys_ndev_hw;
	struct ys_napi *rx_napi_list;
	struct ys_napi *tx_napi_list;

	/* for ethtool priv flag */
	bool priv_enable;
	bool ct_mode_enable;
	bool ip_rule_drop_enable;
	bool coalesce_time_enable;
	bool veb_enable;
	bool multicast_enable;
	bool umc_flood;
	bool pvid_miss_upload;
	bool disable_fw_lldp;
	bool rss_sel_udp_tun_info;

	u8 rx_enabled;
	bool umd_enable;
	netdev_features_t features;

	u32 rx_coalesce_timeout_ns;
	u32 tx_coalesce_timeout_ns;
	u32 speed;
	u32 duplex;
	u32 port_flags;
	struct ys_hash_field hash_field;
	struct q_depth_param q_depth;
	u32 period_ns;
	u32 hw_default_hash_indir[YS_FLOW_HASH_INDIR_TABLE_SIZE];
	struct list_head cvlan_list;
	struct list_head svlan_list;
	u32 loop_queue;
	u8 mac_intr_en;
	u8 old_mac[ETH_ALEN];

	/* for hw tx/rx set looptest func */
	int (*eth_looptest)(struct net_device *ndev, u64 *data);
	int (*eth_checksfp)(struct ys_pdev_priv *pdev_priv, u32 reg, int port);

	u8 debug;
	/* record debug res*/
	struct list_head debug_res;
	/* debug ops */
	struct ys_ndev_debug_ops *debug_ops;
};

int ys_ndev_check_permission(struct ys_ndev_priv *ndev_priv, int bitmap);

/* for adev func */
int ys_aux_sf_probe(struct auxiliary_device *auxdev,
		    const struct auxiliary_device_id *id);
void ys_aux_sf_remove(struct auxiliary_device *auxdev);
int ys_aux_rep_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id);
void ys_aux_rep_remove(struct auxiliary_device *auxdev);
int ys_aux_eth_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id);
void ys_aux_eth_remove(struct auxiliary_device *auxdev);

#endif /* __YS_NDEV_H_ */
