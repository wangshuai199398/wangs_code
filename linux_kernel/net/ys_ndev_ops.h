/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_NDEV_OPS_H_
#define __YS_NDEV_OPS_H_

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

typedef int (*ptp_switch)(void *data);
void set_ptp_switch(ptp_switch ptp_on_cb, ptp_switch ptp_off_cb);

extern const struct net_device_ops ys_ndev_ops;
#ifdef YS_HAVE_UDP_TUNNEL_NIC_INFO
extern const struct udp_tunnel_nic_info ys_udp_tunnels;
#endif

#define YS_NP_DOE_OP_VLAN		BIT(0)
#define YS_NP_DOE_OP_RXQ		BIT(1)
#define YS_NP_DOE_OP_RSS		BIT(2)

struct ys_ndev_hw_ops {
	void (*ys_init_hw_features)(struct net_device *ndev);
	void (*ys_extra_init_hw_features)(struct net_device *ndev);
	void (*ys_get_hash_mode)(struct net_device *ndev);
	int (*ys_ndev_change_mtu)(struct net_device *ndev, int new_mtu);
	int (*ys_update_cfg)(struct net_device *ndev, u16 vf_num);
	int (*ys_delete_cfg)(struct net_device *ndev, u16 vf_num);
	void (*ys_reset_vf_cfg)(struct net_device *ndev, u16 vf_num);
	int (*ys_features_set)(struct net_device *ndev,
			       netdev_features_t features);
	int (*ys_tx_features_set)(struct net_device *ndev,
				  netdev_features_t features);
	int (*ys_extra_features_set)(struct net_device *ndev,
				     netdev_features_t features);
	int (*ys_set_rx_flags)(struct net_device *ndev);
	netdev_features_t (*ys_features_fix)(struct net_device *ndev,
					     netdev_features_t features);
	int (*ys_set_extra_rx_flags)(struct net_device *ndev);
	int (*ys_set_port_vf_vlan)(struct net_device *ndev, u16 vf, u16 vlan,
				   u8 qos, __be16 proto, bool enable);
	int (*ys_set_port_vf_rate)(struct net_device *ndev, int vf,
				   int min_tx_rate, int max_tx_rate);
	int (*ys_set_vf_link_state)(struct net_device *dev,
				    int vf, int link_state);
	void (*ys_set_trunk_vid)(struct net_device *netdev, u16 vlan_id,
				 __be16 proto, u8 enable);
	int (*ys_set_port_udp_tunnel)(struct net_device *ndev, bool enable);
	int (*ys_get_rx_qnum)(struct net_device *ndev, u16 vf_id, u16 *rx_qnum);
	int (*ys_get_rx_rule)(struct net_device *ndev, u16 vf_id, u16 *rss_rule);
	void (*ys_update_vf_cfg)(struct net_device *ndev, u16 vf_id,
				 u16 opcode, u32 *val);
	void (*ys_delete_vf_cfg)(struct net_device *ndev, u16 vf_id);
	int (*ys_set_vf_uc_mc_mac)(struct net_device *ndev, u16 vf_id,
				   u8 *eth_addr, bool enable);
	int (*ys_set_vf_spoofchk)(struct net_device *ndev, u16 vf_id, bool enable);
	int (*ys_check_bonding_slave)(struct net_device *ndev);
	int (*ys_update_uc_mac_addr)(struct net_device *ndev, u16 vf_id,
				     u8 *old_eth_addr, u8 *new_eth_addr);
	void (*ys_get_vf_stats)(struct net_device *ndev, u64 *data);
	int (*ys_set_tc_mc_group)(struct net_device *ndev, u32 group_id, u32 *qbmp);
	int (*ys_get_tc_mc_group)(struct net_device *ndev, u32 group_id, u32 *qbmp);
	void (*ys_ndev_bond_uninit)(struct net_device *ndev);
	struct atomic_notifier_head ys_set_mc_mac_list;
	struct atomic_notifier_head ys_set_uc_mac_list;
	struct atomic_notifier_head ys_set_rxnfc_list;
	struct atomic_notifier_head ys_set_channels_list;
};

struct ys_ndev_debug_ops {
	void (*debug_get_info)(struct net_device *ndev, u32 qid);
};

struct ys_mc_mac {
	struct net_device *ndev;
	const u8 *eth_addr;
	bool enable;
};

struct ys_uc_mac {
	struct net_device *ndev;
	const u8 *eth_addr;
	bool enable;
};

struct ys_np_doe_ctrl {
	struct net_device *ndev;
	unsigned int ctrl_mask;
	unsigned short cmd;
};

int ys_ndev_hw_init(struct net_device *ndev);
int ys_ndev_hw_uninit(struct net_device *ndev);
int ys_ndev_debug_init(struct net_device *ndev);
void ys_ndev_debug_uninit(struct net_device *ndev);

#endif /* __YS_NDEV_OPS_H_ */
