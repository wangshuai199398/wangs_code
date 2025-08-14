/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2ULAN_H_
#define __YS_K2ULAN_H_

#include <linux/ethtool.h>

#include "ys_reg_ops.h"
#include "ys_utils.h"
#include "ys_cuckoo_hash.h"

#define K2ULAN_DEBUG 0

enum {
	YS_K2ULAN_ALLOC_QSET = 1,
	YS_K2ULAN_RELEASE_QSET,
};

enum ys_k2ulan_l2_filter_type {
	YS_K2ULAN_L2UC_FILTER = 0,
	YS_K2ULAN_L2MC_IPV4_FILTER,
	YS_K2ULAN_L2MC_IPV6_FILTER,
	YS_K2ULAN_VLAN_FILTER,
	YS_K2ULAN_FILTER_TYPE_MAX,
};

enum ys_k2ulan_filter_action {
	YS_K2ULAN_FILTER_ADD = 0,
	YS_K2ULAN_FILTER_DEL,
	YS_K2ULAN_FILTER_UPDATE,
};

#define YS_K2ULAN_QSET_BITMAP		32
#define YS_K2U_SMARTNIC_REP_ID_UPLINK_ID 0x200 // according to YS_K2U_ID_NDEV_UPLINK
#define YS_K2U_SMARTNIC_ADEV_ID_TO_VF(adev_id) ((adev_id) - 1)
#define YS_K2ULAN_QSET_BITMAP_BITS	(YS_K2ULAN_QSET_BITMAP * 32)
#define YS_K2ULAN_TC_MC_GROUP_NUM	2048
#define YS_K2ULAN_TC_MC_GROUP_QBMP_LEN	32	//u32 bitmap[32] stand for 1024 bits qset bitmap

struct ys_k2ulan_mac_filter_hw {
	u8 mac[ETH_ALEN];
	u16 qset_bmp_idx : 11;
	u16 enable : 1;
	u16 rsvd : 4;
};

struct ys_k2ulan_mac_uc_filter {
	u8 mac[ETH_ALEN];
	u32 bitmap[YS_K2ULAN_QSET_BITMAP];
	u32 qset_bmp_idx;
	u32 ref_cnt;
	struct list_head uc_key_node;
};

struct ys_k2ulan_mac_ipv4_mc_filter_hw {
	u32 qset_bmp_idx : 11;
	u32 enable : 1;
	u32 rsvd : 21;
	u8 mac[ETH_ALEN];
	u8 rsvd_1;
};

struct ys_k2ulan_mac_ipv4_mc_filter {
	u8 mac[ETH_ALEN];
	u32 qset_bmp_idx;
	u32 bitmap[YS_K2ULAN_QSET_BITMAP];
	struct list_head mc_key_node;
};

union ys_k2ulan_l2_data {
	struct ys_k2ulan_mac_ipv4_mc_filter mc;
	struct ys_k2ulan_mac_uc_filter uc;
};

struct ys_k2ulan_uc_qset_bitmap {
	u32 bitmap[YS_K2ULAN_QSET_BITMAP];
	u32 index;
	u32 ref_cnt;
	struct list_head uc_qbmp_node;
};

struct ys_k2ulan_mc_qset_bitmap {
	u32 bitmap[YS_K2ULAN_QSET_BITMAP];
	u32 index;
	u32 ref_cnt;
	struct list_head mc_qbmp_node;
};

struct ys_k2ulan_steering_bitmap {
	u32 bitmap[YS_K2ULAN_QSET_BITMAP];
};

struct ys_k2ulan_vlan_entry {
	u32 bitmap[YS_K2ULAN_QSET_BITMAP];
	int qbmp_idx;
	u32 member_cnt;
};

struct ys_k2ulan_vlan_qbmp {
	u32 bitmap[YS_K2ULAN_QSET_BITMAP];
	int index;
	u32 ref_cnt;
	struct list_head vlan_qbmp_node;
};

#define YS_K2ULAN_HW_TYPE_NORMAL	0
#define YS_K2ULAN_HW_TYPE_BNIC		1

struct ys_k2ulan_steering {
	u32 lan_hw_type;
	u32 dpu_mode;
	u32 uc_used;
	u32 uc_qbmp_used;
	u32 uc_qbmp_index[32]; // uc qset bitmap number 1024
	struct list_head l2uc_key_list;
	struct list_head l2uc_qbmp_list;
	u32 mc_key_used;
	u32 mc_qbmp_used;
	u32 mc_qbmp_index[32]; // mc qset bitmap number 1024
	struct list_head ipv4_l2mc_key_list;
	struct list_head ipv4_l2mc_qbmp_list;
	struct ys_k2ulan_vlan_entry *vlan_entrys; // 8K vlan entry = 802.1Q 4K + 802.1ad 4K
	u32 vlan_qbmp_num;
	u32 vlan_qbmp_used;
	u32 vlan_qbmp_index[128]; // vlan qset bitmap number max is 4096
	struct list_head vlan_qset_bmp_list;
	/* resoure spinlock */
	spinlock_t lock;
};

struct ys_k2ulan {
	struct ys_k2ulan_steering lan_steering;
	struct ys_cuckoo_table *lan_mac_table;
	struct dentry *debugfs_file;
};

enum {
	YS_K2ULAN_CMD_VF_UC_ADD = 1,
	YS_K2ULAN_CMD_VF_UC_UPD,
	YS_K2ULAN_CMD_VF_UC_DEL,
	YS_K2ULAN_CMD_VF_MC_ADD,
	YS_K2ULAN_CMD_VF_MC_UPD,
	YS_K2ULAN_CMD_VF_MC_DEL,
	YS_K2ULAN_CMD_VF_INNER_VLAN_SET,
	YS_K2ULAN_CMD_VF_HASH_SET,
	YS_K2ULAN_CMD_VF_HASH_GET,
	YS_K2ULAN_CMD_VF_HASH_CLEAR,
	YS_K2ULAN_CMD_VF_MTU_SET,
	YS_K2ULAN_CMD_VF_PORT_EN,
	YS_K2ULAN_CMD_VF_PORT_REMOVE,
	YS_K2ULAN_CMD_VF_RX_FEATURE_SET,
	YS_K2ULAN_CMD_VF_TX_FEATURE_SET,
	YS_K2ULAN_CMD_VF_PROMISC_SET,
	YS_K2ULAN_CMD_PF_SET_VF_UC,
	YS_K2ULAN_CMD_VF_SET_PRIV_FLAG,
	YS_K2ULAN_CMD_END,
};

struct ys_k2ulan_cmd {
	u8 cmd_type;
	s8 cmd_status;
	u8 data_len;
	u8 cmd_data[];
};

/* Definitions for ethtool priv flags interface */
enum {
	YS_K2ULAN_PFLAG_VEB_ENABLE,
	YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO,
	YS_K2ULAN_PFLAG_PVID_MISS_UPLOAD,
	YS_K2ULAN_PFLAG_LEN
};

int ys_k2ulan_probe(struct auxiliary_device *auxdev);
void ys_k2ulan_remove(struct auxiliary_device *auxdev);

int ys_k2ulan_set_rss_hash_opt(struct net_device *ndev, struct ethtool_rxnfc *rxnfc);
u32 ys_k2ulan_get_link_speed(struct net_device *ndev);
u32 ys_k2ulan_get_link_duplex(struct net_device *ndev);

int ys_k2ulan_switch_set_promisc(struct net_device *ndev);
void ys_k2ulan_get_hash_mode(struct net_device *ndev);
void ys_k2ulan_init_hw_features(struct net_device *ndev);
int ys_k2ulan_switch_update_cfg(struct net_device *ndev, u16 vf_id);
int ys_k2ulan_switch_del_cfg(struct net_device *ndev, u16 vf_id);
int ys_k2ulan_set_features(struct net_device *ndev, netdev_features_t features);
void ys_k2ulan_set_inner_vlan(struct net_device *ndev, u16 vlan_id, __be16 proto, u8 enable);
int ys_k2ulan_tx_features_set(struct net_device *ndev, netdev_features_t features);
int ys_k2ulan_set_vf_spoofchk(struct net_device *ndev, u16 vf_id, bool enable);
int ys_k2ulan_set_tc_mc_group(struct net_device *ndev, u32 group_id, u32 *bitmap);
int ys_k2ulan_get_tc_mc_group(struct net_device *ndev, u32 group_id, u32 *bitmap);

#define K2ULAN_ETH_FUNC(k2ulan)                                       \
	do {                                                    \
		typeof(k2ulan) _k2ulan_temp = (k2ulan);                  \
		_k2ulan_temp->et_get_priv_strings = ys_k2ulan_get_priv_strings;		\
		_k2ulan_temp->et_get_priv_flags = ys_k2ulan_get_priv_flags;		\
		_k2ulan_temp->et_set_priv_flags = ys_k2ulan_set_priv_flags;		\
		_k2ulan_temp->et_get_priv_count = ys_k2ulan_get_priv_count;		\
		_k2ulan_temp->ys_set_rss_hash_opt = ys_k2ulan_set_rss_hash_opt;             \
		_k2ulan_temp->et_get_link_speed = ys_k2ulan_get_link_speed;		\
		_k2ulan_temp->et_get_link_duplex = ys_k2ulan_get_link_duplex;		\
	} while (0)

#define K2ULAN_REP_ETH_FUNC(k2ulan)                                       \
	do {                                                    \
		typeof(k2ulan) _k2ulan_temp = (k2ulan);                  \
		_k2ulan_temp->et_get_link_speed = ys_k2ulan_get_link_speed;		\
		_k2ulan_temp->et_get_link_duplex = ys_k2ulan_get_link_duplex;		\
	} while (0)

#define K2ULAN_NDEV_FUNC(k2ulan)                                                \
	do {                                                              \
		typeof(k2ulan) _k2ulan_temp = (k2ulan);                            \
		_k2ulan_temp->ys_get_hash_mode = ys_k2ulan_get_hash_mode; \
		_k2ulan_temp->ys_init_hw_features = ys_k2ulan_init_hw_features; \
		_k2ulan_temp->ys_set_rx_flags = ys_k2ulan_switch_set_promisc; \
		_k2ulan_temp->ys_update_cfg = ys_k2ulan_switch_update_cfg;	\
		_k2ulan_temp->ys_delete_cfg = ys_k2ulan_switch_del_cfg;	\
		_k2ulan_temp->ys_reset_vf_cfg = ys_k2ulan_reset_vf_cfg;	\
		_k2ulan_temp->ys_update_uc_mac_addr = ys_k2ulan_update_uc_mac_addr;	\
		_k2ulan_temp->ys_features_set = ys_k2ulan_set_features;	\
		_k2ulan_temp->ys_ndev_change_mtu = ys_k2ulan_set_qset_mtu;	\
		_k2ulan_temp->ys_tx_features_set = ys_k2ulan_tx_features_set;	\
		_k2ulan_temp->ys_set_trunk_vid = ys_k2ulan_set_inner_vlan;       \
		_k2ulan_temp->ys_set_port_vf_vlan = ys_k2ulan_set_port_vf_vlan;       \
		_k2ulan_temp->ys_set_vf_spoofchk = ys_k2ulan_set_vf_spoofchk;       \
		_k2ulan_temp->ys_set_tc_mc_group = ys_k2ulan_set_tc_mc_group;       \
		_k2ulan_temp->ys_get_tc_mc_group = ys_k2ulan_get_tc_mc_group;       \
	} while (0)

#define K2ULAN_REP_NDEV_FUNC(k2ulan)                                                \
	do {                                                              \
		typeof(k2ulan) _k2ulan_temp = (k2ulan);                            \
		_k2ulan_temp->ys_init_hw_features = ys_k2ulan_init_hw_features; \
		_k2ulan_temp->ys_update_cfg = ys_k2ulan_switch_update_cfg;	\
		_k2ulan_temp->ys_delete_cfg = ys_k2ulan_switch_del_cfg;	\
		_k2ulan_temp->ys_ndev_change_mtu = ys_k2ulan_set_qset_mtu;	\
		_k2ulan_temp->ys_tx_features_set = ys_k2ulan_tx_features_set;	\
		_k2ulan_temp->ys_set_tc_mc_group = ys_k2ulan_set_tc_mc_group;       \
		_k2ulan_temp->ys_get_tc_mc_group = ys_k2ulan_get_tc_mc_group;       \
	} while (0)

#define K2ULAN_DEVLINK_FUNC(k2ulan)

#endif /* __YS_K2ULAN_H_ */
