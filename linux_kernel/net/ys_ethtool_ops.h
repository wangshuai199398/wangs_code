/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_ETHTOOL_OPS_H_
#define __YS_ETHTOOL_OPS_H_

#define YS_EEPROM_SIZE                  256

enum {
	YS_EEPROM_DATA_INFO = 1,
	YS_EEPROM_DATA_EEP,
};

#define SPEED_10M	10
#define SPEED_100M	100
#define SPEED_1G	1000
#define SPEED_10G	10000
#define SPEED_25G	25000
#define SPEED_40G	40000
#define SPEED_50G	50000
#define SPEED_100G	100000
#define SPEED_200G	100000
#define SPEED_AUTO	100001

#define STATS_SCHEDULE_DELAY 18999998
#define LINK_CONFIGS_GET(configs, _item) \
	((configs)->base._item)
#define MAX_COALESCE_US                 (100000)

enum {
	YS_HASH_FIELD_SEL_L3_PROTO	= 1 << 0,
	YS_HASH_FIELD_SEL_SRC_IP	= 1 << 1,
	YS_HASH_FIELD_SEL_DST_IP	= 1 << 2,
	YS_HASH_FIELD_SEL_L4_SPORT	= 1 << 3,
	YS_HASH_FIELD_SEL_L4_DPORT	= 1 << 4,
};

extern const struct ethtool_ops ys_ethtool_ops;

struct ys_ethtool_ksetting {
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(lp_advertising);
};

struct ys_ethtool_hw_ops {
	void (*et_get_self_strings)(struct net_device *ndev, u8 *data);
	void (*et_get_priv_strings)(struct net_device *ndev, u8 *data);
	int (*et_get_self_count)(struct net_device *ndev);
	int (*et_get_priv_count)(struct net_device *ndev);
	void (*et_self_offline_test)(struct net_device *ndev,
				     struct ethtool_test *eth_test, u64 *data);
	void (*et_self_online_test)(struct net_device *ndev,
				    struct ethtool_test *eth_test, u64 *data);
	void (*et_check_link)(struct net_device *ndev);
	void (*et_get_supported_advertising)(struct net_device *ndev,
					     struct ys_ethtool_ksetting *cmd);
	int (*et_get_eeprom_len)(struct net_device *ndev);
	u32 (*et_get_link_speed)(struct net_device *ndev);
	int (*et_set_link_speed)(struct net_device *ndev, u32 speed);
	u32 (*et_get_link_duplex)(struct net_device *ndev);
	int (*et_set_link_duplex_mode)(struct net_device *ndev, u32 duplex_mode);
	u8 (*et_get_link_autoneg)(struct net_device *ndev);
	int (*et_set_link_autoneg)(struct net_device *ndev, bool autoneg);
	u32 (*et_get_link_port_type)(struct net_device *ndev);
	u32 (*et_get_link_transceiver)(struct net_device *ndev);
	u32 (*et_get_priv_flags)(struct net_device *ndev);
	u32 (*et_set_priv_flags)(struct net_device *ndev, u32 flag);
	int (*et_get_coalesce)(struct net_device *ndev,
			       struct ethtool_coalesce *ec);
	int (*et_set_coalesce)(struct net_device *ndev,
			       struct ethtool_coalesce *ec);
	int (*et_get_fec_mode)(struct net_device *ndev,
			       struct ethtool_fecparam *fp);
	int (*et_set_fec_mode)(struct net_device *ndev,
			       u32 fec);
	void (*et_get_mac_stats)(struct net_device *ndev,
				 struct ethtool_eth_mac_stats *mac_stats);
	int (*et_get_module_data)(struct net_device *ndev, u32 d2m_cmd, u8 *data,
				  u32 data_type);
	int (*enable_mac)(struct net_device *ndev);

	int (*ys_set_rxfh)(struct net_device *ndev, const u32 *indir,
			   const u8 *key, const u8 hfunc);

	int (*ys_get_rxfh)(struct net_device *ndev, u32 *indir, u8 *key,
			   u8 *hfunc);
	u32 (*ys_get_rxfh_key_size)(struct net_device *dev);
	u32 (*ys_get_rxfh_indir_size)(struct net_device *dev);
	int (*ys_set_rss_hash_opt)(struct net_device *ndev,
				   struct ethtool_rxnfc *rxnfc);
	int (*ys_get_rss_hash_opt)(struct net_device *ndev,
				   struct ethtool_rxnfc *info);
	int (*ys_get_ethtool_flow_entry)(struct net_device *ndev,
					 struct ethtool_rxnfc *info);
	int (*ys_get_ethtool_all_flows)(struct net_device *ndev,
					struct ethtool_rxnfc *info,
					u32 *rule_locs);
	int (*ys_get_ethtool_rule_count)(struct net_device *ndev,
					 struct ethtool_rxnfc *info);
	int (*ys_add_ethtool_flow_entry)(struct net_device *ndev,
					 struct ethtool_rxnfc *info);
	int (*ys_del_ethtool_flow_entry)(struct net_device *ndev,
					 struct ethtool_rxnfc *info);
	int (*ys_set_phys_id)(struct net_device *ndev,
			      enum ethtool_phys_id_state state);
	int (*ys_get_regs_len)(struct net_device *ndev);
	void (*ys_get_regs)(struct net_device *ndev,
			    struct ethtool_regs *regs, u32 *p);
	int (*ys_set_channels)(struct net_device *ndev,
			       struct ethtool_channels *ch);
	void (*ys_get_ringparam)(struct net_device *dev,
				 struct ethtool_ringparam *param);
	int (*ys_ringparam_check)(struct net_device *dev,
				  struct ethtool_ringparam *param);
	int (*ys_set_ringparam)(struct net_device *dev,
				struct ethtool_ringparam *param);
	void (*ys_get_pauseparam)(struct net_device *dev,
				  struct ethtool_pauseparam *param);
	int (*ys_set_pauseparam)(struct net_device *dev,
				 struct ethtool_pauseparam *param);
};

int ys_ethtool_hw_init(struct net_device *ndev);
void ys_ethtool_hw_uninit(struct net_device *ndev);
void ys_build_ehtool_ksetting_advertising(struct ys_ethtool_ksetting *cmd,
					  enum ethtool_link_mode_bit_indices link_mode);
void ys_build_ehtool_ksetting_supported(struct ys_ethtool_ksetting *cmd,
					enum ethtool_link_mode_bit_indices link_mode);

#ifndef YS_HAVE_ETH_HW_ADDR_SET
static inline void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
	ether_addr_copy(dev->dev_addr, addr);
}
#endif /* YS_HAVE_ETH_HW_ADDR_SET */

#endif /* __YS_ETHTOOL_OPS_H_ */
