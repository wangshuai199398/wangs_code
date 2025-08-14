// SPDX-License-Identifier: GPL-2.0

/* Link Aggregation code */

#include <net/bonding.h>
#include "ys_platform.h"
#include "ys_k2u_np_lag.h"
#include "ys_k2u_np.h"
#include "../edma/ys_k2u_new_ndev.h"

#ifndef YS_TC_DISABLE

#define YS_K2U_NP_SHM_ADDR_REG_OFFSET   (0X10010)
#define YS_k2U_NP_SHM_DATA_REG_OFFSET   (0X10014)
#define YS_k2U_NP_SHM_ATOM_REG_OFFSET   (0X1001C)
#define YS_K2U_NP_SHM_DATA_BOND2MAC_START_OFFSET (0X1010)
#define YS_K2U_NP_SHM_DATA_MAC2BOND_START_OFFSET (0X1030)

static int ys_k2u_np_config_bond2mac_shm(struct ys_pdev_priv *pdev_priv, int id, u32 val)
{
	void __iomem *baddr = pdev_priv->bar_addr[YS_K2U_NP_REGS_BAR];
	int i = 0;
	u32 offset, addr_reg_offset, data_reg_offset;
	u32 addr_reg_data;

	for (i = 0; i < YS_K2U_NP_PPE_CLUSTE_NUM; i++) {
		if (!(YS_K2U_NP_VALID_CLS_BITMAP & BIT(i)))
			continue;

		offset = YS_K2U_NP_BASE + YS_K2U_NP_CLUSTER_SIZE * i;
		addr_reg_offset = offset + YS_K2U_NP_SHM_ADDR_REG_OFFSET;
		data_reg_offset = offset + YS_k2U_NP_SHM_DATA_REG_OFFSET;
		addr_reg_data = YS_K2U_NP_SHM_DATA_BOND2MAC_START_OFFSET + id * 4;

		/* config sharemem_addr_reg*/
		ys_wr32(baddr, addr_reg_offset, addr_reg_data);

		/* write data*/
		ys_wr32(baddr, data_reg_offset, val);
	}

	return 0;
}

static int ys_k2u_np_config_mac2bond_shm(struct ys_pdev_priv *pdev_priv, int id, u16 val)
{
	void __iomem *baddr = pdev_priv->bar_addr[YS_K2U_NP_REGS_BAR];
	int i = 0;
	u32 offset, addr_reg_offset;
	u16 addr_reg_data;
	u32 reg_val;

	for (i = 0; i < YS_K2U_NP_PPE_CLUSTE_NUM; i++) {
		if (!(YS_K2U_NP_VALID_CLS_BITMAP & BIT(i)))
			continue;

		offset = YS_K2U_NP_BASE + YS_K2U_NP_CLUSTER_SIZE * i;
		addr_reg_offset = offset + YS_k2U_NP_SHM_ATOM_REG_OFFSET;
		addr_reg_data = YS_K2U_NP_SHM_DATA_MAC2BOND_START_OFFSET + id * 2;

		reg_val = ((addr_reg_data << 16) & 0xFFFF0000);
		reg_val |= (val & 0xFFFF);

		/* write data*/
		ys_wr32(baddr, addr_reg_offset, reg_val);
	}

	return 0;
}

#define AGG_ENABLE_MASK                 0x1        // [0 : 0]
#define AGG_PORT_NUM_MASK               0xE        // [3 : 1]
#define PHY_PORT_RESERVED_MASK          0xFFFFFFF0 // [31: 4]

#define AGG_MODE_MASK                   0x7        // [2 : 0]
#define AGG_HASH_MODE_MASK              0x38       // [5 : 3]
#define AGG_MASTER_MASK                 0x1C0      // [8 : 6]
#define AGG_PORT_RESERVED_MASK          0xFFFFFE00 // [31: 9]

#define AGG_BITMAP_MASK                 0xFF       // [7 : 0]
#define AGG_BITMAP_RESERVED_MASK        0xFFFFFE00 // [31: 9]

static void ys_k2u_write_agg_config(void __iomem *baddr, int id, u32 agg_mode,
				    u32 agg_hash_mode, u32 agg_master)
{
	u32 value = 0x0;

	value |= (agg_mode & AGG_MODE_MASK);
	value |= ((agg_hash_mode << 3) & AGG_HASH_MODE_MASK);
	value |= ((agg_master << 6) & AGG_MASTER_MASK);
	ys_wr32(baddr, YS_K2U_NP_QOS_AGG_PORT_CONFIG(id), value);
}

static void ys_k2u_write_phy_ports(void __iomem *baddr, u16 slaves, int bond_id, bool enable)
{
	u32 value = enable ? (0x1 | ((bond_id << 1) & AGG_PORT_NUM_MASK)) : 0x0;
	int idx;

	for (idx = 0; idx < YS_K2U_PHY_PORT_NUM; idx++) {
		if (slaves & (1 << idx))
			ys_wr32(baddr, YS_K2U_NP_QOS_AGG_PHY_PORT_CONFIG(idx), value);
	}
}

static void ys_k2u_write_shared_mem(struct ys_pdev_priv *pdev_priv, int bond_id,
				    u32 shm_mode, u32 hash_mode, u32 master, u16 slaves)
{
	u32 value = 0x0;

	value |= (shm_mode & 0xF);
	value |= ((hash_mode << 4) & 0xF0);
	value |= ((master << 8) & 0xFF00);
	value |= ((slaves << 16) & 0xFF0000);
	ys_np_debug("lag config shm value: 0x%x\n", value);
	ys_k2u_np_config_bond2mac_shm(pdev_priv, bond_id, value);
}

static int ys_k2u_bond_hw_setup(struct ys_k2u_lag *lag, struct ys_pdev_priv *pdev_priv,
				int id, bool enable)
{
	void __iomem *baddr = pdev_priv->bar_addr[YS_K2U_NP_REGS_BAR];
	struct ys_k2u_lag_group *lag_group = &lag->lag_group[id];
	u16 mac2bond_value = 0;
	u32 agg_mode, agg_hash_mode, agg_master, agg_shm_mode;
	u8 slaves = lag_group->bond_status;
	int idx;

	if (!baddr)
		return -EINVAL;

	if (enable) {
		agg_hash_mode = 0;
		agg_master = 0;
		agg_shm_mode = 0;

		if (lag_group->tx_type == NETDEV_LAG_TX_TYPE_HASH) {
			if (lag_group->bond_mode != BOND_MODE_8023AD &&
			    lag_group->bond_mode != BOND_MODE_XOR)
				return 0;

			agg_mode = YS_k2U_NP_MODE_HASH_BALANCE;
			agg_shm_mode = lag_group->bond_mode + 1;
			ys_np_debug("hash balance mode.");
#ifdef YS_HAVE_NETDEV_LAG_HASH
			if (lag_group->hash_type == NETDEV_LAG_HASH_L2) {
				agg_hash_mode = YS_k2U_NP_POLICY_L2;
				ys_np_debug("L2 hash type.");
			} else if (lag_group->hash_type == NETDEV_LAG_HASH_L23) {
				agg_hash_mode = YS_k2U_NP_POLICY_L23;
				ys_np_debug("L23 hash type.");
			} else if (lag_group->hash_type == NETDEV_LAG_HASH_L34) {
				agg_hash_mode = YS_k2U_NP_POLICY_L34;
				ys_np_debug("L34 hash type.");
			} else {
				ys_np_debug("Unsupported hash type.");
				return -EOPNOTSUPP;
			}
#endif
		} else if (lag_group->tx_type == NETDEV_LAG_TX_TYPE_ROUNDROBIN) {
			agg_mode = YS_k2U_NP_MODE_ROUND_ROBIN;
			agg_shm_mode = YS_k2U_NP_SHM_MODE_ROUND_ROBIN;
			agg_master = lag_group->primary_pf_id;
			ys_np_debug("round robin mode.");
		} else if (lag_group->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
			agg_mode = YS_k2U_NP_MODE_ACTIVE_BACKUP;
			agg_shm_mode = YS_k2U_NP_SHM_MODE_ACTIVE_BACKUP;
			agg_master = lag_group->primary_pf_id;
			ys_np_debug("active backup mode.");
		} else {
			ys_np_debug("Unsupported mode type.");
			return -EOPNOTSUPP;
		}

		/* single mac bond*/
		if (lag_group->num_slaves == 1)
			ys_np_debug("Single mac bond.");

		ys_np_info("agg_mode: %d, agg_hash_mode: %d, agg_master: %d.\n",
			   agg_mode, agg_hash_mode, agg_master);

		ys_k2u_write_agg_config(baddr, id, agg_mode, agg_hash_mode, agg_master);
		ys_k2u_write_phy_ports(baddr, slaves, id, true);

		for (idx = 0; idx < YS_K2U_PHY_PORT_NUM; idx++) {
			if (slaves & (1 << idx)) {
				mac2bond_value = 0;
				mac2bond_value |= (1 << 0); // bond
				if (lag_group->tx_type == NETDEV_LAG_TX_TYPE_HASH)
					mac2bond_value |= (1 << 1);
				mac2bond_value |= (1 << 2);
				mac2bond_value |= ((id << 8) & 0xFF00);
				ys_k2u_np_config_mac2bond_shm(pdev_priv, idx, mac2bond_value);
			}
		}

		ys_k2u_write_shared_mem(pdev_priv, id, agg_shm_mode, agg_hash_mode,
					agg_master, slaves);
	} else {
		ys_k2u_write_agg_config(baddr, id, 0, 0, 0);
		ys_k2u_write_phy_ports(baddr, lag_group->bond_status, id, false);

		for (idx = 0; idx < YS_K2U_PHY_PORT_NUM; idx++) {
			if (slaves & (1 << idx))
				ys_k2u_np_config_mac2bond_shm(pdev_priv, idx, 0);
		}

		ys_k2u_write_shared_mem(pdev_priv, id, 0, 0, 0, 0);
	}
	return 0;
}

/**
 * ys_k2u_lag_changeupper_event - handle LAG changeupper event
 * @lag: LAG info struct
 * @ptr: opaque pointer data
 *
 * ptr is to be cast into netdev_notifier_changeupper_info
 */
static void ys_k2u_lag_changeupper_event(struct ys_k2u_lag *lag, void *ptr)
{
	struct netdev_notifier_changeupper_info *info;
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	struct net_device *netdev;
	struct net_device *ndev_tmp;
	struct slave *slave;
	u8 primary_pf_id = 0;
	u8 bond_status = 0;
	int num_slaves = 0;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv_member;
	struct ys_pdev_priv *pdev_priv = NULL;
	int i, j, idx;

	info = ptr;
	netdev = netdev_notifier_info_to_dev(ptr);

	if (!info->upper_dev || !netif_is_lag_master(info->upper_dev))
		return;

	ndev_priv = netdev_priv(netdev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ys_np_info("bonding %s\n", info->linking ? "LINK" : "UNLINK");

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(info->upper_dev, ndev_tmp) {
		ndev_priv = netdev_priv(ndev_tmp);
		pdev_priv_member = pci_get_drvdata(ndev_priv->pdev);
		/* same bus id only*/
		if (pdev_priv_member->pdev->bus->number != lag->np_sw->bus_id ||
		    pdev_priv_member->nic_type->is_vf) {
			rcu_read_unlock();
			return;
		}
		bond_status |= (1 << pdev_priv_member->pf_id);

		/* for active-backup, record primary*/
		slave = bond_slave_get_rcu(ndev_tmp);
		if (bond_is_active_slave(slave))
			primary_pf_id = pdev_priv_member->pf_id;

		num_slaves++;
	}
	rcu_read_unlock();

	ys_np_info("upper dev = %s, num_slaves = %d\n", info->upper_dev->name, num_slaves);

	if (num_slaves > 0) {
		/* find the lag group*/
		for (i = 0; i < YS_K2U_LAG_MAX_GROUP; i++) {
			if (lag->lag_group[i].upper_dev == info->upper_dev) {
				idx = i;
				break;
			}
		}

		if (info->linking && lag->active_groups == YS_K2U_LAG_MAX_GROUP) {
			ys_np_err("LAG group full\n");
			return;
		}

		/* not founded, insert */
		if (i == YS_K2U_LAG_MAX_GROUP) {
			for (j = 0; j < YS_K2U_LAG_MAX_GROUP; j++) {
				if (!lag->lag_group[j].upper_dev)
					break;
			}

			if (j == YS_K2U_LAG_MAX_GROUP) {
				ys_np_err("Can't find LAG group to insert!\n");
				return;
			}
			lag->lag_group[j].upper_dev = info->upper_dev;
			dev_hold(lag->lag_group[j].upper_dev);
			idx = j;
			lag->active_groups++;
		}

		ys_np_info("find lag group %d\n", idx);

		if (info->linking) {
			lag_upper_info = info->upper_info;
			lag->lag_group[idx].tx_type = lag_upper_info->tx_type;

#ifdef YS_HAVE_NETDEV_LAG_HASH
			lag->lag_group[idx].hash_type = lag_upper_info->hash_type;
#endif
		} else {
			ys_np_info("clear bond status: %d,\n", lag->lag_group[idx].bond_status);
			ys_k2u_bond_hw_setup(lag, pdev_priv, idx, false);
		}

		lag->lag_group[idx].bond_status = bond_status;
		lag->lag_group[idx].primary_pf_id = primary_pf_id;
		lag->lag_group[idx].num_slaves = num_slaves;

		ys_np_info("bond status: %d, primary_pf_id: %d\n", bond_status, primary_pf_id);

		if (ys_k2u_bond_hw_setup(lag, pdev_priv, idx, true)) {
			ys_np_err("LAG HW setup failed, unsupported mode or tx hash type!\n");
			ys_k2u_bond_hw_setup(lag, pdev_priv, idx, false);
		}

	} else {
		/* find lag group*/
		for (i = 0; i < YS_K2U_LAG_MAX_GROUP; i++) {
			if (lag->lag_group[i].upper_dev == info->upper_dev)
				break;
		}

		if (i == YS_K2U_LAG_MAX_GROUP) {
			ys_np_err("LAG group not found\n");
			return;
		}

		ys_np_info("find lag group %d\n", i);

		dev_put(lag->lag_group[i].upper_dev);
		lag->lag_group[i].upper_dev = NULL;
		lag->active_groups--;

		ys_k2u_bond_hw_setup(lag, pdev_priv, i, false);
	}
}

static int ys_k2u_get_lag_group_id(struct net_device *netdev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_np_sw *np_sw = NULL;
	struct ys_k2u_lag *lag;
	int i;

	ndev_priv = netdev_priv(netdev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	np_sw = ys_get_np_by_bus_id(pdev_priv->pdev->bus->number);
	if (!np_sw)
		return -EINVAL;

	ys_np_debug("netdev: %s, pf_id: %d\n", netdev->name, pdev_priv->pf_id);

	lag = np_sw->lag;
	for (i = 0; i < YS_K2U_LAG_MAX_GROUP; i++) {
		if (lag->lag_group[i].upper_dev) {
			if (lag->lag_group[i].bond_status &
			    (1 << pdev_priv->pf_id)) {
				return i;
			}
		}
	}

	return -1;
}

static void ys_k2u_bond_set_linkstatus(struct ys_pdev_priv *pdev_priv, bool enable)
{
	void __iomem *baddr = pdev_priv->bar_addr[YS_K2U_NP_REGS_BAR];
	u8 pf_id = pdev_priv->pf_id;
	u32 value;

	if (!baddr || pf_id >= YS_K2U_PHY_PORT_NUM)
		return;

	value = ys_rd32(baddr, YS_K2U_NP_QOS_AGG_PORT_LINKSTATUS_CHK);

	if (enable)
		value |= (1 << pf_id);
	else
		value &= ~(1 << pf_id);

	ys_wr32(baddr, YS_K2U_NP_QOS_AGG_PORT_LINKSTATUS_CHK, value);
}

/**
 * ys_k2u_lag_changelower_event - handle LAG changelower event
 * @lag: LAG info struct
 * @ptr: opaque data pointer
 *
 * ptr to be cast to netdev_notifier_changelowerstate_info
 */
static void ys_k2u_lag_changelower_event(struct ys_k2u_lag *lag, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_changelowerstate_info *info;
	struct netdev_lag_lower_state_info *lag_lower_info;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	int idx;

	if (!netif_is_lag_port(netdev))
		return;

	ndev_priv = netdev_priv(netdev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	info = ptr;
	lag_lower_info = info->lower_state_info;

	idx = ys_k2u_get_lag_group_id(netdev);
	if (idx < 0)
		return;

	ys_np_info("lag group:%d, %s change lower. link_up = %d, tx_enabled = %d\n",
		   idx, netdev->name, lag_lower_info->link_up, lag_lower_info->tx_enabled);
	if (lag_lower_info->link_up && lag_lower_info->tx_enabled)
		ys_k2u_bond_set_linkstatus(pdev_priv, true);
}

/**
 * ys_k2u_lag_bondinginfo_event - handle LAG cbondinginfo event
 * @lag: LAG info struct
 * @ptr: opaque data pointer
 *
 * ptr to be cast to netdev_notifier_bonding_info
 */
static void ys_k2u_lag_bondinginfo_event(struct ys_k2u_lag *lag, void *ptr)
{
	struct netdev_notifier_bonding_info *info = ptr;
	struct netdev_bonding_info *bonding_info;
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv_member;
	struct ys_pdev_priv *pdev_priv = NULL;
	u8 old_primary_pf_id;
	int idx;

	if (!netif_is_lag_port(netdev))
		return;

	ndev_priv = netdev_priv(netdev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	bonding_info = &info->bonding_info;

	ys_np_info("bonding info, bonding mode: %d, slave_num: %d\n",
		   bonding_info->master.bond_mode, bonding_info->master.num_slaves);

	idx = ys_k2u_get_lag_group_id(netdev);
	if (idx < 0) {
		ys_np_err("LAG group not found\n");
		return;
	}

	if (bonding_info->master.bond_mode == BOND_MODE_8023AD ||
	    bonding_info->master.bond_mode == BOND_MODE_XOR) {
		if (lag->lag_group[idx].bond_mode != bonding_info->master.bond_mode) {
			lag->lag_group[idx].bond_mode = bonding_info->master.bond_mode;
			ys_np_info("Set hash type through bonding info!");
			ys_k2u_bond_hw_setup(lag, pdev_priv, idx, true);
			return;
		}
	}

	lag->lag_group[idx].bond_mode = bonding_info->master.bond_mode;

	if (bonding_info->master.bond_mode != BOND_MODE_ACTIVEBACKUP ||
	    bonding_info->master.num_slaves < 2)
		return;

	ndev_priv = netdev_priv(netdev);
	pdev_priv_member = pci_get_drvdata(ndev_priv->pdev);

	old_primary_pf_id = lag->lag_group[idx].primary_pf_id;

	ys_np_info("bonding info, pf_id: %d, slave_state: %d\n",
		   pdev_priv_member->pf_id, bonding_info->slave.state);

	if (!bonding_info->slave.state) {
		lag->lag_group[idx].primary_pf_id = pdev_priv_member->pf_id;
		if (old_primary_pf_id != lag->lag_group[idx].primary_pf_id) {
			ys_k2u_bond_hw_setup(lag, pdev_priv, idx, true);
			ys_np_info("primary slave changed!");
		}
	}
}

/**
 * ys_k2u_lag_event_handler - handle LAG events from netdev
 * @notif_blk: notifier block registered by this netdev
 * @event: event type
 * @ptr: opaque data containing notifier event
 * Return: NOTIFY_DONE
 */
static int
ys_k2u_lag_event_handler(struct notifier_block *notif_blk,
			 unsigned long event,
			 void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct ys_k2u_lag *lag;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	if (netdev->netdev_ops != &ys_ndev_ops)
		return NOTIFY_DONE;

	lag = container_of(notif_blk, struct ys_k2u_lag, notif_block);

	ndev_priv = netdev_priv(netdev);
	if (!ys_k2u_ndev_is_uplink(ndev_priv))
		return NOTIFY_DONE;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (pdev_priv->pdev->bus->number != lag->np_sw->bus_id)
		return NOTIFY_DONE;

	/* Check that the netdev is in the working namespace */
	if (!net_eq(dev_net(netdev), &init_net))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		ys_k2u_lag_changeupper_event(lag, ptr);
		break;
	case NETDEV_CHANGELOWERSTATE:
		ys_k2u_lag_changelower_event(lag, ptr);
		break;
	case NETDEV_BONDING_INFO:
		ys_k2u_lag_bondinginfo_event(lag, ptr);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

/**
 * ys_k2u_register_lag_handler - register LAG handler on netdev
 * @np: np module handle
 * @lag: LAG struct
 * Return: 0 on success, -EINVAL if registration fails.
 */
static int ys_k2u_register_lag_handler(struct ys_np *np, struct ys_k2u_lag *lag)
{
	struct notifier_block *notif_blk;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);

	notif_blk = &lag->notif_block;

	if (!notif_blk->notifier_call) {
		notif_blk->notifier_call = ys_k2u_lag_event_handler;
		if (register_netdevice_notifier(notif_blk)) {
			notif_blk->notifier_call = NULL;
			ys_np_err("FAIL register LAG event handler!\n");
			return -EINVAL;
		}
		ys_np_info("LAG event handler registered\n");
	}
	return 0;
}

/**
 * ys_k2u_unregister_lag_handler - unregister LAG handler on netdev
 * @np: np module handle
 * @lag: LAG struct
 * Return: void
 */
static void ys_k2u_unregister_lag_handler(struct ys_np *np, struct ys_k2u_lag *lag)
{
	struct notifier_block *notif_blk;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);

	notif_blk = &lag->notif_block;
	if (notif_blk->notifier_call) {
		unregister_netdevice_notifier(notif_blk);
		ys_np_info("LAG event handler unregistered\n");
	}
}

int ys_k2u_init_lag(struct ys_np *np)
{
	struct ys_k2u_lag *lag;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	struct ys_np_sw *np_sw;
	int err;

	np_sw = np->sw;
	np_sw->lag = kzalloc(sizeof(*lag), GFP_KERNEL);
	if (!np_sw->lag)
		return -ENOMEM;
	lag = np_sw->lag;
	lag->np_sw = np_sw;

	err = ys_k2u_register_lag_handler(np, lag);
	if (err) {
		ys_np_err("INIT LAG: Failed to register event handler\n");
		goto lag_error;
	}

	ys_np_info("INIT LAG complete\n");
	return 0;

lag_error:
	kfree(lag);
	np_sw->lag = NULL;
	return err;
}

void ys_k2u_deinit_lag(struct ys_np *np)
{
	struct ys_k2u_lag *lag;
	struct ys_np_sw *np_sw;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	int i;

	np_sw = np->sw;
	lag = np_sw->lag;

	if (!lag)
		return;

	ys_k2u_unregister_lag_handler(np, lag);

	for (i = 0; i < YS_K2U_LAG_MAX_GROUP; i++) {
		if (lag->lag_group[i].upper_dev) {
			dev_put(lag->lag_group[i].upper_dev);
			lag->lag_group[i].upper_dev = NULL;
			ys_k2u_bond_hw_setup(lag, pdev_priv, i, false);
		}
	}

	kfree(lag);
	np_sw->lag = NULL;
}

int ys_k2u_get_lag_group_id_by_master(int bus_id, struct net_device *netdev)
{
	struct ys_np_sw *np_sw = NULL;
	struct ys_k2u_lag *lag;
	int i;

	np_sw = ys_get_np_by_bus_id(bus_id);
	if (!np_sw)
		return -EINVAL;

	lag = np_sw->lag;
	for (i = 0; i < YS_K2U_LAG_MAX_GROUP; i++) {
		if (lag->lag_group[i].upper_dev == netdev)
			return i;
	}

	return -1;
}

int ys_k2u_np_set_lag_cfg(struct pci_dev *pdev, u8 bond_id, bool enable, u32 val)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	void __iomem *baddr = pdev_priv->bar_addr[YS_K2U_NP_REGS_BAR];
	u32 agg_mode, agg_hash_mode, agg_master, agg_shm_mode;
	u8 mode, slaves, primary, policy;

	if (!baddr)
		return -EINVAL;

	mode = (val >> 24) & 0xFF;
	slaves = (val >> 16) & 0xFF;
	primary = (val >> 8) & 0xFF;
	policy = val & 0xFF;

	if (enable) {
		agg_hash_mode = 0;
		agg_master = 0;
		agg_shm_mode = 0;

		if (mode == BOND_MODE_8023AD || mode == BOND_MODE_XOR) {
			ys_np_debug("hash balance mode.");
			agg_mode = YS_k2U_NP_MODE_HASH_BALANCE;
			agg_shm_mode = mode + 1;
			agg_hash_mode = policy;
		} else if (mode == BOND_MODE_ROUNDROBIN) {
			ys_np_debug("round robin mode.");
			agg_mode = YS_k2U_NP_MODE_ROUND_ROBIN;
			agg_shm_mode = YS_k2U_NP_SHM_MODE_ROUND_ROBIN;
			agg_master = primary;
		} else if (mode == BOND_MODE_ACTIVEBACKUP) {
			ys_np_debug("active backup mode.");
			agg_mode = YS_k2U_NP_MODE_ACTIVE_BACKUP;
			agg_shm_mode = YS_k2U_NP_SHM_MODE_ACTIVE_BACKUP;
			agg_master = primary;
		} else {
			ys_np_debug("Unsupported mode type.");
			return -EOPNOTSUPP;
		}

		ys_np_info("agg_mode: %d, agg_hash_mode: %d, agg_master: %d. slaves: 0x%x\n",
			   agg_mode, agg_hash_mode, agg_master, slaves);

		ys_k2u_write_agg_config(baddr, bond_id, agg_mode, agg_hash_mode, agg_master);
		ys_k2u_write_phy_ports(baddr, slaves, bond_id, true);
		ys_k2u_write_shared_mem(pdev_priv, bond_id, agg_shm_mode, agg_hash_mode,
					agg_master, slaves);
	} else {
		ys_k2u_write_agg_config(baddr, bond_id, 0, 0, 0);
		ys_k2u_write_phy_ports(baddr, slaves, bond_id, false);
		ys_k2u_write_shared_mem(pdev_priv, bond_id, 0, 0, 0, 0);
	}

	return 0;
}

int ys_k2u_np_set_lag_linkstatus_cfg(struct pci_dev *pdev, u16 port_id, bool enable)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	void __iomem *baddr = pdev_priv->bar_addr[YS_K2U_NP_REGS_BAR];
	u32 value;

	if (!baddr || port_id >= YS_K2U_PHY_PORT_NUM)
		return -EINVAL;

	value = ys_rd32(baddr, YS_K2U_NP_QOS_AGG_PORT_LINKSTATUS_CHK);

	if (enable)
		value |= (1 << port_id);
	else
		value &= ~(1 << port_id);

	ys_wr32(baddr, YS_K2U_NP_QOS_AGG_PORT_LINKSTATUS_CHK, value);

	return 0;
}

#endif
