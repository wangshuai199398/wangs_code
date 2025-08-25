// SPDX-License-Identifier: GPL-2.0

#include <net/neighbour.h>
#include <linux/iopoll.h>
#include <linux/netdevice.h>
#include <uapi/linux/if_bridge.h>
#include <net/udp_tunnel.h>
#include <linux/nospec.h>

#include "ys_ndev_ops.h"
#include "ys_ext_ethtool.h"

#include "../platform/ys_ndev.h"
#include "../platform/ys_pdev.h"

#include "ys_debug.h"
#include "ys_reg_ops.h"
#include "ys_utils.h"

#include "../net/lan/ys_lan.h"
#include "../net/mac/ys_mac.h"

#include "tc/ys_tc.h"

#include "../platform/ysif_linux.h"

static ptp_switch ptp_on, ptp_off;
static int ys_uc_addr_unsync(struct net_device *ndev, const u8 *addr);
static int ys_mc_addr_unsync(struct net_device *ndev, const u8 *addr);

void set_ptp_switch(ptp_switch ptp_on_cb, ptp_switch ptp_off_cb)
{
	if (ptp_on_cb)
		ptp_on = ptp_on_cb;
	if (ptp_off_cb)
		ptp_off = ptp_off_cb;
}
EXPORT_SYMBOL(set_ptp_switch);

static void ys_ndo_update_stats(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!(ndev->flags & IFF_UP))
		return;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_update_stat))
		pdev_priv->ops->hw_adp_update_stat(ndev);
}

static int ys_ndo_start(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	int ret;
	const struct ysif_ops *ops = ysif_get_ops();
	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_start)) {
		ret = pdev_priv->ops->hw_adp_start(ndev);
		if (ret)
			return ret;
	}

	ndev_priv->rx_enabled = true;
	ops->netif_tx_start_all_queues(ndev);
	ops->netif_device_attach(ndev);
	ops->netif_tx_schedule_all(ndev);
	if ((IS_ERR_OR_NULL(pdev_priv->ops->ndev_has_mac_link_status) ||
	     (!IS_ERR_OR_NULL(pdev_priv->ops->ndev_has_mac_link_status) &&
	      pdev_priv->ops->ndev_has_mac_link_status(ndev))) &&
	    ndev_priv->ys_eth_hw->et_check_link)
		ndev_priv->ys_eth_hw->et_check_link(ndev_priv->ndev);
	else
		ops->netif_carrier_on(ndev);
	return 0;
}

static int ys_ndo_stop(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	const struct ysif_ops *ops = ysif_get_ops();
	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!ndev_priv->rx_enabled)
		return 0;

	ops->netif_tx_disable(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_stop))
		pdev_priv->ops->hw_adp_stop(ndev);

	__hw_addr_unsync_dev(&ndev->uc, ndev, ys_uc_addr_unsync);
	__hw_addr_unsync_dev(&ndev->mc, ndev, ys_mc_addr_unsync);

	ndev_priv->rx_enabled = false;
	return 0;
}

static int ys_ndo_open(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = 0;
	ys_err("ys_ndo_open\n");
	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	mutex_lock(&ndev_priv->open_lock);
	mutex_lock(&ndev_priv->state_lock);

	/* prevent user open port while umd working */
	if (ndev_priv->umd_enable) {
		mutex_unlock(&ndev_priv->state_lock);
		mutex_unlock(&ndev_priv->open_lock);
		return -EINVAL;
	}

	ret = ys_ndo_start(ndev);
	if (ret)
		ys_net_err("Failed to start port: %d", ndev->dev_port);

	mutex_unlock(&ndev_priv->state_lock);
	mutex_unlock(&ndev_priv->open_lock);
	return ret;
}

static int ys_ndo_close(struct net_device *ndev)
{
	ys_err("ys_ndo_close");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = 0;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	mutex_lock(&ndev_priv->state_lock);

	ret = ys_ndo_stop(ndev);
	if (ret)
		ys_net_err("Failed to stop port: %d", ndev->dev_port);

	mutex_unlock(&ndev_priv->state_lock);
	return ret;
}

static netdev_tx_t ys_ndo_start_xmit(struct sk_buff *skb,
				     struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_send))
		return pdev_priv->ops->hw_adp_send(skb, ndev);
	else
		return NETDEV_TX_BUSY;
}

static int ys_ndo_set_mac(struct net_device *ndev, void *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_pos, *ptemp;
	struct ys_pdev_priv *pdev_priv;
	struct sockaddr *saddr = addr;
	struct ys_adev *adev, *atemp;
	struct list_head *pdev_list;
	struct list_head *adev_list;
	struct net_device *local_ndev;
	u8 old_dev_addr[ETH_ALEN];
	u8 dev_addr[ETH_ALEN];
	int find, i;

	if (!memcmp(addr, saddr->sa_data, ETH_ALEN))
		return 0;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	memcpy(dev_addr, saddr->sa_data, ETH_ALEN);
	memcpy(old_dev_addr, ndev->dev_addr, ETH_ALEN);

	find = 0;
	pdev_list = &pdev_priv->pdev_manager->pdev_list;
	list_for_each_entry_safe(pdev_pos, ptemp, pdev_list, list) {
		adev_list = &pdev_pos->adev_list;
		read_lock(&pdev_pos->adev_list_lock);
		list_for_each_entry_safe(adev, atemp, adev_list, list) {
			if (adev->adev_type == AUX_TYPE_ETH || adev->adev_type == AUX_TYPE_SF) {
				if (IS_ERR_OR_NULL(adev->adev_priv))
					continue;
				local_ndev = (struct net_device *)adev->adev_priv;

				for (i = 0; i < ETH_ALEN; i++) {
					if (dev_addr[i] != local_ndev->dev_addr[i])
						break;
				}
				if (i == ETH_ALEN)
					find = 1;
			}
		}
		read_unlock(&pdev_pos->adev_list_lock);
	}

	if (find == 1)
		ys_net_warn("address duplication");

	if (!is_valid_ether_addr(dev_addr))
		return -EADDRNOTAVAIL;

	eth_hw_addr_set(ndev, dev_addr);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_uc_mac_addr))
		ndev_priv->ys_ndev_hw->ys_update_uc_mac_addr(ndev, pdev_priv->vf_id,
							     old_dev_addr,
							     dev_addr);

	ys_net_err("Set MAC address to %02x:%02x:%02x:%02x:%02x:%02x",
		    dev_addr[0], dev_addr[1], dev_addr[2], dev_addr[3],
		    dev_addr[4], dev_addr[5]);

	return 0;
}

static char *g_hwtstamp_tx_types[] = { "OFF", "ON", "ONESTEP_SYNC",
					"ONESTEP_P2P" };
static char *g_hwtstamp_rx_filters[] = { "NONE",
					 "ALL",
					 "SOME",
					 "PTP_V1_L4_EVENT",
					 "PTP_V1_L4_SYNC",
					 "PTP_V1_L4_DELAY_REQ",
					 "PTP_V2_L4_EVENT",
					 "PTP_V2_L4_SYNC",
					 "PTP_V2_L4_DELAY_REQ",
					 "PTP_V2_L2_EVENT",
					 "PTP_V2_L2_SYNC",
					 "PTP_V2_L2_DELAY_REQ",
					 "PTP_V2_EVENT",
					 "PTP_V2_SYNC",
					 "PTP_V2_DELAY_REQ",
					 "NTP_ALL" };

static int ys_ndo_hwtstamp_set(struct net_device *ndev, struct ifreq *ifr)
{
	struct hwtstamp_config hwts_config;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32 val_tx_type, val_rx_filter;
	struct ys_ptp *ptp;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ptp = pdev_priv->ptp;
	if (IS_ERR_OR_NULL(ptp))
		return -EOPNOTSUPP;

	if (copy_from_user(&hwts_config, ifr->ifr_data, sizeof(hwts_config)))
		return -EFAULT;

	if (hwts_config.flags)
		return -EINVAL;

	val_tx_type = hwts_config.tx_type;

	val_tx_type = array_index_nospec(val_tx_type,
					 ARRAY_SIZE(g_hwtstamp_tx_types));

	val_rx_filter = hwts_config.rx_filter;
	val_rx_filter = array_index_nospec(val_rx_filter,
					   ARRAY_SIZE(g_hwtstamp_rx_filters));
	if (val_tx_type >= ARRAY_SIZE(g_hwtstamp_tx_types) &&
	    val_rx_filter >= ARRAY_SIZE(g_hwtstamp_rx_filters))
		return -EINVAL;

	ys_net_debug("tx_type=%d(%s), rx_filters=%d(%s)\n",
		     hwts_config.tx_type,
		     g_hwtstamp_tx_types[val_tx_type],
		     hwts_config.rx_filter,
		     g_hwtstamp_rx_filters[val_rx_filter]);

	switch (hwts_config.tx_type) {
	case HWTSTAMP_TX_OFF:
		ptp->tx_hw_tstamp = false;
		break;
	case HWTSTAMP_TX_ON:
		ptp->tx_hw_tstamp = true;
		break;
	default:
		return -ERANGE;
	}

	switch (hwts_config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		ptp->rx_hw_tstamp = false;
		if (ptp_off)
			ptp_off(pdev_priv);
		break;
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_SOME:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_NTP_ALL:
		hwts_config.rx_filter = HWTSTAMP_FILTER_ALL;
		ptp->rx_hw_tstamp = true;
		if (ptp_on)
			ptp_on(pdev_priv);
		break;
	default:
		return -ERANGE;
	}
	memcpy(&ptp->hwts_config, &hwts_config, sizeof(hwts_config));

	if (copy_to_user(ifr->ifr_data, &hwts_config, sizeof(hwts_config)))
		return -EFAULT;

	return 0;
}

static int ys_ndo_hwtstamp_get(struct net_device *ndev, struct ifreq *ifr)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_ptp *ptp;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ptp = pdev_priv->ptp;
	if (IS_ERR_OR_NULL(ptp))
		return -EOPNOTSUPP;

	if (copy_to_user(ifr->ifr_data, &ptp->hwts_config,
			 sizeof(ptp->hwts_config)))
		return -EFAULT;
	return 0;
}

static int ys_ndo_ioctl(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_ndo_ioctl)) {
		int ret;

		ret = pdev_priv->ops->hw_adp_ndo_ioctl(ndev, ifr, cmd);
		if (ret != -EOPNOTSUPP)
			return ret;
	}

	switch (cmd) {
	case SIOCSHWTSTAMP:
		return ys_ndo_hwtstamp_set(ndev, ifr);
	case SIOCGHWTSTAMP:
		return ys_ndo_hwtstamp_get(ndev, ifr);
	case YS_IOCG_EXTETHTOOL:
		return ys_ext_ethtool(ndev, ifr);
	default:
		return -EOPNOTSUPP;
	}
	pr_err("ys_ndo_ioctl\n");
}

static int ys_ndo_change_hw_mtu(struct net_device *ndev, int new_mtu)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 ret = 0;

	if (ndev_priv->ys_ndev_hw->ys_ndev_change_mtu) {
		ret = ndev_priv->ys_ndev_hw->ys_ndev_change_mtu(ndev, new_mtu);
		if (ret == 0) {
			ndev->mtu = new_mtu;
			ys_net_info("New MTU: %d", new_mtu);
		} else {
			ys_net_err("Bad MTU: %d", new_mtu);
		}
	}

	return ret;
}

static int ys_ndo_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 ret = 0;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (new_mtu < ndev->min_mtu || new_mtu > ndev->max_mtu) {
		ys_net_err("Bad MTU: %d", new_mtu);
		return -EPERM;
	}

	if (netif_running(ndev)) {
		mutex_lock(&ndev_priv->state_lock);
		ys_ndo_stop(ndev);
		ret = ys_ndo_change_hw_mtu(ndev, new_mtu);
		ys_ndo_start(ndev);
		mutex_unlock(&ndev_priv->state_lock);
	} else {
		mutex_lock(&ndev_priv->state_lock);
		ret = ys_ndo_change_hw_mtu(ndev, new_mtu);
		mutex_unlock(&ndev_priv->state_lock);
	}
	ys_err("ys_ndo_change_mtu\n");
	return ret;
}

static void ys_ndo_get_stats64(struct net_device *ndev,
			       struct rtnl_link_stats64 *stats)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	spin_lock_bh(&ndev_priv->statistics_lock);
	ys_ndo_update_stats(ndev);
	netdev_stats_to_stats64(stats, &ndev->stats);
	spin_unlock_bh(&ndev_priv->statistics_lock);
	pr_err("ys_ndo_get_stats64\n");
}

static void ys_ndo_change_rx_flags(struct net_device *ndev, int flags)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = 0;
	pr_err("ys_ndo_change_rx_flags\n");
	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF))
		return;

	if (flags & IFF_PROMISC) {
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_rx_flags))
			ret = ndev_priv->ys_ndev_hw->ys_set_rx_flags(ndev);
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_extra_rx_flags))
			ret = ndev_priv->ys_ndev_hw->ys_set_extra_rx_flags(ndev);
		if (ret)
			ys_net_info("set promisc mode failed");
	}
}

static int ys_ndo_set_features(struct net_device *ndev,
			       netdev_features_t features)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = 0;
	pr_err("ys_ndo_set_features\n");
	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF))
		return ret;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_features_set))
		ret = ndev_priv->ys_ndev_hw->ys_features_set(ndev, features);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_tx_features_set))
		ret = ndev_priv->ys_ndev_hw->ys_tx_features_set(ndev, features);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_extra_features_set))
		ret = ndev_priv->ys_ndev_hw->ys_extra_features_set(ndev, features);

	return ret;
}

static netdev_features_t ys_ndo_fix_features(struct net_device *ndev,
					     netdev_features_t features)
{
	pr_err("ys_ndo_fix_features\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF))
		return features;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_features_fix))
		return ndev_priv->ys_ndev_hw->ys_features_fix(ndev, features);

	return features;
}

static int ys_uc_addr_sync(struct net_device *ndev, const u8 *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_uc_mac uc_mac;

	uc_mac.ndev = ndev;
	uc_mac.eth_addr = addr;
	uc_mac.enable = true;
	return atomic_notifier_call_chain(&ndev_priv->ys_ndev_hw->ys_set_uc_mac_list, 0, &uc_mac);
}

static int ys_uc_addr_unsync(struct net_device *ndev, const u8 *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_uc_mac uc_mac;

	uc_mac.ndev = ndev;
	uc_mac.eth_addr = addr;
	uc_mac.enable = false;
	return atomic_notifier_call_chain(&ndev_priv->ys_ndev_hw->ys_set_uc_mac_list, 0, &uc_mac);
}

static int ys_mc_addr_sync(struct net_device *ndev, const u8 *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_mc_mac mc_mac;

	mc_mac.ndev = ndev;
	mc_mac.eth_addr = addr;
	mc_mac.enable = true;
	return atomic_notifier_call_chain(&ndev_priv->ys_ndev_hw->ys_set_mc_mac_list, 0, &mc_mac);
}

static int ys_mc_addr_unsync(struct net_device *ndev, const u8 *addr)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_mc_mac mc_mac;

	mc_mac.ndev = ndev;
	mc_mac.eth_addr = addr;
	mc_mac.enable = false;
	return atomic_notifier_call_chain(&ndev_priv->ys_ndev_hw->ys_set_mc_mac_list, 0, &mc_mac);
}

static void ys_ndo_set_rx_mode(struct net_device *ndev)
{
	pr_err("ys_ndo_set_rx_mode\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF))
		return;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		return;

	__dev_mc_sync(ndev, ys_mc_addr_sync, ys_mc_addr_unsync);
	__dev_uc_sync(ndev, ys_uc_addr_sync, ys_uc_addr_unsync);
}

static int ys_ndo_set_vf_mac(struct net_device *ndev, int vf, u8 *mac)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	s32 retval = 0;
	u8 *old_dev_addr;
	bool spoofchk_enable = false;
	pr_err("ys_ndo_set_vf_mac\n");
	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return -EPERM;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return -EPERM;

	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		return -EPERM;

	if (vf >= pdev_priv->sriov_info.num_vfs)
		return -EINVAL;

	old_dev_addr = pdev_priv->sriov_info.vfinfo[vf].vf_mac_addresses;

	if (is_valid_ether_addr(mac)) {
		ys_net_info("setting MAC %pM on VF %d\n", mac, vf);
		ys_net_info("Reload the VF driver to make this change effective.");

		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_uc_mac_addr))
			ndev_priv->ys_ndev_hw->ys_update_uc_mac_addr(ndev, vf + 1,
								     old_dev_addr,
								     mac);

		memcpy(pdev_priv->sriov_info.vfinfo[vf].vf_mac_addresses, mac,
		       ETH_ALEN);

		spoofchk_enable = pdev_priv->sriov_info.vfinfo[vf].spoofchk;
		if (spoofchk_enable) {
			if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_vf_spoofchk)) {
				ys_net_debug("spoofchk vf %d", vf);
				retval =
				ndev_priv->ys_ndev_hw->ys_set_vf_spoofchk(ndev, vf + 1,
									  spoofchk_enable);
				if (retval)
					return retval;
			}
		}
	} else {
		retval = -EINVAL;
	}

	return retval;
}

static int ys_ndo_set_vf_vlan(struct net_device *ndev, int vf, u16 vlan, u8 qos,
			      __be16 proto)
{
	pr_err("ys_ndo_set_vf_vlan\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return -EPERM;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return -EPERM;

	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		return -EPERM;

	if (vf >= pdev_priv->sriov_info.num_vfs || vlan > 4095 || qos > 7)
		return -EINVAL;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_vf_vlan))
		return ndev_priv->ys_ndev_hw->ys_set_port_vf_vlan(ndev,
								  vf,
								  vlan,
								  qos,
								  proto,
								  true);
	return 0;
}

static int ys_ndo_set_vf_rate(struct net_device *ndev, int vf, int min_tx_rate,
			      int max_tx_rate)
{
	pr_err("ys_ndo_set_vf_rate\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return -EPERM;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return -EPERM;

	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		return -EPERM;

	/* verify VF is active */
	if (vf >= pdev_priv->sriov_info.num_vfs)
		return -EINVAL;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_vf_rate))
		return ndev_priv->ys_ndev_hw->ys_set_port_vf_rate(ndev,
								  vf,
								  min_tx_rate,
								  max_tx_rate);
	return 0;
}

static int ys_ndo_get_vf_config(struct net_device *ndev, int vf,
				struct ifla_vf_info *ivf)
{
	pr_err("ys_ndo_get_vf_config\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return -EPERM;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return -EPERM;

	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (vf >= pdev_priv->sriov_info.num_vfs)
		return -EINVAL;

	ivf->vf = vf;
	memcpy(&ivf->mac, pdev_priv->sriov_info.vfinfo[vf].vf_mac_addresses,
	       ETH_ALEN);
	ivf->vlan = pdev_priv->sriov_info.vfinfo[vf].is_vf_vlan_1 ?
		    1 : pdev_priv->sriov_info.vfinfo[vf].vf_vlan;
	ivf->max_tx_rate = pdev_priv->sriov_info.vfinfo[vf].vf_tx_rate;
	ivf->linkstate = pdev_priv->sriov_info.vfinfo[vf].link_state;
	ivf->trusted = pdev_priv->sriov_info.vfinfo[vf].trusted;
	ivf->spoofchk = pdev_priv->sriov_info.vfinfo[vf].spoofchk;

	return 0;
}

static int ys_ndo_set_vf_link_state(struct net_device *ndev,
				    int vf, int link_state)
{
	pr_err("ys_ndo_set_vf_link_state\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return -EPERM;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF))
		return -EOPNOTSUPP;

	if (vf >= pdev_priv->sriov_info.num_vfs)
		return -EINVAL;

	if (IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_vf_link_state))
		return -EOPNOTSUPP;

	return ndev_priv->ys_ndev_hw->ys_set_vf_link_state(ndev, vf, link_state);
}

static int ys_ndo_vlan_rx_add_vid(struct net_device *ndev,
				  __be16 proto, u16 vlan_id)
{
	pr_err("ys_ndo_vlan_rx_add_vid\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF))
		return -EPERM;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_trunk_vid))
		ndev_priv->ys_ndev_hw->ys_set_trunk_vid(ndev, vlan_id, proto, 1);

	return 0;
}

static int ys_ndo_vlan_rx_kill_vid(struct net_device *ndev,
				   __be16 proto, u16 vlan_id)
{
	pr_err("ys_ndo_vlan_rx_kill_vid\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF))
		return -EPERM;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_trunk_vid))
		ndev_priv->ys_ndev_hw->ys_set_trunk_vid(ndev, vlan_id, proto, 0);

	return 0;
}

static int ys_ndo_set_vf_trust(struct net_device *ndev, int vf, bool setting)
{
	struct ys_vf_info *vf_info;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (vf >= pdev_priv->sriov_info.num_vfs)
		return -EINVAL;

	vf_info = &pdev_priv->sriov_info.vfinfo[vf];
	/* nothing to do */
	if (vf_info->trusted == setting)
		return 0;

	vf_info->trusted = setting;
	ys_net_err("VF %d is %strusted\n", vf, setting ? "" : "not ");

	return 0;
}

int ys_ndev_hw_init(struct net_device *ndev)
{
	struct ys_ndev_hw_ops *ndev_hw_ops;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ndev_hw_ops = kzalloc(sizeof(*ndev_hw_ops), GFP_KERNEL);

	if (!ndev_hw_ops)
		return -ENOMEM;

	ndev_priv->ys_ndev_hw = ndev_hw_ops;
	ATOMIC_INIT_NOTIFIER_HEAD(&ndev_priv->ys_ndev_hw->ys_set_mc_mac_list);
	ATOMIC_INIT_NOTIFIER_HEAD(&ndev_priv->ys_ndev_hw->ys_set_uc_mac_list);
	ATOMIC_INIT_NOTIFIER_HEAD(&ndev_priv->ys_ndev_hw->ys_set_rxnfc_list);
	ATOMIC_INIT_NOTIFIER_HEAD(&ndev_priv->ys_ndev_hw->ys_set_channels_list);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->mac_adp_ndev_init))
		pdev_priv->ops->mac_adp_ndev_init(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->lan_adp_ndev_init))
		pdev_priv->ops->lan_adp_ndev_init(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->np_adp_ndev_init))
		pdev_priv->ops->np_adp_ndev_init(ndev);

	return 0;
}

int ys_ndev_hw_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw)) {
		kfree(ndev_priv->ys_ndev_hw);
		ndev_priv->ys_ndev_hw = NULL;
	}

	if (!IS_ERR_OR_NULL(ndev_priv->rx_napi_list)) {
		kfree(ndev_priv->rx_napi_list);
		ndev_priv->rx_napi_list = NULL;
	}

	if (!IS_ERR_OR_NULL(ndev_priv->tx_napi_list)) {
		kfree(ndev_priv->tx_napi_list);
		ndev_priv->tx_napi_list = NULL;
	}

	return 0;
}

int ys_ndev_debug_init(struct net_device *ndev)
{
	struct ys_ndev_debug_ops *debug_ops;
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);
	debug_ops = kzalloc(sizeof(*debug_ops), GFP_KERNEL);

	if (!debug_ops)
		return -ENOMEM;

	ndev_priv->debug_ops = debug_ops;

	return 0;
}

void ys_ndev_debug_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->debug_ops)) {
		kfree(ndev_priv->debug_ops);
		ndev_priv->debug_ops = NULL;
	}
}

static int ys_ndo_get_phys_port_name(struct net_device *ndev, char *buf, size_t len)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_adev *adev = ys_aux_get_adev(ndev_priv->pdev, ndev_priv->adev_type, ndev);
	int ret;

	switch (ndev_priv->adev_type) {
	case AUX_TYPE_ETH:
		if (pdev_priv->dpu_mode == MODE_DPU_SOC ||
		    (pdev_priv->dpu_mode == MODE_SMART_NIC && !pdev_priv->nic_type->is_vf))
			ret = snprintf(buf, len, "p%d", pdev_priv->pf_id);
		else
			return -EOPNOTSUPP;
		break;
	case AUX_TYPE_REP:
		if (adev->idx == 0)
			ret = snprintf(buf, len, "pfr%d", pdev_priv->pf_id);
		else if (adev->idx == 0x200)
			ret = snprintf(buf, len, "pfuplink%d", pdev_priv->pf_id);
		else
			ret = snprintf(buf, len, "pf%dvf%d", pdev_priv->pf_id, adev->idx - 1);
		break;
	case AUX_TYPE_SF:
		ret = snprintf(buf, len, "pfs%d", adev->idx);
		/* nvme-net occupy sf id == 0 */
		if (pdev_priv->dpu_mode == MODE_DPU_SOC && adev->idx == 0)
			ret = snprintf(buf, len, "nvme-net");
		/* for 2100p comm port */
		if (adev->idx == 250 && pdev_priv->hw_type == YS_HW_TYPE_2100P)
			ret = snprintf(buf, len, "comm");
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (ret <= 0)
		return -EOPNOTSUPP;
	pr_err("ys_ndo_get_phys_port_name: buf: %s", buf);
	return 0;
}

static int ys_ndo_get_phys_port_id(struct net_device *ndev,
				   struct netdev_phys_item_id *ppid)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_adev *adev = ys_aux_get_adev(ndev_priv->pdev, ndev_priv->adev_type, ndev);
	u32 port_id = 0;
	int i;

	/* port id length is 5 bytes
	 * ---------------------------------------
	 * | bus_id | type   | pf_id  | vf_id/sf_id/rep_id |
	 * ---------------------------------------
	 * | 8 bits | 8 bits | 8 bits |      16 bits       |
	 * ---------------------------------------
	 *  type: bit0 = AUX_TYPE_ETH
	 *        bit1 = AUX_TYPE_SF
	 *        bit2 = AUX_TYPE_REP
	 *
	 * For example:
	 *  dpusoc p1:            0x01010000
	 *  dpusoc pf1rep:        0x04010200
	 *  dpusoc pf1vf0rep:     0x04010001
	 *  dpusoc pf1sf0:        0x02010000
	 *  dpuhost p1pf0:        0x0101000000
	 *  dpuhost p1pf0vf0:     0x0101000001
	 *  smartnic p1p1:        0x0104010200
	 *  smartnic p1pf1:       0x0101010000
	 *  smartnic p1pf1vf7:    0x0101010008
	 *  smartnic p1pf1rep:    0x0104010000
	 *  smartnic p1pf1vf7rep: 0x0104010008
	 */
#define YS_PORT_ID_BYTE_LEN	5
#define YS_PORT_ID_SUB_ID	GENMASK(15, 0)
#define YS_PORT_ID_PF_ID	GENMASK(23, 16)
#define YS_PORT_ID_TYPE_ID	GENMASK(31, 24)

	if (pdev_priv->dpu_mode != MODE_DPU_SOC)
		ppid->id_len = YS_PORT_ID_BYTE_LEN;
	else
		ppid->id_len = YS_PORT_ID_BYTE_LEN - 1;

	port_id = FIELD_PREP(YS_PORT_ID_PF_ID, pdev_priv->pf_id);
	if (ndev_priv->adev_type == AUX_TYPE_ETH)
		port_id |= FIELD_PREP(YS_PORT_ID_SUB_ID, pdev_priv->vf_id);
	else
		port_id |= FIELD_PREP(YS_PORT_ID_SUB_ID, adev->idx);

	port_id |= FIELD_PREP(YS_PORT_ID_TYPE_ID, ndev_priv->adev_type);

	if (pdev_priv->dpu_mode != MODE_DPU_SOC) {
		for (i = ppid->id_len - 1; i >= 1; --i) {
			ppid->id[i] =  port_id & 0xff;
			port_id >>= 8;
		}
		ppid->id[0] = pdev_priv->pdev->bus->number;
	} else {
		for (i = ppid->id_len - 1; i >= 0; --i) {
			ppid->id[i] =  port_id & 0xff;
			port_id >>= 8;
		}
	}
	pr_err("ys_ndo_get_phys_port_id: port_id: %u", port_id);
	return 0;
}

#define PORT_ID_BYTE_LEN 8
static int ys_ndo_get_port_parent_id(struct net_device *ndev,
				     struct netdev_phys_item_id *ppid)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	int i;
	u8 bus;
	u64 phys_port_id;

	/* FIXME: it should be serial num, 0xabcdab00 is magic num */
	if (!pdev_priv)
		return -EFAULT;

	bus = pdev_priv->pdev->bus->number;
	phys_port_id = 0xabcdab00 | bus;

	if (ndev_priv->adev_type == AUX_TYPE_ETH && pdev_priv->nic_type->is_vf)
		return -EOPNOTSUPP;

	ppid->id_len = sizeof(phys_port_id);
	for (i = PORT_ID_BYTE_LEN - 1; i >= 0; i--) {
		ppid->id[i] =  phys_port_id & 0xff;
		phys_port_id >>= 8;
	}
	pr_err("ys_ndo_get_phys_port_id: ppid->id[0]: %u", ppid->id[0]);

	return 0;
}

static void ys_add_udp_tunnel(struct net_device *ndev,
			      struct udp_tunnel_info *ti)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return;

	ys_net_err("ys add udp tunnel");
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel))
		ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel(ndev, true);
}

static void ys_del_udp_tunnel(struct net_device *ndev,
			      struct udp_tunnel_info *ti)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return;

	ys_net_err("ys del udp tunnel");
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel))
		ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel(ndev, false);
}

static int ys_ndo_set_vf_spoofchk(struct net_device *ndev, int vf, bool setting)
{
	pr_err("ys_ndo_set_vf_spoofchk\n");
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	int ret;

	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return -EPERM;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return -EPERM;

	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		return -EPERM;

	if (vf >= pdev_priv->sriov_info.num_vfs)
		return -EINVAL;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_vf_spoofchk))
		ret = ndev_priv->ys_ndev_hw->ys_set_vf_spoofchk(ndev, vf + 1, setting);
	else
		ret = -EPERM;

	return ret;
}

static u16 ys_ndo_select_queue_nocb(struct net_device *dev,
				    struct sk_buff *skb,
				    struct net_device *sb_dev)
{
	u16 real_num_tx_queues = dev->real_num_tx_queues;
	u16 idx;
	u32 hash;

	if (skb->sk && skb->sk->sk_hash)
		hash = skb->sk->sk_hash;
	else
		hash = skb_get_hash(skb);

	idx = reciprocal_scale(hash, real_num_tx_queues);

	return idx;
}

/* This is need for 4.18 kernel */
static u16 ys_ndo_select_queue(struct net_device *dev, struct sk_buff *skb,
			       struct net_device *sb_dev,
			       select_queue_fallback_t fallback)
{
	pr_err("ys_ndo_select_queue\n");
	return ys_ndo_select_queue_nocb(dev, skb, sb_dev);
}

const struct net_device_ops ys_ndev_ops = {
	.ndo_get_phys_port_name = ys_ndo_get_phys_port_name,
	.ndo_get_phys_port_id = ys_ndo_get_phys_port_id,
	.ndo_get_port_parent_id = ys_ndo_get_port_parent_id,
	.ndo_open = ys_ndo_open,
	.ndo_stop = ys_ndo_close,
	.ndo_start_xmit = ys_ndo_start_xmit,
	.ndo_set_mac_address = ys_ndo_set_mac,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_do_ioctl = ys_ndo_ioctl,
	.ndo_change_mtu = ys_ndo_change_mtu,
	.ndo_get_stats64 = ys_ndo_get_stats64,
	.ndo_change_rx_flags = ys_ndo_change_rx_flags,
	.ndo_set_rx_mode = ys_ndo_set_rx_mode,
	.ndo_set_features = ys_ndo_set_features,
	.ndo_fix_features = ys_ndo_fix_features,
	.ndo_set_vf_mac = ys_ndo_set_vf_mac,
	.ndo_set_vf_rate = ys_ndo_set_vf_rate,
	.ndo_set_vf_vlan = ys_ndo_set_vf_vlan,
	.ndo_get_vf_config = ys_ndo_get_vf_config,
	.ndo_vlan_rx_add_vid = ys_ndo_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = ys_ndo_vlan_rx_kill_vid,
	.ndo_setup_tc		= ys_tc_setup_tc,
	.ndo_set_vf_trust = ys_ndo_set_vf_trust,
	.ndo_udp_tunnel_add = ys_add_udp_tunnel,
	.ndo_udp_tunnel_del = ys_del_udp_tunnel,
	.ndo_set_vf_link_state = ys_ndo_set_vf_link_state,
	.ndo_set_vf_spoofchk = ys_ndo_set_vf_spoofchk,
	.ndo_select_queue = ys_ndo_select_queue,
};

static int ys_udp_tnl_set_port(struct net_device *ndev,
			       unsigned int table, unsigned int entry,
			       struct udp_tunnel_info *ti)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return -EPERM;

	ys_net_err("ys udp tnl set port");
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel))
		ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel(ndev, true);

	return 0;
}

static int ys_udp_tnl_unset_port(struct net_device *ndev,
				 unsigned int table, unsigned int entry,
				 struct udp_tunnel_info *ti)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return -EPERM;

	ys_net_err("ys udp tnl unset port");
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel))
		ndev_priv->ys_ndev_hw->ys_set_port_udp_tunnel(ndev, false);

	return 0;
}

const struct udp_tunnel_nic_info ys_udp_tunnels = {
	.set_port	= ys_udp_tnl_set_port,
	.unset_port	= ys_udp_tnl_unset_port,
	.flags          = UDP_TUNNEL_NIC_INFO_MAY_SLEEP,
	.tables         = {
		{
			.n_entries = 16,
			.tunnel_types = UDP_TUNNEL_TYPE_VXLAN |
					UDP_TUNNEL_TYPE_GENEVE,
		},
	},
};

