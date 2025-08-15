// SPDX-License-Identifier: GPL-2.0

#include <linux/bitmap.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/pci.h>

#include "ys_auxiliary.h"
#include "ys_ndev.h"
#include "ys_pdev.h"
#include "ys_queue.h"

#include "../net/ys_ethtool_ops.h"
#include "../net/ys_ndev_ops.h"
#include "../net/lan/ys_lan.h"
#include "../net/mac/ys_mac.h"

#include "ys_debug.h"
#include "ys_irq.h"
#include "ys_sysfs.h"

int ys_ndev_check_permission(struct ys_ndev_priv *ndev_priv, int bitmap)
{
	if ((ndev_priv->adev_type & bitmap) == 0)
		return -EPERM;

	return 0;
}

static void ys_ndev_destroy(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_vlan *ys_vlan, *temp;
	struct list_head *entry;
	u16 temp_tx_qnum;
	u16 temp_rx_qnum;

	if (IS_ERR_OR_NULL(ndev))
		return;

	temp_tx_qnum = ndev->real_num_tx_queues;
	temp_rx_qnum = ndev->real_num_rx_queues;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	/* delete ndev vlan */
	list_for_each_entry_safe(ys_vlan, temp, &ndev_priv->cvlan_list, list) {
		list_del(&ys_vlan->list);
		kfree(ys_vlan);
	}

	list_for_each_entry_safe(ys_vlan, temp, &ndev_priv->svlan_list, list) {
		list_del(&ys_vlan->list);
		kfree(ys_vlan);
	}

	/* delete ndev group */
	ys_sysfs_remove_group(&pdev_priv->sysfs_list,
			      SYSFS_NDEV, 0, &ndev->dev.kobj);

	if (pdev_priv->nic_type->mac_type)
		del_timer_sync(&ndev_priv->link_timer);

	/* Memory barriers prevent out-of-order */
	mb();
	/* release umd reference */
	entry = &ndev_priv->qres;
	if (!(entry->next == LIST_POISON1 || entry->prev == LIST_POISON2 ||
	      !entry->next || !entry->prev))
		list_del(entry);

	ys_queue_clear_info(ndev_priv->pdev, QUEUE_TYPE_TX,
			    ndev_priv->qi.qbase, ndev_priv->qi.ndev_qnum);
	ys_queue_clear_info(ndev_priv->pdev, QUEUE_TYPE_RX,
			    ndev_priv->qi.qbase, ndev_priv->qi.ndev_qnum);

	/* netif_carrier_off(ndev); */
	ys_ethtool_hw_uninit(ndev);

	if (pdev_priv->dpu_mode == MODE_LEGACY &&
	    !pdev_priv->nic_type->is_vf &&
	    !IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_ndev_bond_uninit))
		ndev_priv->ys_ndev_hw->ys_ndev_bond_uninit(ndev);

	if (ndev->reg_state == NETREG_REGISTERED) {
		ys_net_info("unregister net dev %s\n", ndev->name);
		unregister_netdev(ndev);
	}

	cancel_delayed_work(&ndev_priv->update_stats_work);

	/*
	 * After unregistering in ndev,
	 * temporarily store the transmit and receive queue data
	 * for use by uninit.
	 */
	netif_set_real_num_tx_queues(ndev, temp_tx_qnum);
	netif_set_real_num_rx_queues(ndev, temp_rx_qnum);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->mac_adp_eth_uninit))
		pdev_priv->ops->mac_adp_eth_uninit(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->mac_adp_ndev_uninit))
		pdev_priv->ops->mac_adp_ndev_uninit(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->lan_adp_eth_uninit))
		pdev_priv->ops->lan_adp_eth_uninit(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->lan_adp_ndev_uninit))
		pdev_priv->ops->lan_adp_ndev_uninit(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->np_adp_ndev_uninit))
		pdev_priv->ops->np_adp_ndev_uninit(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_uninit))
		pdev_priv->ops->hw_adp_uninit(ndev);

	ys_ndev_hw_uninit(ndev);
	ys_ndev_debug_uninit(ndev);

	ndev->num_tx_queues = 0;
	ndev->num_rx_queues = 0;
	netif_set_real_num_tx_queues(ndev, 0);
	netif_set_real_num_rx_queues(ndev, 0);
}

static void __maybe_unused ys_link_timer_callback(struct timer_list *link_timer)
{
	struct ys_ndev_priv *ndev_priv =
		container_of(link_timer, struct ys_ndev_priv, link_timer);

	if (IS_ERR_OR_NULL(ndev_priv))
		return;

	if (IS_ERR_OR_NULL(ndev_priv->ys_eth_hw))
		return;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw->et_check_link))
		ndev_priv->ys_eth_hw->et_check_link(ndev_priv->ndev);

	mod_timer(&ndev_priv->link_timer, jiffies + HZ);
}

static int ys_ndev_create_sysfs_group(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	struct device_attribute *device_attrs;
	int attrs_num;
	int ret;

	if (IS_ERR_OR_NULL(pdev_priv->ops->ndev_adp_detect_sysfs_attrs))
		return 0;

	attrs_num = pdev_priv->ops->ndev_adp_detect_sysfs_attrs(&device_attrs);
	ret = ys_sysfs_create_group(list, SYSFS_NDEV, 0, &ndev->dev.kobj,
				    device_attrs, attrs_num, "common");

	return ret;
}

static struct net_device *ys_ndev_create(struct ys_pdev_priv *pdev_priv,
					 struct ys_adev *adev)
{
	struct ys_ndev_priv *ndev_priv = NULL;
	struct net_device *ndev;
	int ret = 0;
	if (adev->qi.ndev_qnum == 0) {
		ys_dev_err("etherdev alloc max queue can't be 0");
		return NULL;
	}

	if (ys_queue_check_info(pdev_priv->pdev, QUEUE_TYPE_TX,
				adev->qi.qbase, adev->qi.ndev_qnum) ||
	    ys_queue_check_info(pdev_priv->pdev, QUEUE_TYPE_RX,
				adev->qi.qbase, adev->qi.ndev_qnum)) {
		ys_dev_err("queue info check failed, qbase %d qnum %d",
			   adev->qi.qbase, adev->qi.ndev_qnum);
		return NULL;
	}

	ndev = alloc_etherdev_mq(sizeof(*ndev_priv), adev->qi.ndev_qnum);
	if (IS_ERR_OR_NULL(ndev)) {
		ys_dev_err("Failed to allocate memory");
		return NULL;
	}

	/* reserved max hw header */
	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		ndev->needed_headroom = 32;

	adev->adev_priv = (void *)ndev;

	/* pf ndev port range:0x000-0x00f
	 * pf rep   port range:0x010-0x0ff
	 * pf sf  port range:0x100-0xfff
	 */
	switch (adev->adev_type) {
	case AUX_TYPE_ETH:
		ndev->dev_port = YS_ADEV_TYPE_ETH_BASE + adev->idx;
		SET_NETDEV_DEV(ndev, pdev_priv->dev);
		break;
	case AUX_TYPE_SF:
		ndev->dev_port = YS_ADEV_TYPE_SF_BASE + adev->idx;
		SET_NETDEV_DEV(ndev, &adev->auxdev.dev);
		break;
	case AUX_TYPE_REP:
		ndev->dev_port = YS_ADEV_TYPE_REP_BASE + adev->idx;
		SET_NETDEV_DEV(ndev, &adev->auxdev.dev);
		break;
	default:
		ys_dev_err("aux type err %d", adev->adev_type);
		goto fail;
	}

	ndev_priv = netdev_priv(ndev);
	memset(ndev_priv, 0, sizeof(*ndev_priv));

	spin_lock_init(&ndev_priv->statistics_lock);
	mutex_init(&ndev_priv->state_lock);
	mutex_init(&ndev_priv->open_lock);
	spin_lock_init(&ndev_priv->mac_tbl_lock);
	INIT_LIST_HEAD(&ndev_priv->cvlan_list);
	INIT_LIST_HEAD(&ndev_priv->svlan_list);

	ndev_priv->ndev = ndev;
	ndev_priv->pdev = pdev_priv->pdev;
	ndev_priv->qi.qbase = adev->qi.qbase;
	ndev_priv->qi.ndev_qnum = adev->qi.ndev_qnum;
	ndev_priv->qi.qset = adev->qi.qset;
	ndev_priv->adev_type = adev->adev_type;
	if (ndev_priv->adev_type == AUX_TYPE_REP) {
		switch (adev->idx) {
		case YS_REP_ADEV_IDX_UPLINK:
			ndev_priv->rep_type = YS_REP_TYPE_UPLINK;
			break;
		case YS_REP_ADEV_IDX_PF:
			ndev_priv->rep_type = YS_REP_TYPE_PF;
			break;
		default:
			ndev_priv->rep_type = YS_REP_TYPE_VF;
		}
	}

	ndev_priv->rx_napi_list = kcalloc(ndev_priv->qi.ndev_qnum,
					  sizeof(struct ys_napi), GFP_KERNEL);

	if (!ndev_priv->rx_napi_list)
		goto fail;

	ndev_priv->tx_napi_list = kcalloc(ndev_priv->qi.ndev_qnum,
					  sizeof(struct ys_napi), GFP_KERNEL);

	if (!ndev_priv->tx_napi_list)
		goto fail;

	ndev->mtu = YS_MTU;
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = YS_MAX_MTU;

	if (!IS_ERR_OR_NULL(pdev_priv->pdev_manager->doe_ops)) {
		ndev->max_mtu = YS_NP_MAX_MTU;
	}

	ret = ys_ethtool_hw_init(ndev);
	if (ret) {
		ys_dev_err("ethtool hw init failed on port %d", adev->idx);
		goto fail;
	}

	ret = ys_ndev_hw_init(ndev);
	if (ret) {
		ys_dev_err("netdevice hw init failed on port %d", adev->idx);
		goto fail;
	}

	ret = ys_ndev_debug_init(ndev);
	if (ret) {
		ys_dev_err("netdevice debug init failed on port %d", adev->idx);
		goto fail;
	}

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_init)) {
		ret = pdev_priv->ops->hw_adp_init(ndev);
		if (ret) {
			ys_dev_err("netdev init failed on port %d", adev->idx);
			goto fail;
		}
	} else {
		ys_dev_err("netdev init failed on port %d", adev->idx);
		goto fail;
	}

	/* get mac from eeprom */
	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_get_mac))
		pdev_priv->ops->hw_adp_get_mac(ndev);

	/* if hw set failed, no hw set func, or invalid MAC address */
	if (!is_valid_ether_addr(ndev->dev_addr)) {
		ys_dev_info("using random MAC");
		ndev->addr_len = ETH_ALEN;
		eth_hw_addr_random(ndev);
	}

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_init_hw_features))
		ndev_priv->ys_ndev_hw->ys_init_hw_features(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_extra_init_hw_features))
		ndev_priv->ys_ndev_hw->ys_extra_init_hw_features(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_get_hash_mode))
		ndev_priv->ys_ndev_hw->ys_get_hash_mode(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_cfg)) {
		/* pf uplink */
		if (pdev_priv->dpu_mode == MODE_DPU_SOC)
			ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, LAN_SOC_UPLINK_VFNUM);
		else
			ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, 0);
	}

	ndev->netdev_ops = &ys_ndev_ops;
	ndev->ethtool_ops = &ys_ethtool_ops;
	ndev->udp_tunnel_nic_info = &ys_udp_tunnels;
	netif_carrier_off(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw->enable_mac))
		ndev_priv->ys_eth_hw->enable_mac(ndev);

	if ((IS_ERR_OR_NULL(pdev_priv->ops->ndev_has_mac_link_status) ||
	     (!IS_ERR_OR_NULL(pdev_priv->ops->ndev_has_mac_link_status) &&
	      pdev_priv->ops->ndev_has_mac_link_status(ndev))) &&
	    pdev_priv->nic_type->mac_type &&
	    !ndev_priv->mac_intr_en) {
		timer_setup(&ndev_priv->link_timer, ys_link_timer_callback, 0);
		mod_timer(&ndev_priv->link_timer, jiffies + HZ);
	}

	ret = register_netdev(ndev);
	if (ret) {
		ys_dev_err("register_netdev fail");
		goto fail;
	}

	adev->ifindex = ndev->ifindex;

	/* in case of unknown state of netdevice */
	netif_carrier_off(ndev);
	ys_queue_update_info(ndev, false, 0);

	/* create ndev sysfs */
	ys_ndev_create_sysfs_group(ndev);

	ys_net_info("register_netdev success %s", ndev->name);

	return ndev;

fail:
	ys_ndev_destroy(ndev);
	free_netdev(ndev);
	ndev = NULL;
	adev->adev_priv = NULL;
	return ndev;
}

static ssize_t ys_aux_sf_num_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct auxiliary_device *auxdev =
		container_of(dev, struct auxiliary_device, dev);
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);

	return sprintf(buf, "%d", adev->idx);
}

static ssize_t ys_aux_sf_info_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct auxiliary_device *auxdev =
		container_of(dev, struct auxiliary_device, dev);
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct pci_dev *pdev = adev->pdev;

	return sprintf(buf, "%02x:%02x.%x %d %d\n",
		       pdev->bus->number,
		       PCI_SLOT(pdev->devfn),
		       PCI_FUNC(pdev->devfn),
		       adev->idx, adev->ifindex);
}

static struct device_attribute sf_nodes[] = {
	__ATTR(sfnum, 0444, ys_aux_sf_num_show, NULL),
	__ATTR(sfinfo, 0444, ys_aux_sf_info_show, NULL),
};

int ys_aux_sf_probe(struct auxiliary_device *auxdev,
		    const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	struct ys_ndev_priv *ndev_priv = NULL;
	struct net_device *ndev = NULL;
	int attrs_num;
	int ret;

	ys_info("sf[%d] probe with qbase %d qnum %d\n", adev->idx,
		adev->qi.qbase, adev->qi.ndev_qnum);
	ndev = ys_ndev_create(pdev_priv, adev);
	if (IS_ERR_OR_NULL(ndev))
		goto sf_fail;

	ndev_priv = netdev_priv(ndev);
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_cfg)) {
		if (pdev_priv->dpu_mode == MODE_LEGACY) {
			ret = ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, 0);
			if (ret)
				goto sf_fail;
		}
	}

	attrs_num = ARRAY_SIZE(sf_nodes);
	ret = ys_sysfs_create_group(list, SYSFS_SF, 0, &auxdev->dev.kobj,
				    sf_nodes, attrs_num, NULL);
	if (ret)
		goto sf_fail;

	ys_dev_info("sf[%d] has been probed", adev->idx);

	return 0;

sf_fail:
	ys_aux_sf_remove(auxdev);
	return -ENOMEM;
}

void ys_aux_sf_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	struct ys_ndev_priv *ndev_priv = NULL;
	struct net_device *ndev = NULL;

	ys_sysfs_remove_group(list, SYSFS_SF, 0, &auxdev->dev.kobj);

	ndev = (struct net_device *)adev->adev_priv;
	if (!IS_ERR_OR_NULL(ndev)) {
		ndev_priv = netdev_priv(ndev);
		mutex_lock(&ndev_priv->open_lock);
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_delete_cfg))
			ndev_priv->ys_ndev_hw->ys_delete_cfg(ndev, 0);
		ys_ndev_destroy(ndev_priv->ndev);
		free_netdev(ndev_priv->ndev);
		ndev_priv->ndev = NULL;
		adev->adev_priv = NULL;
		mutex_unlock(&ndev_priv->open_lock);
	}

	ys_dev_info("sf[%d] has been removed", adev->idx);
}

int ys_aux_rep_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_ndev_priv *ndev_priv = NULL;
	struct net_device *ndev = NULL;
	int ret;

	ys_info("rep[%d] probe with qbase %d qnum %d qset %u\n", adev->idx,
		adev->qi.qbase, adev->qi.ndev_qnum, adev->qi.qset);
	ndev = ys_ndev_create(pdev_priv, adev);
	if (IS_ERR_OR_NULL(ndev))
		goto rep_fail;

	ndev_priv = netdev_priv(ndev);
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_cfg)) {
		/* pf uplink */
		if (pdev_priv->dpu_mode == MODE_DPU_SOC) {
			ret = ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, adev->idx);
			if (ret)
				goto rep_fail;
		}
		if (pdev_priv->dpu_mode == MODE_SMART_NIC &&
		    pdev_priv->nic_type->lan_type == LAN_TYPE_K2U) {
			ret = ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, adev->idx);
			if (ret)
				goto rep_fail;
		}
	}
	return 0;

rep_fail:
	ys_aux_rep_remove(auxdev);
	return -ENOMEM;
}

void ys_aux_rep_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_ndev_priv *ndev_priv = NULL;
	struct net_device *ndev = NULL;

	ndev = (struct net_device *)adev->adev_priv;
	if (!IS_ERR_OR_NULL(ndev)) {
		ndev_priv = netdev_priv(ndev);
		mutex_lock(&ndev_priv->open_lock);
		ys_ndev_destroy(ndev_priv->ndev);
		free_netdev(ndev_priv->ndev);
		mutex_unlock(&ndev_priv->open_lock);
	}
}

int ys_aux_eth_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct net_device *ndev = NULL;

	ndev = ys_ndev_create(pdev_priv, adev);
	if (IS_ERR_OR_NULL(ndev))
		goto eth_fail;

	return 0;

eth_fail:
	ys_aux_eth_remove(auxdev);
	return -ENOMEM;
}

void ys_aux_eth_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_ndev_priv *ndev_priv = NULL;
	struct net_device *ndev = NULL;

	ndev = (struct net_device *)adev->adev_priv;
	if (!IS_ERR_OR_NULL(ndev)) {
		ndev_priv = netdev_priv(ndev);
		mutex_lock(&ndev_priv->open_lock);
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_delete_cfg))
			ndev_priv->ys_ndev_hw->ys_delete_cfg(ndev, 0);

		ys_ndev_destroy(ndev_priv->ndev);
		free_netdev(ndev_priv->ndev);
		ndev_priv->ndev = NULL;
		adev->adev_priv = NULL;
		mutex_unlock(&ndev_priv->open_lock);
	}
}
