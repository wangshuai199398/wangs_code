// SPDX-License-Identifier: GPL-2.0

#include "ys_platform.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"
#include "ys_mac.h"

bool ys_k2u_ndev_has_mac_link_status(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	if (IS_ERR_OR_NULL(ndev))
		return false;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	/* which ndev are affected by mac link status ?
	 * legacy mode: pf, vf, sf
	 * dpu host: none
	 * dpu soc: uplink, nvme-net
	 * smartnic: uplink
	 */
	/* FIXME: vf get status now through interrupts sent by PF */
	if (pdev_priv->dpu_mode == MODE_LEGACY)
		return true;

	if (pdev_priv->dpu_mode == MODE_DPU_SOC &&
	    ((ndev_priv->adev_type & AUX_TYPE_ETH) ||
	     ndev->dev_port == YS_ADEV_TYPE_SF_BASE))
		return true;

	if (pdev_priv->dpu_mode == MODE_SMART_NIC &&
	    ndev->dev_port == (YS_ADEV_TYPE_REP_BASE + 0x200))
		return true;
	return false;
}
EXPORT_SYMBOL(ys_k2u_ndev_has_mac_link_status);

int ys_aux_mac_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_mac *mac;
	int ret = 0;

	mac = kzalloc(sizeof(*mac), GFP_KERNEL);
	if (IS_ERR_OR_NULL(mac)) {
		ys_dev_err("alloc memory failed");
		return -ENOMEM;
	}

	adev->adev_priv = (void *)mac;
	mac->adev = adev;
	mac->irq_vector = -1;

	switch (pdev_priv->nic_type->mac_type) {
#ifdef CONFIG_YSMOD_CMAC
	case MAC_TYPE_CMAC:
		pdev_priv->ops->mac_adp_eth_init = ys_cmac_eth_init;
		pdev_priv->ops->mac_adp_ndev_init = ys_cmac_ndev_init;
		break;
#endif
	case MAC_TYPE_UMAC:
		//pdev_priv->ops->mac_adp_eth_init = ys_umac_eth_init;
		pdev_priv->ops->mac_adp_ndev_init = ys_umac_ndev_init;
		pdev_priv->ops->mac_adp_ndev_uninit = ys_umac_ndev_uninit;
		ret = ys_umac_init(auxdev);

		adev->state_statistics.flag = ET_FLAG_REGISTER;
		adev->state_statistics.et_get_stats = ys_umac_get_stats;
		adev->state_statistics.et_get_stats_strings = ys_umac_get_stats_strings;
		adev->state_statistics.et_get_stats_count = ys_umac_get_stats_count;
		break;
	case MAC_TYPE_XMAC:
		pdev_priv->ops->mac_adp_eth_init = ys_xmac_eth_init;
		pdev_priv->ops->mac_adp_ndev_init = ys_xmac_ndev_init;
		pdev_priv->ops->mac_adp_ndev_uninit = ys_xmac_ndev_uninit;
		ret = ys_xmac_init(auxdev);

		adev->state_statistics.flag = ET_FLAG_REGISTER;
		adev->state_statistics.et_get_stats = ys_xmac_get_stats;
		adev->state_statistics.et_get_stats_strings = ys_xmac_get_stats_strings;
		adev->state_statistics.et_get_stats_count = ys_xmac_get_stats_count;
		break;
	default:
		ys_dev_err("mac type err %d\n", pdev_priv->nic_type->mac_type);
		goto mac_fail;
	}

	return ret;

mac_fail:
	ys_aux_mac_remove(auxdev);

	return -ENOMEM;
}

void ys_aux_mac_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_mac *mac = adev->adev_priv;

	if (pdev_priv->nic_type->mac_type == MAC_TYPE_UMAC)
		ys_umac_uninit(auxdev);
	else if (pdev_priv->nic_type->mac_type == MAC_TYPE_XMAC)
		ys_xmac_uninit(auxdev);

	pdev_priv->ops->mac_adp_eth_init = NULL;
	pdev_priv->ops->mac_adp_ndev_init = NULL;

	if (!IS_ERR_OR_NULL(mac)) {
		kfree(mac);
		adev->adev_priv = NULL;
	}
}
