// SPDX-License-Identifier: GPL-2.0

#include "ys_platform.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"
#include "ys_lan.h"

int ys_aux_lan_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	int ret = 0;

	switch (pdev_priv->nic_type->lan_type) {
#ifdef CONFIG_YSMOD_LAN_K2
	case LAN_TYPE_K2:
		ret = ys_k2lan_probe(auxdev);
		break;
#endif
#ifdef CONFIG_YSMOD_LAN_ESW
	case LAN_TYPE_ESW:
		ret = ys_esw_probe(auxdev);
		break;
#endif
#ifdef CONFIG_YSMOD_LAN_K2U
	case LAN_TYPE_K2U:
		ret = ys_k2ulan_probe(auxdev);
		break;
#endif
	default:
		ys_dev_err("lan type err %d\n", pdev_priv->nic_type->lan_type);
		goto lan_fail;
	}

	return ret;

lan_fail:
	ys_aux_lan_remove(auxdev);

	return -ENOMEM;
}

void ys_aux_lan_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);

	switch (pdev_priv->nic_type->lan_type) {
#ifdef CONFIG_YSMOD_LAN_K2
	case LAN_TYPE_K2:
		ys_k2lan_remove(auxdev);
		break;
#endif
#ifdef CONFIG_YSMOD_LAN_ESW
	case LAN_TYPE_ESW:
		ys_esw_remove(auxdev);
		break;
#endif
#ifdef CONFIG_YSMOD_LAN_K2U
	case LAN_TYPE_K2U:
		ys_k2ulan_remove(auxdev);
		break;
#endif
	default:
		ys_dev_err("lan type err %d\n", pdev_priv->nic_type->lan_type);
	}
}
