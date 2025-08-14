// SPDX-License-Identifier: GPL-2.0

#include "ys_pdev.h"
#include "ys_plat_doe.h"

int ys_aux_doe_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id)
{
	int ret;
	struct ys_adev *adev;
	struct ys_pdev_priv *pdev_priv;

	adev = container_of(auxdev, struct ys_adev, auxdev);
	pdev_priv = pci_get_drvdata(adev->pdev);

	if (pdev_priv->nic_type->pdev_type == YS_PDEV_TYPE_NDEV &&
	    !IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_doe_init)) {
		ret = pdev_priv->ops->hw_adp_doe_init(auxdev);
		if (ret)
			return ret;
	}

	if (IS_ERR_OR_NULL(g_ys_pdev_manager.doe_ops))
		g_ys_pdev_manager.doe_ops = adev->adev_extern_ops;

	return 0;
}

void ys_aux_doe_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev;
	struct ys_pdev_priv *pdev_priv;

	adev = container_of(auxdev, struct ys_adev, auxdev);
	pdev_priv = pci_get_drvdata(adev->pdev);

	if (pdev_priv->nic_type->pdev_type == YS_PDEV_TYPE_NDEV &&
	    !IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_doe_uninit))
		pdev_priv->ops->hw_adp_doe_uninit(auxdev);

	//g_ys_pdev_manager.doe_ops = NULL;
}
