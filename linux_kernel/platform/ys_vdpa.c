// SPDX-License-Identifier: GPL-2.0

#include "ys_pdev.h"
#include "ys_vdpa.h"

int ys_aux_vdpa_probe(struct auxiliary_device *auxdev,
		      const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);

	if (pdev_priv->dpu_mode != MODE_DPU_HOST && pdev_priv->dpu_mode != MODE_SMART_NIC)
		return 0;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_vdpa_init))
		adev->adev_priv =
			pdev_priv->ops->hw_adp_vdpa_init(pdev_priv->pdev);

	return 0;
}

void ys_aux_vdpa_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_vdpa_uninit))
		pdev_priv->ops->hw_adp_vdpa_uninit(pdev_priv->pdev);
}
