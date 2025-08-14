// SPDX-License-Identifier: GPL-2.0

#include "ys_pdev.h"
#include "ys_plat_np.h"

int ys_aux_np_probe(struct auxiliary_device *auxdev,
		    const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	int ret = 0;

	if (pdev_priv->nic_type->np_type &&
	    !IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_np_init)) {
		ret = pdev_priv->ops->hw_adp_np_init(auxdev);
	}
	return ret;
}

void ys_aux_np_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);

	if (pdev_priv->nic_type->np_type &&
	    !IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_np_uninit))
		pdev_priv->ops->hw_adp_np_uninit(auxdev);
}
