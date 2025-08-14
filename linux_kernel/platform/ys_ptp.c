// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/etherdevice.h>

#include "ys_pdev.h"
#include "ys_ptp.h"

int ys_aux_ptp_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_ptp *ptp = NULL;
	int ret;

	if (pdev_priv->nic_type->is_vf) {
		ys_dev_info("VF does not support PTP");
		goto ptp_fail;
	}

	ptp = kzalloc(sizeof(*ptp), GFP_KERNEL);
	if (IS_ERR_OR_NULL(ptp))
		goto ptp_fail;

	adev->adev_priv = (void *)ptp;
	/* store ptp in pdev_priv */
	pdev_priv->ptp = ptp;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_ptp_init)) {
		ret = pdev_priv->ops->hw_adp_ptp_init(pdev_priv->pdev);
		if (ret) {
			ys_dev_err("hw_adp_ptp_init failed, ret=%d", ret);
			goto ptp_fail;
		}
	} else {
		ys_dev_err("hw_adp_ptp_init is NULL");
		goto ptp_fail;
	}

	ptp->pdev = adev->pdev;
	ptp->clock_info.owner = THIS_MODULE;
	ptp->pclock = ptp_clock_register(&ptp->clock_info, pdev_priv->dev);
	if (IS_ERR(ptp->pclock)) {
		ptp->pclock = NULL;
		ys_dev_err("Register PTP hardware clock error");
		goto ptp_fail;
	}

	return 0;

ptp_fail:
	ys_aux_ptp_remove(auxdev);

	return -ENOMEM;
}

void ys_aux_ptp_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_ptp *ptp = (struct ys_ptp *)adev->adev_priv;

	if (pdev_priv->nic_type->is_vf)
		return;

	if (!IS_ERR_OR_NULL(ptp)) {
		if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_ptp_uninit))
			pdev_priv->ops->hw_adp_ptp_uninit(pdev_priv->pdev);

		if (ptp->pclock) {
			ptp_clock_unregister(ptp->pclock);
			ptp->pclock = NULL;
		}
		kfree(ptp);
	}
}
