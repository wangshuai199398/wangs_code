// SPDX-License-Identifier: GPL-2.0

#include "ys_devlink.h"
#include "ys_pdev.h"
#include "ys_ndev.h"

#include "ys_reg_ops.h"
#include "ys_utils.h"


#include "../net/ys_devlink_ops.h"

#include "ysif_linux.h"

static const struct devlink_param ys_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(YS_DEVLINK_PARAM_ID_SWITCH_MODE, "switch_mode",
			     DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME) |
			     BIT(DEVLINK_PARAM_CMODE_DRIVERINIT),
			     ys_devlink_switch_mode_get,
			     ys_devlink_switch_mode_set,
			     ys_devlink_switch_mode_validate),
};

static void ys_devlink_set_params_init_values(struct devlink *devlink)
{
	struct ys_pdev_priv *pdev_priv;
	union devlink_param_value value;
	int mode = 0;

	pdev_priv = devlink_priv(devlink);
	mode = ys_devlink_get_switch_mode_init_value(devlink);
	switch (mode) {
	case MODE_DPU_HOST:
		strscpy(value.vstr, "dpu", sizeof(value.vstr));
		break;
	case MODE_LEGACY:
		strscpy(value.vstr, "legacy", sizeof(value.vstr));
		break;
	case MODE_SMART_NIC:
		strscpy(value.vstr, "smartnic", sizeof(value.vstr));
		break;
	default:
		strscpy(value.vstr, "dpu", sizeof(value.vstr));
		mode = MODE_LEGACY;
		break;
	}
	pdev_priv->devlink_info.switch_mode = mode;
	devlink_param_driverinit_value_set(devlink, YS_DEVLINK_PARAM_ID_SWITCH_MODE, value);
}

static int ys_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct ys_pdev_priv *pdev_priv;
	int dpu_mode;

	pdev_priv = devlink_priv(devlink);
	dpu_mode = pdev_priv->dpu_mode;
	switch (dpu_mode) {
	case MODE_LEGACY:
		*mode = DEVLINK_ESWITCH_MODE_LEGACY;
		break;
	case MODE_SMART_NIC:
		*mode = DEVLINK_ESWITCH_MODE_SWITCHDEV;
		break;
	default:
		/* MODE_DPU_HOST/MODE_DPU_SOC */
		return -EPROTONOSUPPORT;
	}

	return 0;
}

static const struct devlink_ops ys_devlink_ops = {
	.eswitch_mode_get = ys_devlink_eswitch_mode_get,
};

struct devlink *ys_devlink_alloc(struct device *dev)
{
	struct ysif_ops *ops = ysif_get_ops();
	return ops->devlink_alloc(&ys_devlink_ops, sizeof(struct ys_pdev_priv), dev);
}

void ys_devlink_release(struct devlink *devlink)
{
	if (devlink)
		devlink_free(devlink);
}

static int ys_devlink_params_register(struct devlink *devlink)
{
	int err = 0;

	err = devlink_params_register(devlink, ys_devlink_params,
				      ARRAY_SIZE(ys_devlink_params));
	if (err)
		return err;
	ys_devlink_set_params_init_values(devlink);
	return 0;
}

static void ys_devlink_params_unregister(struct devlink *devlink)
{
	devlink_params_unregister(devlink, ys_devlink_params,
				  ARRAY_SIZE(ys_devlink_params));
}

int ys_devlink_init(struct pci_dev *pdev)
{
	struct ys_devlink_hw_ops *devlink_hw_ops;
	struct ys_pdev_priv *pdev_priv;
	struct devlink *devlink;
	int err = 0;

	pdev_priv = pci_get_drvdata(pdev);
	devlink = priv_to_devlink(pdev_priv);

	if (pdev_priv->dpu_mode == MODE_LEGACY)
		return 0;

	devlink_hw_ops = kzalloc(sizeof(*devlink_hw_ops), GFP_KERNEL);
	if (!devlink_hw_ops)
		return -ENOMEM;

	pdev_priv->devlink_info.devlink_hw_ops = devlink_hw_ops;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->lan_adp_devlink_init))
		pdev_priv->ops->lan_adp_devlink_init(pdev);

	pdev_priv->devlink_info.devlink_registered = 0;

	devlink_register(devlink);
	err = ys_devlink_params_register(devlink);
	if (err)
		return err;

	pdev_priv->devlink_info.devlink_registered = 1;
	return 0;
}

void ys_devlink_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct devlink *devlink = priv_to_devlink(pdev_priv);

	if (pdev_priv->dpu_mode == MODE_LEGACY)
		return;

	kfree(pdev_priv->devlink_info.devlink_hw_ops);
	if (pdev_priv->devlink_info.devlink_registered) {
		devlink_unregister(devlink);
		ys_devlink_params_unregister(devlink);
	}
}
