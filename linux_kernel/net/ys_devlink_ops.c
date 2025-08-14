// SPDX-License-Identifier: GPL-2.0

#include "ys_platform.h"
#include "ys_utils.h"

#ifdef YS_HAVE_DEVLINK_PARAM_DRIVER

int ys_devlink_get_switch_mode_init_value(struct devlink *devlink)
{
	struct ys_pdev_priv *pdev_priv = devlink_priv(devlink);

	if (!IS_ERR_OR_NULL(pdev_priv->devlink_info.devlink_hw_ops->get_switch_mode))
		return pdev_priv->devlink_info.devlink_hw_ops->get_switch_mode(pdev_priv->pdev);

	return -EINVAL;
}

int ys_devlink_switch_mode_get(struct devlink *devlink, u32 id,
			       struct devlink_param_gset_ctx *ctx)
{
	struct ys_pdev_priv *pdev_priv = devlink_priv(devlink);
	int switch_mode;

	switch_mode = pdev_priv->devlink_info.switch_mode;
	if (switch_mode == MODE_DPU_HOST)
		strscpy(ctx->val.vstr, "dpu", sizeof(ctx->val.vstr));
	else if (switch_mode == MODE_LEGACY)
		strscpy(ctx->val.vstr, "legacy", sizeof(ctx->val.vstr));
	else if (switch_mode == MODE_SMART_NIC)
		strscpy(ctx->val.vstr, "smartnic", sizeof(ctx->val.vstr));
	else
		return -EINVAL;

	return 0;
}

int ys_devlink_switch_mode_set(struct devlink *devlink, u32 id,
			       struct devlink_param_gset_ctx *ctx)
{
	struct ys_pdev_priv *pdev_priv = devlink_priv(devlink);
	enum ys_dpu_mode switch_mode;

	if (!strcmp(ctx->val.vstr, "dpu"))
		switch_mode = MODE_DPU_HOST;
	else if (!strcmp(ctx->val.vstr, "legacy"))
		switch_mode = MODE_LEGACY;
	else if (!strcmp(ctx->val.vstr, "smartnic"))
		switch_mode = MODE_SMART_NIC;
	else
		return -EINVAL;

	pdev_priv->devlink_info.switch_mode = switch_mode;
	if (!IS_ERR_OR_NULL(pdev_priv->devlink_info.devlink_hw_ops->set_switch_mode))
		pdev_priv->devlink_info.devlink_hw_ops->set_switch_mode(pdev_priv->pdev,
									switch_mode);

	return 0;
}

#ifdef YS_HAVE_DEVLINK_VALIDATE
int ys_devlink_switch_mode_validate(struct devlink *devlink, u32 id,
				    union devlink_param_value val)
{
	char *value = val.vstr;

	if (!strcmp(value, "dpu") || !strcmp(value, "legacy") ||
	    !strcmp(value, "smartnic"))
		return 0;
	return 0;
}
#else
int ys_devlink_switch_mode_validate(struct devlink *devlink, u32 id,
				    union devlink_param_value val,
				    struct netlink_ext_ack *extack)
{
	char *value = val.vstr;

	if (!strcmp(value, "dpu") || !strcmp(value, "legacy") ||
	    !strcmp(value, "smartnic"))
		return 0;

	NL_SET_ERR_MSG_MOD(extack,
			   "Bad parameter: supported values are [\"dpu\", \"smartnic\", \"legacy\"]");
	return -EINVAL;
}
#endif /* YS_HAVE_DEVLINK_VALIDATE */
#endif /* YS_HAVE_DEVLINK_PARAM_DRIVER */
