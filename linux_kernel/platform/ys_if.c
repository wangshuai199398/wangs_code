#include <net/devlink.h>
#include <linux/debugfs.h>

#include "ys_if.h"

#include "ys_devlink.h"
#include "ys_pdev.h"
#include "ys_platform.h"
#include "ys_debug.h"

//extern struct dentry *ys_debugfs_root;

struct dentry *ys_debugfs_root;
EXPORT_SYMBOL(ys_debugfs_root);

void ys_debugfs_init(void)
{
	ys_debugfs_root = debugfs_create_dir("yusur", NULL);
	if (IS_ERR(ys_debugfs_root))
		ys_err("Failed to create debugfs root directory");
}

void ys_debugfs_uninit(void)
{
	debugfs_remove(ys_debugfs_root);
}


static const struct devlink_ops ys_devlink_ops = {
	.eswitch_mode_get = ys_devlink_eswitch_mode_get,
};

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

struct devlink *ys_devlink_alloc(struct device *dev)
{
	return devlink_alloc(&ys_devlink_ops, sizeof(struct ys_pdev_priv), dev);
}





