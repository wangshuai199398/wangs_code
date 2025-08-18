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

void ys_pdev_manager_init(void)
{
	static bool init;

	if (init)
		return;

	bitmap_zero(g_ys_pdev_manager.eth_dev_id, YS_DEV_MAX);
	bitmap_zero(g_ys_pdev_manager.sf_dev_id, YS_DEV_MAX);
	bitmap_zero(g_ys_pdev_manager.rep_dev_id, YS_DEV_MAX);

	bitmap_zero(g_ys_pdev_manager.i2c_dev_id, YS_PDEV_MAX);
	bitmap_zero(g_ys_pdev_manager.ptp_dev_id, YS_PDEV_MAX);
	bitmap_zero(g_ys_pdev_manager.lan_dev_id, YS_PDEV_MAX);
	bitmap_zero(g_ys_pdev_manager.mac_dev_id, YS_PDEV_MAX);
	bitmap_zero(g_ys_pdev_manager.mbox_dev_id, YS_PDEV_MAX);
	bitmap_zero(g_ys_pdev_manager.np_dev_id, YS_PDEV_MAX);
	bitmap_zero(g_ys_pdev_manager.pf_index, YS_PDEV_MAX);
	bitmap_zero(g_ys_pdev_manager.vdpa_dev_id, YS_PDEV_MAX);

	INIT_LIST_HEAD(&g_ys_pdev_manager.pdev_list);

	g_ys_pdev_manager.doe_ops = NULL;
	spin_lock_init(&g_ys_pdev_manager.doe_manager_lock);
	spin_lock_init(&g_ys_pdev_manager.doe_schedule_lock);
	INIT_LIST_HEAD(&g_ys_pdev_manager.doe_schedule_list);

	init = true;
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
	return devlink_alloc(&ys_devlink_ops, sizeof(struct ys_pdev_priv), dev);
}





