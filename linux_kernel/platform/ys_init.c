// SPDX-License-Identifier: GPL-2.0

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/rtc.h>

#include "ys_init.h"
#include "ys_auxiliary.h"
#include "ys_pdev.h"

#include "ys_debug.h"
#include "ys_utils.h"
#include "ysc_dev.h"
#include "ys_debugfs.h"

#include "ysif_linux.h"

int ys_init(struct ys_pci_driver *ys_pdrv)
{
	int ret;

	ys_info("YUSUR Platform Driver %s Init\n", THIS_MODULE->name);
	ysif_ops_init();
	ys_debugfs_init();

	ys_pdev_manager_init();

	ret = ys_aux_init(ys_pdrv->aux_drv_support);
	if (ret)
		goto err_aux_init;
	ret = ys_pdev_init(&ys_pdrv->pdrv);
	if (ret)
		goto err_pdev_init;

	ret = ysc_init();
	if (ret)
		goto err_ysc_init;

	return 0;

err_ysc_init:
err_pdev_init:
	ys_pdev_uninit(&ys_pdrv->pdrv);
err_aux_init:
	ys_aux_uninit(ys_pdrv->aux_drv_support);
	return ret;
}

void ys_exit(struct ys_pci_driver *ys_pdrv)
{
	ys_info("YUSUR Platform Driver %s Exit\n", THIS_MODULE->name);
	ysc_exit();
	ys_pdev_uninit(&ys_pdrv->pdrv);
	ys_aux_uninit(ys_pdrv->aux_drv_support);
	ys_debugfs_uninit();
}

