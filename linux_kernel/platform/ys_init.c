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

static int check_compile_args(void)
{
	/* check compile PAGE_SIZE */
	if (PAGE_SIZE != YS_COMPILE_PAGE_SIZE) {
		ys_err("PAGE_SIZE(%ld) is not equal to YS_COMPILE_PAGE_SIZE(%d)\n",
		       PAGE_SIZE, YS_COMPILE_PAGE_SIZE);
		return -EINVAL;
	}

	return 0;
}

int ys_init(struct ys_pci_driver *ys_pdrv)
{
	int ret;

	ys_info("YUSUR Platform Driver %s Init\n", THIS_MODULE->name);

	ret = check_compile_args();
	if (ret)
		goto err_check_compile_args;

	ys_debugfs_init();

#ifndef CONFIG_YSARCH_PLAT
	ys_pdev_manager_init();

	ret = ys_aux_init(ys_pdrv->aux_drv_support);
	if (ret)
		goto err_aux_init;
#endif /* CONFIG_YSARCH_PLAT */

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
#ifndef CONFIG_YSARCH_PLAT
err_aux_init:
	ys_aux_uninit(ys_pdrv->aux_drv_support);
#endif /* CONFIG_YSARCH_PLAT */
err_check_compile_args:
	return ret;
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_init);
#endif /* CONFIG_YSARCH_PLAT */

void ys_exit(struct ys_pci_driver *ys_pdrv)
{
	ys_info("YUSUR Platform Driver %s Exit\n", THIS_MODULE->name);
	ysc_exit();
	ys_pdev_uninit(&ys_pdrv->pdrv);
#ifndef CONFIG_YSARCH_PLAT
	ys_aux_uninit(ys_pdrv->aux_drv_support);
#endif /* CONFIG_YSARCH_PLAT */
	ys_debugfs_uninit();
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_exit);
#endif /* CONFIG_YSARCH_PLAT */

#ifdef CONFIG_YSARCH_PLAT
static int __init ys_platform_init(void)
{
	ys_pdev_manager_init();
	return ys_aux_init(0xFFFF);
}

static void __exit ys_platform_exit(void)
{
	ys_aux_uninit(0xFFFF);
}

module_init(ys_platform_init);
module_exit(ys_platform_exit);

MODULE_DESCRIPTION("YUSUR Platform Driver");
MODULE_AUTHOR("YUSUR Technology Co., Ltd.");
MODULE_LICENSE("GPL");
#endif /* CONFIG_YSARCH_PLAT */
