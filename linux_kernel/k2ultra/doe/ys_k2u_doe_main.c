// SPDX-License-Identifier: GPL-2.0
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/rtc.h>

#include "ys_k2u_doe_core.h"
#include "ys_k2u_doe_mm.h"

bool smart_nic;
module_param_named(smart_nic, smart_nic, bool, 0444);
MODULE_PARM_DESC(smart_nic, "driver for smart_nic");

bool dpu_soc;
module_param_named(dpu_soc, dpu_soc, bool, 0444);
MODULE_PARM_DESC(dpu_soc, "driver for dpu_soc");

bool dpu_host;
module_param_named(dpu_host, dpu_host, bool, 0444);
MODULE_PARM_DESC(dpu_host, "driver for dpu_host");

const struct ys_pdev_hw ys_k2u_doe_type = {
	.irq_flag = PCI_IRQ_MSIX | PCI_IRQ_MSI,
	.irq_sum = 2,
	.pdev_type = YS_PDEV_TYPE_DOE,
	.bar_status = { 0x00 },
	.func_name = YS_DEV_NAME("doe"),
	.hw_pdev_init = ys_k2u_doe_pdev_init,
	.hw_pdev_uninit = ys_k2u_doe_pdev_uninit,
	.hw_pdev_fix_mode = ys_k2u_doe_pdev_fix_mode,
	.hw_pdev_unfix_mode = ys_k2u_doe_pdev_unfix_mode
};

#define YS_DOE_DEVICE(device_id)                               \
	{                                                           \
		PCI_DEVICE(PCI_YS_VENDOR_ID, device_id),            \
			.driver_data = (unsigned long)&ys_k2u_doe_type \
	}

static const struct pci_device_id ys_k2u_doe_pdev_ids[] = {
	YS_DOE_DEVICE(0x1001),
	YS_DOE_DEVICE(0x1011),
	{ PCI_DEVICE(0x10ee, 0x9338),
		.driver_data = (unsigned long)&ys_k2u_doe_type },
	{ 0 /* end */ }
};

static struct ys_pci_driver ys_k2u_doe_driver = {
	.aux_drv_support = 0,
	.pdrv = {
		.name = YS_DEV_NAME("doe"),
		.id_table = ys_k2u_doe_pdev_ids,
		.probe = ys_pdev_probe,
		.remove = ys_pdev_remove,
	},
};

static int __init ys_k2u_doe_init(void)
{
	int ret;

	ret = ys_init(&ys_k2u_doe_driver);
	if (ret)
		goto err_ys_init;

	return 0;

err_ys_init:

	return ret;
}

static void __exit ys_k2u_doe_exit(void)
{
	ys_exit(&ys_k2u_doe_driver);
}

module_init(ys_k2u_doe_init);
module_exit(ys_k2u_doe_exit);

MODULE_DESCRIPTION("YUSUR DOE PCI Express Device Driver");
MODULE_AUTHOR("YUSUR Technology Co., Ltd.");
MODULE_LICENSE("GPL");
MODULE_VERSION(YS_GIT_VERSION);
