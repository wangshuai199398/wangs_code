// SPDX-License-Identifier: GPL-2.0
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/rtc.h>

#include "ys_platform.h"
#include "ys_adapter.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"

#include "edma/ys_k2u_new_core.h"

bool smart_nic;
module_param_named(smart_nic, smart_nic, bool, 0444);
MODULE_PARM_DESC(smart_nic, "driver for smart_nic");

bool dpu_soc;
module_param_named(dpu_soc, dpu_soc, bool, 0444);
MODULE_PARM_DESC(dpu_soc, "driver for dpu_soc");

bool dpu_host;
module_param_named(dpu_host, dpu_host, bool, 0444);
MODULE_PARM_DESC(dpu_host, "driver for dpu_host");

static int mac_type;
module_param_named(mac_type, mac_type, int, 0444);
MODULE_PARM_DESC(mac_type, "mac_type: 3 = umac, 5 = xmac");

static struct ys_pdev_hw k2u_pf_type = {
	.irq_flag = PCI_IRQ_MSIX | PCI_IRQ_MSI,
	.ndev_sum = 1,
	.mbox_enable = true,
	.irq_sum = 32,
	.ndev_qcount = 1,
	.bar_status = { 0x00 },
	.func_name = YS_DEV_NAME("k2u_pf"),
	.is_vf = false,
	.doe_enable = true,
	.lan_type = LAN_TYPE_K2U,
	.np_type = NP_TYPE_K2U,
	.hw_pdev_init = ys_k2u_pdev_init,
	.hw_pdev_uninit = ys_k2u_pdev_uninit,
	.hw_pdev_fix_mode = ys_k2u_pdev_fix_mode,
	.hw_pdev_unfix_mode = ys_k2u_pdev_unfix_mode,
};

static struct ys_pdev_hw k2u_vf_type = {
	.irq_flag = PCI_IRQ_MSIX | PCI_IRQ_MSI,
	.ndev_sum = 1,
	.mbox_enable = true,
	.irq_sum = 24,
	.ndev_qcount = 1,
	.bar_status = { 0x00 },
	.func_name = YS_DEV_NAME("k2u_vf"),
	.is_vf = true,
	.doe_enable = false,
	.lan_type = LAN_TYPE_K2U,
	.hw_pdev_init = ys_k2u_pdev_init,
	.hw_pdev_uninit = ys_k2u_pdev_uninit,
};

#define YS_K2U_NIC_DEVICE_PF(device_id)                            \
	{                                                         \
		PCI_DEVICE(PCI_YS_VENDOR_ID, device_id),          \
		.driver_data = (unsigned long)&k2u_pf_type \
	}

#define YS_K2U_NIC_DEVICE_VF(device_id)                            \
	{                                                         \
		PCI_DEVICE(PCI_YS_VENDOR_ID, device_id),          \
		.driver_data = (unsigned long)&k2u_vf_type \
	}

#define YS_K2U_NIC_DEVICE_MBOX(device_id)                            \
	{                                                         \
		PCI_DEVICE(0x10ee, device_id),          \
		.driver_data = (unsigned long)&k2u_pf_type \
	}

static const struct pci_device_id ys_k2u_pdev_ids[] = {
	YS_K2U_NIC_DEVICE_PF(0x1001),
	YS_K2U_NIC_DEVICE_VF(0x1101),
	YS_K2U_NIC_DEVICE_MBOX(0x9038),
	YS_K2U_NIC_DEVICE_MBOX(0x9138),

	YS_K2U_NIC_DEVICE_PF(0x1011),
	YS_K2U_NIC_DEVICE_VF(0x1012),

	YS_K2U_NIC_DEVICE_PF(0x4011),
	YS_K2U_NIC_DEVICE_VF(0x4012),

	YS_K2U_NIC_DEVICE_PF(0x5011),
	YS_K2U_NIC_DEVICE_VF(0x5012),
	{ 0 /* end */ }
};

static struct ys_pci_driver ys_k2u_driver = {
	.aux_drv_support = AUX_TYPE_ETH |
			   AUX_TYPE_REP |
			   AUX_TYPE_LAN |
			   AUX_TYPE_DOE |
			   AUX_TYPE_NP |
			   AUX_TYPE_MAC |
			   AUX_TYPE_MBOX,
	.pdrv = {
		.name = YS_DEV_NAME("unic3"),
		.id_table = ys_k2u_pdev_ids,
		.probe = ys_pdev_probe,
		.remove = ys_pdev_remove,
		.sriov_configure = ys_sriov_configure,
	},
};

static int __init ys_k2u_init(void)
{
	if (mac_type == MAC_TYPE_UMAC || mac_type == MAC_TYPE_XMAC) {
		k2u_pf_type.mac_type = (u8)mac_type;
		ys_debug("k2u init mac_type %d ok\n", mac_type);
	} else {
		ys_debug("k2u init mac_type %d error\n", mac_type);
		return -1;
	}
	pr_debug("wangshuai");
	return ys_init(&ys_k2u_driver);
}

static void __exit ys_k2u_exit(void)
{
	ys_exit(&ys_k2u_driver);
}

module_init(ys_k2u_init);
module_exit(ys_k2u_exit);

MODULE_DESCRIPTION("Yusur KPU K2PRO+ PCI Express Device Driver");
MODULE_AUTHOR("YUSUR Technology Co., Ltd.");
MODULE_LICENSE("GPL");
MODULE_VERSION(YS_GIT_VERSION);

