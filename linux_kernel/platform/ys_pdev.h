/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_PDEV_H_
#define __YS_PDEV_H_

#include <linux/miscdevice.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/types.h>

#include "ys_auxiliary.h"
#include "ys_i2c.h"
#include "ys_ptp.h"
#include "ys_sriov.h"
#include "ys_sysfs.h"
#include "ys_intr.h"
#include "ys_devlink.h"
#include "ys_queue.h"

#include "ys_adapter.h"
#include "ys_reg_ops.h"
#include "ys_utils.h"
#include "ys_debug.h"

#include "ysnic.h"

#define YS_DEV_NAME(name) YS_HW_STRING("ysk_", name)

#define YS_FUNC_NAME_LEN 32

#define YS_DEV_TYPE_PF 0x01
#define YS_DEV_TYPE_VF 0x10

#define PCI_YS_VENDOR_ID 0x1f47

#define YS_DEV_PTON_PARA_MAX_LEN 128

#define YS_DEV_MAX 8192
#define YS_PDEV_MAX 1024
#define YS_NDEV_MAX 8
#define YS_MAX_I2C 8

#define BAR4_NIC_INFO_ADDR          (0x200000)
#define SERIAL_NUM_LEN_MAX          (20)
#define PRODUCT_NUM_LEN_MAX         (20)
#define MODULE_INFO_LEN_MAX         (512)
#define MAC_NUM_MAX                 (8)

enum BAR { BAR0 = 0, BAR1, BAR2, BAR3, BAR4, BAR5, BAR_MAX };

/*
 * This enumeration type will be assigned to pdev_priv->hw_type according
 * to hardware requirements.
 * The enumeration values themselves do not hold any practical significance.
 * The purpose is to convert compile-time macros into variables at
 * the hardware layer, thereby reducing the use of macros.
 * When the hardware can read the hw_type from a register
 * this variable can be replaced with the register value.
 */

enum ys_pdev_hw_type {
	YS_HW_TYPE_K2 = 0,
	YS_HW_TYPE_K2PRO,
	YS_HW_TYPE_K2ULTRA,
	YS_HW_TYPE_K2ULTRA_CS,
	YS_HW_TYPE_2100P,
	YS_HW_TYPE_SWIFTN,
	YS_HW_TYPE_LDMA3,
	YS_HW_TYPE_SEC,
};

#define MAX_MISC_DEV_NAME_BYTES (16)

struct ys_pdev_manager {
	struct list_head pdev_list;

	struct ys_doe_ops *doe_ops;
	/* doe mac table operating lock */
	spinlock_t doe_manager_lock;
	struct list_head doe_schedule_list;
	/* doe schedule lock */
	spinlock_t doe_schedule_lock;

	unsigned long eth_dev_id[BITS_TO_LONGS(YS_DEV_MAX)];
	unsigned long sf_dev_id[BITS_TO_LONGS(YS_DEV_MAX)];
	unsigned long rep_dev_id[BITS_TO_LONGS(YS_DEV_MAX)];

	unsigned long i2c_dev_id[BITS_TO_LONGS(YS_PDEV_MAX)];
	unsigned long ptp_dev_id[BITS_TO_LONGS(YS_PDEV_MAX)];
	unsigned long lan_dev_id[BITS_TO_LONGS(YS_PDEV_MAX)];
	unsigned long mac_dev_id[BITS_TO_LONGS(YS_PDEV_MAX)];
	unsigned long mbox_dev_id[BITS_TO_LONGS(YS_PDEV_MAX)];
	unsigned long np_dev_id[BITS_TO_LONGS(YS_PDEV_MAX)];
	unsigned long pf_index[BITS_TO_LONGS(YS_PDEV_MAX)];
	unsigned long vdpa_dev_id[BITS_TO_LONGS(YS_PDEV_MAX)];
};

struct ys_pdev_umem {
	struct list_head list;
	struct ys_pdev_priv *pdev_priv;
	struct device *dev;
	u16 vf_num;
	u64 vaddr;
	u64 nr_pages;
	struct page **pages;
	struct scatterlist *sg_list;
};

struct hw_info {
	/* offset = 0 */
	struct nic_info {
		u32 mode;
		u8 serial_num[SERIAL_NUM_LEN_MAX];
		u8 product_num[PRODUCT_NUM_LEN_MAX];
		u32 port_type;
		u32 mac_num;
		u8 mac_array[MAC_NUM_MAX][8];
		u8 pad[12];	// 32-byte align
	} __packed nic_info;
	/* offset =  */
	struct ver_info {
		u32 m3_ver[4];		//m3_ver[0]-m3_ver[3]：major、minor、patch、resv
		u32 pxe_ver[4];	//pxe_ver[0]-pxe_ver[3]：major、minor、patch、resv
		u32 mcode_ver[4];	//mcode_ver[0]-mcode_ver[3]：major、minor、patch、resv
		u8 pad[16];			// 32-byte align
	} __packed ver_info;
	/* offset = */
	struct env_info {
		u8 mod_info[MODULE_INFO_LEN_MAX];
		u32 temperature_l;
		u32 temperature_h;
		u32 power_voltage;
		u32 power_current;
		u32 power_power;
		u8 pad[24];	// 32-byte align
	} __packed env_info;
} __packed;

struct ys_pdev_priv {
	struct device *dev;
	struct pci_dev *pdev;

	const struct ys_pdev_hw *nic_type;
	void __iomem *bar_addr[BAR_MAX];
	u64 bar_size[BAR_MAX];
	u64 bar_offset[BAR_MAX];
	u64 bar_pa[BAR_MAX];
	u8 index;
	u32 hw_ver;
	u32 hw_type;
	int ptp_mode;

	enum ys_dpu_mode dpu_mode;
	struct ys_irq_table irq_table;

	struct list_head cdev_list;
	/* user dma map resource manager */
	struct list_head umem_list;

	/* Logically, pf_id should not be in the platform abstraction layer.
	 * But for some hardware module, registers is designed without logic,
	 * hardware pf_id is necessary for platform and must be set by
	 * adapter driver.
	 *
	 * For example, pf0mac is based on 0x600_0000 and pf1mac is based on
	 * 0x608_0000 instead of based on the same address.
	 */
	u8 pf_id;

	/* Port id and tc flower module may be necessary */
	u16 vf_id;

	/*
	 * pdev_priv->func_qnum = Sum-of-all(ys_adev->netdev_qnum) +
	 *                      unuesd_qnum
	 */
	u16 func_qnum;
	/*
	 * Total queue numbers for this function, include the own netdevice,
	 * sub-function's netdevice, representor's netdevice and vf's
	 * netdevice.
	 *
	 * pdev_priv->total_qnum = Sum-of-all(ys_adev->netdev_qnum) +
	 *                         sriov_info->vfs_total_qnum +
	 *                         unuesd_qnum
	 */
	u16 total_qnum;
	u16 real_qbase;
	struct ys_queue_info txq_res[YS_MAX_QUEUES];
	struct ys_queue_info rxq_res[YS_MAX_QUEUES];
	struct ys_qset_pool qset_pool;

	/* adev device list */
	struct list_head adev_list;
	/* rwlock for adev_list */
	rwlock_t adev_list_lock;

	struct hw_adapter_ops *ops;
	struct ys_doe_ops *doe_ops;
	struct list_head doe_list;
	struct ys_doe_schedule doe_schedule;
	void *padp_priv;
	void *flow_steering_priv;

	struct ys_sriov sriov_info;

	/* The purpose of placing the PTP pointer here
	 * instead of reading it through auxiliary is
	 * that a PCI device will only have one PTP implementation logic.
	 * Since the PTP pointer will be frequently called
	 * in the network card data path, storing the PTP pointer here
	 * separately is done to improve efficiency.
	 */
	struct ys_ptp *ptp;

	struct ys_devlink devlink_info;
	struct list_head sysfs_list;
	struct ys_sysfs_info *vf_sysfs_infos;

	struct ys_state_statistics state_statistics;

	/* pdev global */
	struct mutex state_lock;
	struct list_head list;
	struct ys_pdev_manager *pdev_manager;

	/* for smartnic & dpu_soc mode */
	u16 sum_vf;

	/* for global debug info */
	struct ys_debug_type diagnose;

	u32 master;

	/*only use in K2PRO*/
	struct hw_info *hw_info;

	/* vlan Qos speed limiting switch */
	u8 vlan_meter;

	/* switch mac */
	u8 switch_mac;

	u8 link_status;
};

enum {
	MAC_TYPE_NULL = 0,
	MAC_TYPE_CMAC,
	MAC_TYPE_LMAC,
	MAC_TYPE_UMAC,
	MAC_TYPE_LMAC3,
	MAC_TYPE_XMAC,
};

enum {
	LAN_TYPE_NULL = 0,
	LAN_TYPE_K2,
	LAN_TYPE_ESW,
	LAN_TYPE_K2U,
};

enum {
	NP_TYPE_NULL = 0,
	NP_TYPE_K2,
	NP_TYPE_K2U,
};

enum {
	YS_PDEV_TYPE_NDEV = 0,
	YS_PDEV_TYPE_DOE,
	YS_PDEV_TYPE_SEC,
	YS_PDEV_TYPE_KMACHINE,
};

enum {
	YS_PF_SLAVE = 1,
	YS_PF_MASTER,
};

/* bar_status:
 * BIT(x):BAR x IOREMAP FUNC
 * 0: ioremap_nocache
 * 1: ioremap_wc
 * bar_addr:
 * 0:bar0
 * 1:bar1
 * 2:bar2
 */

struct ys_pdev_hw {
	char func_name[YS_FUNC_NAME_LEN];

	int irq_flag;
	int irq_sum;

	int pdev_type;

	int ndev_sum;
	int ndev_qcount;
	DECLARE_BITMAP(bar_status, 6);

	u8 is_vf;

	u8 i2c_enable;
	u8 ptp_enable;
	u8 lan_type;
	u8 mac_type;
	u8 mbox_enable;
	u8 np_type;
	u8 vdpa_enable;
	u8 doe_enable;

	int (*hw_pdev_init)(struct ys_pdev_priv *priv);
	void (*hw_pdev_uninit)(struct ys_pdev_priv *priv);
	int (*hw_pdev_fix_mode)(struct ys_pdev_priv *priv);
	void (*hw_pdev_unfix_mode)(struct ys_pdev_priv *priv);
};

extern struct ys_pdev_manager g_ys_pdev_manager;
bool ys_pdev_supports_sriov(struct pci_dev *dev);

struct pci_dev *ys_pdev_find_another_pf(struct pci_dev *pdev);
int ys_pdev_init(struct pci_driver *pdrv);
void ys_pdev_uninit(struct pci_driver *pdrv);
int ys_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ys_pdev_remove(struct pci_dev *pdev);

#endif /* __YS_PDEV_H_ */
