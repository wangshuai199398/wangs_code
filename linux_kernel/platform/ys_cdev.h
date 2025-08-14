/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_CDEV_H_
#define __YS_CDEV_H_

#include <linux/cdev.h>
#include <linux/miscdevice.h>

#include "ys_pdev.h"

struct ys_cdev_priv {
	struct miscdevice *mdev;
	struct pci_dev *pdev;

	/* hardware addr */
	unsigned long bar_start[BAR_MAX];
	unsigned long bar_end[BAR_MAX];
	unsigned long bar_flags[BAR_MAX];
	unsigned long bar_size[BAR_MAX];
	unsigned long bar_offset[BAR_MAX];
	/* virtual addr */
	void __iomem *bar_vaddr[BAR_MAX];
	/* queue resource manager */
	struct list_head qres_list;
	/* debug resource manager */
	struct list_head debug_list;

	u16 vf_num;
};

struct ys_cdev {
	/* cmd_mutex */
	struct mutex cmd_mutex;
	char misc_dev_name[MAX_MISC_DEV_NAME_BYTES];
	struct miscdevice mdev;
	struct pci_dev *pdev;
	struct list_head list;
};

long ys_cdev_ioctl(struct file *filp, u32 cmd, unsigned long arg);
int ys_cdev_release(struct inode *inode, struct file *filp);
int ys_cdev_init(struct pci_dev *pdev);
void ys_cdev_uninit(struct pci_dev *pdev);
int ys_add_cdev(struct pci_dev *pdev, const char *name, const struct file_operations *ops);
void ys_umem_unmap(struct ys_pdev_umem *umem);

#endif /* __YS_CDEV_H_ */
