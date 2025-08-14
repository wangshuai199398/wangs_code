/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_SYSFS_H_
#define __YS_SYSFS_H_
#include <linux/device.h>
#include <linux/pci.h>

#define YS_MAX_SF_ID	256

struct ys_sysfs_info {
	struct device_attribute attr;
	int idx;
};

struct ys_sysfs_group {
	int type;
	int idx;
	struct kobject *kobj;
	struct attribute_group attr_group;
	struct list_head list;
};

enum { SYSFS_COMMON, SYSFS_HW, SYSFS_NDEV, SYSFS_SF, SYSFS_MTR };

int ys_sysfs_create_group(struct list_head *list,
			  int type, int idx, struct kobject *kobj,
			  struct device_attribute *device_attrs,
			  int attrs_num, const char *grp_name);
int ys_sysfs_create_info_group(struct list_head *list,
			       int type, int idx, struct kobject *kobj,
			       struct ys_sysfs_info *sysfs_info,
			       int attrs_num, const char *grp_name);
void ys_sysfs_remove_group(struct list_head *list,
			   int type, int idx, struct kobject *kobj);
int ys_sysfs_init(struct pci_dev *pdev);
void ys_sysfs_uninit(struct pci_dev *pdev);

#endif /* __YS_SYSFS_H_ */
