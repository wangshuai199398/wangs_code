// SPDX-License-Identifier: GPL-2.0

#include <linux/sysfs.h>
#include <linux/kernel.h>

#include "ys_pdev.h"
#include "ys_ndev.h"
#include "ys_sysfs.h"
#include "ys_auxiliary.h"
#include "ys_mbox.h"

#include "ys_debug.h"

#include "ysif_linux.h"

static int cmd_parse(const char *str, const char *param, u32 *val)
{
	const char *start, *end;
	char val_str[256];
	int ret;

	/* find the parameter start position */
	start = strstr(str, param);
	if (!start)
		return -EINVAL;
	start += strlen(param) + 1;

	/* find the parameter end position */
	end = strstr(start, " ");
	if (!end)
		end = str + strlen(str);

	if ((end - start) > (sizeof(val_str) - 1))
		return -EINVAL;

	/* sort the value string */
	strscpy(val_str, start, end - start + 1);
	val_str[end - start] = 0;

	/* parse the value of parameter */
	ret = kstrtou32(val_str, 10, val);
	if (ret)
		return ret;

	return 0;
}

static ssize_t ys_sysfs_aux_bind_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ys_queue_params qi;
	struct ys_adev *adev;
	u32 idx, qnum, qbase;
	int ret;

	ret = cmd_parse(buf, "sf", &idx);
	if (ret)
		return -EINVAL;

	ret = cmd_parse(buf, "qnum", &qnum);
	if (ret)
		return -EINVAL;

	if (idx > YS_MAX_SF_ID) {
		ys_err("sf %d is out of range, max is %d\n",
		       idx, YS_MAX_SF_ID);
		return -EINVAL;
	}

	if (qnum > YS_MAX_QUEUES || qnum < 1) {
		ys_err("qnum %d is out of range, max is %d, min is 1\n",
		       qnum, YS_MAX_QUEUES);
		return -EINVAL;
	}

	/* if no input qbase
	 * use tx queue to get qbase temporary
	 */
	ret = cmd_parse(buf, "qbase", &qbase);
	if (ret) {
		ret = ys_queue_find_available_base(pdev,
						   QUEUE_TYPE_TX,
						   qnum);
		if (ret < 0) {
			ys_err("no available queue base %d\n", qi.qbase);
			return -EINVAL;
		}
		qi.qbase = (u16)ret;
	} else {
		qi.qbase = qbase;
	}

	qi.ndev_qnum = (u16)qnum;
	qi.qset = 0;

	adev = ys_aux_add_adev(pdev, (int)idx, AUX_NAME_SF, &qi);
	if (IS_ERR_OR_NULL(adev))
		return -EINVAL;

	if (IS_ERR_OR_NULL(adev->adev_priv)) {
		ys_aux_del_match_adev(pdev, (int)idx, AUX_NAME_SF);
		return -EINVAL;
	}

	return count;
}

static ssize_t ys_sysfs_aux_unbind_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int idx;
	int ret;

	ret = cmd_parse(buf, "sf", &idx);
	if (ret)
		return ret;

	if (idx > YS_MAX_SF_ID) {
		ys_err("sf %d is out of range, max is %d\n",
		       idx, YS_MAX_SF_ID);
		return -EINVAL;
	}

	ys_aux_del_match_adev(pdev, (int)idx, AUX_NAME_SF);

	return count;
}

static ssize_t ys_sysfs_mbox_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	int ret;

	ret = ys_mbox_sysfs_send(to_pci_dev(dev), buf);

	if (ret)
		return -EFAULT;

	return count;
}

static ssize_t ys_sysfs_rep_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct net_device *ndev;
	struct ys_ndev_priv *ndev_priv;
	u32 nums;
	int ret;

	if (IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_rep_update))
		return -EINVAL;

	if (pdev_priv->dpu_mode != MODE_DPU_SOC)
		return -EPERM;

	ndev = ys_aux_match_eth(pdev, 0);
	if (!ndev)
		return -EPERM;

	ndev_priv = netdev_priv(ndev);
	if (ndev_priv->umd_enable) {
		ys_dev_warn("VF representor config before umd stop!");
		return -EPERM;
	}

	ret = kstrtou32(buf, 10, &nums);
	if (ret)
		return ret;

	if (pdev_priv->ops->hw_adp_rep_update(pdev, nums))
		return -EINVAL;

	return count;
}

static ssize_t ys_sysfs_rep_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	return sprintf(buf, "%ld\n",
		       find_first_zero_bit(pdev_priv->pdev_manager->rep_dev_id, YS_DEV_MAX));
}

static ssize_t ys_sysfs_queue_info_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int offset = 0;
	int i;

	offset += sprintf(buf + offset, "TX Queue Info:\n");
	for (i = 0; i < YS_MAX_QUEUES; i++) {
		if (pdev_priv->txq_res[i].is_used) {
			offset += sprintf(buf + offset,
					  "TX Queue %d: Index: %d, QSet: %d, IS_VF: %d VF_ID: %d\n",
					  i, pdev_priv->txq_res[i].index,
					  pdev_priv->txq_res[i].qset,
					  pdev_priv->txq_res[i].is_vf,
					  pdev_priv->txq_res[i].vf_id);
			if (offset > 4000)
				return offset;
		}
	}

	return offset;
}

static ssize_t ys_sysfs_version_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	int offset = 0;

	offset += sprintf(buf + offset, "|Git version:%49s|\n", YS_GIT_VERSION);
	offset += sprintf(buf + offset, "|Compile time:%48s|\n", YS_COMPILE_TIME);
	offset += sprintf(buf + offset, "|Compile PAGE_SIZE:%43d|\n", YS_COMPILE_PAGE_SIZE);
	offset += sprintf(buf + offset, "|GCC version:%49s|\n", YS_GCC_VERSION);
	offset += sprintf(buf + offset, "|KerHeader path:%46s|\n", YS_KERNEL_HEADER_VERSION);
	offset += sprintf(buf + offset, "|HW name :%52s|\n", YS_HW_NAME);
	offset += sprintf(buf + offset, "|HW type :%52s|\n", YS_HW_TYPE);

	return offset;
}

static struct ys_sysfs_info common_nodes[] = {
	{__ATTR(queue_info, 0444, ys_sysfs_queue_info_show, NULL), 0},
	{__ATTR(aux_bind, 0200, NULL, ys_sysfs_aux_bind_store), 1},
	{__ATTR(aux_unbind, 0200, NULL, ys_sysfs_aux_unbind_store), 2},
	{__ATTR(mailbox, 0200, NULL, ys_sysfs_mbox_store), 3},
	{__ATTR(rep_nums, 0644, ys_sysfs_rep_show, ys_sysfs_rep_store), 4},
	{__ATTR(version, 0444, ys_sysfs_version_show, NULL), 5},
};

int ys_sysfs_create_group(struct list_head *list,
			  int type, int idx, struct kobject *kobj,
			  struct device_attribute *device_attrs,
			  int attrs_num, const char *grp_name)
{
	struct ysif_ops *ops = ysif_get_ops();
	struct attribute **grp_attrs = NULL;
	struct ys_sysfs_group *grp = NULL;
	int ret;
	int i;

	if (IS_ERR_OR_NULL(device_attrs) || attrs_num <= 0)
		goto done;

	grp_attrs = kzalloc((attrs_num + 1) * sizeof(struct attribute *),
			    GFP_KERNEL);
	if (!grp_attrs)
		goto err;

	for (i = 0; i < attrs_num; i++)
		grp_attrs[i] = &device_attrs[i].attr;
	grp_attrs[attrs_num] = NULL;

	grp = kzalloc(sizeof(*grp), GFP_KERNEL);
	if (!grp)
		goto err;

	grp->type = type;
	grp->idx = idx;
	grp->kobj = kobj;
	grp->attr_group.name = grp_name;
	grp->attr_group.attrs = grp_attrs;
	ops->INIT_LIST_HEAD(&grp->list);

	ret = ops->sysfs_create_group(grp->kobj, &grp->attr_group);
	if (ret) {
		ys_err("create sysfs group failed. ret: %d\n", ret);
		goto err;
	}

	list_add(&grp->list, list);
done:
	return 0;
err:
	kfree(grp_attrs);
	kfree(grp);
	return -ENOMEM;
}

int ys_sysfs_create_info_group(struct list_head *list,
			       int type, int idx, struct kobject *kobj,
			       struct ys_sysfs_info *sysfs_info,
			       int attrs_num, const char *grp_name)
{
	struct ysif_ops *ops = ysif_get_ops();
	struct attribute **grp_attrs = NULL;
	struct ys_sysfs_group *grp = NULL;
	int ret;
	int i;

	if (IS_ERR_OR_NULL(sysfs_info) || attrs_num <= 0)
		goto done;

	grp_attrs = kzalloc((attrs_num + 1) * sizeof(struct attribute *),
			    GFP_KERNEL);
	if (!grp_attrs)
		goto err;

	for (i = 0; i < attrs_num; i++)
		grp_attrs[i] = &sysfs_info[i].attr.attr;

	grp_attrs[attrs_num] = NULL;

	grp = kzalloc(sizeof(*grp), GFP_KERNEL);
	if (!grp)
		goto err;

	grp->type = type;
	grp->idx = idx;
	grp->kobj = kobj;
	grp->attr_group.name = grp_name;
	grp->attr_group.attrs = grp_attrs;
	ops->INIT_LIST_HEAD(&grp->list);

	ret = ops->sysfs_create_group(grp->kobj, &grp->attr_group);
	if (ret) {
		ys_err("create sysfs group failed. ret: %d\n", ret);
		goto err;
	}

	ops->list_add(&grp->list, list);
done:
	return 0;
err:
	kfree(grp_attrs);
	kfree(grp);
	return -ENOMEM;
}

void ys_sysfs_remove_group(struct list_head *list,
			   int type, int idx, struct kobject *kobj)
{
	struct ys_sysfs_group *grp, *n;

	list_for_each_entry_safe(grp, n, list, list) {
		if (grp->type == type &&
		    grp->idx == idx &&
		    grp->kobj == kobj) {
			sysfs_remove_group(grp->kobj, &grp->attr_group);
			list_del(&grp->list);
			kfree(grp->attr_group.attrs);
			kfree(grp);
		}
	}
}

static int ys_sysfs_create_common_group(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	int attrs_num;
	int ret;

	attrs_num = ARRAY_SIZE(common_nodes);

	ret = ys_sysfs_create_info_group(list, SYSFS_COMMON, 0, &pdev->dev.kobj,
					 common_nodes, attrs_num, "common");

	return ret;
}

static int ys_sysfs_create_hw_group(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	struct device_attribute *device_attrs;
	int attrs_num;
	int ret;

	if (IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_detect_sysfs_attrs))
		return 0;

	attrs_num = pdev_priv->ops->hw_adp_detect_sysfs_attrs(&device_attrs);

	ret = ys_sysfs_create_group(list, SYSFS_HW, 0, &pdev->dev.kobj,
				    device_attrs, attrs_num, "hw");

	return ret;
}

int ys_sysfs_init(struct pci_dev *pdev)
{
	int ret;

	ret = ys_sysfs_create_common_group(pdev);
	if (ret)
		goto err;

	ret = ys_sysfs_create_hw_group(pdev);
	if (ret)
		goto err;

	return 0;
err:
	ys_sysfs_uninit(pdev);
	return -ENOMEM;
}

void ys_sysfs_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *list = &pdev_priv->sysfs_list;
	struct ys_sysfs_group *grp, *n;

	list_for_each_entry_safe(grp, n, list, list) {
		sysfs_remove_group(grp->kobj, &grp->attr_group);
		list_del(&grp->list);
		kfree(grp->attr_group.attrs);
		kfree(grp);
	}
}
