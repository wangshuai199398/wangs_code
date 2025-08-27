// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>
#include <linux/rwlock_types.h>
#include <net/devlink.h>
#include <linux/delay.h>

#include "ys_auxiliary.h"
#include "ys_plat_doe.h"
#include "ys_plat_np.h"
#include "ys_ndev.h"
#include "ys_pdev.h"
#include "ys_mbox.h"
#include "ys_vdpa.h"

#include "../net/ys_ethtool_ops.h"
#include "../net/ys_ndev_ops.h"
#include "../net/lan/ys_lan.h"
#include "../net/mac/ys_mac.h"

#include "ys_debug.h"
#include "ysif_linux.h"

static int ys_aux_allocate_id(unsigned long *bitmap, int max_devices)
{
	const struct ysif_ops *ops = ysif_get_ops();
	int id = ops->yfind_first_zero_bit(bitmap, max_devices);

	if (id >= max_devices)
		return -1;

	ops->set_bit(id, bitmap);
	return id;
}

static void ys_aux_free_id(unsigned long *bitmap, int id)
{
	clear_bit(id, bitmap);
}

static void ys_aux_set_dev_info(struct ys_adev *adev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct auxiliary_device *auxdev = &adev->auxdev;

	if (strcmp(auxdev->name, AUX_NAME_ETH) == 0) {
		adev->adev_type = AUX_TYPE_ETH;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->eth_dev_id,
						YS_DEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_SF) == 0) {
		adev->adev_type = AUX_TYPE_SF;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->sf_dev_id,
						YS_DEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_REP) == 0) {
		adev->adev_type = AUX_TYPE_REP;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->rep_dev_id,
						YS_DEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_I2C) == 0) {
		adev->adev_type = AUX_TYPE_I2C;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->i2c_dev_id,
						YS_PDEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_PTP) == 0) {
		adev->adev_type = AUX_TYPE_PTP;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->ptp_dev_id,
						YS_PDEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_LAN) == 0) {
		adev->adev_type = AUX_TYPE_LAN;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->lan_dev_id,
						YS_PDEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_MAC) == 0) {
		adev->adev_type = AUX_TYPE_MAC;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->mac_dev_id,
						YS_PDEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_MBOX) == 0) {
		adev->adev_type = AUX_TYPE_MBOX;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->mbox_dev_id,
						YS_PDEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_NP) == 0) {
		adev->adev_type = AUX_TYPE_NP;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->np_dev_id,
						YS_PDEV_MAX);
	} else if (strcmp(auxdev->name, AUX_NAME_DOE) == 0) {
		adev->adev_type = AUX_TYPE_DOE;
		auxdev->id = pdev_priv->pdev->bus->number;
	} else if (strcmp(auxdev->name, AUX_NAME_VDPA) == 0) {
		adev->adev_type = AUX_TYPE_VDPA;
		auxdev->id = ys_aux_allocate_id(pdev_priv->pdev_manager->vdpa_dev_id,
						YS_PDEV_MAX);
	} else {
		ys_dev_err("unknown adev name %s\n", auxdev->name);
	}
}

static void ys_aux_clear_dev_info(struct ys_adev *adev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct auxiliary_device *auxdev = &adev->auxdev;

	if (strcmp(auxdev->name, AUX_NAME_ETH) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->eth_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_SF) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->sf_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_REP) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->rep_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_I2C) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->i2c_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_PTP) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->ptp_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_LAN) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->lan_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_MAC) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->mac_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_MBOX) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->mbox_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_NP) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->np_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_VDPA) == 0)
		ys_aux_free_id(pdev_priv->pdev_manager->vdpa_dev_id, auxdev->id);
	else if (strcmp(auxdev->name, AUX_NAME_DOE) == 0)
		auxdev->id = 0;
	else
		ys_dev_err("unknown adev name %s\n", auxdev->name);
}

static void ys_aux_release_adev(struct device *dev)
{
	struct ys_adev *adev = container_of(dev, struct ys_adev, auxdev.dev);

	complete(&adev->comp);
}

static void ys_aux_del_adev(struct auxiliary_device *auxdev)
{
	auxiliary_device_delete(auxdev);
	auxiliary_device_uninit(auxdev);
}

void *ys_aux_match_ndev_by_qset(struct pci_dev *pdev, u16 qset)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct net_device *ndev;
	struct ys_ndev_priv *ndev_priv;
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *adev, *temp;

	read_lock(&pdev_priv->adev_list_lock);
	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (adev->adev_type == AUX_TYPE_ETH ||
		    adev->adev_type == AUX_TYPE_SF) {
			ndev = (struct net_device *)adev->adev_priv;
			ndev_priv = netdev_priv(ndev);
			if (ndev_priv->qi.qset == qset) {
				read_unlock(&pdev_priv->adev_list_lock);
				return ndev;
			}
		}
	}
	read_unlock(&pdev_priv->adev_list_lock);
	return NULL;
}

void *ys_aux_match_adev(struct pci_dev *pdev, int adev_type, int id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *adev, *temp;

	read_lock(&pdev_priv->adev_list_lock);
	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (adev->adev_type == adev_type && adev->idx == id) {
			read_unlock(&pdev_priv->adev_list_lock);
			return adev->adev_priv;
		}
	}

	read_unlock(&pdev_priv->adev_list_lock);
	return NULL;
}

int ys_aux_match_id(struct pci_dev *pdev, int adev_type, void *adev_priv)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *adev, *temp;

	read_lock(&pdev_priv->adev_list_lock);
	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (adev->adev_type == adev_type &&
		    adev->adev_priv == adev_priv) {
			read_unlock(&pdev_priv->adev_list_lock);
			return adev->idx;
		}
	}

	read_unlock(&pdev_priv->adev_list_lock);
	return -1;
}

struct ys_adev *ys_aux_get_adev(struct pci_dev *pdev, int adev_type,
				void *adev_priv)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *adev, *temp;

	read_lock(&pdev_priv->adev_list_lock);
	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (adev->adev_type == adev_type &&
		    adev->adev_priv == adev_priv) {
			read_unlock(&pdev_priv->adev_list_lock);
			return adev;
		}
	}

	read_unlock(&pdev_priv->adev_list_lock);
	return NULL;
}

void ys_aux_del_all_adev(struct pci_dev *pdev, const char *name)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *adev, *temp;
	unsigned long flags;

	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (!strcmp(adev->auxdev.name, name)) {
			ys_aux_clear_dev_info(adev);
			ys_aux_del_adev(&adev->auxdev);
			wait_for_completion(&adev->comp);
			write_lock_irqsave(&pdev_priv->adev_list_lock, flags);
			list_del_rcu(&adev->list);
			write_unlock_irqrestore(&pdev_priv->adev_list_lock, flags);
			kfree(adev);
			adev = NULL;
		}
	}
}

void ys_aux_del_match_adev(struct pci_dev *pdev, int idx, const char *name)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct ys_adev *adev, *temp;
	unsigned long flags;

	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (!strcmp(adev->auxdev.name, name) && adev->idx == idx) {
			ys_aux_clear_dev_info(adev);
			ys_aux_del_adev(&adev->auxdev);
			wait_for_completion(&adev->comp);
			write_lock_irqsave(&pdev_priv->adev_list_lock, flags);
			list_del_rcu(&adev->list);
			write_unlock_irqrestore(&pdev_priv->adev_list_lock, flags);
			kfree(adev);
			adev = NULL;
		}
	}
}

struct ys_adev *ys_aux_add_adev(struct pci_dev *pdev, int idx,
				const char *name, void *arg)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_pdev_priv *pdev_priv = ops->pci_get_drvdata(pdev);
	struct list_head *adev_list = &pdev_priv->adev_list;
	struct auxiliary_device *auxdev;
	struct ys_adev *adev, *temp;
	struct ys_queue_params *qi;
	u32 adev_index;
	int ret;
	unsigned long flags;

	adev_index = (pdev_priv->index << AUX_INDEX_OFFSET) + idx;

	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (!strcmp(adev->auxdev.name, name) &&
		    adev->adev_index == adev_index) {
			ys_dev_err("adev %s:%d exist\n", name, idx);
			return ERR_PTR(-EEXIST);
		}
	}

	adev = kzalloc(sizeof(*adev), GFP_KERNEL);
	if (!adev)
		return ERR_PTR(-ENOMEM);

	auxdev = &adev->auxdev;
	auxdev->name = name;
	auxdev->dev.parent = &pdev->dev;
	auxdev->dev.release = ys_aux_release_adev;
	adev->pdev = pdev;
	adev->idx = idx;
	adev->adev_index = adev_index;
	adev->state_statistics.flag = ET_FLAG_UNREGISTER;

	ops->yinit_completion(&adev->comp);
	ys_aux_set_dev_info(adev);

	if (strcmp(auxdev->name, AUX_NAME_DOE) == 0)
		adev->adev_extern_ops = arg;

	if (adev->adev_type == AUX_TYPE_ETH ||
	    adev->adev_type == AUX_TYPE_SF ||
	    adev->adev_type == AUX_TYPE_REP) {
		qi = arg;
		if (!qi) {
			ys_dev_err("no queue resource allocated\n");
			kfree(adev);
			return ERR_PTR(-EINVAL);
		}
		adev->qi.qbase = qi->qbase;
		adev->qi.ndev_qnum = qi->ndev_qnum;
		adev->qi.qset = qi->qset;
	}

	ret = ops->auxiliary_device_init(auxdev);
	if (ret) {
		kfree(adev);
		return ERR_PTR(ret);
	}

	ops->ywrite_lock_irqsave(&pdev_priv->adev_list_lock, flags);
	ops->list_add_rcu(&adev->list, adev_list);
	ops->ywrite_unlock_irqrestore(&pdev_priv->adev_list_lock, flags);

	ret = ops->yauxiliary_device_add(auxdev);
	if (ret) {
		ops->auxiliary_device_uninit(auxdev);
		return ERR_PTR(ret);
	}

	ys_dev_err("add aux device %s:%d\n\n", name, idx);

	return adev;
}

static int ys_aux_i2c_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;

	if (pdev_priv->nic_type->i2c_enable) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_I2C, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

static void ys_aux_i2c_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->i2c_enable)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_I2C);
}

int ys_aux_ndev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;
	struct ys_queue_params qi;
	int ret;
	int i;

	qi.qbase = 0;
	qi.qset = 0;

	for (i = 0; i < pdev_priv->nic_type->ndev_sum; i++) {
		if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_get_init_qbase))
			qi.qbase = pdev_priv->ops->hw_adp_get_init_qbase(pdev);

		if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_get_init_qnum))
			qi.ndev_qnum = pdev_priv->ops->hw_adp_get_init_qnum(pdev);
		else
			qi.ndev_qnum = pdev_priv->nic_type->ndev_qcount;

		adev = ys_aux_add_adev(pdev_priv->pdev, (int)i, AUX_NAME_ETH,
				       &qi);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	ret = ys_irq_register_ndev_irqs(pdev);
	if (ret)
		return ret;

	return 0;
}

void ys_aux_ndev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int i;

	ys_irq_unregister_ndev_irqs(pdev);

	/* delete sf */
	ys_aux_del_all_adev(pdev_priv->pdev, AUX_NAME_SF);

	/* delete rep */
	ys_aux_del_all_adev(pdev_priv->pdev, AUX_NAME_REP);

	for (i = 0; i < pdev_priv->nic_type->ndev_sum; i++)
		ys_aux_del_match_adev(pdev_priv->pdev, (int)i, AUX_NAME_ETH);
}

static int ys_aux_ptp_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;

	if (pdev_priv->nic_type->ptp_enable) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_PTP, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

static void ys_aux_ptp_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->ptp_enable)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_PTP);
}

static int ys_aux_lan_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;

	if (pdev_priv->nic_type->lan_type) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_LAN, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

static void ys_aux_lan_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->lan_type)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_LAN);
}

static int ys_aux_mac_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;

	if (pdev_priv->nic_type->mac_type) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_MAC, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

static void ys_aux_mac_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->mac_type)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_MAC);
}

int ys_aux_mbox_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;

	if (pdev_priv->nic_type->mbox_enable) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_MBOX, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

void ys_aux_mbox_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->mbox_enable)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_MBOX);
}

static int ys_aux_doe_dev_init(struct pci_dev *pdev)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;
	int doe_enable = false;
	struct ys_pdev_priv *other_priv = NULL;
	struct list_head *schedule_list = NULL;
	bool find_it = false;

	doe_enable = pdev_priv->nic_type->doe_enable &&
		       !pdev_priv->nic_type->is_vf &&
		       (pdev_priv->dpu_mode == MODE_SMART_NIC ||
		       pdev_priv->dpu_mode == MODE_DPU_SOC ||
		       pdev_priv->dpu_mode == MODE_LEGACY);
	if (!doe_enable)
		return 0;

	ops->spin_lock(&pdev_priv->pdev_manager->doe_schedule_lock);
	schedule_list = &pdev_priv->pdev_manager->doe_schedule_list;

	list_for_each_entry(other_priv, schedule_list, doe_list) {
		if (other_priv->pdev->bus->number == pdev_priv->pdev->bus->number &&
		    PCI_SLOT(other_priv->pdev->devfn) == PCI_SLOT(pdev_priv->pdev->devfn)) {
			find_it = true;
			break;
		}
	}
	ops->list_add(&pdev_priv->doe_list, schedule_list);
	if (!find_it)
		pdev_priv->doe_schedule.doe_master = true;

	ops->spin_unlock(&pdev_priv->pdev_manager->doe_schedule_lock);

	if (pdev_priv->doe_schedule.doe_master) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_DOE, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

static void ys_aux_doe_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int doe_enable = false;
	struct ys_pdev_priv *other_priv = NULL;
	struct ys_pdev_priv *schedule_priv = NULL;
	struct ys_pdev_priv *temp = NULL;
	struct list_head *schedule_list = NULL;
	struct ys_adev *adev;
	void *adev_priv = NULL;

	doe_enable = pdev_priv->nic_type->doe_enable &&
		     !pdev_priv->nic_type->is_vf  &&
		     (pdev_priv->dpu_mode == MODE_SMART_NIC ||
		     pdev_priv->dpu_mode == MODE_DPU_SOC ||
		     pdev_priv->dpu_mode == MODE_LEGACY);
	if (!doe_enable)
		return;

	spin_lock(&pdev_priv->pdev_manager->doe_schedule_lock);
	schedule_list = &pdev_priv->pdev_manager->doe_schedule_list;

	list_for_each_entry_safe(other_priv, temp, schedule_list, doe_list) {
		if (other_priv->index == pdev_priv->index)
			list_del(&other_priv->doe_list);
	}

	list_for_each_entry(other_priv, schedule_list, doe_list) {
		if (other_priv->pdev->bus->number == pdev_priv->pdev->bus->number &&
		    PCI_SLOT(other_priv->pdev->devfn) == PCI_SLOT(pdev_priv->pdev->devfn) &&
		    other_priv != pdev_priv) {
			schedule_priv = other_priv;
			break;
		}
	}

	spin_unlock(&pdev_priv->pdev_manager->doe_schedule_lock);

	if (pdev_priv->doe_schedule.doe_master && schedule_priv) {
		ys_dev_info("DOE will be schedule master PF to PF%d\n", schedule_priv->pf_id);
		adev_priv = ys_aux_match_adev(pdev, AUX_TYPE_DOE, 0);
		adev = ys_aux_get_adev(pdev, AUX_TYPE_DOE, adev_priv);

		schedule_priv->doe_schedule.schedule_buf = adev_priv;
		adev->adev_priv = NULL;
	}

	if (pdev_priv->doe_schedule.doe_master)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_DOE);

	if (pdev_priv->doe_schedule.doe_master && schedule_priv) {
		adev = ys_aux_add_adev(schedule_priv->pdev, 0, AUX_NAME_DOE, NULL);
		if (IS_ERR_OR_NULL(adev)) {
			ys_dev_err("DOE schedule master PF fail\n");
			return;
		}
		pdev_priv->doe_schedule.ys_doe_schedule(schedule_priv->pdev);
		ys_dev_info("DOE schedule master PF success\n");
		pdev_priv->doe_schedule.doe_master = false;
		schedule_priv->doe_schedule.doe_master = true;
	}
}

static int ys_aux_np_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;

	if (pdev_priv->nic_type->np_type) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_NP, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

static void ys_aux_np_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->np_type)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_NP);
}

static int ys_aux_vdpa_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_adev *adev;

	if (pdev_priv->nic_type->vdpa_enable) {
		adev = ys_aux_add_adev(pdev_priv->pdev, 0, AUX_NAME_VDPA, NULL);
		if (IS_ERR_OR_NULL(adev))
			return -ENODEV;
	}

	return 0;
}

static void ys_aux_vdpa_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->vdpa_enable)
		ys_aux_del_match_adev(pdev_priv->pdev, 0, AUX_NAME_VDPA);
}

int ys_aux_dev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int ret;

	if (pdev_priv->nic_type->pdev_type != YS_PDEV_TYPE_NDEV)
		return 0;

	ret = ys_aux_doe_dev_init(pdev);
	if (ret)
		return ret;

	ret = ys_aux_mac_dev_init(pdev);
	if (ret)
		return ret;

	ret = ys_aux_lan_dev_init(pdev);
	if (ret)
		return ret;

	ret = ys_aux_np_dev_init(pdev);
	if (ret)
		return ret;

	ret = ys_aux_i2c_dev_init(pdev);
	if (ret)
		return ret;

	ret = ys_aux_ndev_init(pdev);
	if (ret)
		return ret;

	ret = ys_aux_ptp_dev_init(pdev);
	if (ret)
		return ret;

	ret = ys_aux_vdpa_dev_init(pdev);
	if (ret)
		return ret;

	return 0;
}

void ys_aux_dev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->nic_type->pdev_type == YS_PDEV_TYPE_DOE)
		return;

	ys_aux_vdpa_dev_uninit(pdev);
	ys_aux_ptp_dev_uninit(pdev);
	ys_aux_ndev_uninit(pdev);
	ys_aux_i2c_dev_uninit(pdev);
	ys_aux_np_dev_uninit(pdev);
	ys_aux_lan_dev_uninit(pdev);
	ys_aux_mac_dev_uninit(pdev);
	ys_aux_doe_dev_uninit(pdev);
}

static const struct auxiliary_device_id ys_eth_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_ETH },
	{ },
};

static const struct auxiliary_device_id ys_sf_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_SF },
	{ },
};

static const struct auxiliary_device_id ys_rep_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_REP },
	{ },
};

static const struct auxiliary_device_id ys_i2c_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_I2C },
	{ },
};

static const struct auxiliary_device_id ys_ptp_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_PTP },
	{ },
};

static const struct auxiliary_device_id ys_lan_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_LAN },
	{ },
};

static const struct auxiliary_device_id ys_mac_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_MAC },
	{ },
};

static const struct auxiliary_device_id ys_mbox_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_MBOX },
	{ },
};

static const struct auxiliary_device_id ys_np_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_NP },
	{ },
};

static const struct auxiliary_device_id ys_doe_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_DOE },
	{ },
};

static const struct auxiliary_device_id ys_vdpa_id_table[] = {
	{ .name = YS_AUX_MODULE_NAME "." AUX_NAME_VDPA },
	{ },
};

static struct ys_auxiliary_driver ys_adrvs[] = {
	YS_AUX_DRV(AUX_NAME_ETH, ys_aux_eth_probe, ys_aux_eth_remove, ys_eth_id_table, AUX_TYPE_ETH),
	YS_AUX_DRV(AUX_NAME_SF, ys_aux_sf_probe, ys_aux_sf_remove, ys_sf_id_table, AUX_TYPE_SF),
	YS_AUX_DRV(AUX_NAME_REP, ys_aux_rep_probe, ys_aux_rep_remove, ys_rep_id_table, AUX_TYPE_REP),
	YS_AUX_DRV(AUX_NAME_I2C, ys_aux_i2c_probe, ys_aux_i2c_remove, ys_i2c_id_table, AUX_TYPE_I2C),
	YS_AUX_DRV(AUX_NAME_PTP, ys_aux_ptp_probe, ys_aux_ptp_remove, ys_ptp_id_table, AUX_TYPE_PTP),
	YS_AUX_DRV(AUX_NAME_LAN, ys_aux_lan_probe, ys_aux_lan_remove, ys_lan_id_table, AUX_TYPE_LAN),
	YS_AUX_DRV(AUX_NAME_MAC, ys_aux_mac_probe, ys_aux_mac_remove, ys_mac_id_table, AUX_TYPE_MAC),
	YS_AUX_DRV(AUX_NAME_MBOX, ys_aux_mbox_probe, ys_aux_mbox_remove, ys_mbox_id_table, AUX_TYPE_MBOX),
	YS_AUX_DRV(AUX_NAME_NP, ys_aux_np_probe, ys_aux_np_remove, ys_np_id_table, AUX_TYPE_NP),
	YS_AUX_DRV(AUX_NAME_DOE, ys_aux_doe_probe, ys_aux_doe_remove, ys_doe_id_table, AUX_TYPE_DOE),
	YS_AUX_DRV(AUX_NAME_VDPA, ys_aux_vdpa_probe, ys_aux_vdpa_remove, ys_vdpa_id_table, AUX_TYPE_VDPA),
	YS_AUX_DRV(NULL, NULL, NULL, NULL, 0) /* end */
};

int ys_aux_init(u32 pci_support_type)
{
	int ret;
	int i = 0;
	const struct ysif_ops *ops = ysif_get_ops();
	for (; !IS_ERR_OR_NULL(ys_adrvs[i].drv.name); i++) {
		if (pci_support_type & ys_adrvs[i].aux_drv_support) {
			if (!ys_adrvs[i].is_registered) {
				ret = ops->yauxiliary_driver_register(&ys_adrvs[i].drv);
				if (ret)
					return ret;
				ys_adrvs[i].is_registered = true;
			}
		}
	}

	return 0;
}

void ys_aux_uninit(u32 pci_support_type)
{
	int i = 0;

	for (; !IS_ERR_OR_NULL(ys_adrvs[i].drv.name); i++) {
		if (pci_support_type & ys_adrvs[i].aux_drv_support) {
			if (ys_adrvs[i].is_registered) {
				auxiliary_driver_unregister(&ys_adrvs[i].drv);
				ys_adrvs[i].is_registered = false;
			}
		}
	}
}
