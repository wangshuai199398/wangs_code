// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>
#include <net/devlink.h>

#include "ys_auxiliary.h"
#include "ys_cdev.h"
#include "ys_devlink.h"
#include "ys_intr.h"
#include "ys_ndev.h"
#include "ys_pdev.h"

#include "ysc_dev.h"

#include "ys_debug.h"
#include "ysif_linux.h"

struct ys_pdev_manager g_ys_pdev_manager;

bool ys_pdev_supports_sriov(struct pci_dev *dev)
{
	int pos;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (pos == 0)
		return false;

	return true;
}

static int ys_pdev_dmaconfig(struct ys_pdev_priv *pdev_priv)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct pci_dev *pdev = pdev_priv->pdev;
	int ret;

	ret = ops->dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		ys_dev_err("Failed to set PCI DMA mask");
		return ret;
	}

	ret = ops->dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		ys_dev_err("Failed to set PCI COHERENT DMA mask");
		return ret;
	}

	/* Set max segment size */
	ops->dma_set_max_seg_size(&pdev->dev, DMA_BIT_MASK(32));

	return 0;
}

static int ys_pdev_mmap(struct ys_pdev_priv *pdev_priv)
{
	struct pci_dev *pdev = pdev_priv->pdev;
	unsigned long bar_start;
	unsigned long bar_flags;
	unsigned long bar_end;
	u64 bar_offset = 0;
	int i;
	const struct ysif_ops *ops = ysif_get_ops();

	for (i = 0; i < BAR_MAX; i++) {
		bar_start = pci_resource_start(pdev, i);
		bar_end = pci_resource_end(pdev, i);
		bar_flags = pci_resource_flags(pdev, i);

		pdev_priv->bar_size[i] = pci_resource_len(pdev, i);
		if (!pdev_priv->bar_size[i]) {
			pdev_priv->bar_addr[i] = NULL;
			continue;
		}

		if (test_bit(i, pdev_priv->nic_type->bar_status))
			pdev_priv->bar_addr[i] = ioremap_wc(bar_start,
							    pdev_priv->bar_size[i]);
		else
			pdev_priv->bar_addr[i] =
				ops->yioremap(bar_start, pdev_priv->bar_size[i]);

		if (!pdev_priv->bar_addr[i]) {
			ys_dev_err("could't map BAR_%d[0x%08lx-0x%08lx] flag[0x%08lx]",
				   i, bar_start, bar_end, bar_flags);
			return -1;
		}

		pdev_priv->bar_pa[i] = bar_start;
		ys_dev_info("BAR_%d ioremap [0x%08lx-0x%08lx] flag[0x%08lx] mapped to 0x%p, length %lu mode %d",
			     i, bar_start, bar_end, bar_flags,
			     pdev_priv->bar_addr[i],
			     (unsigned long)pdev_priv->bar_size[i],
			     test_bit(i, pdev_priv->nic_type->bar_status));

		pdev_priv->bar_offset[i] = bar_offset;
		bar_offset += pdev_priv->bar_size[i];
	}

	return 0;
}

static void ys_pdev_unmap(struct ys_pdev_priv *pdev_priv)
{
	int i;

	for (i = 0; i < BAR_MAX; i++) {
		if (pdev_priv->bar_addr[i]) {
			pci_iounmap(pdev_priv->pdev, pdev_priv->bar_addr[i]);
			pdev_priv->bar_addr[i] = NULL;
		}
	}
}

static int ys_pdev_update_vfinfo(bool is_add_info, struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv;
	struct pci_dev *pfdev;
	struct ys_pdev_priv *pfdev_priv;
	int ret = 0;

	pdev_priv = pci_get_drvdata(pdev);
	if (!pdev->is_virtfn)
		return ret;

	pfdev = pci_physfn(pdev);
	pfdev_priv = pci_get_drvdata(pfdev);
	if (!pfdev_priv) {
		ret = -EFAULT;
		return ret;
	}

	if (is_add_info)
		pfdev_priv->sriov_info.vfinfo[pdev_priv->vf_id - 1].vfdev = pdev;
	else
		pfdev_priv->sriov_info.vfinfo[pdev_priv->vf_id - 1].vfdev = NULL;

	pfdev_priv->sriov_info.vfinfo[pdev_priv->vf_id - 1].done = 0x1;

	return ret;
}

int ys_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ys_pdev_priv *pdev_priv = NULL;
	struct device *dev = &pdev->dev;
	struct list_head *pdev_list;
	int ret = 0;
	struct devlink *devlink = NULL;
	const struct ysif_ops *ops = ysif_get_ops();
	devlink = ys_devlink_alloc(dev);
	if (!devlink) {
		/* Here ys_dev_err is not valid as pdev_priv is NULL. */
		dev_err(dev, "pci_devlink_alloc() failed\n");
		ret = -ENOMEM;
		goto err_priv_alloc;
	}

	pdev_priv = ops->devlink_priv(devlink);
	ops->INIT_LIST_HEAD(&pdev_priv->umem_list);
	pdev_priv->dev = dev;
	pdev_priv->pdev = pdev;
	pdev_priv->nic_type = (const struct ys_pdev_hw *)id->driver_data;
	pdev_priv->pdev_manager = &g_ys_pdev_manager;

	/* init all pf is master */
	if (!pdev_priv->nic_type->is_vf)
		pdev_priv->master = YS_PF_MASTER;

	ops->INIT_LIST_HEAD(&pdev_priv->sysfs_list);
	ops->INIT_LIST_HEAD(&pdev_priv->adev_list);
	ops->INIT_LIST_HEAD(&pdev_priv->doe_list);
	ops->yrwlock_init(&pdev_priv->adev_list_lock);

	/*
	 * After insmod pci driver
	 * First generate 2 VF from PF1
	 * Second generate 3 VF from PF0
	 * The index of all PCI devices is as follows
	 *
	 * PF0------------INDEX0
	 *      |
	 *      |---VF0---INDEX4
	 *      |
	 *      |---VF1---INDEX5
	 *      |
	 *      |---VF2---INDEX6
	 *
	 * PF1------------INDEX1
	 *      |
	 *      |---VF0---INDEX2
	 *      |
	 *      |---VF1---INDEX3
	 */
	pdev_priv->index = ops->yfind_first_zero_bit(g_ys_pdev_manager.pf_index, YS_PDEV_MAX);
	/* pf_id init */
	pdev_priv->pf_id = pdev_priv->index;
	/* default mode is legacy */
	pdev_priv->dpu_mode = MODE_LEGACY;

	ops->pci_set_drvdata(pdev, pdev_priv);

	ops->bitmap_set(g_ys_pdev_manager.pf_index, pdev_priv->index, 1);

	ys_dev_debug("Vendor: 0x%04x, Device: 0x%04x", pdev->vendor, pdev->device);
	ys_dev_debug("Sub vendor: 0x%04x, Sub device: 0x%04x", pdev->subsystem_vendor, pdev->subsystem_device);
	ys_dev_debug("PCI ID: %04x:%02x:%02x.%d, Class: 0x%06x", pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn), pdev->class);

	/* Enable the device */
	ret = ops->pci_enable_device(pdev);
	if (ret) {
		ys_dev_err("pci_enable_device() failed\n");
		goto err_pci_enable;
	}

	ops->pci_set_master(pdev);

	/* Request MMIO/IOP resources */
	ret = ops->pci_request_regions(pdev, pdev->driver->name);
	if (ret) {
		ys_dev_err("pci_request_regions() failed\n");
		goto err_regions;
	}

	/* Allocate and initialize shared control data */
	ret = ys_pdev_mmap(pdev_priv);
	if (ret) {
		ys_dev_err("ys_pdev_mmap failed\n");
		goto err_mmap;
	}

	ys_queue_clear(pdev);

	if (pdev_priv->nic_type->is_vf) {
		/* VF register IRQ handler before hw_pdev_init*/
		ret = ys_irq_init(pdev);
		if (ret) {
			ys_dev_err("ys_init_irq failed\n");
			goto err_irq_vf;
		}

		ret = ys_aux_mbox_dev_init(pdev);
		if (ret) {
			ys_dev_err("ys_aux_mbox_dev_init failed");
			goto err_mbox_vf;
		}
	}

	/* YUSUR adapter init(need to be realize by hw) */
	ret = pdev_priv->nic_type->hw_pdev_init(pdev_priv);
	if (ret) {
		ys_dev_err("ys_hw_adapter_init failed");
		goto err_hw_adapter_init;
	}

	ys_qset_pool_init(pdev);

	/* pci ver print */
	if (pdev_priv->hw_ver)
		ys_dev_info("pci hw ver: %x", pdev_priv->hw_ver);

	ret = ys_pdev_dmaconfig(pdev_priv);
	if (ret) {
		ys_dev_err("dma config failed");
		goto err_pci_dma_config;
	}

	if (!pdev_priv->nic_type->is_vf) {
		/* PF register IRQ handler after hw_pdev_init*/
		ret = ys_irq_init(pdev);
		if (ret) {
			ys_dev_err("ys_init_irq failed\n");
			goto err_irq_pf;
		}

		ret = ys_aux_mbox_dev_init(pdev);
		if (ret) {
			ys_dev_err("ys_aux_mbox_dev_init failed");
			goto err_mbox_pf;
		}
	}

	ret = ys_aux_dev_init(pdev);
	if (ret) {
		ys_dev_err("ys_init_auxiliary failed\n");
		goto err_initaux;
	}

	ret = ys_debug_init(pdev);
	if (ret) {
		ys_dev_err("ys_debug_init failed\n");
		goto err_debug;
	}

	/* YUSUR mdev init */
	ret = ys_cdev_init(pdev);
	if (ret) {
		ys_dev_err("ys_mdev_init failed\n");
		goto err_initmiscdev;
	}

	ret = ys_sysfs_init(pdev);
	if (ret)
		goto err_register_sysfs;

	ret = ys_devlink_init(pdev);
	if (ret)
		goto err_register_devlink;

	if (!IS_ERR_OR_NULL(pdev_priv->nic_type->hw_pdev_fix_mode)) {
		ret = pdev_priv->nic_type->hw_pdev_fix_mode(pdev_priv);
		if (ret)
			goto err_register_fix_mode;
	}

	pdev_list = &pdev_priv->pdev_manager->pdev_list;
	ops->list_add(&pdev_priv->list, pdev_list);

	/* update VF info */
	ret = ys_pdev_update_vfinfo(true, pdev);
	if (ret)
		goto err_register_fix_mode;

	return 0;

err_register_fix_mode:
	if (!IS_ERR_OR_NULL(pdev_priv->nic_type->hw_pdev_unfix_mode))
		pdev_priv->nic_type->hw_pdev_unfix_mode(pdev_priv);
err_register_devlink:
	ys_devlink_uninit(pdev);
err_register_sysfs:
	ys_sysfs_uninit(pdev);
err_initmiscdev:
	ys_cdev_uninit(pdev);
err_debug:
	ys_debug_uninit(pdev);
err_initaux:
	ys_aux_dev_uninit(pdev);
err_mbox_pf:
	if (!pdev_priv->nic_type->is_vf)
		ys_aux_mbox_dev_uninit(pdev);
err_irq_pf:
	if (!pdev_priv->nic_type->is_vf)
		ys_irq_uninit(pdev);
err_pci_dma_config:
	ys_qset_pool_uninit(pdev);
err_hw_adapter_init:
	/* need to be realize by hw */
	pdev_priv->nic_type->hw_pdev_uninit(pdev_priv);
err_mbox_vf:
	if (pdev_priv->nic_type->is_vf)
		ys_aux_mbox_dev_uninit(pdev);
err_irq_vf:
	if (pdev_priv->nic_type->is_vf)
		ys_irq_uninit(pdev);
err_mmap:
	ys_queue_clear(pdev);
	ys_pdev_unmap(pdev_priv);
err_regions:
	pci_set_drvdata(pdev, NULL);
	pci_clear_master(pdev);
	pci_disable_device(pdev);
	pci_release_regions(pdev);
err_pci_enable:
	ys_devlink_release(devlink);
err_priv_alloc:
	return ret;
}

void ys_pdev_remove(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_pdev_umem *umem, *temp_umem;
	struct ys_pdev_priv  *pdev_pr, *temp;
	struct ys_pdev_priv *pfdev_priv;
	struct list_head *pdev_list;
	struct pci_dev *pfdev;
	struct devlink *devlink;

	if (IS_ERR_OR_NULL(pdev_priv)) {
		ys_err("Failed to remove pci_dev because pdev_priv is NULL!\n");
		return;
	}

	if (!IS_ERR_OR_NULL(pdev_priv->nic_type->hw_pdev_unfix_mode))
		pdev_priv->nic_type->hw_pdev_unfix_mode(pdev_priv);

	devlink = priv_to_devlink(pdev_priv);
	ys_devlink_uninit(pdev);
	ys_disable_sriov(pdev);
	ys_pdev_update_vfinfo(false, pdev);
	ys_sysfs_uninit(pdev);
	ys_cdev_uninit(pdev);
	ys_debug_uninit(pdev);
	ys_aux_dev_uninit(pdev);
	ys_aux_mbox_dev_uninit(pdev);
	ys_irq_uninit(pdev);
	ys_qset_pool_uninit(pdev);
	pdev_priv->nic_type->hw_pdev_uninit(pdev_priv);
	bitmap_clear(g_ys_pdev_manager.pf_index, pdev_priv->index, 1);
	ys_queue_clear(pdev);
	ys_pdev_unmap(pdev_priv);
	pci_set_drvdata(pdev, NULL);
	pci_clear_master(pdev);
	pci_disable_device(pdev);
	pci_release_regions(pdev);

	pdev_list = &pdev_priv->pdev_manager->pdev_list;
	list_for_each_entry_safe(pdev_pr, temp, pdev_list, list) {
		if (pdev_pr->index == pdev_priv->index)
			list_del(&pdev_pr->list);
	}

	/* get pdev_priv of pf */
	if (pdev->is_virtfn) {
		pfdev = pci_physfn(pdev);
		pfdev_priv = pci_get_drvdata(pfdev);
		if (!pfdev_priv)
			return;
	} else {
		pfdev_priv = pdev_priv;
	}

	list_for_each_entry_safe(umem, temp_umem, &pfdev_priv->umem_list, list) {
		/*
		 * release dma map resources belong to this function, if it is
		 * physical function, it will release umem of vf when disabling
		 * SRIOV.
		 */
		if (umem->dev == &pdev->dev)
			ys_umem_unmap(umem);
	}

	ys_devlink_release(devlink);
}

void ys_pdev_manager_init(void)
{
	static bool init;
	const struct ysif_ops *ops = ysif_get_ops();

	if (init)
		return;
	
	ops->bitmap_zero(g_ys_pdev_manager.eth_dev_id, YS_DEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.sf_dev_id, YS_DEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.rep_dev_id, YS_DEV_MAX);

	ops->bitmap_zero(g_ys_pdev_manager.i2c_dev_id, YS_PDEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.ptp_dev_id, YS_PDEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.lan_dev_id, YS_PDEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.mac_dev_id, YS_PDEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.mbox_dev_id, YS_PDEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.np_dev_id, YS_PDEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.pf_index, YS_PDEV_MAX);
	ops->bitmap_zero(g_ys_pdev_manager.vdpa_dev_id, YS_PDEV_MAX);

	ops->INIT_LIST_HEAD(&g_ys_pdev_manager.pdev_list);

	g_ys_pdev_manager.doe_ops = NULL;
	ops->yspin_lock_init(&g_ys_pdev_manager.doe_manager_lock);
	ops->yspin_lock_init(&g_ys_pdev_manager.doe_schedule_lock);
	ops->INIT_LIST_HEAD(&g_ys_pdev_manager.doe_schedule_list);

	init = true;
}

struct pci_dev *ys_pdev_find_another_pf(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_pdev_priv *pdev_pr, *temp;
	struct list_head *pdev_list;

	pdev_priv = pci_get_drvdata(pdev);
	if (pdev_priv->nic_type->is_vf)
		return NULL;

	pdev_list = &pdev_priv->pdev_manager->pdev_list;
	list_for_each_entry_safe(pdev_pr, temp, pdev_list, list) {
		if (pdev_pr->index != pdev_priv->index &&
		    !pdev_pr->nic_type->is_vf &&
		    pdev_pr->pdev->bus == pdev_priv->pdev->bus &&
		    PCI_SLOT(pdev_pr->pdev->devfn) == PCI_SLOT(pdev_priv->pdev->devfn) &&
		    ((PCI_FUNC(pdev_priv->pdev->devfn) == 0x1) ?
		     (PCI_FUNC(pdev_pr->pdev->devfn) == 0x0) :
		     (PCI_FUNC(pdev_pr->pdev->devfn) == 0x1)))
			return pdev_pr->pdev;
	}

	return NULL;
}

int ys_pdev_init(struct pci_driver *pdrv)
{
	int ret = 0;
	const struct ysif_ops *ops = ysif_get_ops();
	ret = ops->ypci_register_driver(pdrv);
	if (ret) {
		ys_err("PCI driver registration failed\n");
		return -1;
	}

	return 0;
}

void ys_pdev_uninit(struct pci_driver *pdrv)
{
	pci_unregister_driver(pdrv);
}

