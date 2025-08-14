// SPDX-License-Identifier: GPL-2.0

#include <linux/pci.h>
#include <net/devlink.h>
#include <linux/idr.h>

#include "ys_auxiliary.h"
#include "ys_cdev.h"
#include "ys_debug.h"
#include "ys_devlink.h"
#include "ys_intr.h"
#include "ys_ndev.h"
#include "ys_pdev.h"
#include "ys_queue.h"

void ys_queue_clear(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int i;

	for (i = 0; i < YS_MAX_QUEUES; i++) {
		pdev_priv->txq_res[i].is_used = false;
		pdev_priv->txq_res[i].index = -1;
		pdev_priv->txq_res[i].qset = -1;
		pdev_priv->txq_res[i].type = QUEUE_TYPE_TX;
		pdev_priv->txq_res[i].is_vf = false;
		pdev_priv->txq_res[i].vf_id = -1;

		pdev_priv->rxq_res[i].is_used = false;
		pdev_priv->rxq_res[i].index = -1;
		pdev_priv->rxq_res[i].qset = -1;
		pdev_priv->rxq_res[i].type = QUEUE_TYPE_RX;
		pdev_priv->rxq_res[i].is_vf = false;
		pdev_priv->rxq_res[i].vf_id = -1;
	}
}

void ys_queue_set_info(struct pci_dev *pdev,
		       enum ys_queue_type type, int qbase, int qset,
		       int qcount, int index, int is_vf, int vf_id, int pio_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_queue_info *queue_info;
	int i;

	if (type == QUEUE_TYPE_TX)
		queue_info = pdev_priv->txq_res;
	else
		queue_info = pdev_priv->rxq_res;

	for (i = qbase; i < qbase + qcount; i++) {
		queue_info[i].is_used = true;
		queue_info[i].index = index;
		queue_info[i].qset = qset;
		queue_info[i].is_vf = is_vf;
		queue_info[i].vf_id = vf_id;
		queue_info[i].pio_id = pio_id;
	}
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_queue_set_info);
#endif /* CONFIG_YSARCH_PLAT */

void ys_queue_update_info(struct net_device *ndev,
			  int is_vf,
			  int vf_id)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	ys_queue_set_info(ndev_priv->pdev, QUEUE_TYPE_TX,
			  ndev_priv->qi.qbase, ndev_priv->qi.qset,
			  ndev_priv->qi.ndev_qnum,
			  ndev->dev_port, is_vf, vf_id, -1);
	ys_queue_set_info(ndev_priv->pdev, QUEUE_TYPE_RX,
			  ndev_priv->qi.qbase, ndev_priv->qi.qset,
			  ndev_priv->qi.ndev_qnum,
			  ndev->dev_port, is_vf, vf_id, -1);
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_queue_update_info);
#endif /* CONFIG_YSARCH_PLAT */

void ys_queue_clear_info(struct pci_dev *pdev,
			 enum ys_queue_type type,
			 int qbase,
			 int qcount)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_queue_info *queue_info;
	int i;

	if (type == QUEUE_TYPE_TX)
		queue_info = pdev_priv->txq_res;
	else
		queue_info = pdev_priv->rxq_res;

	for (i = qbase; i < qbase + qcount; i++) {
		queue_info[i].is_used = false;
		queue_info[i].index = -1;
		queue_info[i].qset = -1;
		queue_info[i].is_vf = false;
		queue_info[i].vf_id = -1;
		queue_info[i].pio_id = -1;
	}
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_queue_clear_info);
#endif /* CONFIG_YSARCH_PLAT */

bool ys_queue_check_info(struct pci_dev *pdev,
			 enum ys_queue_type type,
			 int qbase,
			 int qcount)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_queue_info *queue_info;
	int i;

	if (type == QUEUE_TYPE_TX)
		queue_info = pdev_priv->txq_res;
	else
		queue_info = pdev_priv->rxq_res;

	for (i = qbase; i < qbase + qcount; i++)
		if (!queue_info[i].is_used)
			return false;

	return true;
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_queue_check_info);
#endif /* CONFIG_YSARCH_PLAT */

int ys_queue_cal_vf_max_queue(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int num_vfs;
	u16 min_vf_qnum;
	u16 ndev_qnum;
	u16 vfs_total_qnum;
	u16 vfs_max_qnum = 0;

	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return 0;

	/* When the device supports SR-IOV,
	 * the allocation scheme for all VFs will occupy
	 * the maximum number of queues,
	 * will cal vfs_max_qnum.
	 * Therefore, when determining the available queue range here,
	 * it should be total_qnum - vfs_max_qnum.
	 */

	for (num_vfs = 1; num_vfs < pdev_priv->sriov_info.max_vfs + 1; num_vfs++) {
		min_vf_qnum = max_t(u16, pdev_priv->sriov_info.vf_min_qnum, 1);
		ndev_qnum = pdev_priv->sriov_info.max_vfs * min_vf_qnum / num_vfs;
		ndev_qnum = min_t(u16, pdev_priv->sriov_info.vf_max_qnum, ndev_qnum);
		vfs_total_qnum = ndev_qnum * num_vfs;
		vfs_max_qnum = max_t(u16, vfs_total_qnum, vfs_max_qnum);
	}

	ys_dev_debug("vfs_max_qnum: %d\n", vfs_max_qnum);
	return vfs_max_qnum;
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_queue_cal_vf_max_queue);
#endif /* CONFIG_YSARCH_PLAT */

int ys_queue_find_available_base(struct pci_dev *pdev,
				 enum ys_queue_type type,
				 int qcount)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_queue_info *queue_info;
	int i, j, available_count;
	int func_qnum = 0;

	if (type == QUEUE_TYPE_TX)
		queue_info = pdev_priv->txq_res;
	else
		queue_info = pdev_priv->rxq_res;

	func_qnum = max_t(u32, pdev_priv->func_qnum,
			  pdev_priv->nic_type->ndev_qcount);

	for (i = 0; i <= func_qnum - qcount; i++) {
		available_count = 0;
		for (j = i; j < i + qcount; j++) {
			if (!queue_info[j].is_used)
				available_count++;
			else
				break;
		}
		if (available_count == qcount)
			return i;
	}

	return -1;
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_queue_find_available_base);
#endif /* CONFIG_YSARCH_PLAT */

int ys_qset_get_id(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int ret;

	if (pdev_priv->qset_pool.qset_end <= 0 ||
	    pdev_priv->qset_pool.qset_end > YS_MAX_QSET) {
		ys_dev_err("Invalid max_qset: %d\n",
			   pdev_priv->qset_pool.qset_end);
		return -EINVAL;
	}

	if (pdev_priv->qset_pool.qset_start >= pdev_priv->qset_pool.qset_end) {
		ys_dev_err("Invalid qset range: %d - %d\n",
			   pdev_priv->qset_pool.qset_start,
			   pdev_priv->qset_pool.qset_end);
		return -EINVAL;
	}

	spin_lock(&pdev_priv->qset_pool.lock);
	ret = idr_alloc(&pdev_priv->qset_pool.pool, NULL,
			pdev_priv->qset_pool.qset_start,
			pdev_priv->qset_pool.qset_end,
			GFP_ATOMIC);
	spin_unlock(&pdev_priv->qset_pool.lock);

	if (ret >= 0) {
		ys_dev_info("Allocated Qset ID: %d\n", ret);
		return ret;
	}

	ys_dev_err("Failed to allocate ID\n");
	return ret;
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_qset_get_id);
#endif /* CONFIG_YSARCH_PLAT */

void ys_qset_release_id(struct pci_dev *pdev, int id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	spin_lock(&pdev_priv->qset_pool.lock);
	idr_remove(&pdev_priv->qset_pool.pool, id);
	spin_unlock(&pdev_priv->qset_pool.lock);
	ys_dev_info("Release Qset ID: %d\n", id);
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_qset_release_id);
#endif /* CONFIG_YSARCH_PLAT */

void ys_qset_pool_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	idr_init(&pdev_priv->qset_pool.pool);
	spin_lock_init(&pdev_priv->qset_pool.lock);
}

void ys_qset_pool_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	idr_destroy(&pdev_priv->qset_pool.pool);
}
