// SPDX-License-Identifier: GPL-2.0

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/rtc.h>

#include "ys_intr.h"
#include "ys_ndev.h"
#include "ys_pdev.h"
#include "ys_sriov.h"

#include "ys_debug.h"
#include "ys_reg_ops.h"

#include "../net/lan/ys_lan.h"
#include "../net/ys_ndev_ops.h"

static void ys_get_vfs(struct ys_pdev_priv *pdev_priv)
{
	struct pci_dev *pdev = pdev_priv->pdev;
	u16 vendor = pdev->vendor;
	struct pci_dev *vfdev;
	int vf = 0;
	u16 vf_id;
	int pos;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return;

	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_DID, &vf_id);

	vfdev = pci_get_device(vendor, vf_id, NULL);
	for (; vfdev; vfdev = pci_get_device(vendor, vf_id, vfdev)) {
		if (!vfdev->is_virtfn)
			continue;
		if (vfdev->physfn != pdev)
			continue;
		if (vf >= pdev_priv->sriov_info.num_vfs)
			continue;
		pci_dev_get(vfdev);
		pdev_priv->sriov_info.vfinfo[vf].vfdev = vfdev;
		++vf;
	}
}

static void generate_vf_mac(const u8 *base_mac, u8 *dst_mac, u16 stride)
{
	u32 complex_mac;

	if (!base_mac || !dst_mac)
		return;

	complex_mac = base_mac[2];
	complex_mac |= (base_mac[1] << 8);
	complex_mac |= (base_mac[0] << 16);
	complex_mac += stride;
	memcpy(dst_mac, base_mac, ETH_ALEN);
	dst_mac[0] = (complex_mac >> 16) & 0xff;
	dst_mac[1] = (complex_mac >> 8) & 0xff;
	dst_mac[2] = complex_mac & 0xff;
}

static int ys_enable_sriov(struct pci_dev *pdev, int num_vfs)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct net_device *ndev = ys_aux_match_eth(pdev, 0);
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_vf_info *vf_info;
	u16 pre_existing_vfs;
	u16 func_qnum;
	u16 min_vf_qnum;
	u16 qbase;
	int ret = 0;
	int i;

	pre_existing_vfs = pci_num_vf(pdev);
	if (pre_existing_vfs) {
		if (pre_existing_vfs != num_vfs)
			return -EBUSY;
		else
			return num_vfs;
	}

	/* check max vfs */
	if (pdev_priv->sriov_info.max_vfs < num_vfs)
		return -EINVAL;

	/* Allocate memory for per VF control structures */
	pdev_priv->sriov_info.vfinfo =
		kcalloc(num_vfs, sizeof(struct ys_vf_info), GFP_KERNEL);
	if (!pdev_priv->sriov_info.vfinfo)
		return -ENOMEM;

	pdev_priv->sriov_info.num_vfs = num_vfs;

	/* Allocate queue resources */
	min_vf_qnum = max_t(u16, pdev_priv->sriov_info.vf_min_qnum, 1);
	func_qnum = pdev_priv->sriov_info.max_vfs * min_vf_qnum / num_vfs;
	if (pdev_priv->dpu_mode == MODE_SMART_NIC && pdev_priv->sriov_info.rep_ratio) {
		func_qnum = pdev_priv->sriov_info.max_vfs / num_vfs;
		func_qnum -= max_t(u16, 1, func_qnum / (pdev_priv->sriov_info.rep_ratio + 1));
		if (!func_qnum) {
			ys_dev_err("queue resource isn't enough!!!!, please reduce vf number");
			kfree(pdev_priv->sriov_info.vfinfo);
			return -EINVAL;
		}
	}
	func_qnum = min_t(u16, pdev_priv->sriov_info.vf_max_qnum, func_qnum);
	pdev_priv->sriov_info.vfs_total_qnum = func_qnum * num_vfs;
	qbase = pdev_priv->total_qnum - pdev_priv->sriov_info.vfs_total_qnum;

	for (i = 0; i < num_vfs; i++) {
		vf_info = &pdev_priv->sriov_info.vfinfo[i];
		vf_info->vf_id = i;
		vf_info->qbase = qbase;
		vf_info->qset = 0;
		vf_info->func_qnum = func_qnum;
		qbase += func_qnum;

		ys_queue_set_info(pdev_priv->pdev, QUEUE_TYPE_TX,
				  vf_info->qbase, 0,
				  vf_info->func_qnum,
				  0, true, vf_info->vf_id, -1);
		ys_queue_set_info(pdev_priv->pdev, QUEUE_TYPE_RX,
				  vf_info->qbase, 0,
				  vf_info->func_qnum,
				  0, true, vf_info->vf_id, -1);

		/* assign random mac addr for pf */
		generate_vf_mac(ndev->dev_addr, vf_info->vf_mac_addresses,
				vf_info->vf_id + 1);

		ys_dev_info("Set vf%d MAC address to %02x:%02x:%02x:%02x:%02x:%02x\n",
			    i, vf_info->vf_mac_addresses[0],
			    vf_info->vf_mac_addresses[1],
			    vf_info->vf_mac_addresses[2],
			    vf_info->vf_mac_addresses[3],
			    vf_info->vf_mac_addresses[4],
			    vf_info->vf_mac_addresses[5]);

		vf_info->vf_vlan = 0;
		vf_info->is_vf_vlan_1 = 0;
		vf_info->vf_inner_vlan_count = 0;

		/* init value for qos */
		vf_info->vf_tx_rate = 0;

		vf_info->link_state = IFLA_VF_LINK_STATE_AUTO;
		vf_info->promisc_mode = 0;
		vf_info->done = 0;
		vf_info->spoofchk = 0;
	}

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_sriov_enable)) {
		ret = pdev_priv->ops->hw_adp_sriov_enable(pdev, num_vfs);
		if (ret)
			goto err_with_vfinfo;
	}

	/* lan update must be after than hw_adp enable */
	if (pdev_priv->nic_type->lan_type == LAN_TYPE_K2)
		for (i = 0; i < num_vfs; i++) {
			if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_cfg))
				ret = ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, i + 1);
			if (ret) {
				ys_dev_err("update switch failed for vfnum=%d\n",
					   i + 1);
				goto err_with_lan;
			}

			if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_vf_vlan))
				ret = ndev_priv->ys_ndev_hw->ys_set_port_vf_vlan(ndev,
										 i,
										 0,
										 0,
										 0,
										 true);
		}

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret) {
		ys_dev_warn("Failed to enable PCI sriov: %d\n", ret);
		goto err_with_lan;
	}

	ys_get_vfs(pdev_priv);

	for (i = 0; i < num_vfs; i++) {
		/* disables rate limiting */
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_set_port_vf_rate))
			ndev_priv->ys_ndev_hw->ys_set_port_vf_rate(ndev, i, 0, 0);
	}

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_sriov_config_change))
		pdev_priv->ops->hw_adp_sriov_config_change(pdev);

	if (pdev_priv->nic_type->lan_type == NP_TYPE_K2 &&
	    !IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_vf_cfg))
		for (i = 0; i < num_vfs; i++) {
			ndev_priv->ys_ndev_hw->ys_update_vf_cfg(ndev, i + 1,
								YS_MBOX_OPCODE_SET_RXFH,
								NULL);
		}

	return num_vfs;

err_with_lan:
	if (pdev_priv->nic_type->lan_type == LAN_TYPE_K2)
		for (; i >= 0; i--)
			if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_delete_cfg))
				ret = ndev_priv->ys_ndev_hw->ys_delete_cfg(ndev, i + 1);
err_with_vfinfo:
	for (i = 0; i < num_vfs; i++) {
		vf_info = &pdev_priv->sriov_info.vfinfo[i];
		ys_queue_clear_info(pdev_priv->pdev, QUEUE_TYPE_TX,
				    vf_info->qbase, vf_info->func_qnum);
		ys_queue_clear_info(pdev_priv->pdev, QUEUE_TYPE_RX,
				    vf_info->qbase, vf_info->func_qnum);
	}

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_sriov_disable))
		pdev_priv->ops->hw_adp_sriov_disable(pdev_priv->pdev);

	pdev_priv->sriov_info.vfs_total_qnum = 0;
	/* free VF control structures */
	kfree(pdev_priv->sriov_info.vfinfo);
	pdev_priv->sriov_info.vfinfo = NULL;

	return ret;
}

void ys_disable_sriov(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct net_device *ndev = ys_aux_match_eth(pdev, 0);
	struct ys_ndev_priv *ndev_priv = NULL;
	u32 num_vfs = pdev_priv->sriov_info.num_vfs;
	struct ys_vf_info *vf_info;
	struct pci_dev *vfdev;
	int i;

	if (!ys_pdev_supports_sriov(pdev_priv->pdev))
		return;

	/* reset vf configs which configured by pf */
	for (i = 0; i < num_vfs; i++) {
		if (IS_ERR_OR_NULL(ndev))
			break;
		ndev_priv = netdev_priv(ndev);
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_reset_vf_cfg))
			ndev_priv->ys_ndev_hw->ys_reset_vf_cfg(ndev, i);
	}

	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(pdev_priv->pdev);

	if (IS_ERR_OR_NULL(pdev_priv->sriov_info.vfinfo))
		return;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_sriov_disable))
		pdev_priv->ops->hw_adp_sriov_disable(pdev_priv->pdev);

	for (i = 0; i < num_vfs; i++) {
		vf_info = &pdev_priv->sriov_info.vfinfo[i];
		ys_queue_clear_info(pdev_priv->pdev, QUEUE_TYPE_TX,
				    vf_info->qbase, vf_info->func_qnum);
		ys_queue_clear_info(pdev_priv->pdev, QUEUE_TYPE_RX,
				    vf_info->qbase, vf_info->func_qnum);

		/* put the reference to all of the vf devices */
		vfdev = pdev_priv->sriov_info.vfinfo[i].vfdev;
		if (IS_ERR_OR_NULL(vfdev))
			continue;

		pdev_priv->sriov_info.vfinfo[i].vfdev = NULL;
		pci_dev_put(vfdev);
	}

	pdev_priv->sriov_info.vfs_total_qnum = 0;

	/* free VF control structures */
	kfree(pdev_priv->sriov_info.vfinfo);
	pdev_priv->sriov_info.vfinfo = NULL;

	/* set num VFs to 0 to prevent access to vfinfo */
	pdev_priv->sriov_info.num_vfs = 0;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_sriov_config_change))
		pdev_priv->ops->hw_adp_sriov_config_change(pdev);
}

int ys_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct net_device *ndev;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	int ret = 0;

	if (pdev_priv->nic_type->is_vf)
		return -EPERM;

	if (pdev_priv->dpu_mode == MODE_SMART_NIC)
		ndev = ys_aux_match_rep(pdev, 0x200);
	else
		ndev = ys_aux_match_eth(pdev, 0);

	if (ndev) {
		ndev_priv = netdev_priv(ndev);
		if (ndev_priv->umd_enable) {
			ys_dev_warn("Userspace driver must be stop before SRIOV config\n");
			return -EPERM;
		}
	}

	/* record the number of vf for umd at smartnic mode */
	pdev_priv->sum_vf = num_vfs;

	if (num_vfs) {
		ret = ys_enable_sriov(pdev, num_vfs);
	} else {
		/* If our VFs are assigned we cannot shut down SR-IOV
		 * without causing issues, so just leave the hardware
		 * available but disabled
		 */
		if (pci_vfs_assigned(pdev_priv->pdev)) {
			ys_dev_warn("Unloading driver while VFs are assigned - VFs will not be deallocated\n");
			return -EPERM;
		}
		ys_disable_sriov(pdev);
	}

	return ret;
}
