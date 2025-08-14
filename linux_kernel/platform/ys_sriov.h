/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YS_SRIOV_H_
#define __YS_SRIOV_H_

#include <linux/etherdevice.h>
#include <linux/pci.h>

#include "ys_auxiliary.h"
#include "ys_pdev.h"

struct ys_vf_info {
	u16 vf_id;
	struct pci_dev *vfdev;
	u8 vf_mac_addresses[ETH_ALEN];
	u16 vf_vlan;
	u8 is_vf_vlan_1;
	u16 vf_inner_vlan_count;
	int vf_tx_rate;
	u16 qbase;
	u8 netdev_qnum;
	u8 func_qnum;
	u16 qset;
	u8 trusted;
	u8 rx_mtr_enabled;
	u64 rx_rate;
	u64 rx_burst;
	u32 link_state;
	u8 promisc_mode;
	u8 spoofchk;
	/* Whether vf has completed initialization */
	u8 done;
};

struct ys_sriov {
	u16 num_vfs;
	struct ys_vf_info *vfinfo;
	/*
	 * Vfs always use the queue with the largest index, for example 4vfs:
	 *    pf       q0   - q31
	 *    unuesd   q32  - q351
	 *    sf250    q352 - q383
	 *    vf0      q384 - q415
	 *    vf1      q416 - q447
	 *    vf2      q448 - q479
	 *    vf3      q480 - q511
	 *
	 * In this case:
	 *    vfs_total_qnum = 128,
	 *    num_vfs = 4,
	 *    pdev_priv->total_qnum = 512,
	 *    pdev_priv->avail_qnum = 384,
	 *    eth.0->qbase = 0,
	 *    sf.250->qbase = 352,
	 *    vf0->qbase = 384
	 *
	 * To simplify queue management, sf must growned after vf if both
	 * of them exist.
	 */
	u16 vfs_total_qnum;
	u16 rep_ratio;

	/* max capability from dma such as k2 */
	u16 max_vfs;
	u16 vf_max_qnum;
	/*
	 * This variable represents the minimum number of queues
	 * required to create each VF.
	 */
	u16 vf_min_qnum;
};

void ys_disable_sriov(struct pci_dev *pdev);
int ys_sriov_configure(struct pci_dev *pdev, int num_vfs);

#endif /* __YS_SRIOV_H_ */
