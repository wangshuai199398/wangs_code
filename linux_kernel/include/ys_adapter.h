/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_ADPTER_H_
#define __YS_ADPTER_H_

#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/pci.h>

#include <linux/auxiliary_bus.h>
struct hw_adapter_ops {
	int (*hw_adp_init)(struct net_device *ndev);
	void (*hw_adp_uninit)(struct net_device *ndev);
	int (*hw_adp_start)(struct net_device *ndev);
	void (*hw_adp_stop)(struct net_device *ndev);
	void (*hw_adp_update_stat)(struct net_device *ndev);
	int (*hw_adp_send)(struct sk_buff *skb, struct net_device *ndev);
	int (*hw_adp_get_init_irq_sub)(struct pci_dev *pdev, int index,
				       void *irq_sub);
	int (*hw_adp_irq_pre_init)(struct pci_dev *pdev);
	int (*hw_adp_get_init_qbase)(struct pci_dev *pdev);
	int (*hw_adp_get_init_qnum)(struct pci_dev *pdev);
	void (*hw_adp_get_mac)(struct net_device *ndev);
	int (*hw_adp_detect_sysfs_attrs)(struct device_attribute **attrs);
	int (*hw_adp_sriov_enable)(struct pci_dev *pdev, u32 num_vfs);
	int (*hw_adp_sriov_config_change)(struct pci_dev *pdev);
	int (*hw_adp_sriov_disable)(struct pci_dev *pdev);
	int (*hw_adp_i2c_init)(struct pci_dev *pdev);
	int (*hw_adp_ptp_init)(struct pci_dev *pdev);
	void (*hw_adp_ptp_uninit)(struct pci_dev *pdev);
	int (*hw_adp_ndo_ioctl)(struct net_device *ndev, struct ifreq *ifr, int cmd);
	int (*hw_adp_add_cdev)(struct pci_dev *pdev);
	int (*hw_adp_mbox_init)(struct pci_dev *pdev);
	int (*hw_adp_mbox_uninit)(struct pci_dev *pdev);
	int (*hw_adp_rep_update)(struct pci_dev *pdev, u32 vf_nums);
	void * (*hw_adp_vdpa_init)(struct pci_dev *pdev);
	void (*hw_adp_vdpa_uninit)(struct pci_dev *pdev);

	int (*hw_adp_doe_init)(struct auxiliary_device *auxdev);
	void (*hw_adp_doe_uninit)(struct auxiliary_device *auxdev);

	int (*hw_adp_np_init)(struct auxiliary_device *auxdev);
	void (*hw_adp_np_uninit)(struct auxiliary_device *auxdev);
	int (*hw_adp_np_set_cfg)(struct pci_dev *pdev, u16 type, u16 val);
	int (*hw_adp_np_bond_set_cfg)(struct pci_dev *pdev, u8 bond_id, bool enable, u32 val);
	int (*hw_adp_np_bond_linkstatus_set_cfg)(struct pci_dev *pdev, u16 port_id, bool enable);

	int (*mac_adp_eth_init)(struct net_device *ndev);
	void (*mac_adp_eth_uninit)(struct net_device *ndev);
	int (*mac_adp_ndev_init)(struct net_device *ndev);
	void (*mac_adp_ndev_uninit)(struct net_device *ndev);
	int (*lan_adp_eth_init)(struct net_device *ndev);
	void (*lan_adp_eth_uninit)(struct net_device *ndev);
	int (*lan_adp_ndev_init)(struct net_device *ndev);
	void (*lan_adp_ndev_uninit)(struct net_device *ndev);
	int (*lan_adp_devlink_init)(struct pci_dev *pdev);
	int (*np_adp_ndev_init)(struct net_device *ndev);
	void (*np_adp_ndev_uninit)(struct net_device *ndev);

	bool (*ndev_has_mac_link_status)(struct net_device *ndev);
	int (*ndev_adp_detect_sysfs_attrs)(struct device_attribute **attrs);
	int (*hw_adp_cdev_start)(struct net_device *ndev, bool start, u16 txqnum, u16 rxqnum);
	int (*hw_adp_cdev_qgroup_get)(struct net_device *ndev, u16 qid);
	int (*hw_adp_cdev_qgroup_set)(struct net_device *ndev, u16 qid, u16 qgroup);
	int (*hw_adp_cdev_qos_sync)(struct net_device *ndev, u16 qid);
	int (*hw_adp_cdev_link_gqbase_get)(struct net_device *ndev, u16 *qstart, u16 *qnum);
	u16 (*hw_adp_cdev_peer_qset_get)(struct net_device *ndev);
};

#endif /* __YS_ADPTER_H_ */
