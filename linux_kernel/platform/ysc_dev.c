// SPDX-License-Identifier: GPL-2.0

#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/inetdevice.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/property.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <net/rtnetlink.h>
#include <linux/iommu.h>
#include <linux/cdev.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/rbtree.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/nospec.h>
#include <linux/slab.h>

#include "ysc_dev.h"
#include "ysnic.h"

#include "ysif_linux.h"

#define YSC_DEV_NAME "yusur"

struct ysc_dev {
	struct miscdevice mdev;
	atomic_t refcnt;
};

typedef long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);

struct ysc_cfgsave {
	struct list_head node;
	int type;
	u8 data[];
};

struct ysc_page_map {
	u64 vaddr;
	size_t npages;
	struct page **pages;
};

struct ysc_priv {
	struct ys_pdev_priv *pdev_priv;
	struct ys_adev *adev;
	struct net_device *ndev;
	struct ys_ndev_priv *ndev_priv;

	/* config */
	struct list_head cfgsave_head;
	u64 cfgchange_flags;
	bool umd_enabled;

	/* dma map */
	struct ys_dmamap_table *dmamap_table;
};

static struct ysc_dev ysc_dev;

static struct ys_adev *ysc_find_adev(struct ys_pdev_priv *pdev_priv, struct ysc_comm_devid *devid);

static struct ys_pdev_priv *ysc_find_pdev_priv(struct ysc_comm_devid *devid)
{
	struct list_head *pdev_list;
	struct ys_pdev_priv *pdev_pos, *ptemp;
	s32 domain;
	u8 bus, deviceid, function;

	pdev_list = &g_ys_pdev_manager.pdev_list;

	switch (devid->type) {
	case YSC_COMM_DEVTYPE_REP:
		domain = devid->rep.domain;
		bus = devid->rep.bus;
		deviceid = devid->rep.devid;
		function = devid->rep.function;
		break;
	case YSC_COMM_DEVTYPE_PCI:
		domain = devid->pci.domain;
		bus = devid->pci.bus;
		deviceid = devid->pci.devid;
		function = devid->pci.function;
		break;
	case YSC_COMM_DEVTYPE_NDEV:
		domain = 0;	/* for compile warn */
		bus = 0;
		deviceid = 0;
		function = 0;
		break;
	default:
		return NULL;
	}

	list_for_each_entry_safe(pdev_pos, ptemp, pdev_list, list) {
		if (devid->type != YSC_COMM_DEVTYPE_NDEV &&
		    pci_domain_nr(pdev_pos->pdev->bus) == domain &&
		    pdev_pos->pdev->bus->number == bus &&
		    PCI_SLOT(pdev_pos->pdev->devfn) == deviceid &&
		    PCI_FUNC(pdev_pos->pdev->devfn) == function)
			return pdev_pos;
		if (devid->type == YSC_COMM_DEVTYPE_NDEV &&
		    !!ysc_find_adev(pdev_pos, devid))
			return pdev_pos;
	}

	return NULL;
}

static struct ys_adev *ysc_find_adev(struct ys_pdev_priv *pdev_priv, struct ysc_comm_devid *devid)
{
	struct list_head *adev_list;
	struct ys_adev *adev, *adev_pos, *atemp;
	struct net_device *ndev;

	adev_list = &pdev_priv->adev_list;

	adev = NULL;
	read_lock(&pdev_priv->adev_list_lock);
	list_for_each_entry_safe(adev_pos, atemp, adev_list, list) {
		if (devid->type == YSC_COMM_DEVTYPE_NDEV &&
		    (adev_pos->adev_type == AUX_TYPE_ETH ||
		     adev_pos->adev_type == AUX_TYPE_SF ||
		     adev_pos->adev_type == AUX_TYPE_REP)) {
			ndev = (struct net_device *)adev_pos->adev_priv;
			if (ndev->ifindex == devid->ndev.ifindex) {
				adev = adev_pos;
				break;
			}
		}

		if (devid->type == YSC_COMM_DEVTYPE_PCI &&
		    adev_pos->adev_type == AUX_TYPE_ETH) {
			adev = adev_pos;
			break;
		}

		if (devid->type == YSC_COMM_DEVTYPE_REP &&
		    adev_pos->adev_type == AUX_TYPE_REP &&
		    adev_pos->idx == devid->rep.rep_id) {
			adev = adev_pos;
			break;
		}
	}
	read_unlock(&pdev_priv->adev_list_lock);

	return adev;
}

static int ysc_cfg_save(struct ysc_priv *priv, int type, void *data, size_t size)
{
	size_t total_size;
	struct ysc_cfgsave *cfgsave;

	total_size = sizeof(*cfgsave) + size;

	cfgsave = kzalloc(total_size, GFP_KERNEL);
	if (!cfgsave)
		return -ENOMEM;

	INIT_LIST_HEAD(&cfgsave->node);
	cfgsave->type = type;
	memcpy(cfgsave->data, data, size);
	list_add_tail(&cfgsave->node, &priv->cfgsave_head);

	return 0;
}

static void ysc_cfg_restore(struct ysc_priv *priv,
			    void (*cb)(struct ysc_priv *priv, int type, void *data))
{
	struct ysc_cfgsave *cfgsave, *cfgsave_tmp;

	list_for_each_entry_safe(cfgsave, cfgsave_tmp, &priv->cfgsave_head, node) {
		if (priv->cfgchange_flags & (1 << cfgsave->type))
			cb(priv, cfgsave->type, cfgsave->data);
		list_del(&cfgsave->node);
		kfree(cfgsave);
	}
}

static void ysc_cfg_flags_set(struct ysc_priv *priv, int type)
{
	priv->cfgchange_flags |= (1 << type);
}

static int ysc_open(struct inode *inode, struct file *file)
{
	struct ysc_priv *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	file->private_data = priv;
	INIT_LIST_HEAD(&priv->cfgsave_head);

	return 0;
}

static int ysc_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret, i;
	struct ysc_priv *priv = file->private_data;
	struct ys_pdev_priv *pdev_priv = priv->pdev_priv;

	size_t req_size = vma->vm_end - vma->vm_start;
	u64 req_addr = vma->vm_pgoff << PAGE_SHIFT;

	u64 bar_addr = 0;
	u64 bar_size = 0;

	for (i = 0; i < BAR_MAX; i++) {
		if (req_addr == pdev_priv->bar_pa[i] &&
		    req_size == pdev_priv->bar_size[i]) {
			bar_addr = pdev_priv->bar_pa[i];
			bar_size = pdev_priv->bar_size[i];
			break;
		}
	}

	if (!bar_addr || !bar_size)
		return -EINVAL;

	ret = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, req_size,
			      pgprot_noncached(vma->vm_page_prot));

	return ret;
}

static long ysc_comm_dev_bind(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;
	void *data;
	struct ysc_priv *priv = file->private_data;
	struct ysc_comm_devid devid;

	if (copy_from_user(&devid, (void __user *)arg, sizeof(devid)))
		return -EFAULT;

	if (priv->pdev_priv)
		return -EEXIST;

	priv->pdev_priv = ysc_find_pdev_priv(&devid);
	if (!priv->pdev_priv)
		return -ENODEV;

	priv->adev = ysc_find_adev(priv->pdev_priv, &devid);
	if (!priv->adev)
		return -ENODEV;

	priv->ndev = (struct net_device *)priv->adev->adev_priv;
	priv->ndev_priv = netdev_priv(priv->ndev);

	if (!priv->ndev || !priv->ndev_priv)
		return -ENODEV;

	data = (void *)(priv->ndev->dev_addr);
	ret = ysc_cfg_save(priv, YSC_NET_MACADDR, data, ETH_ALEN);
	if (ret)
		return ret;

	ret = ysc_cfg_save(priv, YSC_NET_MTU, &priv->ndev->mtu, sizeof(priv->ndev->mtu));
	if (ret)
		return ret;

	ret = ysc_cfg_save(priv, YSC_NET_PROMISC, &priv->ndev->flags, sizeof(priv->ndev->flags));
	if (ret)
		return ret;

	ret = ysc_cfg_save(priv, YSC_NET_OFFLOADCAP, &priv->ndev->features,
			   sizeof(priv->ndev->features));
	if (ret)
		return ret;

	if (iommu_present(priv->pdev_priv->dev->bus)) {
		priv->dmamap_table = ys_dmamap_table_create(priv->pdev_priv->dev);
		if (!priv->dmamap_table)
			ys_err("dmamap table create failed!");
	}

	return 0;
}

static long ysc_net_devinfo(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ys_pdev_priv *pdev_priv = priv->pdev_priv;
	struct ysc_net_devinfo devinfo;
	void *pt_addr;
	dma_addr_t pt_dma_addr;

	if (copy_from_user(&devinfo, (void __user *)arg, sizeof(devinfo)))
		return -EFAULT;

	/* check iommu passthrough arg */
	pt_addr = dma_alloc_coherent(&pdev_priv->pdev->dev, 512,
				     &pt_dma_addr, GFP_KERNEL);
	if (!pt_addr)
		return -ENOMEM;

	if (virt_to_phys(pt_addr) == pt_dma_addr)
		devinfo.is_pt = true;
	else
		devinfo.is_pt = false;
	dma_free_coherent(&pdev_priv->pdev->dev, 512, pt_addr, pt_dma_addr);

	devinfo.mode = pdev_priv->dpu_mode;
	devinfo.pf_id = pdev_priv->pf_id;
	devinfo.vf_id = pdev_priv->vf_id;
	devinfo.vf_num = pdev_priv->sum_vf;
	devinfo.ifindex = priv->ndev->ifindex;
	devinfo.min_mtu = priv->ndev->min_mtu;
	devinfo.max_mtu = priv->ndev->max_mtu;

	if (copy_to_user((void __user *)arg, &devinfo, sizeof(devinfo)))
		return -EFAULT;

	return 0;
}

static long ysc_net_qinfo(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ys_adev *adev = priv->adev;
	struct ethtool_ringparam ringparam;
	struct ysc_net_qinfo qinfo;

	qinfo.qbase = adev->qi.qbase;
	qinfo.qnum = adev->qi.ndev_qnum;
	qinfo.real_qnum = priv->ndev->real_num_tx_queues;
	qinfo.qset_id = adev->qi.qset;

	if (priv->ndev_priv->ys_eth_hw->ys_get_ringparam) {
		priv->ndev_priv->ys_eth_hw->ys_get_ringparam(priv->ndev, &ringparam);
		qinfo.max_qdepth = ringparam.rx_max_pending;
		qinfo.min_qdepth = 64;
	} else {
		qinfo.max_qdepth = 1024;
		qinfo.min_qdepth = 1024;
	}

	if (copy_to_user((void __user *)arg, &qinfo, sizeof(qinfo)))
		return -EFAULT;

	return 0;
}

static int ysc_net_macaddr_set(struct net_device *ndev, void *addr)
{
	struct sockaddr sa;

	memcpy(sa.sa_data, addr, ETH_ALEN);
	return ndev->netdev_ops->ndo_set_mac_address(ndev, &sa);
}

static long ysc_net_macaddr(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct ysc_priv *priv = file->private_data;
	struct net_device *ndev = priv->ndev;
	struct ysc_net_macaddr macaddr;

	switch (_IOC_DIR(cmd)) {
	case _IOC_WRITE:
		if (copy_from_user(&macaddr, (void __user *)arg, sizeof(macaddr)))
			return -EFAULT;
		ret = ysc_net_macaddr_set(ndev, macaddr.addr);
		break;
	case _IOC_READ:
		memcpy(macaddr.addr, ndev->dev_addr, ETH_ALEN);
		if (copy_to_user((void __user *)arg, &macaddr, sizeof(macaddr)))
			return -EFAULT;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int ysc_net_mtu_set(struct net_device *ndev, int mtu)
{
	return ndev->netdev_ops->ndo_change_mtu(ndev, mtu);
}

static long ysc_net_mtu(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct ysc_priv *priv = file->private_data;
	struct net_device *ndev = priv->ndev;
	struct ysc_net_mtu mtu;

	switch (_IOC_DIR(cmd)) {
	case _IOC_WRITE:
		if (copy_from_user(&mtu, (void __user *)arg, sizeof(mtu)))
			return -EFAULT;
		ret = ysc_net_mtu_set(ndev, mtu.size);
		break;
	case _IOC_READ:
		mtu.size = (u16)(ndev->mtu);
		if (copy_to_user((void __user *)arg, &mtu, sizeof(mtu)))
			return -EFAULT;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static long ysc_net_linkinfo(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ys_ndev_priv *ndev_priv = priv->ndev_priv;
	struct ysc_net_linkinfo linkinfo;

	linkinfo.link_speed = ndev_priv->speed;
	linkinfo.link_duplex = !!ndev_priv->duplex;
	linkinfo.link_autoneg = !!(ndev_priv->port_flags & 0x1 << YS_PORT_FLAG_AUTONEG_ENABLE);

	if (copy_to_user((void __user *)arg, &linkinfo, sizeof(linkinfo)))
		return -EFAULT;
	return 0;
}

static void ysc_net_offloadcap_set(struct ys_ndev_priv *ndev_priv, netdev_features_t features)
{
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_features_set))
		ndev_priv->ys_ndev_hw->ys_features_set(ndev_priv->ndev, features);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_extra_features_set))
		ndev_priv->ys_ndev_hw->ys_extra_features_set(ndev_priv->ndev, features);
}

static void ysc_net_offload_cap_get(struct ys_ndev_priv *ndev_priv, struct ysc_net_offloadcap *cap)
{
	if (ndev_priv->features & NETIF_F_RXCSUM) {
		cap->rxsupport |= YSC_RXOLCAP_IPV4_CKSUM;
		cap->rxsupport |= YSC_RXOLCAP_UDP_CKSUM;
		cap->rxsupport |= YSC_RXOLCAP_TCP_CKSUM;
	}

	if (ndev_priv->features & NETIF_F_RXHASH)
		cap->rxsupport |= YSC_RXOLCAP_RSS_HASH;

	if (ndev_priv->features & NETIF_F_HW_CSUM) {
		cap->txsupport |= YSC_TXOLCAP_IPV4_CKSUM;
		cap->txsupport |= YSC_TXOLCAP_UDP_CKSUM;
		cap->txsupport |= YSC_TXOLCAP_TCP_CKSUM;
	}

	if (ndev_priv->features & NETIF_F_TSO) {
		cap->txsupport |= YSC_TXOLCAP_TCP_TSO;
		cap->txsupport |= YSC_TXOLCAP_UDP_TSO;
	}
}

static long ysc_net_offloadcap(struct file *file, unsigned int cmd, unsigned long arg)
{
	u64 tx_mask = 0;
	u64 rx_mask = 0;
	struct ysc_priv *priv = file->private_data;
	struct ys_ndev_priv *ndev_priv = priv->ndev_priv;
	struct ysc_net_offloadcap offloadcap = {0};

	switch (_IOC_DIR(cmd)) {
	case _IOC_READ:
		ysc_net_offload_cap_get(ndev_priv, &offloadcap);
		if (copy_to_user((void __user *)arg, &offloadcap, sizeof(offloadcap)))
			return -EFAULT;
		break;
	case _IOC_WRITE:
		if (copy_from_user(&offloadcap, (void __user *)arg, sizeof(offloadcap)))
			return -EFAULT;
		tx_mask = YSC_TXOLCAP_IPV4_CKSUM;
		tx_mask |= YSC_TXOLCAP_TCP_CKSUM;
		tx_mask |= YSC_TXOLCAP_UDP_CKSUM;

		rx_mask = YSC_RXOLCAP_IPV4_CKSUM;
		rx_mask |= YSC_RXOLCAP_UDP_CKSUM;
		rx_mask |= YSC_RXOLCAP_TCP_CKSUM;

		if (offloadcap.txconfig & tx_mask)
			ndev_priv->features |= NETIF_F_HW_CSUM;
		else
			ndev_priv->features &= ~NETIF_F_HW_CSUM;

		if (offloadcap.rxconfig & rx_mask)
			ndev_priv->features |= NETIF_F_RXCSUM;
		else
			ndev_priv->features &= ~NETIF_F_RXCSUM;

		if (offloadcap.txconfig & YSC_TXOLCAP_TCP_TSO)
			ndev_priv->features |= NETIF_F_TSO;
		else
			ndev_priv->features &= ~NETIF_F_TSO;

		if (offloadcap.rxconfig & NETIF_F_SG)
			ndev_priv->features |= NETIF_F_SG;
		else
			ndev_priv->features &= ~NETIF_F_SG;

		ysc_net_offloadcap_set(ndev_priv, ndev_priv->features);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static long ysc_net_promisc(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct net_device *ndev = priv->ndev;
	struct ys_ndev_priv *ndev_priv = priv->ndev_priv;
	struct ysc_net_promisc promisc;

	if (copy_from_user(&promisc, (void __user *)arg, sizeof(promisc)))
		return -EFAULT;

	if (promisc.enable && (ndev->flags & IFF_PROMISC))
		return 0;
	if (!promisc.enable && !(ndev->flags & IFF_PROMISC))
		return 0;

	if (promisc.enable)
		ndev->flags |= IFF_PROMISC;
	else
		ndev->flags &= ~IFF_PROMISC;
	ndev_priv->ys_ndev_hw->ys_set_rx_flags(ndev);

	return 0;
}

static struct ysc_page_map *ysc_page_map_alloc(u64 vaddr, size_t size)
{
	struct ysc_page_map *page_map;
	size_t npages = size >> PAGE_SHIFT;

	page_map = kzalloc(sizeof(*page_map) + (sizeof(struct page *) * npages), GFP_KERNEL);
	if (!page_map)
		return NULL;

	page_map->vaddr = vaddr;
	page_map->npages = npages;
	page_map->pages = (struct page **)((u8 *)page_map + sizeof(*page_map));

	return page_map;
}

static void ysc_page_map_free(struct ysc_page_map *page_map)
{
	kfree(page_map);
}

static void ysc_unpin_user_pages(struct page **pages, unsigned long npages)
{
	unpin_user_pages(pages, npages);
}

static void ys_dmamap_unmap_cb(void *opaque)
{
	struct page *page = opaque;

	ysc_unpin_user_pages(&page, 1);
}

static long ysc_net_dma_map(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;
	unsigned int flags;
	struct ysc_priv *priv = file->private_data;
	struct ysc_page_map *page_map;
	int i = 0;
	u64 paddr;
	u64 iova;
	struct ysc_net_dmamap dmamap;

	if (copy_from_user(&dmamap, (void __user *)arg, sizeof(dmamap)))
		return -EFAULT;

	if (!priv->dmamap_table)
		return -EOPNOTSUPP;

	if (!dmamap.len || ((dmamap.len | dmamap.iova | dmamap.vaddr) & ~PAGE_MASK))
		return -EINVAL;

	if (dmamap.iova + dmamap.len - 1 < dmamap.iova ||
	    dmamap.vaddr + dmamap.len - 1 < dmamap.vaddr)
		return -EINVAL;

	page_map = ysc_page_map_alloc(dmamap.vaddr, dmamap.len);
	if (!page_map)
		return -ENOMEM;

	/* should be flags = FOLL_WRITE | FOLL_LONGTERM; */
	flags = FOLL_WRITE;
	ret = pin_user_pages(page_map->vaddr, page_map->npages, flags,
			     page_map->pages, NULL);
	if (ret <= 0) {
		ysc_page_map_free(page_map);
		return ret;
	}

	if (ret != page_map->npages) {
		ysc_unpin_user_pages(page_map->pages, ret);
		ysc_page_map_free(page_map);
		return -ENOMEM;
	}

	for (i = 0, iova = dmamap.iova; i < page_map->npages; i++, iova += PAGE_SIZE) {
		paddr = page_to_pfn(page_map->pages[i]) << PAGE_SHIFT;
		ret = ys_dmamap_map(priv->dmamap_table, iova, PAGE_SIZE,
				    paddr, page_map->pages[i]);
		if (ret)
			goto failed;
	}

	ysc_page_map_free(page_map);

	return 0;

failed:
	for (i--; i >= 0; i--, iova -= PAGE_SIZE)
		ys_dmamap_unmap(priv->dmamap_table, iova, PAGE_SIZE, ys_dmamap_unmap_cb);
	ysc_unpin_user_pages(page_map->pages, page_map->npages);
	ysc_page_map_free(page_map);

	return ret;
}

static long ysc_net_dma_unmap(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ysc_net_dmamap dmamap;

	if (copy_from_user(&dmamap, (void __user *)arg, sizeof(dmamap)))
		return -EFAULT;

	if (!priv->dmamap_table)
		return -EOPNOTSUPP;

	if (!dmamap.len || ((dmamap.len | dmamap.iova | dmamap.vaddr) & ~PAGE_MASK))
		return -EINVAL;

	if (dmamap.iova + dmamap.len - 1 < dmamap.iova ||
	    dmamap.vaddr + dmamap.len - 1 < dmamap.vaddr)
		return -EINVAL;

	ys_dmamap_unmap(priv->dmamap_table, dmamap.iova, dmamap.len, ys_dmamap_unmap_cb);

	return 0;
}

static long ysc_net_umd(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ys_ndev_priv *ndev_priv = priv->ndev_priv;
	struct net_device *ndev = priv->ndev;
	struct ysc_net_umd umd;

	if (ndev_priv->tc_priv)
		return -EOPNOTSUPP;

	if (copy_from_user(&umd, (void __user *)arg, sizeof(umd)))
		return -EFAULT;

	mutex_lock(&ndev_priv->state_lock);

	if (umd.enable && ndev_priv->umd_enable) {
		mutex_unlock(&ndev_priv->state_lock);
		return -EINVAL;
	}

	if (!umd.enable && !ndev_priv->umd_enable) {
		mutex_unlock(&ndev_priv->state_lock);
		return 0;
	}

	mutex_unlock(&ndev_priv->state_lock);

	rtnl_lock();
	if (umd.enable) {
		ndev_priv->umd_enable = true;
		ndev_priv->features = ndev->features;
		ys_net_debug("umd enable");
		dev_close(ndev);
		priv->umd_enabled = true;
		netif_device_detach(ndev);
	} else {
		netif_device_attach(ndev);
		dev_open(ndev, NULL);
		ndev_priv->umd_enable = false;
		priv->umd_enabled = false;
		ys_net_debug("umd disable");
	}
	rtnl_unlock();

	return 0;
}

static long ysc_net_pcibar(struct file *file, unsigned int cmd, unsigned long arg)
{
	int bar;
	struct ysc_priv *priv = file->private_data;
	struct ysc_net_pcibar pcibar;

	if (copy_from_user(&pcibar, (void __user *)arg, sizeof(pcibar)))
		return -EFAULT;

	bar = pcibar.req.bar_idx;
	if (bar < 0 || bar >= BAR_MAX)
		return -EINVAL;

	bar = array_index_nospec(bar, BAR_MAX);
	pcibar.rsp.bar_addr = priv->pdev_priv->bar_pa[bar];
	pcibar.rsp.bar_size = priv->pdev_priv->bar_size[bar];
	pcibar.rsp.bar_offset = priv->pdev_priv->bar_offset[bar];

	if (copy_to_user((void __user *)arg, &pcibar, sizeof(pcibar)))
		return -EFAULT;

	return 0;
}

static long ysc_net_start(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ysc_net_start start;

	if (copy_from_user(&start, (void __user *)arg, sizeof(start)))
		return -EFAULT;

	if (priv->pdev_priv->ops->hw_adp_cdev_start)
		return priv->pdev_priv->ops->hw_adp_cdev_start(priv->ndev, start.enable,
							       start.txqnum, start.rxqnum);
	else
		return -EOPNOTSUPP;
}

static long ysc_net_peer_qset(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ysc_net_peer_qset peer_qset;

	if (!priv->pdev_priv->ops->hw_adp_cdev_peer_qset_get)
		return -EOPNOTSUPP;

	if (copy_from_user(&peer_qset, (void __user *)arg, sizeof(peer_qset)))
		return -EFAULT;

	peer_qset.qset_id = priv->pdev_priv->ops->hw_adp_cdev_peer_qset_get(priv->ndev);

	if (copy_to_user((void __user *)arg, &peer_qset, sizeof(peer_qset)))
		return -EFAULT;

	return 0;
}

static int ysc_qos_qgroup_get(struct ysc_priv *priv, struct ysc_qos_qgroup *qgroup)
{
	int ret;

	if (!priv->pdev_priv->ops->hw_adp_cdev_qgroup_get)
		return -EOPNOTSUPP;

	ret = priv->pdev_priv->ops->hw_adp_cdev_qgroup_get(priv->ndev, qgroup->qid);
	if (ret < 0)
		return ret;

	qgroup->qgroup = ret;
	return 0;
}

static int ysc_qos_qgroup_set(struct ysc_priv *priv, struct ysc_qos_qgroup *qgroup)
{
	int ret;

	if (!priv->pdev_priv->ops->hw_adp_cdev_qgroup_set)
		return -EOPNOTSUPP;

	ret = priv->pdev_priv->ops->hw_adp_cdev_qgroup_set(priv->ndev, qgroup->qid, qgroup->qgroup);
	if (ret < 0)
		return ret;

	return 0;
}

static long ysc_qos_qgroup(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;
	struct ysc_priv *priv = file->private_data;
	struct ysc_qos_qgroup qgroup;

	if (copy_from_user(&qgroup, (void __user *)arg, sizeof(qgroup)))
		return -EFAULT;

	switch (_IOC_DIR(cmd)) {
	case _IOC_READ:
		ret = ysc_qos_qgroup_get(priv, &qgroup);
		break;
	case _IOC_WRITE:
		ret = ysc_qos_qgroup_set(priv, &qgroup);
		break;
	default:
		return -EINVAL;
	}

	if (ret < 0)
		return ret;

	if (copy_to_user((void __user *)arg, &qgroup, sizeof(qgroup)))
		return -EFAULT;

	return 0;
}

static long ysc_qos_queue(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct net_device *ndev = priv->ndev;
	struct ysc_qos_queue queue;

	queue.qnum = ndev->num_tx_queues;
	queue.real_qnum = ndev->real_num_tx_queues;

	if (copy_to_user((void __user *)arg, &queue, sizeof(queue)))
		return -EFAULT;

	return 0;
}

static long ysc_qos_sync(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ysc_qos_sync sync;

	if (copy_from_user(&sync, (void __user *)arg, sizeof(sync)))
		return -EFAULT;

	if (!priv->pdev_priv->ops->hw_adp_cdev_qos_sync)
		return -EOPNOTSUPP;

	return priv->pdev_priv->ops->hw_adp_cdev_qos_sync(priv->ndev, sync.qid);
}

static long ysc_link_gqbase(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ysc_priv *priv = file->private_data;
	struct ysc_link_gqbase gqbase;
	int ret;

	if (!priv->pdev_priv->ops->hw_adp_cdev_link_gqbase_get)
		return -EOPNOTSUPP;

	ret = priv->pdev_priv->ops->hw_adp_cdev_link_gqbase_get(priv->ndev, &gqbase.qstart,
								&gqbase.qnum);
	if (ret < 0)
		return ret;

	if (copy_to_user((void __user *)arg, &gqbase, sizeof(gqbase)))
		return -EFAULT;

	return 0;
}

static long ysc_np_cfg(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct ysc_priv *priv = file->private_data;
	struct ysc_np_cfg_arg cfg = {0};

	if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
		return -EFAULT;

	switch (_IOC_DIR(cmd)) {
	case _IOC_WRITE:
		if (IS_ERR_OR_NULL(priv->pdev_priv->ops->hw_adp_np_set_cfg))
			return -EFAULT;

		ret = priv->pdev_priv->ops->hw_adp_np_set_cfg(priv->ndev_priv->pdev,
							      cfg.type, cfg.value);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static long ysc_np_bond_cfg(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct ysc_priv *priv = file->private_data;
	struct ysc_np_bond_cfg_arg cfg = {0};

	if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
		return -EFAULT;

	switch (_IOC_DIR(cmd)) {
	case _IOC_WRITE:
		if (IS_ERR_OR_NULL(priv->pdev_priv->ops->hw_adp_np_bond_set_cfg))
			return -EFAULT;

		ret = priv->pdev_priv->ops->hw_adp_np_bond_set_cfg(priv->ndev_priv->pdev,
							      cfg.bond_id, cfg.enable, cfg.value);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static long ysc_np_bond_linkstatus_cfg(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct ysc_priv *priv = file->private_data;
	struct ysc_np_bond_linkstatus_cfg_arg cfg = {0};

	if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
		return -EFAULT;

	switch (_IOC_DIR(cmd)) {
	case _IOC_WRITE:
		if (IS_ERR_OR_NULL(priv->pdev_priv->ops->hw_adp_np_bond_linkstatus_set_cfg))
			return -EFAULT;

		ret = priv->pdev_priv->ops->hw_adp_np_bond_linkstatus_set_cfg(priv->ndev_priv->pdev,
									cfg.port_id, cfg.enable);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static long ysc_lan_cfg(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct ysc_priv *priv = file->private_data;
	struct ysc_lan_cfg_arg cfg = {0};

	if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
		return -EFAULT;

	switch (_IOC_DIR(cmd)) {
	case _IOC_WRITE:
		if (IS_ERR_OR_NULL(priv->ndev_priv->ys_ndev_hw->ys_set_tc_mc_group))
			return -EFAULT;

		ret = priv->ndev_priv->ys_ndev_hw->ys_set_tc_mc_group(priv->ndev,
							      cfg.group_id, cfg.bitmap);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static unlocked_ioctl ysc_comm_ioctls[] = {
	[YSC_COMM_DEVBIND] = ysc_comm_dev_bind,
};

static size_t ysc_comm_arg_sizes[] = {
	[YSC_COMM_DEVBIND] = sizeof(struct ysc_comm_devid),
};

static unlocked_ioctl ysc_net_ioctls[] = {
	[YSC_NET_DEVINFO] = ysc_net_devinfo,
	[YSC_NET_QINFO] = ysc_net_qinfo,
	[YSC_NET_MACADDR] = ysc_net_macaddr,
	[YSC_NET_MTU] = ysc_net_mtu,
	[YSC_NET_LINKINFO] = ysc_net_linkinfo,
	[YSC_NET_OFFLOADCAP] = ysc_net_offloadcap,
	[YSC_NET_PROMISC] = ysc_net_promisc,
	[YSC_NET_DMAMAP] = ysc_net_dma_map,
	[YSC_NET_DMAUNMAP] = ysc_net_dma_unmap,
	[YSC_NET_UMD] = ysc_net_umd,
	[YSC_NET_PCIBAR] = ysc_net_pcibar,
	[YSC_NET_START] = ysc_net_start,
	[YSC_NET_PEER_QSET] = ysc_net_peer_qset,
};

static size_t ysc_net_arg_sizes[] = {
	[YSC_NET_DEVINFO] = sizeof(struct ysc_net_devinfo),
	[YSC_NET_QINFO] = sizeof(struct ysc_net_qinfo),
	[YSC_NET_MACADDR] = sizeof(struct ysc_net_macaddr),
	[YSC_NET_MTU] = sizeof(struct ysc_net_mtu),
	[YSC_NET_LINKINFO] = sizeof(struct ysc_net_linkinfo),
	[YSC_NET_OFFLOADCAP] = sizeof(struct ysc_net_offloadcap),
	[YSC_NET_PROMISC] = sizeof(struct ysc_net_promisc),
	[YSC_NET_DMAMAP] = sizeof(struct ysc_net_dmamap),
	[YSC_NET_DMAUNMAP] = sizeof(struct ysc_net_dmamap),
	[YSC_NET_UMD] = sizeof(struct ysc_net_umd),
	[YSC_NET_PCIBAR] = sizeof(struct ysc_net_pcibar),
	[YSC_NET_START] = sizeof(struct ysc_net_start),
	[YSC_NET_PEER_QSET] = sizeof(struct ysc_net_peer_qset),
};

static unlocked_ioctl ysc_qos_ioctls[] = {
	[YSC_QOS_QGROUP] = ysc_qos_qgroup,
	[YSC_QOS_QUEUE] = ysc_qos_queue,
	[YSC_QOS_SYNC] = ysc_qos_sync,
};

static size_t ysc_qos_arg_sizes[] = {
	[YSC_QOS_QGROUP] = sizeof(struct ysc_qos_qgroup),
	[YSC_QOS_QUEUE] = sizeof(struct ysc_qos_queue),
	[YSC_QOS_SYNC] = sizeof(struct ysc_qos_sync),
};

static unlocked_ioctl ysc_link_ioctls[] = {
	[YSC_LINK_GQBASE] = ysc_link_gqbase,
};

static size_t ysc_link_arg_sizes[] = {
	[YSC_LINK_GQBASE] = sizeof(struct ysc_link_gqbase),
};

static unlocked_ioctl ysc_np_ioctls[] = {
	[YSC_NP_CFG] = ysc_np_cfg,
	[YSC_NP_BOND_CFG] = ysc_np_bond_cfg,
	[YSC_NP_BOND_LINKSTATUS_CFG] = ysc_np_bond_linkstatus_cfg,
};

static size_t ysc_np_arg_sizes[] = {
	[YSC_NP_CFG] = sizeof(struct ysc_np_cfg_arg),
	[YSC_NP_BOND_CFG] = sizeof(struct ysc_np_bond_cfg_arg),
	[YSC_NP_BOND_LINKSTATUS_CFG] = sizeof(struct ysc_np_bond_linkstatus_cfg_arg),
};

static unlocked_ioctl ysc_lan_ioctls[] = {
	[YSC_LAN_CFG] = ysc_lan_cfg,
};

static size_t ysc_lan_arg_sizes[] = {
	[YSC_LAN_CFG] = sizeof(struct ysc_lan_cfg_arg),
};

static long ysc_comm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int nr = _IOC_NR(cmd);

	if (nr >= YSC_COMM_MAX)
		return -EINVAL;

	if (_IOC_SIZE(cmd) != ysc_comm_arg_sizes[nr])
		return -EINVAL;

	return ysc_comm_ioctls[nr](file, cmd, arg);
}

static long ysc_net_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int nr = _IOC_NR(cmd);
	struct ysc_priv *priv = file->private_data;

	if (nr >= YSC_NET_MAX)
		return -EINVAL;

	if (_IOC_DIR(cmd) & _IOC_WRITE)
		ysc_cfg_flags_set(priv, _IOC_NR(cmd));

	if (!priv->pdev_priv || !priv->adev || !priv->ndev || !priv->ndev_priv)
		return -ENODEV;

	if (nr != YSC_NET_UMD && nr != YSC_NET_DEVINFO && !priv->umd_enabled)
		return -EPERM;

	if (_IOC_SIZE(cmd) != ysc_net_arg_sizes[nr])
		return -EINVAL;

	return ysc_net_ioctls[nr](file, cmd, arg);
}

static long ysc_qos_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int nr = _IOC_NR(cmd);
	struct ysc_priv *priv = file->private_data;

	if (!priv->pdev_priv || !priv->adev || !priv->ndev || !priv->ndev_priv)
		return -ENODEV;

	if (_IOC_SIZE(cmd) != ysc_qos_arg_sizes[nr])
		return -EINVAL;

	return ysc_qos_ioctls[nr](file, cmd, arg);
}

static long ysc_link_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int nr = _IOC_NR(cmd);
	struct ysc_priv *priv = file->private_data;

	if (!priv->pdev_priv || !priv->adev || !priv->ndev || !priv->ndev_priv)
		return -ENODEV;

	if (_IOC_SIZE(cmd) != ysc_link_arg_sizes[nr])
		return -EINVAL;

	return ysc_link_ioctls[nr](file, cmd, arg);
}

static long ysc_np_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int nr = _IOC_NR(cmd);
	struct ysc_priv *priv = file->private_data;

	if (!priv->pdev_priv || !priv->adev || !priv->ndev || !priv->ndev_priv)
		return -ENODEV;

	if (_IOC_SIZE(cmd) != ysc_np_arg_sizes[nr])
		return -EINVAL;

	return ysc_np_ioctls[nr](file, cmd, arg);
}

static long ysc_lan_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int nr = _IOC_NR(cmd);
	struct ysc_priv *priv = file->private_data;

	if (!priv->pdev_priv || !priv->adev || !priv->ndev || !priv->ndev_priv)
		return -ENODEV;

	if (_IOC_SIZE(cmd) != ysc_lan_arg_sizes[nr])
		return -EINVAL;

	return ysc_lan_ioctls[nr](file, cmd, arg);
}

static long ysc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (_IOC_TYPE(cmd)) {
	case YSC_IOCTL_COMM_TYPE:
		return ysc_comm_ioctl(file, cmd, arg);

	case YSC_IOCTL_NET_TYPE:
		return ysc_net_ioctl(file, cmd, arg);

	case YSC_IOCTL_QOS_TYPE:
		return ysc_qos_ioctl(file, cmd, arg);

	case YSC_IOCTL_LINK_TYPE:
		return ysc_link_ioctl(file, cmd, arg);

	case YSC_IOCTL_NP_TYPE:
		return ysc_np_ioctl(file, cmd, arg);

	case YSC_IOCTL_LAN_TYPE:
		return ysc_lan_ioctl(file, cmd, arg);

	default:
		return -EINVAL;
	};
}

static void ysc_release_restore_cfg(struct ysc_priv *priv, int type, void *data)
{
	switch (type) {
	case YSC_NET_MACADDR:
		ysc_net_macaddr_set(priv->ndev, data);
		break;
	case YSC_NET_MTU:
		ysc_net_mtu_set(priv->ndev, *(int *)data);
		break;
	case YSC_NET_PROMISC:
		priv->ndev->flags = (priv->ndev->flags & ~IFF_PROMISC) |
				    ((*(unsigned int *)data) & IFF_PROMISC);
		priv->ndev_priv->ys_ndev_hw->ys_set_rx_flags(priv->ndev);
		break;
	case YSC_NET_OFFLOADCAP:
		ysc_net_offloadcap_set(priv->ndev_priv, *(netdev_features_t *)data);
		break;
	default:
		break;
	}
}

static int ysc_release(struct inode *inode, struct file *file)
{
	struct ysc_priv *priv = file->private_data;
	struct net_device *ndev = priv->ndev;
	struct ys_ndev_priv *ndev_priv = priv->ndev_priv;

	if (priv->dmamap_table)
		ys_dmamap_table_destroy(priv->dmamap_table);

	/* restore config */
	ysc_cfg_restore(priv, ysc_release_restore_cfg);

	/* exit umd */
	if (ndev && priv->umd_enabled) {
		rtnl_lock();
		/* Change umd state before to call dev_open -> ys_ndo_open.*/
		ndev_priv->umd_enable = false;
		netif_device_attach(ndev);
		dev_open(ndev, NULL);
		rtnl_unlock();
		ys_net_debug("umd disable");
	}

	kfree(priv);
	file->private_data = NULL;

	return 0;
}

static const struct file_operations ysc_fops = {
	.owner = THIS_MODULE,
	.open = ysc_open,
	.mmap = ysc_mmap,
	.unlocked_ioctl = ysc_ioctl,
	.release = ysc_release,
};

int ysc_init(void)
{
	int ret;
	static bool inited;

	if (inited) {
		atomic_inc(&ysc_dev.refcnt);
		return 0;
	}
	struct ysif_ops *ops = ysif_get_ops();
	ysc_dev.mdev.minor = MISC_DYNAMIC_MINOR;
	ysc_dev.mdev.name = YSC_DEV_NAME;
	ysc_dev.mdev.fops = &ysc_fops;
	atomic_set(&ysc_dev.refcnt, 1);

	ret = ops->misc_register(&ysc_dev.mdev);
	if (ret < 0) {
		ys_err("Failed to register misc device yusur, error: %d\n", ret);
		return ret;
	}

	inited = true;

	return 0;
}

void ysc_exit(void)
{
	if (atomic_dec_and_test(&ysc_dev.refcnt))
		misc_deregister(&ysc_dev.mdev);
}
