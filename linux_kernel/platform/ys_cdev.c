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
#include <linux/nospec.h>

#include "ys_cdev.h"
#include "ys_i2c.h"
#include "ys_ndev.h"

#include "ys_auxiliary.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"
#include "ys_utils.h"
#include "../net/ys_ndev_ops.h"
#include "../net/lan/ys_lan.h"

static int ys_umd_set(struct net_device *ndev, struct ys_cdev_priv *cdev_priv,
		      bool enable)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	unsigned int change_mtu;
	netdev_features_t feature_tmp;

	mutex_lock(&ndev_priv->state_lock);

	if (enable) {
		/* only one process can take the ownership of queue resources */
		if (ndev_priv->umd_enable) {
			mutex_unlock(&ndev_priv->state_lock);
			return -EINVAL;
		}

		list_add(&ndev_priv->qres, &cdev_priv->qres_list);
		ndev_priv->umd_enable = true;
		ys_dev_debug("umd enable");
	} else {
		/* already disabled */
		if (!ndev_priv->umd_enable) {
			mutex_unlock(&ndev_priv->state_lock);
			return 0;
		}

		list_del(&ndev_priv->qres);
	}

	mutex_unlock(&ndev_priv->state_lock);

	rtnl_lock();
	if (enable) {
		dev_close(ndev);
		/* get maxinum size supported by the hardware */
		change_mtu = ndev->gso_max_size;
		ys_dev_debug("close dev");
		/* Configure the default offload */
		if (pdev_priv->dpu_mode == MODE_LEGACY) {
			feature_tmp = (ndev->features | (NETIF_F_IP_CSUM | NETIF_F_RXCSUM));
			ndev_priv->ys_ndev_hw->ys_features_set(ndev, feature_tmp);
			ndev_priv->ys_ndev_hw->ys_extra_features_set(ndev, feature_tmp);
			ndev->features = feature_tmp;
		}
	} else {
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_update_cfg)) {
			/* pf uplink */
			if (pdev_priv->dpu_mode == MODE_DPU_SOC)
				ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, LAN_SOC_UPLINK_VFNUM);
			else
				ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, 0);
		}
		ys_dev_debug("open dev");
		/* get current netdevice mtu */
		change_mtu = ndev->mtu;
	}

	/* UMD mode need to disable tx limit by netdev mtu
	 * kernel mode need to enable tx limit by netdev mtu
	 */
	if (!ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH) &&
	    !IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw->ys_ndev_change_mtu)) {
		ndev_priv->ys_ndev_hw->ys_ndev_change_mtu(ndev, change_mtu);
		ys_dev_debug("ys_ndev_change_mtu");
	}

	/* change umd_enable status before netdev open/close op otherwise port is down */
	if (!enable) {
		ndev_priv->umd_enable = false;
		ys_dev_debug("umd disable");
		dev_open(ndev, NULL);
	}
	rtnl_unlock();

	return 0;
}

static int ys_ioctl_umd_cfg(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct ysioctl_umd_cfg cfg;
	struct ys_pdev_priv *pdev_priv;
	struct pci_dev *vfpdev;
	struct net_device *ndev;
	struct ys_ndev_priv *ndev_priv, *temp_ndev_priv;
	bool rep = false;
	int ret;
	void *pt_addr;
	dma_addr_t pt_dma_addr;

	/* copy data from user space */
	if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
		return -EFAULT;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;

	cfg.dpu_mode = pdev_priv->dpu_mode;
	if (pdev_priv->dpu_mode == MODE_SMART_NIC ||
	    pdev_priv->dpu_mode == MODE_DPU_SOC)
		cfg.sum_vf = pdev_priv->sum_vf;

	/* check iommu passthrough arg */
	pt_addr = dma_alloc_coherent(&pdev_priv->pdev->dev, 512,
				     &pt_dma_addr, GFP_KERNEL);
	if (!pt_addr)
		return -ENOMEM;

	if (virt_to_phys(pt_addr) == pt_dma_addr)
		cfg.is_pt = true;
	else
		cfg.is_pt = false;
	dma_free_coherent(&pdev_priv->pdev->dev, 512, pt_addr, pt_dma_addr);

	if ((!cfg.is_virtual || pdev_priv->nic_type->is_vf) && !cfg.is_rep) {
		if (pdev_priv->dpu_mode == MODE_SMART_NIC &&
		    !pdev_priv->nic_type->is_vf) {
			/* uplink port, all representors should down */
			ndev = ys_aux_match_rep(pdev_priv->pdev, 0x200);
			rep = true;
		} else if (pdev_priv->dpu_mode == MODE_DPU_SOC) {
			/* uplink port, all representors should down */
			rep = true;
			ndev = ys_aux_match_eth(pdev_priv->pdev, 0);
		} else if (cfg.is_pf_sf) {
			/* get pf sf ndev */
			ndev = ys_aux_match_sf(pdev_priv->pdev, cfg.sf_id);
			ys_dev_debug("pf sf ndev:%p", ndev);
		} else {
			/* pf port or vf port in vm */
			ndev = ys_aux_match_eth(pdev_priv->pdev, 0);
			ys_dev_debug("pf ndev:%p", ndev);
		}
	} else if (!cfg.is_virtual_sf && !cfg.is_rep) {
		u32 val = 0;

		if (!ys_pdev_supports_sriov(pdev_priv->pdev))
			return -EINVAL;

		/* get vf pdev and ndev */
		if (pdev_priv->sriov_info.num_vfs <= cfg.vfsf_id ||
		    !pdev_priv->sriov_info.vfinfo)
			return -EINVAL;

		val = array_index_nospec(cfg.vfsf_id,
					 pdev_priv->sriov_info.num_vfs);

		ys_dev_info("vfsf_id index:%d\n", val);
		vfpdev = pdev_priv->sriov_info.vfinfo[val].vfdev;
		if (!vfpdev)
			return -EINVAL;
		if (cfg.is_pf_sf) {
			/* get vf sf ndev */
			ndev = ys_aux_match_sf(vfpdev, cfg.sf_id);
			ys_dev_debug("vf sf ndev:%p", ndev);
		} else {
			ndev = ys_aux_match_eth(vfpdev, 0);
			ys_dev_debug("vf ndev:%p", ndev);
		}
	} else if (cfg.is_virtual_sf && !cfg.is_rep) {
		/* get sf ndev */
		ndev = ys_aux_match_sf(pdev_priv->pdev, cfg.vfsf_id);
		ys_dev_debug("sf ndev");
	} else if (cfg.is_rep) {
		/* rep port, all representors should down */
		rep = true;
		/* get rep ndev */
		ndev = ys_aux_match_rep(pdev_priv->pdev, cfg.rep_id);
		ys_dev_debug("rep ndev:%p", ndev);
	}

	if (!ndev)
		return -EINVAL;
	ndev_priv = netdev_priv(ndev);
	cfg.qbase = ndev_priv->qi.qbase;
	cfg.qnum = ndev_priv->qi.ndev_qnum;
	ether_addr_copy(cfg.dev_addr, ndev->dev_addr);

	if (ys_umd_set(ndev, cdev_priv, cfg.start)) {
		ret = -EINVAL;
		/* stop preivous umd port when failed */
		goto err_umd_cfg;
	}

	/* copy data to user space */
	if (cfg.start) {
		if (copy_to_user((void __user *)arg, &cfg, sizeof(cfg)))
			return -EFAULT;
	}

	return 0;

err_umd_cfg:
	if (!rep)
		return ret;

	/* release queue resources belong to this fd */
	list_for_each_entry_safe(ndev_priv, temp_ndev_priv, &cdev_priv->qres_list, qres)
		ys_umd_set(ndev_priv->ndev, cdev_priv, 0);

	return ret;
}

static int ys_ioctl_umd_feature(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct ysioctl_umd_hw cfg;
	struct ys_pdev_priv *pdev_priv;
	struct pci_dev *vfpdev;
	struct net_device *ndev;
	struct ys_ndev_priv *ndev_priv;
	u64 data[20];

	/* copy data from user space */
	if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
		return -EFAULT;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;
	/*     pf port      or    vf port in vm */
	if (!cfg.is_virtual || pdev_priv->nic_type->is_vf) {
		if (cfg.is_pf_sf) {
			/* get pf sf ndev */
			ndev = ys_aux_match_sf(pdev_priv->pdev, cfg.sf_id);
			ys_dev_debug("pf sf ndev:%p", ndev);
		} else {
			/* pf port or vf port in vm */
			ndev = ys_aux_match_eth(pdev_priv->pdev, 0);
			ys_dev_debug("pf ndev :%p", ndev);
		}
	} else if (!cfg.is_virtual_sf) { /* vf port */
		u32 val = 0;

		if (!ys_pdev_supports_sriov(pdev_priv->pdev))
			return -EINVAL;

		/* get vf pdev and ndev */
		if (pdev_priv->sriov_info.num_vfs <= cfg.vfsf_id ||
		    !pdev_priv->sriov_info.vfinfo)
			return -EINVAL;

		val = array_index_nospec(cfg.vfsf_id,
					 pdev_priv->sriov_info.num_vfs);

		ys_dev_info("vfsf_id index:%d\n", val);
		vfpdev = pdev_priv->sriov_info.vfinfo[val].vfdev;
		if (cfg.is_pf_sf) {
			/* get vf sf ndev */
			ndev = ys_aux_match_sf(vfpdev, cfg.sf_id);
			ys_dev_debug("vf sf ndev:%p", ndev);
		} else {
			ndev = ys_aux_match_eth(vfpdev, 0);
			ys_dev_debug("vf ndev:%p", ndev);
		}
	} else if (cfg.is_virtual_sf) {
		/* get sf ndev */
		ndev = ys_aux_match_sf(pdev_priv->pdev, cfg.vfsf_id);
		ys_dev_debug("sf ndev in host");
	}

	ndev_priv = netdev_priv(ndev);
	if (cfg.action == YS_SET) {
		if (cfg.cfg & YS_SET_RX_QSET_HASH) {
			/* TODO add mac */
			data[0] = ndev_priv->qi.ndev_qnum;
			ndev_priv->qi.ndev_qnum = cfg.qnum;
			ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, 0);
			ndev_priv->qi.ndev_qnum = data[0];
			ys_net_debug("umd set hash cnt : %lld", cfg.qnum);
		}
		if (cfg.cfg & YS_SET_MTU) {
			data[0] = ndev->mtu;
			ndev->mtu = cfg.mtu;
			ndev_priv->ys_ndev_hw->ys_ndev_change_mtu(ndev, ndev->mtu);
			ndev->mtu = data[0];
			ys_net_debug("umd set mtu : %lld", cfg.mtu);
		}
		if (cfg.cfg & YS_SET_RX_PROMISC) {
			if (ndev->flags & IFF_PROMISC)
				data[0] = 1;
			else
				data[0] = 0;
			if (cfg.promisc)
				ndev->flags = ndev->flags | IFF_PROMISC;
			else
				ndev->flags = ndev->flags & (~IFF_PROMISC);
			ndev_priv->ys_ndev_hw->ys_set_rx_flags(ndev);
			if (data[0])
				ndev->flags = ndev->flags | IFF_PROMISC;
			else
				ndev->flags = ndev->flags & (~IFF_PROMISC);
			ys_net_debug("umd set promisc : %lld", cfg.promisc);
		}
	}

	return 0;
}

static int ys_ioctl_dma_map(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct device *dev;
	struct ysioctl_dma_map map;
	struct ys_pdev_priv *pdev_priv;
	struct ys_pdev_umem *umem;
	s64 nr_pinned_pages, nr_mapped_pages;
	u64 vaddr;
	int ret = 0;
	int i;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;

	/* copy data from user space */
	if (copy_from_user(&map, (void __user *)arg, sizeof(map)))
		return -EFAULT;

	vaddr = map.vaddr & PAGE_MASK;
	map.size += map.vaddr - vaddr;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return -ENOMEM;

	umem->vaddr = map.vaddr;
	umem->nr_pages = (map.size + ~PAGE_MASK) >> PAGE_SHIFT;
	umem->pages = kvcalloc(umem->nr_pages, sizeof(*umem->pages), GFP_KERNEL | __GFP_ZERO);
	if (!umem->pages) {
		ret = -ENOMEM;
		goto err_with_umem;
	}

	/* pin pages */
	nr_pinned_pages = pin_user_pages_fast(vaddr, umem->nr_pages,
					      0, umem->pages);
	if (nr_pinned_pages != umem->nr_pages) {
		if (nr_pinned_pages < 0)
			ret = (int)nr_pinned_pages;
		else
			ret = -ENOMEM;
		goto err_with_pages;
	}

	/* get dev to do dma map */
	if (!map.vf_num || pdev_priv->nic_type->is_vf) {
		dev = pdev_priv->dev;
	} else {
		u32 val = 0;

		if (!ys_pdev_supports_sriov(pdev_priv->pdev))
			return -EINVAL;

		if (pdev_priv->sriov_info.num_vfs <= map.vf_num - 1 ||
		    !pdev_priv->sriov_info.vfinfo)
			return -EINVAL;

		val = array_index_nospec(map.vf_num - 1,
					 pdev_priv->sriov_info.num_vfs);

		dev = &pdev_priv->sriov_info.vfinfo[val].vfdev->dev;
	}
	umem->dev = dev;
	umem->vf_num = map.vf_num;
	umem->pdev_priv = pdev_priv;

	/* record vf num because releaseing umem need it */
	cdev_priv->vf_num = map.vf_num;

	/* do dma map */
	umem->sg_list = kvcalloc(nr_pinned_pages, sizeof(*umem->sg_list), GFP_KERNEL | __GFP_ZERO);
	if (!umem->sg_list) {
		ret = -ENOMEM;
		goto err_with_pages;
	}
	sg_init_table(umem->sg_list, nr_pinned_pages);
	for (i = 0; i < nr_pinned_pages; i++)
		sg_set_page(&umem->sg_list[i], umem->pages[i], PAGE_SIZE, 0);

	/* contiguous iova only at one map entry */
	nr_mapped_pages = dma_map_sg(dev, umem->sg_list, nr_pinned_pages,
				     DMA_BIDIRECTIONAL);
	if (nr_mapped_pages != 1) {
		ys_dev_debug("failed to get contiguous iova (%lld pages)\n",
			     nr_mapped_pages);
		ret = -EINVAL;
		goto err_with_dma_map;
	}

	map.iova = umem->sg_list[0].dma_address;
	map.iova += map.vaddr - vaddr;

	ys_dev_info("MAP vfnum[%d] vaddr 0x%016llx iova 0x%016lx size 0x%016lx pages %lld\n",
		    umem->vf_num, umem->vaddr, map.iova, map.size, umem->nr_pages);

	/* copy data to user space */
	if (copy_to_user((void __user *)arg, &map, sizeof(map))) {
		ret = -EFAULT;
		goto err_with_dma_map;
	}

	list_add(&umem->list, &pdev_priv->umem_list);

	return ret;

err_with_dma_map:
	if (nr_mapped_pages > 0)
		dma_unmap_sg(dev, umem->sg_list, nr_mapped_pages, DMA_BIDIRECTIONAL);
	kvfree(umem->sg_list);
err_with_pages:

	if (nr_pinned_pages > 0)
		unpin_user_pages(umem->pages, umem->nr_pages);

	kvfree(umem->pages);
err_with_umem:
	kfree(umem);

	return ret;
}

void ys_umem_unmap(struct ys_pdev_umem *umem)
{
	struct ys_pdev_priv *pdev_priv;
	if (!umem)
		return;

	pdev_priv = umem->pdev_priv;

	list_del(&umem->list);
	dma_unmap_sg(umem->dev, umem->sg_list, umem->nr_pages, DMA_BIDIRECTIONAL);
	kvfree(umem->sg_list);
	unpin_user_pages(umem->pages, umem->nr_pages);
	kvfree(umem->pages);

	ys_dev_debug("UNMAP vfnum[%d] vaddr 0x%016llx pages %lld\n",
		     umem->vf_num, umem->vaddr, umem->nr_pages);
	kfree(umem);
}

static int ys_ioctl_dma_unmap(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct ysioctl_dma_map unmap;
	struct ys_pdev_priv *pdev_priv;
	struct ys_pdev_umem *umem, *temp;
	bool find = false;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;

	/* copy data from user space */
	if (copy_from_user(&unmap, (void __user *)arg, sizeof(unmap)))
		return -EFAULT;

	list_for_each_entry_safe(umem, temp, &pdev_priv->umem_list, list) {
		if (umem->vaddr == unmap.vaddr && umem->vf_num == unmap.vf_num) {
			find = true;
			break;
		}
	}

	if (!find)
		return -EINVAL;

	ys_umem_unmap(umem);

	return 0;
}

static int ys_ioctl_get_barsize(struct ys_cdev_priv *cdev_priv,
				unsigned long arg)
{
	int ret;

	ret = copy_to_user((void __user *)arg, cdev_priv->bar_size, sizeof(cdev_priv->bar_size));
	if (ret != 0)
		return -EFAULT;

	return 0;
}

static long ys_ioctl_rw_reg(struct ys_cdev_priv *cdev_priv,
			    unsigned long arg)
{
	struct ysioctl_rw_reg_arg user_arg;
	u32 val;
	/* copy data from user space */
	if (copy_from_user(&user_arg, (void __user *)arg, sizeof(user_arg)))
		return -EFAULT;

	if (user_arg.bar >= ARRAY_SIZE(cdev_priv->bar_vaddr))
		return -EINVAL;

	val = array_index_nospec(user_arg.bar, ARRAY_SIZE(cdev_priv->bar_vaddr));

	switch (user_arg.op) {
	case YS_IOCTL_OP_READ:
		user_arg.val = ys_rd32(cdev_priv->bar_vaddr[val],
				       user_arg.reg);
		if (copy_to_user((void __user *)arg, &user_arg,
				 sizeof(user_arg)))
			return -EFAULT;
		break;
	case YS_IOCTL_OP_WRITE:
		ys_wr32(cdev_priv->bar_vaddr[val], user_arg.reg,
			user_arg.val);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static long ys_ioctl_rw_i2c(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	struct ysioctl_i2c_arg user_arg;
	struct ys_i2c *i2c;
	long ret = 0;
	u8 *kbuffer;
	u32 val;

	/* copy data from user space */
	if (copy_from_user(&user_arg, (void __user *)arg, sizeof(user_arg)))
		return -EFAULT;

	/* check size */
	if (user_arg.size == 0)
		return -EINVAL;

	/* allocate memory for kernel buffer */
	kbuffer = kmalloc(user_arg.size, GFP_KERNEL);
	if (!kbuffer)
		return -ENOMEM;

	if (user_arg.i2c_num >= YS_I2C_MAX_I2C_DEVICES) {
		ret = -EINVAL;
		goto out;
	}

	val = array_index_nospec(user_arg.i2c_num, YS_I2C_MAX_I2C_DEVICES);

	i2c = ys_aux_match_i2c_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(i2c)) {
		ret = -EOPNOTSUPP;
		ys_err("Cannot find i2c device, i2c operation not supported.\n");
		goto out;
	}

	switch (user_arg.op) {
	case YS_IOCTL_OP_READ:
		ret = ys_i2c_read(i2c->idev + val, user_arg.regaddr, kbuffer, user_arg.size);
		if (ret < 0)
			goto out;

		/* copy data to user space */
		ret = copy_to_user((void __user *)user_arg.buffer, kbuffer, user_arg.size);
		if (ret) {
			ret = -EFAULT;
			goto out;
		}
		break;
	case YS_IOCTL_OP_WRITE:
		if (copy_from_user(kbuffer, (void __user *)user_arg.buffer, user_arg.size)) {
			ret = -EFAULT;
			goto out;
		}
		ret = ys_i2c_write(i2c->idev + val, user_arg.regaddr, kbuffer, user_arg.size);
		if (ret < 0)
			goto out;
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	kfree(kbuffer);
	return ret;
}

static int ys_cdev_mmap_bar(struct file *filp, struct vm_area_struct *vma)
{
	struct ys_cdev_priv *cdev_priv = filp->private_data;
	unsigned long bar_offset = (vma->vm_pgoff << PAGE_SHIFT);
	int ret = 0;
	int i;

	for (i = 0; i < BAR_MAX; i++) {
		if (bar_offset <= cdev_priv->bar_offset[i] &&
		    cdev_priv->bar_size[i] != 0) {
			/* Size check */
			if (vma->vm_end - vma->vm_start >
			    cdev_priv->bar_size[i]) {
				ys_err("Tried to map registers region with wrong size %lu (expected <=%zu).\n",
				       vma->vm_end - vma->vm_start,
				       cdev_priv->bar_size[i]);
				return -EINVAL;
			}

			ys_info("mmap bar[%d]:%ld 0x%lx to 0x%lx offset: %lu mmap len: %lx\n",
				i, cdev_priv->bar_start[i], vma->vm_start,
				vma->vm_end, bar_offset,
				(unsigned long)vma->vm_end - vma->vm_start);

			ret = remap_pfn_range(vma, vma->vm_start,
					      cdev_priv->bar_start[i] >> PAGE_SHIFT,
					      vma->vm_end - vma->vm_start,
					      pgprot_noncached(vma->vm_page_prot));
			if (ret)
				break;

			return ret;
		}
	}

	ys_err("bar remap pfn range failed for card bar_offset:%lu\n",
	       bar_offset);
	return -EAGAIN;
}

static int ys_cdev_open(struct inode *inode, struct file *filp)
{
	struct ys_cdev *ys_cdev =
		container_of(filp->private_data, struct ys_cdev, mdev);
	struct ys_cdev_priv *cdev_priv = NULL;
	struct ys_pdev_priv *pdev_priv = NULL;
	int i;

	if (IS_ERR_OR_NULL(ys_cdev))
		return -EFAULT;

	pdev_priv = pci_get_drvdata(ys_cdev->pdev);
	if (!pdev_priv)
		return -EFAULT;

	cdev_priv = kzalloc(sizeof(*cdev_priv), GFP_KERNEL);
	if (!cdev_priv)
		return -ENOMEM;

	cdev_priv->pdev = ys_cdev->pdev;
	cdev_priv->mdev = &ys_cdev->mdev;
	INIT_LIST_HEAD(&cdev_priv->qres_list);
	INIT_LIST_HEAD(&cdev_priv->debug_list);

	for (i = 0; i < BAR_MAX; i++) {
		cdev_priv->bar_start[i] =
			pci_resource_start(ys_cdev->pdev, i);
		cdev_priv->bar_end[i] = pci_resource_end(ys_cdev->pdev, i);
		cdev_priv->bar_flags[i] =
			pci_resource_flags(ys_cdev->pdev, i);
		cdev_priv->bar_size[i] = pci_resource_len(ys_cdev->pdev, i);
		if (!cdev_priv->bar_size[i]) {
			cdev_priv->bar_vaddr[i] = NULL;
			continue;
		}
		cdev_priv->bar_vaddr[i] = pdev_priv->bar_addr[i];
		cdev_priv->bar_offset[i] = pdev_priv->bar_offset[i];

		ys_debug("CDEV BAR_%d [0x%08lx-0x%08lx] flag[0x%08lx] mapped to 0x%p, length %lu",
			 i, cdev_priv->bar_start[i], cdev_priv->bar_end[i],
			 cdev_priv->bar_flags[i], cdev_priv->bar_vaddr[i],
			 (unsigned long)cdev_priv->bar_size[i]);
	}

	filp->private_data = cdev_priv;

	return 0;
}

static int ys_cdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct ys_cdev_priv *cdev_priv = filp->private_data;
	int ret = 0;
	struct ys_pdev_priv *pdev_priv;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);

	switch (vma->vm_pgoff) {
	case YS_DEBUG_CFG_PAGE_OFFSET:
		break;

	case YS_DEBUG_RUNTIME_PAGE_OFFSET:
		ys_dev_info("debug mmap size :%#lx", vma->vm_end - vma->vm_start);
		ret = remap_vmalloc_range(vma, pdev_priv->diagnose.runtime_data, 0);
		break;

	default:
		ret = ys_cdev_mmap_bar(filp, vma);
	}
	return ret;
}

static int ys_ioctl_get_eth_link(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct ysioctl_eth_link  eth_link;
	struct net_device *ndev;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;

	if (pdev_priv->dpu_mode == MODE_SMART_NIC)
		ndev = ys_aux_match_rep(pdev_priv->pdev, 0x200);
	else
		ndev = ys_aux_match_eth(pdev_priv->pdev, 0);
	if (!ndev)
		return -EFAULT;

	/* when mac is not exist or inaccessiable, generate a default config */
	eth_link.link_speed = 100000; /* 100G */
	eth_link.link_duplex = YS_ETH_LINK_DUPLEX_FULL;
	eth_link.link_autoneg = YS_ETH_LINK_AUTONEG;
	eth_link.link_status = YS_ETH_LINK_UP;
	ndev_priv = netdev_priv(ndev);
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_speed)
		eth_link.link_speed = ndev_priv->ys_eth_hw->et_get_link_speed(ndev);

	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_duplex) {
		if (ndev_priv->ys_eth_hw->et_get_link_duplex(ndev) == DUPLEX_HALF)
			eth_link.link_duplex = YS_ETH_LINK_HALF_DUPLEX;
	}

	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_autoneg) {
		if (ndev_priv->ys_eth_hw->et_get_link_autoneg(ndev) == AUTONEG_DISABLE)
			eth_link.link_autoneg = YS_ETH_LINK_AUTONEG_FIXED;
	}

	if (!netif_carrier_ok(ndev))
		eth_link.link_status = YS_ETH_LINK_DOWN;

	/* copy data to user space */
	if (copy_to_user((void __user *)arg, &eth_link, sizeof(eth_link)))
		return -EFAULT;

	return 0;
}

static int ys_ioctl_rw_doe(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct ysioctl_doe_ctrl doe_ctrl;
	struct ys_pdev_priv *pdev_priv;
	// struct ys_mac_tbl *mac_tbl;
	struct net_device *ndev;
	int ret = 0;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;

	ndev = ys_aux_match_eth(pdev_priv->pdev, 0);
	if (!ndev)
		return -EFAULT;

	/* copy data from user space */
	if (copy_from_user(&doe_ctrl, (void __user *)arg, sizeof(doe_ctrl)))
		return -EFAULT;

	switch (doe_ctrl.cmd) {
	case ADD_MAC_FILTER:
		ys_debug("add-fl:%02x:%02x:%02x:%02x:%02x:%02x vlan:%d vf:%d rxq:%d action:%d\n",
			 doe_ctrl.mac[0], doe_ctrl.mac[1], doe_ctrl.mac[2],
			 doe_ctrl.mac[3], doe_ctrl.mac[4], doe_ctrl.mac[5], doe_ctrl.vlan,
			 doe_ctrl.vf, doe_ctrl.rxq, doe_ctrl.action);
		// ret = ys_np_set_uc_mac_bidir(ndev, &doe_ctrl, 1);
		break;
	case DEL_MAC_FILTER:
		ys_debug("del-fl:%02x:%02x:%02x:%02x:%02x:%02x vlan:%d vf:%d\n",
			 doe_ctrl.mac[0], doe_ctrl.mac[1], doe_ctrl.mac[2], doe_ctrl.mac[3],
			 doe_ctrl.mac[4], doe_ctrl.mac[5], doe_ctrl.vlan, doe_ctrl.vf);
		// ret = ys_np_set_uc_mac_bidir(ndev, &doe_ctrl, 0);
		break;
	case FIND_MAC_FILTER:
		ys_debug("find-fl:vf:%d\n", doe_ctrl.vf);
		// ret = ys_np_find_uc_tbl(ndev, &doe_ctrl, &mac_tbl);
		if (ret != 0)
			return ret;
		/* copy data to user space */
		if (copy_to_user((void __user *)arg, &doe_ctrl, sizeof(doe_ctrl)))
			ret = -EFAULT;
		// kfree(mac_tbl);
		break;
	case ADD_MULTICAST:
		ys_debug("add-mc:%02x:%02x:%02x:%02x:%02x:%02x vlan:%d vf:%d rxq:%d action:%d\n",
			 doe_ctrl.mac[0], doe_ctrl.mac[1], doe_ctrl.mac[2],
			 doe_ctrl.mac[3], doe_ctrl.mac[4], doe_ctrl.mac[5], doe_ctrl.vlan,
			 doe_ctrl.vf, doe_ctrl.rxq, doe_ctrl.action);
		// ret = ys_np_set_mc_mac_bidir(ndev, &doe_ctrl, 1);
		break;
	case DEL_MULTICAST:
		ys_debug("del-mc:%02x:%02x:%02x:%02x:%02x:%02x vlan:%d vf:%d\n",
			 doe_ctrl.mac[0], doe_ctrl.mac[1], doe_ctrl.mac[2], doe_ctrl.mac[3],
			 doe_ctrl.mac[4], doe_ctrl.mac[5], doe_ctrl.vlan, doe_ctrl.vf);
		// ret = ys_np_set_mc_mac_bidir(ndev, &doe_ctrl, 0);
		break;
	case FIND_MULTICAST:
		ys_debug("find-mc:vf:%d\n", doe_ctrl.vf);
		// ret = ys_np_find_mc_tbl(ndev, &doe_ctrl, &mac_tbl);
		if (ret != 0)
			return ret;
		/* copy data to user space */
		if (copy_to_user((void __user *)arg, &doe_ctrl, sizeof(doe_ctrl)))
			ret = -EFAULT;
		// kfree(mac_tbl);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int ys_ioctl_debug(struct ys_cdev_priv *cdev_priv, unsigned long arg)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_debug_cfg data;
	struct ys_ndev_priv *ndev_priv;
	struct pci_dev *pdev;
	struct ys_adev *adev, *temp;
	struct list_head *adev_list;
	struct net_device *ndev;

	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	/* copy data from user space */
	if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
		return -EFAULT;

	if (!data.function_id) {
		pdev = pdev_priv->pdev;
	} else {
		u32 val = 0;

		if (!ys_pdev_supports_sriov(pdev_priv->pdev))
			return -EINVAL;

		if (pdev_priv->sriov_info.num_vfs <= data.function_id - 1 ||
		    !pdev_priv->sriov_info.vfinfo)
			return -EINVAL;

		val = array_index_nospec(data.function_id - 1,
					 pdev_priv->sriov_info.num_vfs);

		pdev = pdev_priv->sriov_info.vfinfo[val].vfdev;
	}

	pdev_priv = pci_get_drvdata(pdev);
	adev_list = &pdev_priv->adev_list;

	read_lock(&pdev_priv->adev_list_lock);
	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (adev->adev_type == AUX_TYPE_ETH ||
		    adev->adev_type == AUX_TYPE_SF  ||
		    adev->adev_type == AUX_TYPE_REP) {
			ndev = (struct net_device *)adev->adev_priv;
			if (ndev->ifindex == data.ifindex) {
				read_unlock(&pdev_priv->adev_list_lock);
				ndev_priv = netdev_priv(ndev);
				if (data.action == YS_DEBUG_OFF || data.action == YS_DEBUG_ON) {
					ndev_priv->debug = data.action;
					if (ndev_priv->debug == YS_DEBUG_ON)
						list_add(&ndev_priv->debug_res,
							 &cdev_priv->debug_list);
					else if (ndev_priv->debug == YS_DEBUG_OFF)
						list_del(&ndev_priv->debug_res);
					ys_net_info("debug setting : %d\n", ndev_priv->debug);
				} else if (data.action == YS_DEBUG_EGT_INFO) {
					ndev_priv->debug_ops->debug_get_info(ndev,
									     data.qtypeid);
				}
				return 0;
			}
		}
	}
	read_unlock(&pdev_priv->adev_list_lock);

	return -EINVAL;
}

long ys_cdev_ioctl(struct file *filp, u32 cmd, unsigned long arg)
{
	struct ys_cdev_priv *cdev_priv = filp->private_data;
	struct ys_pdev_priv *pdev_priv;
	int ret = 0;

	if (!cdev_priv)
		return -EFAULT;
	if (!cdev_priv->pdev)
		return -EFAULT;
	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;

	ys_dev_debug("cmd=0x%08x(dir=%02x,type=%02x,size=%02x,nr=%02x)\n", cmd,
		     _IOC_DIR(cmd), _IOC_TYPE(cmd), _IOC_SIZE(cmd), _IOC_NR(cmd));

	switch (cmd) {
	case YS_IOCX_RW_REG:
		return ys_ioctl_rw_reg(cdev_priv, arg);
	case YS_IOCR_GET_BAR_SIZE:
		return ys_ioctl_get_barsize(cdev_priv, arg);
	case YS_IOCX_RW_I2C:
		return ys_ioctl_rw_i2c(cdev_priv, arg);
	case YS_IOCX_UMD_CFG:
		return ys_ioctl_umd_cfg(cdev_priv, arg);
	case YS_IOCX_UMD_HW:
		return ys_ioctl_umd_feature(cdev_priv, arg);
	case YS_IOCX_DMA_MAP:
		return ys_ioctl_dma_map(cdev_priv, arg);
	case YS_IOCX_DMA_UNMAP:
		return ys_ioctl_dma_unmap(cdev_priv, arg);
	case YS_IOCX_GET_ETH_LINK:
		return ys_ioctl_get_eth_link(cdev_priv, arg);
	case YS_IOCX_DOE_CTRL:
		return ys_ioctl_rw_doe(cdev_priv, arg);
	case YS_IOCX_DEBUG_SET:
		return ys_ioctl_debug(cdev_priv, arg);
	default:
		ys_err("invalid cmd=0x%08x\n", cmd);
		ret = -EOPNOTSUPP;
	}
	return ret;
}

int ys_cdev_release(struct inode *inode, struct file *filp)
{
	struct ys_cdev_priv *cdev_priv = filp->private_data;
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv, *temp_ndev_priv;
	struct ys_pdev_umem *umem, *temp_umem;

	if (!cdev_priv)
		return -EFAULT;
	if (!cdev_priv->pdev)
		return -EFAULT;
	pdev_priv = pci_get_drvdata(cdev_priv->pdev);
	if (!pdev_priv)
		return -EFAULT;

	/* close ndev debug_setting */
	list_for_each_entry_safe(ndev_priv, temp_ndev_priv, &cdev_priv->debug_list, debug_res) {
		ndev_priv->debug = YS_DEBUG_OFF;
		ys_net_info("debug setting : %d\n", ndev_priv->debug);
	}

	/* release queue resources belong to this fd */
	list_for_each_entry_safe(ndev_priv, temp_ndev_priv, &cdev_priv->qres_list, qres)
		ys_umd_set(ndev_priv->ndev, cdev_priv, 0);

	/* TODO: Concurrent operations may have problem */
	/* release dma map resources belong to this fd */
	list_for_each_entry_safe(umem, temp_umem, &pdev_priv->umem_list, list) {
		/* release dma map resources belong to this function. */
		if (umem->vf_num == cdev_priv->vf_num)
			ys_umem_unmap(umem);
	}

	kfree(cdev_priv);
	filp->private_data = NULL;
	return 0;
}

static const struct file_operations ys_cdev_ops = {
	.owner = THIS_MODULE,
	.open = ys_cdev_open,
	.release = ys_cdev_release,
	.unlocked_ioctl = ys_cdev_ioctl,
	.mmap = ys_cdev_mmap,
};

int ys_add_cdev(struct pci_dev *pdev, const char *name, const struct file_operations *ops)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *cdev_list = &pdev_priv->cdev_list;
	struct ys_cdev *ys_cdev, *entry;
	struct list_head *pos;
	int ret;

	list_for_each(pos, cdev_list) {
		entry = list_entry(pos, struct ys_cdev, list);
		if (!strcmp(entry->mdev.name, name)) {
			ys_dev_err("cdev %s exist\n", name);
			return -EINVAL;
		}
	}

	ys_cdev = kzalloc(sizeof(*ys_cdev), GFP_KERNEL);
	if (!ys_cdev)
		return -ENOMEM;

	snprintf(ys_cdev->misc_dev_name, MAX_MISC_DEV_NAME_BYTES,
		 "%s", name);

	ys_cdev->mdev.minor = MISC_DYNAMIC_MINOR;
	ys_cdev->mdev.name = ys_cdev->misc_dev_name;
	ys_cdev->mdev.fops = ops;
	ys_cdev->mdev.mode = 0666; // allow non-root user to access
	ys_cdev->mdev.parent = &pdev->dev;

	mutex_init(&ys_cdev->cmd_mutex);
	ys_cdev->pdev = pdev;

	ret = misc_register(&ys_cdev->mdev);
	if (ret) {
		ys_err("Failed to register misc device: %d\n", ret);
		kfree(ys_cdev);
		return ret;
	}
	ys_info("Registered miscdev, name=%s, minor_number=%d\n",
		ys_cdev->misc_dev_name, ys_cdev->mdev.minor);

	list_add(&ys_cdev->list, cdev_list);

	return 0;
}

int ys_cdev_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *cdev_list = &pdev_priv->cdev_list;
	char misc_dev_name[MAX_MISC_DEV_NAME_BYTES];
	int ret;
	u32 device;
	u32 function;
	u32 bus;

	/* Creating cdev of VF is not allowed in a non-virtual environment */
	if (pdev->is_virtfn)
		return 0;

	INIT_LIST_HEAD(cdev_list);

	bus = pdev->bus->number;
	device = PCI_SLOT(pdev->devfn);
	function = PCI_FUNC(pdev->devfn);

	snprintf(misc_dev_name, MAX_MISC_DEV_NAME_BYTES, "%s-%02x:%02x.%02x",
		 "ys", bus, device, function);

	ret = ys_add_cdev(pdev, misc_dev_name, &ys_cdev_ops);
	if (ret) {
		ys_err("Failed to register platform misc device: %d\n", ret);
		goto err_cdev_init;
	}

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_add_cdev)) {
		ret = pdev_priv->ops->hw_adp_add_cdev(pdev);
		if (ret) {
			ys_err("Failed to register hardware's misc device: %d\n", ret);
			goto err_cdev_init;
		}
	}

	return 0;

err_cdev_init:
	ys_cdev_uninit(pdev);
	return ret;
}

void ys_cdev_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct list_head *cdev_list = &pdev_priv->cdev_list;
	struct ys_cdev *ys_cdev, *temp;

	if (!pdev_priv)
		return;

	if (pdev->is_virtfn)
		return;

	list_for_each_entry_safe(ys_cdev, temp, cdev_list, list) {
		misc_deregister(&ys_cdev->mdev);
		list_del(&ys_cdev->list);
		kfree(ys_cdev);
		ys_cdev = NULL;
	}
}
