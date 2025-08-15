// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/net_tstamp.h>
#include <linux/phy.h>
#include <linux/bitops.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/string.h>
#include "ys_ext_ethtool.h"

static int ys_ext_ethtool_read_eeprom_by_agent(struct net_device *dev, void __user *useraddr,
					       int (*getter)(struct net_device *ndev,
							     struct ethtool_eeprom *eep, u8 *d),
					       struct ethtool_eeprom *eeprom)
{
	void __user *userbuf = useraddr + sizeof(*eeprom);
	u32 bytes_remaining;
	u8 *data;
	int ret = 0;

	data = kzalloc(eeprom->len, GFP_USER);
	if (!data)
		return -ENOMEM;

	bytes_remaining = eeprom->len;
	while (bytes_remaining > 0) {
		ret = getter(dev, eeprom, data);
		if (ret)
			break;
		if (!eeprom->len) {
			ret = -EIO;
			break;
		}
		if (copy_to_user(userbuf, data, eeprom->len)) {
			ret = -EFAULT;
			break;
		}
		userbuf += eeprom->len;
		eeprom->offset += eeprom->len;
		bytes_remaining -= eeprom->len;
	}

	eeprom->len = userbuf - (useraddr + sizeof(*eeprom));
	eeprom->offset -= eeprom->len;

	kfree(data);
	return ret;
}

static int ys_ext_ethtool_write_eeprom(struct net_device *dev, void __user *useraddr,
				       struct ethtool_eeprom *eeprom)
{
	void __user *userbuf = useraddr + sizeof(*eeprom);
	u32 bytes_remaining;
	u8 *data;
	int ret = 0;

	data = kzalloc(eeprom->len, GFP_USER);
	if (!data)
		return -ENOMEM;

	bytes_remaining = eeprom->len;
	while (bytes_remaining > 0) {
		if (copy_from_user(data, userbuf, eeprom->len)) {
			ret = -EFAULT;
			break;
		}
		ret = exttool_ops.set_eeprom(dev, eeprom, data);
		if (ret)
			break;
		userbuf += eeprom->len;
		eeprom->offset += eeprom->len;
		bytes_remaining -= eeprom->len;
	}

	kfree(data);
	return ret;
}

static int ys_ext_ethtool_read_regs(struct net_device *dev, char __user *useraddr,
				    struct ethtool_regs *regs)
{
	void *regbuf;
	int reglen;

	reglen = regs->len;
	regbuf = vzalloc(reglen);
	if (!regbuf)
		return -ENOMEM;

	exttool_ops.get_regs(dev, regs, regbuf);

	useraddr += offsetof(struct ethtool_regs, data);
	if (copy_to_user(useraddr, regbuf, reglen))
		return -EFAULT;

	vfree(regbuf);
	return 0;
}

static int ys_ext_ethtool_get_drvinfo(struct net_device *dev, void __user *useraddr,
				      struct ethtool_drvinfo *info)
{
	info->cmd = ETHTOOL_GDRVINFO;
	//memcpy(info->version, UTS_RELEASE, sizeof(info->version));

	if (exttool_ops.get_drvinfo) {
		exttool_ops.get_drvinfo(dev, info);
	} else if (dev->dev.parent && dev->dev.parent->driver) {
		memcpy(info->bus_info, dev_name(dev->dev.parent), sizeof(info->bus_info));
		memcpy(info->driver, dev->dev.parent->driver->name, sizeof(info->driver));
	} else {
		return -EOPNOTSUPP;
	}

	/*
	 *if (!info->fw_version[0])
	 *	devlink_compat_running_version(dev, info->fw_version, sizeof(info->fw_version));
	 */

	return 0;
}

static int ys_ext_ethtool_get_perm_addr(struct net_device *dev, void __user *useraddr,
					struct ethtool_perm_addr *epaddr)
{
	if (epaddr->size < dev->addr_len)
		return -ETOOSMALL;
	epaddr->size = dev->addr_len;

	useraddr += sizeof(epaddr);
	if (copy_to_user(useraddr, dev->perm_addr, epaddr->size))
		return -EFAULT;
	return 0;
}

static int ys_ext_ethtool_set_phys_id(struct net_device *dev, void __user *useraddr,
				      struct ethtool_value *id)
{
	static bool busy;
	int rc;

	if (busy)
		return -EBUSY;

	rc = exttool_ops.set_phys_id(dev, ETHTOOL_ID_ACTIVE);
	if (rc < 0)
		return rc;

	/* Drop the RTNL lock while waiting, but prevent reentry or
	 * removal of the device.
	 */
	busy = true;
	dev_hold(dev);
	rtnl_unlock();

	if (rc == 0) {
		rtnl_lock();
		rc = exttool_ops.set_phys_id(dev, id->data);
		rtnl_unlock();
	}

	rtnl_lock();
	dev_put(dev);
	busy = false;

	(void)exttool_ops.set_phys_id(dev, ETHTOOL_ID_INACTIVE);
	return rc;
}

static u32 ys_ext_ethtool_get_flags(struct net_device *dev)
{
	u32 flags = 0;

	flags |= (dev->features & NETIF_F_LRO) ? ETH_FLAG_LRO : 0;
	flags |= (dev->features & NETIF_F_HW_VLAN_CTAG_RX) ? ETH_FLAG_RXVLAN : 0;
	flags |= (dev->features & NETIF_F_HW_VLAN_CTAG_TX) ? ETH_FLAG_TXVLAN : 0;
	flags |= (dev->features & NETIF_F_NTUPLE) ? ETH_FLAG_NTUPLE : 0;
	flags |= (dev->features & NETIF_F_RXHASH) ? ETH_FLAG_RXHASH : 0;

	return flags;
}

static int ys_ext_ethtool_set_flags(struct net_device *dev, u32 flags)
{
	netdev_features_t features = 0, changed = 0, old_features = 0;
	u32 all_flags = ETH_FLAG_LRO & ETH_FLAG_RXVLAN & ETH_FLAG_TXVLAN &
			ETH_FLAG_NTUPLE & ETH_FLAG_RXHASH;
	netdev_features_t all_features = NETIF_F_LRO & NETIF_F_HW_VLAN_CTAG_RX &
					NETIF_F_HW_VLAN_CTAG_TX & NETIF_F_NTUPLE &
					NETIF_F_RXHASH;

	old_features = dev->features;
	if (flags & ~all_flags)
		return -EINVAL;

	features |= (flags & ETH_FLAG_LRO) ? NETIF_F_LRO : 0;
	features |= (flags & ETH_FLAG_RXVLAN) ? NETIF_F_HW_VLAN_CTAG_RX : 0;
	features |= (flags & ETH_FLAG_TXVLAN) ? NETIF_F_HW_VLAN_CTAG_TX : 0;
	features |= (flags & ETH_FLAG_NTUPLE) ? NETIF_F_NTUPLE : 0;
	features |= (flags & ETH_FLAG_RXHASH) ?  NETIF_F_RXHASH : 0;

	/* allow changing only bits set in hw_features */
	changed = (features ^ dev->features) & all_features;
	if (changed & ~dev->hw_features)
		return (changed & dev->hw_features) ? -EINVAL : -EOPNOTSUPP;

	dev->wanted_features = (dev->wanted_features & ~changed) | (features & changed);

	if (old_features != dev->features)
		netdev_features_change(dev);
	netdev_update_features(dev);

	return 0;
}

static int ys_ext_ethtool_get_stats(struct net_device *dev, void __user *useraddr,
				    struct ethtool_stats *stats)
{
	u64 *data;
	int ret, n_stats;

	n_stats = stats->n_stats;

	if (n_stats) {
		data = vmalloc(n_stats * sizeof(u64));
		if (!data)
			return -ENOMEM;
		exttool_ops.get_ethtool_stats(dev, stats, data);
	} else {
		data = NULL;
	}

	useraddr += sizeof(*stats);
	if (n_stats && copy_to_user(useraddr, data, n_stats * sizeof(u64)))
		ret = -EFAULT;
	else
		ret = 0;

	vfree(data);
	return ret;
}

static int ys_ext_ethtool_get_rxnfc_rule_all(struct net_device *dev, void __user *useraddr,
					     struct ethtool_rxnfc *info)
{
	void *rule_buf = NULL;
	int ret = 0;

	if (info->rule_cnt > 0) {
		if (info->rule_cnt <= KMALLOC_MAX_SIZE / sizeof(u32))
			rule_buf = kcalloc(info->rule_cnt, sizeof(u32), GFP_USER);
		if (!rule_buf)
			return -ENOMEM;
	}

	ret = exttool_ops.get_rxnfc(dev, info, rule_buf);
	if (ret < 0) {
		kfree(rule_buf);
		return ret;
	}

	if (rule_buf) {
		useraddr += offsetof(struct ethtool_rxnfc, rule_locs);
		if (copy_to_user(useraddr, rule_buf, info->rule_cnt * sizeof(u32)))
			ret = -EFAULT;
		else
			ret = 0;
	}

	kfree(rule_buf);
	return ret;
}

static int ys_ext_ethtool_get_rxnfc_fh(struct net_device *dev, void __user *useraddr,
				       struct ethtool_rxnfc *info)
{
	size_t info_size = sizeof(*info);
	int ret;
	u32 cmd = info->cmd;

	/* struct ethtool_rxnfc was originally defined for
	 * ETHTOOL_{G,S}RXFH with only the cmd, flow_type and data
	 * members.  User-space might still be using that
	 * definition.
	 */
	if (cmd == ETHTOOL_GRXFH)
		info_size = (offsetof(struct ethtool_rxnfc, data) + sizeof(info->data));
	else if (cmd == ETHTOOL_GRXFH && info->flow_type & FLOW_RSS)
		info_size = sizeof(*info);

	if (copy_from_user(info, useraddr, info_size))
		return -EFAULT;

	/* If FLOW_RSS was requested then user-space must be using the
	 * new definition, as FLOW_RSS is newer.
	 */
	if (cmd == ETHTOOL_GRXFH && info->flow_type & FLOW_RSS) {
		/* Since malicious users may modify the original data,
		 * we need to check whether FLOW_RSS is still requested.
		 */
		if (!(info->flow_type & FLOW_RSS))
			return -EINVAL;
	}

	if (info->cmd != cmd)
		return -EINVAL;

	ret = exttool_ops.get_rxnfc(dev, info, NULL);
	if (ret < 0)
		return -EINVAL;

	ret = -EFAULT;
	if (copy_to_user(useraddr, info, info_size))
		return -EINVAL;

	return 0;
}

static netdev_features_t ys_ext_ethtool_get_feature_mask(u32 eth_cmd)
{
	/* feature masks of legacy discrete ethtool ops */

	switch (eth_cmd) {
	case ETHTOOL_GTXCSUM:
	case ETHTOOL_STXCSUM:
		return NETIF_F_CSUM_MASK | NETIF_F_FCOE_CRC |
		       NETIF_F_SCTP_CRC;
	case ETHTOOL_GRXCSUM:
	case ETHTOOL_SRXCSUM:
		return NETIF_F_RXCSUM;
	case ETHTOOL_GSG:
	case ETHTOOL_SSG:
		return NETIF_F_SG | NETIF_F_FRAGLIST;
	case ETHTOOL_GTSO:
	case ETHTOOL_STSO:
		return NETIF_F_ALL_TSO;
	case ETHTOOL_GGSO:
	case ETHTOOL_SGSO:
		return NETIF_F_GSO;
	case ETHTOOL_GGRO:
	case ETHTOOL_SGRO:
		return NETIF_F_GRO;
	default:
		WARN_ON_ONCE(1);
		return 0;
	}
}

static int ys_ext_ethtool_get_one_feature(struct net_device *dev,
					  char __user *useraddr, u32 ethcmd)
{
	netdev_features_t mask = ys_ext_ethtool_get_feature_mask(ethcmd);
	struct ethtool_value edata = {
		.cmd = ethcmd,
		.data = !!(dev->features & mask),
	};

	if (copy_to_user(useraddr, &edata, sizeof(edata)))
		return -EFAULT;
	return 0;
}

static int ys_ext_ethtool_set_one_feature(struct net_device *dev,
					  void __user *useraddr, u32 ethcmd)
{
	netdev_features_t old_features = 0;
	struct ethtool_value edata;
	netdev_features_t mask;

	if (copy_from_user(&edata, useraddr, sizeof(edata)))
		return -EFAULT;

	old_features = dev->features;
	mask = ys_ext_ethtool_get_feature_mask(ethcmd);
	mask &= dev->hw_features;
	if (!mask)
		return -EOPNOTSUPP;

	if (edata.data)
		dev->wanted_features |= mask;
	else
		dev->wanted_features &= ~mask;

	if (old_features != dev->features)
		netdev_features_change(dev);
	netdev_update_features(dev);

	return 0;
}

static int ys_ext_ethtool_get_ssetinfo(struct net_device *dev, void __user *useraddr,
				       struct ethtool_sset_info *info)
{
	u64 sset_mask;
	int i, idx = 0, n_bits = 0, rc;
	u32 *info_buf = NULL;

	/* store copy of mask, because we zero struct later on */
	sset_mask = info->sset_mask;

	/* calculate size of return buffer */
	n_bits = hweight64(sset_mask);

	memset(info, 0, sizeof(*info));
	info->cmd = ETHTOOL_GSSET_INFO;

	info_buf = kcalloc(n_bits, sizeof(u32), GFP_USER);
	if (!info_buf)
		return -ENOMEM;

	/*
	 * fill return buffer based on input bitmask and successful
	 * get_sset_count return
	 */
	for (i = 0; i < 64; i++) {
		if (!(sset_mask & (1ULL << i)))
			continue;

		rc = exttool_ops.get_sset_count(dev, i);
		if (rc >= 0) {
			info->sset_mask |= (1ULL << i);
			info_buf[idx++] = rc;
		}
	}

	useraddr += offsetof(struct ethtool_sset_info, data);
	if (copy_to_user(useraddr, info_buf, idx * sizeof(u32)))
		return -EFAULT;
	kfree(info_buf);

	return 0;
}

static int ys_ext_ethtool_get_rxfh_indir(struct net_device *dev, void __user *useraddr,
					 struct ethtool_rxfh_indir *rxfh_indir)
{
	u32 dev_size;
	u32 *indir;
	int ret;

	dev_size = rxfh_indir->size;
	indir = kcalloc(dev_size, sizeof(indir[0]), GFP_USER);
	if (!indir)
		return -ENOMEM;

	ret = exttool_ops.get_rxfh(dev, indir, NULL, NULL);
	if (ret) {
		kfree(indir);
		return ret;
	}

	if (copy_to_user(useraddr + sizeof(struct ethtool_rxfh_indir),
			 indir, dev_size * sizeof(indir[0])))
		ret = -EFAULT;

	kfree(indir);
	return ret;
}

static int ys_ext_ethtool_set_rxfh_indir(struct net_device *dev, void __user *useraddr,
					 struct ethtool_rxfh_indir *rxfh_indir)
{
	u32 *indir;
	int ret;

	indir = kcalloc(rxfh_indir->size, sizeof(indir[0]), GFP_USER);
	if (!indir)
		return -ENOMEM;

	ret = exttool_ops.set_rxfh(dev, indir, NULL, ETH_RSS_HASH_NO_CHANGE);
	if (ret) {
		kfree(indir);
		return ret;
	}

	/* indicate whether rxfh was set to default */
	if (rxfh_indir->size == 0)
		dev->priv_flags &= ~IFF_RXFH_CONFIGURED;
	else
		dev->priv_flags |= IFF_RXFH_CONFIGURED;

	kfree(indir);
	return ret;
}

static int ys_ext_ethtool_get_rxfh(struct net_device *dev, void __user *useraddr,
				   struct ethtool_rxfh *rxfh)
{
	int ret;
	u32 total_size;
	u32 indir_bytes;
	u32 *indir = NULL;
	u8 dev_hfunc = 0;
	u8 *hkey = NULL;
	u8 *rss_config;

	indir_bytes = rxfh->indir_size * sizeof(indir[0]);
	total_size = indir_bytes + rxfh->key_size;
	rss_config = kzalloc(total_size, GFP_USER);
	if (!rss_config)
		return -ENOMEM;

	if (rxfh->indir_size)
		indir = (u32 *)rss_config;

	if (rxfh->key_size)
		hkey = rss_config + indir_bytes;

	if (rxfh->rss_context)
		ret = exttool_ops.get_rxfh_context(dev, indir, hkey, &dev_hfunc,
						   rxfh->rss_context);
	else
		ret = exttool_ops.get_rxfh(dev, indir, hkey, &dev_hfunc);

	if (ret) {
		kfree(rss_config);
		return ret;
	}

	if (copy_to_user(useraddr + offsetof(struct ethtool_rxfh, rss_config[0]),
			 rss_config, total_size)) {
		ret = -EFAULT;
	}

	kfree(rss_config);
	return ret;
}

static int ys_ext_ethtool_set_rxfh(struct net_device *dev, void __user *useraddr,
				   struct ethtool_rxfh *rxfh)
{
	int ret;
	u32 *indir = NULL, indir_bytes = 0;
	u8 *hkey = NULL;
	u8 *rss_config;
	u32 rss_cfg_offset = offsetof(struct ethtool_rxfh, rss_config[0]);
	bool delete = false;

	if (rxfh->indir_size != ETH_RXFH_INDIR_NO_CHANGE)
		indir_bytes = rxfh->indir_size * sizeof(indir[0]);

	rss_config = kzalloc(indir_bytes + rxfh->key_size, GFP_USER);
	if (!rss_config)
		return -ENOMEM;

	/* rxfh.indir_size == 0 means reset the indir table to default (master
	 * context) or delete the context (other RSS contexts).
	 * rxfh.indir_size == ETH_RXFH_INDIR_NO_CHANGE means leave it unchanged.
	 */
	if (rxfh->indir_size && rxfh->indir_size != ETH_RXFH_INDIR_NO_CHANGE) {
		indir = (u32 *)rss_config;
		if (copy_from_user(indir, useraddr + rss_cfg_offset,
				   rxfh->indir_size * sizeof(indir[0]))) {
			kfree(rss_config);
			return -EFAULT;
		}
	} else if (rxfh->indir_size == 0) {
		if (rxfh->rss_context)
			delete = true;
	}

	if (rxfh->key_size) {
		hkey = rss_config + indir_bytes;
		if (copy_from_user(hkey,
				   useraddr + rss_cfg_offset + indir_bytes,
				   rxfh->key_size)) {
			kfree(rss_config);
			return -EFAULT;
		}
	}

	if (rxfh->rss_context)
		ret = exttool_ops.set_rxfh_context(dev, indir, hkey, rxfh->hfunc,
					    &rxfh->rss_context, delete);
	else
		ret = exttool_ops.set_rxfh(dev, indir, hkey, rxfh->hfunc);
	if (ret) {
		kfree(rss_config);
		return ret;
	}

	if (!rxfh->rss_context) {
		/* indicate whether rxfh was set to default */
		if (rxfh->indir_size == 0)
			dev->priv_flags &= ~IFF_RXFH_CONFIGURED;
		else if (rxfh->indir_size != ETH_RXFH_INDIR_NO_CHANGE)
			dev->priv_flags |= IFF_RXFH_CONFIGURED;
	}

	kfree(rss_config);
	return ret;
}

static int ys_ext_ethtool_get_strings(struct net_device *dev, void __user *useraddr,
				      struct ethtool_gstrings *gstrings)
{
	u8 *data;
	int rc;

	rc = exttool_ops.get_sset_count(dev, gstrings->string_set);
	if (rc < 0)
		return rc;
	if (rc > S32_MAX / ETH_GSTRING_LEN)
		return -ENOMEM;
	WARN_ON_ONCE(!rc);

	gstrings->len = rc;
	data = vzalloc(gstrings->len * ETH_GSTRING_LEN);
	if (gstrings->len && !data)
		return -ENOMEM;

	exttool_ops.get_strings(dev, gstrings->string_set, data);

	useraddr += sizeof(*gstrings);
	if (gstrings->len && copy_to_user(useraddr, data, gstrings->len * ETH_GSTRING_LEN))
		rc = -EFAULT;
	else
		rc = 0;

	vfree(data);
	return rc;
}

static int ys_ext_ethtool_self_test(struct net_device *dev, char __user *useraddr,
				    struct ethtool_test *test)
{
	u64 *data;
	int ret;

	data = kmalloc_array(test->len, sizeof(u64), GFP_USER);
	if (!data)
		return -ENOMEM;

	exttool_ops.self_test(dev, test, data);

	useraddr += sizeof(*test);
	if (copy_to_user(useraddr, data, test->len * sizeof(u64)))
		ret = -EFAULT;
	else
		ret = 0;

	kfree(data);
	return ret;
}

union buffer_t {
	struct ethtool_link_ksettings link_ksettings;
	struct ethtool_fecparam fecparam;
	struct ethtool_modinfo modinfo;
	struct ethtool_ts_info ts_info;
	struct ethtool_channels channels;
	struct ethtool_ringparam ringparam;
	struct ethtool_coalesce coalesce;
	struct ethtool_eeprom eeprom;
	struct ethtool_value edata;
	struct ethtool_regs regs;
	struct ethtool_drvinfo drvinfo;
	struct ethtool_perm_addr epaddr;
	struct ethtool_value id;
	struct ethtool_stats stats;
	struct ethtool_rxnfc nfcinfo;
	struct ethtool_sset_info ssetinfo;
	struct ethtool_rxfh_indir indir;
	struct ethtool_rxfh rxfh;
	struct ethtool_gstrings gstrings;
	struct ethtool_test test;
};

static int ys_do_ext_action(struct net_device *dev, void __user *useraddr, u32 ethcmd)
{
	int rc = 0;
	netdev_features_t old_features;
	union buffer_t buffer;
	int cp_to_user_size = sizeof(buffer);

	old_features = dev->features;
	if (exttool_ops.begin) {
		rc = exttool_ops.begin(dev);
		if (rc  < 0)
			return rc;
	}

	if (copy_from_user((void *)&buffer, useraddr, sizeof(buffer)))
		return -EFAULT;

	switch (ethcmd) {
	case YS_EXT_ETHTOOL_TEST: {
		if (!IS_ERR_OR_NULL(exttool_ops.self_test))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_self_test(dev, useraddr, &buffer.test);
		cp_to_user_size = sizeof(buffer.test);
		break;
	}
	case YS_EXT_ETHTOOL_GSSET_COUNT: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_sset_count))
			return -EOPNOTSUPP;

		rc = exttool_ops.get_sset_count(dev, buffer.ssetinfo.sset_mask);
		if (rc > 0)
			buffer.ssetinfo.reserved = rc;
		cp_to_user_size = sizeof(buffer.ssetinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GSTRINGS: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_strings))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_get_strings(dev, useraddr, &buffer.gstrings);
		cp_to_user_size = sizeof(buffer.gstrings);
		break;
	}
	case YS_EXT_ETHTOOL_GRXFHKEY_SIZE: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_rxfh_key_size))
			return -EOPNOTSUPP;
		buffer.rxfh.key_size = exttool_ops.get_rxfh_key_size(dev);
		rc = 0;
		cp_to_user_size = sizeof(buffer.rxfh);
		break;
	}
	case YS_EXT_ETHTOOL_GRXFHINDIR_SIZE: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_rxfh_indir_size))
			return -EOPNOTSUPP;
		buffer.rxfh.indir_size = exttool_ops.get_rxfh_indir_size(dev);
		rc = 0;
		cp_to_user_size = sizeof(buffer.rxfh);
		break;
	}
	case YS_EXT_ETHTOOL_GRXFHINDIR:
		if (!IS_ERR_OR_NULL(exttool_ops.get_rxfh))
			return -EOPNOTSUPP;
		rc = ys_ext_ethtool_get_rxfh_indir(dev, useraddr, &buffer.indir);
		cp_to_user_size = sizeof(buffer.indir);
		break;
	case YS_EXT_ETHTOOL_SRXFHINDIR:
		if (!IS_ERR_OR_NULL(exttool_ops.set_rxfh))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_set_rxfh_indir(dev, useraddr, &buffer.indir);
		cp_to_user_size = sizeof(buffer.indir);
		break;
	case YS_EXT_ETHTOOL_GRSSH:
		if (!IS_ERR_OR_NULL(exttool_ops.get_rxfh) &&
		    !IS_ERR_OR_NULL(exttool_ops.get_rxfh_context))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_get_rxfh(dev, useraddr, &buffer.rxfh);
		cp_to_user_size = sizeof(buffer.rxfh);
		break;
	case YS_EXT_ETHTOOL_SRSSH:
		if (!IS_ERR_OR_NULL(exttool_ops.set_rxfh))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_set_rxfh(dev, useraddr, &buffer.rxfh);
		cp_to_user_size = sizeof(buffer.rxfh);
		break;
	case YS_EXT_ETHTOOL_GSSET_INFO: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_sset_count))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_get_ssetinfo(dev, useraddr, &buffer.ssetinfo);
		cp_to_user_size = sizeof(buffer.ssetinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GTXCSUM:
	case YS_EXT_ETHTOOL_GRXCSUM:
	case YS_EXT_ETHTOOL_GSG:
	case YS_EXT_ETHTOOL_GTSO:
	case YS_EXT_ETHTOOL_GGSO:
	case YS_EXT_ETHTOOL_GGRO:
		rc = ys_ext_ethtool_get_one_feature(dev, useraddr, ethcmd);
		break;
	case YS_EXT_ETHTOOL_STXCSUM:
	case YS_EXT_ETHTOOL_SRXCSUM:
	case YS_EXT_ETHTOOL_SSG:
	case YS_EXT_ETHTOOL_STSO:
	case YS_EXT_ETHTOOL_SGSO:
	case YS_EXT_ETHTOOL_SGRO:
		rc = ys_ext_ethtool_set_one_feature(dev, useraddr, ethcmd);
		break;
	case YS_EXT_ETHTOOL_GFEATURES:
		//rc = ethtool_get_features(dev, useraddr);
		break;
	case YS_EXT_ETHTOOL_SFEATURES:
		//rc = ethtool_set_features(dev, useraddr);
		break;
	case YS_EXT_ETHTOOL_SRXFH:
	case YS_EXT_ETHTOOL_SRXCLSRLDEL:
	case YS_EXT_ETHTOOL_SRXCLSRLINS: {
		if (!IS_ERR_OR_NULL(exttool_ops.set_rxnfc))
			return -EOPNOTSUPP;

		rc = exttool_ops.set_rxnfc(dev, &buffer.nfcinfo);
		cp_to_user_size = sizeof(buffer.nfcinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GRXFH: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_rxnfc))
			return -EOPNOTSUPP;
		rc = ys_ext_ethtool_get_rxnfc_fh(dev, useraddr, &buffer.nfcinfo);
		cp_to_user_size = sizeof(buffer.nfcinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GRXRINGS:
	case YS_EXT_ETHTOOL_GRXCLSRLCNT:
	case YS_EXT_ETHTOOL_GRXCLSRULE: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_rxnfc))
			return -EOPNOTSUPP;

		rc = exttool_ops.get_rxnfc(dev, &buffer.nfcinfo, NULL);
		cp_to_user_size = sizeof(buffer.nfcinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GRXCLSRLALL: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_rxnfc))
			return -EOPNOTSUPP;
		rc = ys_ext_ethtool_get_rxnfc_rule_all(dev, useraddr, &buffer.nfcinfo);
		cp_to_user_size = sizeof(buffer.nfcinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GSTATS: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_ethtool_stats))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_get_stats(dev, useraddr, &buffer.stats);
		cp_to_user_size = sizeof(buffer.stats);
		break;
	}
	case YS_EXT_ETHTOOL_SFLAGS: {
		ys_ext_ethtool_set_flags(dev, buffer.edata.data);
		rc = 0;
		break;
	}
	case YS_EXT_ETHTOOL_GFLAGS: {
		buffer.edata.data = ys_ext_ethtool_get_flags(dev);
		cp_to_user_size = sizeof(buffer.edata);
		rc = 0;
		break;
	}
	case YS_EXT_ETHTOOL_PHYS_ID: {
		if (!IS_ERR_OR_NULL(exttool_ops.set_phys_id))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_set_phys_id(dev, useraddr, &buffer.id);
		cp_to_user_size = sizeof(buffer.id);
		break;
	}
	case YS_EXT_ETHTOOL_GPERMADDR: {
		rc = ys_ext_ethtool_get_perm_addr(dev, useraddr, &buffer.epaddr);
		cp_to_user_size = sizeof(buffer.epaddr);
		break;
	}
	case YS_EXT_ETHTOOL_GDRVINFO: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_drvinfo) &&
		    !IS_ERR_OR_NULL(exttool_ops.get_sset_count))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_get_drvinfo(dev, useraddr, &buffer.drvinfo);
		cp_to_user_size = sizeof(buffer.drvinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GREGS: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_regs))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_read_regs(dev, useraddr, &buffer.regs);
		cp_to_user_size = sizeof(buffer.regs);
		break;
	}
	case YS_EXT_ETHTOOL_GREGS_LEN: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_regs_len))
			return -EOPNOTSUPP;

		rc = exttool_ops.get_regs_len(dev);
		buffer.regs.len = rc < 0 ? 0 : rc;
		cp_to_user_size = sizeof(buffer.regs);
		break;
	}
	case YS_EXT_ETHTOOL_GLINK: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_link))
			return -EOPNOTSUPP;

		buffer.edata.data = netif_running(dev) && exttool_ops.get_link(dev);
		cp_to_user_size = sizeof(buffer.edata);
		rc = 0;
		break;
	}
	case YS_EXT_ETHTOOL_GEEPROM: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_eeprom))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_read_eeprom_by_agent(dev, useraddr, exttool_ops.get_eeprom,
							 &buffer.eeprom);
		cp_to_user_size = sizeof(buffer.eeprom);
		break;
	}
	case YS_EXT_ETHTOOL_GEEPROM_LEN: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_eeprom_len))
			return -EOPNOTSUPP;

		buffer.eeprom.len = exttool_ops.get_eeprom_len(dev);
		cp_to_user_size = sizeof(buffer.eeprom);
		break;
	}
	case YS_EXT_ETHTOOL_SEEPROM: {
		if (!IS_ERR_OR_NULL(exttool_ops.set_eeprom))
			return -EOPNOTSUPP;

		rc = ys_ext_ethtool_write_eeprom(dev, useraddr, &buffer.eeprom);
		break;
	}
	case YS_EXT_ETHTOOL_GCOALESCE: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_coalesce))
			return -EOPNOTSUPP;
		rc = exttool_ops.get_coalesce(dev, &buffer.coalesce, NULL, NULL);
		cp_to_user_size = sizeof(buffer.coalesce);
		break;
	}
	case YS_EXT_ETHTOOL_SCOALESCE: {
		if (!IS_ERR_OR_NULL(exttool_ops.set_coalesce))
			return -EOPNOTSUPP;
		rc = exttool_ops.set_coalesce(dev, &buffer.coalesce, NULL, NULL);
		break;
	}
	case YS_EXT_ETHTOOL_SRINGPARAM: {
		if (!IS_ERR_OR_NULL(exttool_ops.set_ringparam))
			return -EOPNOTSUPP;
		rc = exttool_ops.set_ringparam(dev, &buffer.ringparam, NULL, NULL);
		break;
	}
	case YS_EXT_ETHTOOL_GRINGPARAM: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_ringparam))
			return -EOPNOTSUPP;
		exttool_ops.get_ringparam(dev, &buffer.ringparam, NULL, NULL);
		cp_to_user_size = sizeof(buffer.ringparam);
		rc = 0;
		break;
	}
	case YS_EXT_ETHTOOL_GCHANNELS: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_channels))
			return -EOPNOTSUPP;

		exttool_ops.get_channels(dev, &buffer.channels);
		cp_to_user_size = sizeof(buffer.channels);
		rc = 0;
		break;
	}
	case YS_EXT_ETHTOOL_SCHANNELS: {
		if (!IS_ERR_OR_NULL(exttool_ops.set_channels))
			return -EOPNOTSUPP;
		break;
	}
	case YS_EXT_ETHTOOL_GET_TS_INFO: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_ts_info))
			return -EOPNOTSUPP;

		rc = exttool_ops.get_ts_info(dev, &buffer.ts_info);
		cp_to_user_size = sizeof(buffer.ts_info);
		break;
	}
	case YS_EXT_ETHTOOL_GMODULEINFO: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_module_info))
			return -EOPNOTSUPP;

		rc = exttool_ops.get_module_info(dev, &buffer.modinfo);
		cp_to_user_size = sizeof(buffer.modinfo);
		break;
	}
	case YS_EXT_ETHTOOL_GMODULEEEPROM: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_module_eeprom))
			return -EOPNOTSUPP;
		rc = ys_ext_ethtool_read_eeprom_by_agent(dev, useraddr,
							 exttool_ops.get_module_eeprom,
							 &buffer.eeprom);
		cp_to_user_size = sizeof(buffer.eeprom);
		break;
	}
	case YS_EXT_ETHTOOL_GLINKSETTINGS: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_link_ksettings))
			return -EOPNOTSUPP;

		rc = exttool_ops.get_link_ksettings(dev, &buffer.link_ksettings);
		cp_to_user_size = sizeof(buffer.link_ksettings);
		break;
	}
	case YS_EXT_ETHTOOL_SLINKSETTINGS: {
		break;
	}
	case YS_EXT_ETHTOOL_GFECPARAM: {
		if (!IS_ERR_OR_NULL(exttool_ops.get_fecparam))
			return -EOPNOTSUPP;

		rc = exttool_ops.get_fecparam(dev, &buffer.fecparam);
		cp_to_user_size = sizeof(buffer.fecparam);
		break;
	}
	case YS_EXT_ETHTOOL_SFECPARAM: {
		if (!IS_ERR_OR_NULL(exttool_ops.set_fecparam))
			return -EOPNOTSUPP;

		rc =  exttool_ops.set_fecparam(dev, &buffer.fecparam);
		break;
	}
	default:
		rc = -EOPNOTSUPP;
	}

	if (copy_to_user(useraddr, (void *)&buffer, cp_to_user_size))
		return -EFAULT;

	if (exttool_ops.complete)
		exttool_ops.complete(dev);

	if (old_features != dev->features)
		netdev_features_change(dev);

	return rc;
}

/* The main entry point in this file.  Called from net/core/dev_ioctl.c */
int ys_ext_ethtool(struct net_device *dev, struct ifreq *ifr)
{
	void __user *useraddr = ifr->ifr_data;
	u32 ethcmd;
	int rc;

	if (!dev || !netif_device_present(dev))
		return -ENODEV;

	if (copy_from_user(&ethcmd, useraddr, sizeof(ethcmd)))
		return -EFAULT;

	rc = ys_do_ext_action(dev, useraddr, ethcmd);

	return rc;
}

