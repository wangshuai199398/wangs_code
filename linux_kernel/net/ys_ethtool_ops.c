// SPDX-License-Identifier: GPL-2.0

#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/pci.h>
#include <linux/ptp_clock_kernel.h>

#include "ys_utils.h"
#include "ys_platform.h"
#include "ys_debug.h"
#include "../net/lan/ys_lan.h"
#include "../net/mac/ys_mac.h"
#include "ys_ext_ethtool.h"

#define SFF_8024_ID_BYTE (0)
#define SFP_DIAG_MON_BYTE (92)
#define SFP_DIAG_MON_BIT (6)
#define MODINFO_MAX_SIZE (512)

static void ys_get_drvinfo(struct net_device *ndev,
			   struct ethtool_drvinfo *drvinfo)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	size_t copy_len;
	u8 major_ver;
	u8 minor_ver;
	u8 debug_ver;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	copy_len = min(strlen(pci_name(ndev_priv->pdev)),
		       sizeof(drvinfo->bus_info) - 1);
	memcpy(drvinfo->bus_info, pci_name(ndev_priv->pdev), copy_len);
	drvinfo->bus_info[copy_len] = '\0';

	copy_len = min(strlen(ndev_priv->pdev->driver->name),
		       sizeof(drvinfo->driver) - 1);
	memcpy(drvinfo->driver, ndev_priv->pdev->driver->name, copy_len);
	drvinfo->driver[copy_len] = '\0';

	strscpy(drvinfo->version, YS_K2U_DRV_VERSION, sizeof(drvinfo->version));

	major_ver = (pdev_priv->hw_ver >> 16) & 0xff;
	minor_ver = (pdev_priv->hw_ver >> 8) & 0xff;
	debug_ver = pdev_priv->hw_ver & 0xff;
	snprintf(drvinfo->fw_version, ETHTOOL_FWVERS_LEN, "%d.%d.%d",
		 major_ver, minor_ver, debug_ver);

#ifdef YS_HAVE_EROM_VERSION
	if (pdev_priv->hw_info) {
		major_ver = pdev_priv->hw_info->ver_info.pxe_ver[0];
		minor_ver = pdev_priv->hw_info->ver_info.pxe_ver[1];
		debug_ver = pdev_priv->hw_info->ver_info.pxe_ver[2];
		snprintf(drvinfo->erom_version, ETHTOOL_FWVERS_LEN, "%d.%d.%d",
			 major_ver, minor_ver, debug_ver);
	}
#endif
}

static int ys_get_module_eeprom(struct net_device *ndev,
				struct ethtool_eeprom *eeep, u8 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;
	struct ys_i2c *i2c;
	struct ys_i2c_dev *idev;
	size_t offset = eeep->offset, len = eeep->len, read_len, total_read = 0;
	u8 origin_dev_addr;
	u8 mod_data[MODINFO_MAX_SIZE];
	int ret;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (ndev_priv->ys_eth_hw->et_get_module_data) {
		if (pdev_priv->nic_type->is_vf)
			return -EOPNOTSUPP;

		ret = ndev_priv->ys_eth_hw->et_get_module_data(ndev,
							       pdev_priv->pf_id,
							       mod_data,
							       YS_EEPROM_DATA_EEP);
		if (ret)
			return -EINVAL;

		ys_net_debug("port_id=%d, offset=0x%04lx, len=0x%04lx\n",
			     pdev_priv->pf_id, offset, len);
		memcpy(data, &mod_data[0] + offset, len);
	} else {
		i2c = ys_aux_match_i2c_dev(pdev_priv->pdev);
		if (IS_ERR_OR_NULL(i2c))
			return -EOPNOTSUPP;
		if (unlikely(ndev->dev_port >= i2c->idev_num))
			return -EINVAL;
		if (unlikely(!strstr(i2c->idev[ndev->dev_port + i2c->sfp_base_index].name, "sfp")))
			return -EINVAL;

		idev = &i2c->idev[ndev->dev_port + i2c->sfp_base_index];
		origin_dev_addr = idev->dev_addr;
		while (total_read < len) {
			read_len = len - total_read > 256 ? 256 : len - total_read;
			idev->dev_addr += ((offset + total_read) / 256) * 0x02;
			ys_i2c_read(idev, (offset + total_read) % 256, idev->data, read_len);
			ys_net_debug("port_id=%d, i2c_dev_name=%s, dev_addr %x, offset=0x%04lx, len=0x%04lx\n",
				     ndev->dev_port, idev->name, idev->dev_addr,
				     offset, len);
			memcpy(data + total_read, idev->data, read_len);
			total_read += read_len;
		}
		idev->dev_addr = origin_dev_addr;
	}

	return 0;
}

static int ys_get_module_info(struct net_device *ndev,
			      struct ethtool_modinfo *modinfo)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;
	struct ys_i2c_dev *idev;
	struct ys_i2c *i2c;
	u8 *i2c_data;
	u8 mod_data[MODINFO_MAX_SIZE];
	int ret;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (ndev_priv->ys_eth_hw->et_get_module_data) {
		if (pdev_priv->nic_type->is_vf)
			return -EOPNOTSUPP;

		ret = ndev_priv->ys_eth_hw->et_get_module_data(ndev,
							       pdev_priv->pf_id,
							       mod_data,
							       YS_EEPROM_DATA_INFO);
		if (ret)
			return -EINVAL;

		i2c_data = &mod_data[0];

		/* SFF8024_ID */
		if (i2c_data[SFF_8024_ID_BYTE] == 0x03) {
			if (i2c_data[SFP_DIAG_MON_BYTE] & (1 << SFP_DIAG_MON_BIT)) {
				modinfo->type = ETH_MODULE_SFF_8472;
				modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
			} else {
				modinfo->type = ETH_MODULE_SFF_8079;
				modinfo->eeprom_len = ETH_MODULE_SFF_8079_LEN;
			}
		}

		ys_net_debug("port_id=%d, type=%u, eeprom_len=%u\n",
			     pdev_priv->pf_id, modinfo->type, modinfo->eeprom_len);
	} else {
		i2c = ys_aux_match_i2c_dev(pdev_priv->pdev);
		if (IS_ERR_OR_NULL(i2c))
			return -EOPNOTSUPP;

		if (unlikely(ndev->dev_port >= i2c->idev_num))
			return -EINVAL;
		idev = &i2c->idev[ndev->dev_port + i2c->sfp_base_index];
		if (unlikely(!strstr(idev->name, "sfp")))
			return -EINVAL;

		ys_i2c_read(idev, 0, idev->data, idev->data_len);
		i2c_data = idev->data;

		/* SFF8024_ID */
		if (i2c_data[SFF_8024_ID_BYTE] == 0x03) {
			if (i2c_data[SFP_DIAG_MON_BYTE] & (1 << SFP_DIAG_MON_BIT)) {
				modinfo->type = ETH_MODULE_SFF_8472;
				modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
			} else {
				modinfo->type = ETH_MODULE_SFF_8079;
				modinfo->eeprom_len = ETH_MODULE_SFF_8079_LEN;
			}
		}

		if (modinfo->eeprom_len > idev->data_len) {
			ys_net_info("I2C_%s change data_len from %u to %u\n",
				    idev->name, idev->data_len, modinfo->eeprom_len);
			idev->data_len = modinfo->eeprom_len;
		}
		ys_net_debug("port_id=%d, name=%s, type=%u, eeprom_len=%u\n",
			     ndev->dev_port, idev->name, modinfo->type,
			     modinfo->eeprom_len);
	}

	return 0;
}

static void ys_get_ethtool_stats(struct net_device *ndev,
				 struct ethtool_stats *stats, u64 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct list_head *adev_list;
	struct ys_pdev_priv *pdev_priv;
	struct ys_adev *adev, *temp;
	int len = 0;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	adev_list = &pdev_priv->adev_list;

	if (pdev_priv->state_statistics.flag == ET_FLAG_REGISTER) {
		pdev_priv->state_statistics.et_get_stats(ndev, &data[len]);
		len += pdev_priv->state_statistics.et_get_stats_count(ndev);
	}

	list_for_each_entry_safe(adev, temp, adev_list, list) {
		if (adev->state_statistics.flag == ET_FLAG_REGISTER ||
		    adev->state_statistics.flag == ndev->dev_port) {
			adev->state_statistics.et_get_stats(ndev, &data[len]);
			len += adev->state_statistics.et_get_stats_count(ndev);
		}
	}
}

static void ys_get_strings(struct net_device *ndev, u32 stringset, u8 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct list_head *adev_list;
	struct ys_pdev_priv *pdev_priv;
	struct ys_adev *adev, *temp;
	int len = 0;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	adev_list = &pdev_priv->adev_list;

	switch (stringset) {
	case ETH_SS_TEST:
		if (ndev_priv->ys_eth_hw->et_get_self_strings)
			ndev_priv->ys_eth_hw->et_get_self_strings(ndev, data);
		break;
	case ETH_SS_STATS:
		if (pdev_priv->state_statistics.flag == ET_FLAG_REGISTER) {
			pdev_priv->state_statistics.et_get_stats_strings(ndev, &data[len]);
			len += ETH_GSTRING_LEN *
				pdev_priv->state_statistics.et_get_stats_count(ndev);
		}

		list_for_each_entry_safe(adev, temp, adev_list, list) {
			if (adev->state_statistics.flag == ET_FLAG_REGISTER ||
			    adev->state_statistics.flag == ndev->dev_port) {
				adev->state_statistics.et_get_stats_strings(ndev,
					 &data[len]);
				len += ETH_GSTRING_LEN *
					adev->state_statistics.et_get_stats_count(ndev);
			}
		}
		break;
	case ETH_SS_PRIV_FLAGS:
		if (ndev_priv->ys_eth_hw->et_get_priv_strings)
			ndev_priv->ys_eth_hw->et_get_priv_strings(ndev, data);
		break;
	}
}

static int ys_get_sset_count(struct net_device *ndev, int sset)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct list_head *adev_list;
	struct ys_pdev_priv *pdev_priv;
	struct ys_adev *adev, *temp;
	int len = 0;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	adev_list = &pdev_priv->adev_list;

	switch (sset) {
	case ETH_SS_TEST:
		if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_self_count)
			return ndev_priv->ys_eth_hw->et_get_self_count(ndev);
		else
			return -EOPNOTSUPP;
	case ETH_SS_STATS:
		if (pdev_priv->state_statistics.flag == ET_FLAG_REGISTER)
			len += pdev_priv->state_statistics.et_get_stats_count(ndev);

		list_for_each_entry_safe(adev, temp, adev_list, list) {
			if (adev->state_statistics.flag == ET_FLAG_REGISTER ||
			    adev->state_statistics.flag == ndev->dev_port) {
				len += adev->state_statistics.et_get_stats_count(ndev);
			}
		}
		if (len > 0)
			return len;
		else
			return -EOPNOTSUPP;
	case ETH_SS_PRIV_FLAGS:
		if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_priv_count)
			return ndev_priv->ys_eth_hw->et_get_priv_count(ndev);
		else
			return -EOPNOTSUPP;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

static void ys_self_test(struct net_device *ndev, struct ethtool_test *eth_test,
			 u64 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;
	struct napi_struct napi;
	struct ys_napi *rx_napi;
	u32 carrier_ok = 0;
	u16 i = 0;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		memset(&napi, 0, sizeof(struct napi_struct));

		if (pdev_priv->nic_type->mac_type)
			del_timer_sync(&ndev_priv->link_timer);

		if (ndev_priv->rx_enabled) {
			for (i = 0; i < ndev_priv->qi.ndev_qnum; i++) {
				rx_napi = &ndev_priv->rx_napi_list[i];
				if (memcmp(&rx_napi->napi, &napi,
					   sizeof(struct napi_struct)) != 0)
					napi_disable(&rx_napi->napi);
			}
		}
		carrier_ok = netif_carrier_ok(ndev);
		if (carrier_ok)
			netif_carrier_off(ndev);
		netif_stop_queue(ndev);
		/* Wait until all tx queues are empty. */
		msleep(200);
		if (ndev_priv->ys_eth_hw->et_self_offline_test)
			ndev_priv->ys_eth_hw->et_self_offline_test(ndev,
								   eth_test, data);
		if (carrier_ok)
			netif_carrier_on(ndev);
		netif_start_queue(ndev);

		if (pdev_priv->nic_type->mac_type)
			mod_timer(&ndev_priv->link_timer, jiffies + HZ);

		if (ndev_priv->rx_enabled) {
			for (i = 0; i < ndev_priv->qi.ndev_qnum; i++) {
				rx_napi = &ndev_priv->rx_napi_list[i];
				if (memcmp(&rx_napi->napi, &napi,
					   sizeof(struct napi_struct)) != 0)
					napi_enable(&rx_napi->napi);
			}
		}
	} else {
		if (ndev_priv->ys_eth_hw->et_self_online_test)
			ndev_priv->ys_eth_hw->et_self_online_test(ndev, eth_test,
								  data);
	}
}

void ys_build_ehtool_ksetting_advertising(struct ys_ethtool_ksetting *cmd,
					  enum ethtool_link_mode_bit_indices link_mode)
{
	const unsigned int modes = link_mode;
	unsigned int bit, idx;

	bit = modes % 64;
	idx = modes / 64;
	__set_bit(bit, &cmd->advertising[idx]);
}

void ys_build_ehtool_ksetting_supported(struct ys_ethtool_ksetting *cmd,
					enum ethtool_link_mode_bit_indices link_mode)
{
	const unsigned int modes = link_mode;
	unsigned int bit, idx;

	bit = modes % 64;
	idx = modes / 64;
	__set_bit(bit, &cmd->supported[idx]);
}

#ifdef YS_HAVE_ETHTOOL_GET_LINK_SETTING
static int ys_get_link_ksettings(struct net_device *ndev,
				 struct ethtool_link_ksettings *ksettings)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 port_type;
#ifdef YS_HAVE_TRANSCEIVER
	u32 transceiver_type;
#endif /* YS_HAVE_TRANSCEIVER */
	u8 autoneg_enable;
	struct ys_ethtool_ksetting cmd;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	memset(&cmd, 0, sizeof(struct ys_ethtool_ksetting));

	ethtool_link_ksettings_zero_link_mode(ksettings, supported);
	ethtool_link_ksettings_zero_link_mode(ksettings, advertising);
	ethtool_link_ksettings_zero_link_mode(ksettings, lp_advertising);

	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_supported_advertising) {
		ndev_priv->ys_eth_hw->et_get_supported_advertising(ndev, &cmd);

		bitmap_copy(ksettings->link_modes.supported,
			    cmd.supported,
			    __ETHTOOL_LINK_MODE_MASK_NBITS);
		bitmap_copy(ksettings->link_modes.advertising,
			    cmd.advertising,
			    __ETHTOOL_LINK_MODE_MASK_NBITS);
		bitmap_copy(ksettings->link_modes.lp_advertising,
			    cmd.lp_advertising,
			    __ETHTOOL_LINK_MODE_MASK_NBITS);
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_speed) {
		ndev_priv->speed = ndev_priv->ys_eth_hw->et_get_link_speed(ndev);
		ksettings->base.speed = ndev_priv->speed;
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_duplex) {
		ndev_priv->duplex = ndev_priv->ys_eth_hw->et_get_link_duplex(ndev);
		ksettings->base.duplex = ndev_priv->duplex;
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_autoneg) {
		autoneg_enable = ndev_priv->ys_eth_hw->et_get_link_autoneg(ndev);
		ksettings->base.autoneg = autoneg_enable;
		if (autoneg_enable == AUTONEG_DISABLE)
			ndev_priv->port_flags &= ~(0x1 << YS_PORT_FLAG_AUTONEG_ENABLE);
		else
			ndev_priv->port_flags |= 0x1 << YS_PORT_FLAG_AUTONEG_ENABLE;
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_port_type) {
		port_type = ndev_priv->ys_eth_hw->et_get_link_port_type(ndev);
		ksettings->base.port = port_type;
	}
#ifdef YS_HAVE_TRANSCEIVER
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_transceiver) {
		transceiver_type = ndev_priv->ys_eth_hw->et_get_link_transceiver(ndev);
		ksettings->base.transceiver = transceiver_type;
	}
#endif /* YS_HAVE_TRANSCEIVER */

	return 0;
}

#else
static int ys_get_link_ksettings(struct net_device *ndev,
				 struct ethtool_cmd *ksettings)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 port_type;
#ifdef YS_HAVE_TRANSCEIVER
	u32 transceiver_type;
#endif /* YS_HAVE_TRANSCEIVER */
	u8 autoneg_enable;
	struct ys_ethtool_ksetting cmd;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	memset(&cmd, 0, sizeof(struct ys_ethtool_ksetting));
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_supported_advertising) {
		ndev_priv->ys_eth_hw->et_get_supported_advertising(ndev, &cmd);
		memcpy(&ksetings->supported,
		       cmd.supported,
		       __ETHTOOL_LINK_MODE_MASK_NBITS);
		memcpy(&ksetings->advertising,
		       cmd.advertising,
		       __ETHTOOL_LINK_MODE_MASK_NBITS);
		memcpy(&ksetings->lp_advertising,
		       cmd.lp_advertising,
		       __ETHTOOL_LINK_MODE_MASK_NBITS);
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_speed) {
		ndev_priv->speed = ndev_priv->ys_eth_hw->et_get_link_speed(ndev);
		ksettings->speed = ndev_priv->speed;
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_duplex) {
		ndev_priv->duplex = ndev_priv->ys_eth_hw->et_get_link_duplex(ndev);
		ksettings->duplex = ndev_priv->duplex;
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_autoneg) {
		autoneg_enable = ndev_priv->ys_eth_hw->et_get_link_autoneg(ndev);
		ksettings->autoneg = autoneg_enable;
		ndev_priv->port_flags |= autoneg_enable << YS_PORT_FLAG_AUTONEG_ENABLE;
	}
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_port_type) {
		port_type = ndev_priv->ys_eth_hw->et_get_link_port_type(ndev);
		ksettings->port = port_type;
	}
#ifdef YS_HAVE_TRANSCEIVER
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_link_transceiver) {
		transceiver_type = ndev_priv->ys_eth_hw->et_get_link_transceiver(ndev);
		ksettings->transceiver = transceiver_type;
	}
#endif /* YS_HAVE_TRANSCEIVER */

	return 0;
}
#endif /* YS_HAVE_ETHTOOL_GET_LINK_SETTING */

static int ys_set_link_ksettings(struct net_device *ndev,
				 const struct ethtool_link_ksettings *ksettings)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 speed;
	u32 duplex;
	u32 ret = 0;
	bool autoneg_enable;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	speed = LINK_CONFIGS_GET(ksettings, speed);
	autoneg_enable = LINK_CONFIGS_GET(ksettings, autoneg);
	duplex = LINK_CONFIGS_GET(ksettings, duplex);

	if (speed != ndev_priv->speed) {
		if (ndev_priv->ys_eth_hw->et_set_link_speed) {
			ret = ndev_priv->ys_eth_hw->et_set_link_speed(ndev, speed);
		} else {
			ys_net_info("Modification of speed is not supported\n");
			return -EOPNOTSUPP;
		}
	}
	if (ret) {
		ys_net_info("Failed to modify speed\n");
		return ret;
	}
	if (duplex != ndev_priv->duplex) {
		if (ndev_priv->ys_eth_hw->et_set_link_duplex_mode) {
			ret = ndev_priv->ys_eth_hw->et_set_link_duplex_mode(ndev, duplex);
		} else {
			ys_net_info("Modification of duplex mode is not supported\n");
			return -EOPNOTSUPP;
		}
	}
	if (ret) {
		ys_net_info("Failed to modify duplex mode\n");
		return ret;
	}
	if (((ndev_priv->port_flags >> YS_PORT_FLAG_AUTONEG_ENABLE) & 1) != autoneg_enable) {
		if (ndev_priv->ys_eth_hw->et_set_link_autoneg) {
			ret = ndev_priv->ys_eth_hw->et_set_link_autoneg(ndev, autoneg_enable);
		} else {
			ys_net_info("Modification of autoneg is not supported\n");
			return -EOPNOTSUPP;
		}
	}
	if (ret) {
		ys_net_info("Failed to modify autoneg\n");
		return ret;
	}
	return ret;
}

static u32 ys_get_priv_flags(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->et_get_priv_flags)
		return ndev_priv->ys_eth_hw->et_get_priv_flags(ndev);
	return -EOPNOTSUPP;
}

static int ys_set_priv_flags(struct net_device *ndev, u32 flag)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->et_set_priv_flags)
		return ndev_priv->ys_eth_hw->et_set_priv_flags(ndev, flag);
	return -EOPNOTSUPP;
}

#ifdef YS_HAVE_ETHTOOL_COALESCE_CQE

static int ys_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec,
			   struct kernel_ethtool_coalesce *kec,
			   struct netlink_ext_ack *ack)
#else
static int ys_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec)
#endif /* YS_HAVE_ETHTOOL_COALESCE_CQE */
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;
	if (ndev_priv->ys_eth_hw->et_get_coalesce)
		return ndev_priv->ys_eth_hw->et_get_coalesce(ndev, ec);
	return -EOPNOTSUPP;
}

#ifdef YS_HAVE_ETHTOOL_COALESCE_CQE
static int ys_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec,
			   struct kernel_ethtool_coalesce *kec,
			   struct netlink_ext_ack *ack)
#else
static int ys_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ec)
#endif /* YS_HAVE_ETHTOOL_COALESCE_CQE */
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;
	if (ec->rx_coalesce_usecs > MAX_COALESCE_US || ec->tx_coalesce_usecs > MAX_COALESCE_US)
		return -EINVAL;
	if (ndev_priv->ys_eth_hw->et_set_coalesce)
		return ndev_priv->ys_eth_hw->et_set_coalesce(ndev, ec);

	return -EOPNOTSUPP;
}

static int ys_get_ts_info(struct net_device *ndev, struct ethtool_ts_info *eti)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;
	struct ys_ptp *ptp;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ptp = pdev_priv->ptp;

	if (!IS_ERR_OR_NULL(ptp) && !IS_ERR_OR_NULL(ptp->pclock)) {
		eti->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
				       SOF_TIMESTAMPING_RX_HARDWARE |
				       SOF_TIMESTAMPING_RAW_HARDWARE;
		eti->phc_index = ptp_clock_index(ptp->pclock);
		eti->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);
		eti->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
				  (1 << HWTSTAMP_FILTER_ALL);
	} else {
		eti->so_timestamping = SOF_TIMESTAMPING_RX_SOFTWARE |
				       SOF_TIMESTAMPING_TX_SOFTWARE |
				       SOF_TIMESTAMPING_SOFTWARE;
		eti->phc_index = -1;
		eti->tx_types = 0;
		eti->rx_filters = 0;
	}

	return 0;
}

static int ys_get_fecparam(struct net_device *ndev, struct ethtool_fecparam *fp)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;
	if (ndev_priv->ys_eth_hw->et_get_fec_mode)
		ndev_priv->ys_eth_hw->et_get_fec_mode(ndev, fp);
	else
		return -EOPNOTSUPP;
	if (ndev_priv->fec_cfg)
		fp->fec = ndev_priv->fec_cfg;
	else
		fp->fec = fp->active_fec;
	return 0;
}

static int ys_set_fecparam(struct net_device *ndev, struct ethtool_fecparam *fp)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 fec = fp->fec;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;
	if (ndev_priv->ys_eth_hw->et_set_fec_mode)
		return ndev_priv->ys_eth_hw->et_set_fec_mode(ndev, fec);

	return -EOPNOTSUPP;
}

static void ys_get_eth_mac_stats(struct net_device *ndev,
				 struct ethtool_eth_mac_stats *mac_stats)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	if (ndev_priv->ys_eth_hw->et_get_mac_stats)
		ndev_priv->ys_eth_hw->et_get_mac_stats(ndev, mac_stats);
}

static void ys_get_rss_hash_opts(struct ys_ndev_priv *ndev_priv,
				 struct ethtool_rxnfc *info)
{
	struct ys_hash_field *hash_field;

	info->data = 0;
	hash_field = &ndev_priv->hash_field;
	switch (info->flow_type) {
	case TCP_V4_FLOW:
		if (hash_field->ipv4_tcp_hash_mode & YS_HASH_FIELD_SEL_SRC_IP)
			info->data |= RXH_IP_SRC;
		if (hash_field->ipv4_tcp_hash_mode & YS_HASH_FIELD_SEL_DST_IP)
			info->data |= RXH_IP_DST;
		if (hash_field->ipv4_tcp_hash_mode & YS_HASH_FIELD_SEL_L4_SPORT)
			info->data |= RXH_L4_B_0_1;
		if (hash_field->ipv4_tcp_hash_mode & YS_HASH_FIELD_SEL_L4_DPORT)
			info->data |= RXH_L4_B_2_3;
		if (hash_field->ipv4_tcp_hash_mode & YS_HASH_FIELD_SEL_L3_PROTO)
			info->data |= RXH_L3_PROTO;
		break;
	case TCP_V6_FLOW:
		if (hash_field->ipv6_tcp_hash_mode & YS_HASH_FIELD_SEL_SRC_IP)
			info->data |= RXH_IP_SRC;
		if (hash_field->ipv6_tcp_hash_mode & YS_HASH_FIELD_SEL_DST_IP)
			info->data |= RXH_IP_DST;
		if (hash_field->ipv6_tcp_hash_mode & YS_HASH_FIELD_SEL_L4_SPORT)
			info->data |= RXH_L4_B_0_1;
		if (hash_field->ipv6_tcp_hash_mode & YS_HASH_FIELD_SEL_L4_DPORT)
			info->data |= RXH_L4_B_2_3;
		if (hash_field->ipv6_tcp_hash_mode & YS_HASH_FIELD_SEL_L3_PROTO)
			info->data |= RXH_L3_PROTO;
		break;
	case UDP_V4_FLOW:
		if (hash_field->ipv4_udp_hash_mode & YS_HASH_FIELD_SEL_SRC_IP)
			info->data |= RXH_IP_SRC;
		if (hash_field->ipv4_udp_hash_mode & YS_HASH_FIELD_SEL_DST_IP)
			info->data |= RXH_IP_DST;
		if (hash_field->ipv4_udp_hash_mode & YS_HASH_FIELD_SEL_L4_SPORT)
			info->data |= RXH_L4_B_0_1;
		if (hash_field->ipv4_udp_hash_mode & YS_HASH_FIELD_SEL_L4_DPORT)
			info->data |= RXH_L4_B_2_3;
		if (hash_field->ipv4_udp_hash_mode & YS_HASH_FIELD_SEL_L3_PROTO)
			info->data |= RXH_L3_PROTO;
		break;
	case UDP_V6_FLOW:
		if (hash_field->ipv6_udp_hash_mode & YS_HASH_FIELD_SEL_SRC_IP)
			info->data |= RXH_IP_SRC;
		if (hash_field->ipv6_udp_hash_mode & YS_HASH_FIELD_SEL_DST_IP)
			info->data |= RXH_IP_DST;
		if (hash_field->ipv6_udp_hash_mode & YS_HASH_FIELD_SEL_L4_SPORT)
			info->data |= RXH_L4_B_0_1;
		if (hash_field->ipv6_udp_hash_mode & YS_HASH_FIELD_SEL_L4_DPORT)
			info->data |= RXH_L4_B_2_3;
		if (hash_field->ipv6_udp_hash_mode & YS_HASH_FIELD_SEL_L3_PROTO)
			info->data |= RXH_L3_PROTO;
		break;
	default:
		break;
	}
}

static int ys_get_rxnfc_eth(struct net_device *ndev,
			    struct ethtool_rxnfc *info,
			    u32 *rule_locs __always_unused)
{
	int ret = 0;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;
	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = ndev->real_num_rx_queues;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		info->rule_cnt = 0;
		info->data = 0;
		if (ndev_priv->ys_eth_hw->ys_get_ethtool_rule_count)
			ret = ndev_priv->ys_eth_hw->ys_get_ethtool_rule_count(ndev, info);
		break;
	case ETHTOOL_GRXCLSRULE:
		if (ndev_priv->ys_eth_hw->ys_get_ethtool_flow_entry)
			ret = ndev_priv->ys_eth_hw->ys_get_ethtool_flow_entry(ndev, info);
		break;
	case ETHTOOL_GRXCLSRLALL:
		if (ndev_priv->ys_eth_hw->ys_get_ethtool_all_flows)
			ret = ndev_priv->ys_eth_hw->ys_get_ethtool_all_flows(ndev, info,
									     rule_locs);
		break;
	case ETHTOOL_GRXFH:
		ys_get_rss_hash_opts(ndev_priv, info);
		break;
	default:
		info->data = 0;
		ret = -EOPNOTSUPP;
		ys_net_info("Command parameters not supported\n");
		break;
	}
	return ret;
}

static int ys_set_rxnfc_eth(struct net_device *ndev,
			    struct ethtool_rxnfc *rxnfc)
{
	int ret = 0;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;
	switch (rxnfc->cmd) {
	case ETHTOOL_SRXFH:
		if (ndev_priv->ys_eth_hw->ys_set_rss_hash_opt)
			ret = ndev_priv->ys_eth_hw->ys_set_rss_hash_opt(ndev, rxnfc);
		break;
	case ETHTOOL_SRXCLSRLINS:
		if (ndev_priv->ys_eth_hw->ys_add_ethtool_flow_entry)
			ret = ndev_priv->ys_eth_hw->ys_add_ethtool_flow_entry(ndev, rxnfc);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		if (ndev_priv->ys_eth_hw->ys_del_ethtool_flow_entry)
			ret = ndev_priv->ys_eth_hw->ys_del_ethtool_flow_entry(ndev, rxnfc);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	/* if np exist */
	if (ret == 0 && rxnfc->cmd == ETHTOOL_SRXFH)
		ret = atomic_notifier_call_chain(&ndev_priv->ys_ndev_hw->ys_set_rxnfc_list,
						 YS_NP_DOE_OP_RSS, ndev);

	return ret;
}

static u32 ys_get_rxfh_indir_size_eth(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_get_rxfh_indir_size)
		return ndev_priv->ys_eth_hw->ys_get_rxfh_indir_size(ndev);

	return -EOPNOTSUPP;
}

static u32 ys_get_rxfh_key_size_eth(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_get_rxfh_key_size)
		return ndev_priv->ys_eth_hw->ys_get_rxfh_key_size(ndev);

	return -EOPNOTSUPP;
}

#ifdef YS_HAVE_ETHTOOL_GET_RXFH_PARAM
static int ys_get_rxfh_eth(struct net_device *ndev, struct ethtool_rxfh_param *param)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_get_rxfh)
		return ndev_priv->ys_eth_hw->ys_get_rxfh(ndev,
							 param->indir,
							 param->key,
							 &param->hfunc);

	return -EOPNOTSUPP;
}
#endif /* YS_HAVE_ETHTOOL_GET_RXFH_PARAM */

static int ys_get_rxfh_eth_old(struct net_device *ndev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_get_rxfh)
		return ndev_priv->ys_eth_hw->ys_get_rxfh(ndev, indir, key,
							 hfunc);

	return -EOPNOTSUPP;
}

#ifdef YS_HAVE_ETHTOOL_SET_RXFH_PARAM
static int ys_set_rxfh_eth(struct net_device *ndev,
			   struct ethtool_rxfh_param *param,
			   struct netlink_ext_ack *extack)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_set_rxfh)
		return ndev_priv->ys_eth_hw->ys_set_rxfh(ndev,
							 param->indir,
							 param->key,
							 param->hfunc);

	return -EOPNOTSUPP;
}
#endif /* YS_HAVE_ETHTOOL_SET_RXFH_PARAM */

static int ys_set_rxfh_eth_old(struct net_device *ndev, const u32 *indir,
			       const u8 *key, const u8 hfunc)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_set_rxfh)
		return ndev_priv->ys_eth_hw->ys_set_rxfh(ndev, indir, key,
							 hfunc);

	return -EOPNOTSUPP;
}

static int ys_get_eeprom_len(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;
	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->et_get_eeprom_len)
		return ndev_priv->ys_eth_hw->et_get_eeprom_len(ndev);

	return 0;
}

static int ys_get_eeprom(struct net_device *ndev,
			 struct ethtool_eeprom *eeep, u8 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;
	u8 offset = eeep->offset;
	size_t len = eeep->len;
	struct ys_i2c *i2c;
	u8 *i2c_data;
	int i;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	i2c = ys_aux_match_i2c_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(i2c))
		return -EOPNOTSUPP;
	if (unlikely(ndev->dev_port >= i2c->idev_num))
		return -EINVAL;

	for (i = 0; i < YS_I2C_MAX_I2C_DEVICES; i++)
		if (i2c->idev[i].type == I2C_EEPROM)
			break;

	if (i >= YS_I2C_MAX_I2C_DEVICES)
		return -EINVAL;

	ys_i2c_read(&i2c->idev[i], 0, i2c->idev[i].data, i2c->idev[i].data_len);
	i2c_data = i2c->idev[i].data;
	ys_net_debug("i2c_id=%d, i2c_dev_name=%s, offset=0x%04x, len=0x%04lx\n",
		     i, i2c->idev[i].name, offset,
		     len);
	memcpy(data, i2c_data + offset, len);
	return 0;
}

static int ys_set_eeprom(struct net_device *ndev,
			 struct ethtool_eeprom *eeep, u8 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;
	u8 offset = eeep->offset;
	size_t len = eeep->len;
	struct ys_i2c *i2c;
	int i;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	i2c = ys_aux_match_i2c_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(i2c))
		return -EOPNOTSUPP;
	if (unlikely(ndev->dev_port >= i2c->idev_num))
		return -EINVAL;

	for (i = 0; i < YS_I2C_MAX_I2C_DEVICES; i++)
		if (i2c->idev[i].type == I2C_EEPROM)
			break;

	if (i >= YS_I2C_MAX_I2C_DEVICES)
		return -EINVAL;

	ys_i2c_write(&i2c->idev[i], offset, data, len);
	ys_net_debug("i2c_id=%d, i2c_dev_name=%s, offset=0x%04x, len=0x%04lx\n",
		     i, i2c->idev[i].name, offset,
		     len);
	return 0;
}

static int ys_set_phys_id_eth(struct net_device *ndev,
			      enum ethtool_phys_id_state state)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_set_phys_id)
		return ndev_priv->ys_eth_hw->ys_set_phys_id(ndev, state);

	return -EOPNOTSUPP;
}

#ifdef YS_HAVE_KERNEL_RING
static void ys_get_ringparam_eth(struct net_device *ndev,
				 struct ethtool_ringparam *ring,
				 struct kernel_ethtool_ringparam *kring,
				 struct netlink_ext_ack *ext_ack)
#else
static void ys_get_ringparam_eth(struct net_device *ndev,
				 struct ethtool_ringparam *ring)
#endif /* YS_HAVE_KERNEL_RING */
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	if (ndev_priv->ys_eth_hw->ys_get_ringparam)
		ndev_priv->ys_eth_hw->ys_get_ringparam(ndev, ring);
}

#ifdef YS_HAVE_KERNEL_RING
static int ys_set_ringparam_eth(struct net_device *ndev,
				struct ethtool_ringparam *ring,
				struct kernel_ethtool_ringparam *kring,
				struct netlink_ext_ack *ext_ack)
#else
static int ys_set_ringparam_eth(struct net_device *ndev,
				struct ethtool_ringparam *ring)
#endif /* YS_HAVE_KERNEL_RING */
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret = -EOPNOTSUPP;
	u8 rx_enabled = ndev_priv->rx_enabled;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw->ys_ringparam_check &&
	    ndev_priv->ys_eth_hw->ys_ringparam_check(ndev, ring))
		return -EINVAL;

	if (ndev->netdev_ops->ndo_stop)
		ndev->netdev_ops->ndo_stop(ndev);
	ndev->flags &= ~IFF_UP;

	mutex_lock(&ndev_priv->state_lock);
	if (ndev_priv->ys_eth_hw->ys_set_ringparam)
		ret = ndev_priv->ys_eth_hw->ys_set_ringparam(ndev, ring);
	mutex_unlock(&ndev_priv->state_lock);

	/* restore states */
	if (ndev->netdev_ops->ndo_open && rx_enabled) {
		ret = ndev->netdev_ops->ndo_open(ndev);
		ndev->flags |= IFF_UP;
	}

	return ret;
}

static int ys_get_regs_len_eth(struct net_device __always_unused *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ndev_priv->ys_eth_hw && ndev_priv->ys_eth_hw->ys_get_regs_len)
		return ndev_priv->ys_eth_hw->ys_get_regs_len(ndev);

	return -EOPNOTSUPP;
}

static void ys_get_regs_eth(struct net_device *ndev,
			    struct ethtool_regs *regs, void *p)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 *regs_buff = p;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;

	if (ndev_priv->ys_eth_hw->ys_get_regs)
		ndev_priv->ys_eth_hw->ys_get_regs(ndev, regs, regs_buff);
}

static void ys_get_channels_eth(struct net_device *ndev,
				struct ethtool_channels *ch)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;
	ch->max_combined = ndev->num_rx_queues;
	ch->combined_count = ndev->real_num_tx_queues;
}

static void ys_get_pauseparam(struct net_device *ndev,
			      struct ethtool_pauseparam *pause)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return;
	if (ndev_priv->ys_eth_hw->ys_get_pauseparam) {
		ndev_priv->ys_eth_hw->ys_get_pauseparam(ndev, pause);
	} else {
		pause->rx_pause = 0;
		pause->tx_pause = 0;
		pause->autoneg = 0;
	}
}

static int ys_set_pauseparam(struct net_device *ndev,
			     struct ethtool_pauseparam *pause)
{
	int rc = -EOPNOTSUPP;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return rc;
	if (ndev_priv->ys_eth_hw->ys_set_pauseparam)
		rc = ndev_priv->ys_eth_hw->ys_set_pauseparam(ndev, pause);

	return rc;
}

static int ys_channels_check(struct net_device *ndev,
			     struct ethtool_channels *ch)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!ch->combined_count) {
		ys_net_info("combined_count=0 not supported");
		return -EINVAL;
	}

	if (ch->combined_count > ndev->num_rx_queues) {
		ys_net_info("combined_count > max combined_count");
		return -EINVAL;
	}

	if (ch->other_count || ch->tx_count || ch->rx_count) {
		ys_net_info("command parameters not supported\n");
		return -EINVAL;
	}

	return 0;
}

static int ys_set_channels_eth(struct net_device *ndev,
			       struct ethtool_channels *ch)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv;
	int ret = -EOPNOTSUPP;
	u8 rx_enabled = ndev_priv->rx_enabled;
	u16 id;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH | AUX_TYPE_SF | AUX_TYPE_REP))
		return -EPERM;

	if (ys_channels_check(ndev, ch))
		return -EINVAL;

	if (ndev->netdev_ops->ndo_stop)
		ndev->netdev_ops->ndo_stop(ndev);
	ndev->flags &= ~IFF_UP;

	mutex_lock(&ndev_priv->state_lock);
	if (ndev_priv->ys_eth_hw->ys_set_channels)
		ret = ndev_priv->ys_eth_hw->ys_set_channels(ndev, ch);
	mutex_unlock(&ndev_priv->state_lock);
	if (ret) {
		ys_net_info("set channel failed\n");
		return -EINVAL;
	}

	/* restore states */
	if (ndev->netdev_ops->ndo_open && rx_enabled) {
		ret = ndev->netdev_ops->ndo_open(ndev);
		ndev->flags |= IFF_UP;
	}
	if (ret)
		return -EINVAL;

	/* rep port only have one queue for now */
	if (ndev_priv->adev_type == AUX_TYPE_REP)
		return ret;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	/* soc eth is uplink port */
	if (pdev_priv->dpu_mode == MODE_DPU_SOC)
		id = LAN_SOC_UPLINK_VFNUM;
	else
		id = 0;

	if (ndev_priv->ys_ndev_hw->ys_update_cfg)
		ret = ndev_priv->ys_ndev_hw->ys_update_cfg(ndev, id);

	/* if np exist */
	if (ret == 0)
		ret = atomic_notifier_call_chain(&ndev_priv->ys_ndev_hw->ys_set_channels_list,
						 YS_NP_DOE_OP_RXQ, ndev);

	return ret;
}

int ys_ethtool_hw_init(struct net_device *ndev)
{
	struct ys_ethtool_hw_ops *eth_hw_ops;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	eth_hw_ops = kzalloc(sizeof(*eth_hw_ops), GFP_KERNEL);

	if (!eth_hw_ops)
		return -ENOMEM;

	ndev_priv->ys_eth_hw = eth_hw_ops;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->mac_adp_eth_init))
		pdev_priv->ops->mac_adp_eth_init(ndev);

	if (!IS_ERR_OR_NULL(pdev_priv->ops->lan_adp_eth_init))
		pdev_priv->ops->lan_adp_eth_init(ndev);

	return 0;
}

void ys_ethtool_hw_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw)) {
		kfree(ndev_priv->ys_eth_hw);
		ndev_priv->ys_eth_hw = NULL;
	}
}

const struct ethtool_ops ys_ethtool_ops = {
#ifdef ETHTOOL_COALESCE_USECS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS | ETHTOOL_COALESCE_USE_ADAPTIVE,
#endif /* ETHTOOL_COALESCE_USECS */
	.get_drvinfo = ys_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ethtool_stats = ys_get_ethtool_stats,
	.get_strings = ys_get_strings,
	.get_sset_count = ys_get_sset_count,
	.get_module_eeprom = ys_get_module_eeprom,
	.get_module_info = ys_get_module_info,
	.self_test = ys_self_test,
#ifdef YS_HAVE_ETHTOOL_GET_LINK_SETTING
	.get_link_ksettings = ys_get_link_ksettings,
#else
	.get_settings = ys_get_link_ksettings,
#endif /* YS_HAVE_ETHTOOL_GET_LINK_SETTING */
	.set_link_ksettings = ys_set_link_ksettings,
	.get_priv_flags = ys_get_priv_flags,
	.set_priv_flags = ys_set_priv_flags,
	.get_coalesce = ys_get_coalesce,
	.set_coalesce = ys_set_coalesce,
	.get_ts_info = ys_get_ts_info,
	.get_fecparam = ys_get_fecparam,
	.set_fecparam = ys_set_fecparam,
#ifdef YS_HAVE_ETHTOOL_MAC_STATS
	.get_eth_mac_stats = ys_get_eth_mac_stats,
#endif /* YS_HAVE_ETHTOOL_MAC_STATS */
	.get_rxfh_indir_size = ys_get_rxfh_indir_size_eth,
	.get_rxfh_key_size = ys_get_rxfh_key_size_eth,
#ifdef YS_HAVE_ETHTOOL_GET_RXFH_PARAM
	.get_rxfh = ys_get_rxfh_eth,
	.set_rxfh = ys_set_rxfh_eth,
#else
	.get_rxfh = ys_get_rxfh_eth_old,
	.set_rxfh = ys_set_rxfh_eth_old,
#endif
	.get_rxnfc = ys_get_rxnfc_eth,
	.set_rxnfc = ys_set_rxnfc_eth,
	.get_eeprom_len = ys_get_eeprom_len,
	.get_eeprom = ys_get_eeprom,
	.set_eeprom = ys_set_eeprom,
	.set_phys_id = ys_set_phys_id_eth,
	.get_ringparam = ys_get_ringparam_eth,
	.set_ringparam = ys_set_ringparam_eth,
	.get_regs_len = ys_get_regs_len_eth,
	.get_regs = ys_get_regs_eth,
	.get_channels = ys_get_channels_eth,
	.set_channels = ys_set_channels_eth,
	.get_pauseparam = ys_get_pauseparam,
	.set_pauseparam = ys_set_pauseparam,
};

struct ys_ext_ethtool_ops exttool_ops = {
#ifdef ETHTOOL_COALESCE_USECS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS | ETHTOOL_COALESCE_USE_ADAPTIVE,
#endif /* ETHTOOL_COALESCE_USECS */
	.get_fecparam = ys_get_fecparam,
	.set_fecparam = ys_set_fecparam,
#ifdef YS_HAVE_ETHTOOL_GET_LINK_SETTING
	.get_link_ksettings = ys_get_link_ksettings,
#else
	.get_settings = ys_get_link_ksettings,
#endif /* YS_HAVE_ETHTOOL_GET_LINK_SETTING */
	.set_link_ksettings = ys_set_link_ksettings,
	.get_module_info = ys_get_module_info,
	.get_ts_info = ys_get_ts_info,
	.get_channels = ys_get_channels_eth,
	.set_channels = ys_set_channels_eth,
	.get_ringparam = ys_get_ringparam_eth,
	.set_ringparam = ys_set_ringparam_eth,
	.get_coalesce = ys_get_coalesce,
	.set_coalesce = ys_set_coalesce,
	.get_eeprom_len = ys_get_eeprom_len,
	.get_eeprom = ys_get_eeprom,
	.set_eeprom = ys_set_eeprom,
	.get_link = ethtool_op_get_link,
	.get_regs_len = ys_get_regs_len_eth,
	.get_regs = ys_get_regs_eth,
	.get_module_eeprom = ys_get_module_eeprom,
	.set_phys_id = ys_set_phys_id_eth,
	.get_sset_count = ys_get_sset_count,
	.get_ethtool_stats = ys_get_ethtool_stats,
	.get_drvinfo = ys_get_drvinfo,
	.get_strings = ys_get_strings,
	.self_test = ys_self_test,
	.get_priv_flags = ys_get_priv_flags,
	.set_priv_flags = ys_set_priv_flags,
	.get_eth_mac_stats = ys_get_eth_mac_stats,
	.get_rxfh_indir_size = ys_get_rxfh_indir_size_eth,
	.get_rxfh_key_size = ys_get_rxfh_key_size_eth,
	.get_rxfh = ys_get_rxfh_eth_old,
	.set_rxfh = ys_set_rxfh_eth_old,
	.get_rxnfc = ys_get_rxnfc_eth,
	.set_rxnfc = ys_set_rxnfc_eth,
};
