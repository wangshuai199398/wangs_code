// SPDX-License-Identifier: GPL-2.0

#include "ys_cmac.h"

static const char ys_cmac_self_test_strings[][ETH_GSTRING_LEN] = {
	"Register test  (offline)", "Eeprom test    (offline)",
	"Interrupt test (offline)", "Loopback test  (offline)",
	"Link test   (on/offline)"
};

static const char ys_cmac_priv_strings[][ETH_GSTRING_LEN] = { "cmac_flag" };

#define CMAC_PRIV_STR_LEN ARRAY_SIZE(ys_cmac_priv_strings)
#define CMAC_SELF_TEST_LEN ARRAY_SIZE(ys_cmac_self_test_strings)

void ys_cmac_netdev_check_link(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32 reg = 0;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[CMAC_REGS_BAR];
	reg = ys_rd32(addr, CMAC_OFFSET_STAT_RX_STATUS(pdev_priv->pf_id));

	if (reg & CMAC_LINK_STATUS) {
		if (!netif_carrier_ok(ndev)) {
			netif_carrier_on(ndev);
			ys_net_info("link up");
		}
	} else if (netif_carrier_ok(ndev)) {
		netif_carrier_off(ndev);
		ys_net_info("link down\n");
	}
}

void ys_cmac_get_self_strings(struct net_device *ndev, u8 *data)
{
	memcpy(data, ys_cmac_self_test_strings,
	       sizeof(ys_cmac_self_test_strings));
}

void ys_cmac_get_priv_strings(struct net_device *ndev, u8 *data)
{
	memcpy(data, ys_cmac_priv_strings, sizeof(ys_cmac_priv_strings));
}

int ys_cmac_get_self_count(struct net_device *ndev)
{
	return CMAC_SELF_TEST_LEN;
}

int ys_cmac_get_priv_count(struct net_device *ndev)
{
	return CMAC_PRIV_STR_LEN;
}

void ys_cmac_get_supported_advertising(struct net_device *ndev,
				       struct ys_ethtool_ksetting *cmd)
{
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_1000baseKX_Full_BIT);
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT);
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT);
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_1000baseKX_Full_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT);
}

u32 ys_cmac_get_link_speed(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32 speed = 0;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[CMAC_REGS_BAR];

	if (netif_carrier_ok(ndev)) {
		speed = ys_rd32(addr, CMAC_OFFSET_STAT_AN_LINK_CTL_1(CMAC_ID));
		if (speed & CMAC_SPEED_10G)
			speed = SPEED_10G;
		else if (speed & CMAC_SPEED_25G)
			speed = SPEED_25G;
		else if (speed & CMAC_SPEED_40G)
			speed = SPEED_40G;
		else if (speed & CMAC_SPEED_50G)
			speed = SPEED_50G;
		else if (speed & CMAC_SPEED_100G)
			speed = SPEED_100G;
		else
			speed = SPEED_1G;
	} else {
		speed = SPEED_UNKNOWN;
	}
	return speed;
}

u32 ys_cmac_get_link_duplex(struct net_device *ndev)
{
	/* Parameters are set by the Vivado IDE */
	u32 duplex;

	duplex = DUPLEX_FULL;
	return duplex;
}

u8 ys_cmac_get_link_autoneg(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u8 autoneg = 0;
	u32 reg_val = 0;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[CMAC_REGS_BAR];
	reg_val = ys_rd32(addr, CMAC_OFFSET_CONF_AN_CTRL_1(CMAC_ID));

	autoneg = (reg_val | XCMAC_CTL_AUTONEG_ENABLE_BIT) ?
		   AUTONEG_ENABLE :
		   AUTONEG_DISABLE;
	return autoneg;
}

u32 ys_cmac_get_link_port_type(struct net_device *ndev)
{
	u32 port_type;

	port_type = PORT_FIBRE;
	return port_type;
}

u32 ys_cmac_get_priv_flags(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 flag = 0;

	if (ndev_priv->priv_enable)
		flag |= (1 << CMAC_PRIV_FLAG);

	return flag;
}

u32 ys_cmac_set_priv_flags(struct net_device *ndev, u32 flag)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	bool cmac_flag = false;

	cmac_flag = (1 << CMAC_PRIV_FLAG) & flag;
	if (cmac_flag && !ndev_priv->priv_enable)
		ndev_priv->priv_enable = true;
	else
		ndev_priv->priv_enable = false;

	return 0;
}

int ys_cmac_get_fec_mode(struct net_device *ndev, struct ethtool_fecparam *fp)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	fp->active_fec = ndev_priv->fec_cfg;

	return 0;
}

int ys_cmac_set_fec_mode(struct net_device *ndev, u32 fec)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[CMAC_REGS_BAR];

	switch (fec) {
	case ETHTOOL_FEC_RS:
		if (ndev_priv->fec_cfg == ETHTOOL_FEC_RS)
			return 0;
		ys_wr32(addr, CMAC_OFFSET_RSFEC_CONF_ENABLE(CMAC_ID), 0x3);
		ys_wr32(addr, CMAC_OFFSET_RSFEC_CONF_IND_CORRECTION(CMAC_ID),
			0x7);
		ndev_priv->fec_cfg = ETHTOOL_FEC_RS;
		return 0;
	case ETHTOOL_FEC_OFF:
		ys_wr32(addr, CMAC_OFFSET_RSFEC_CONF_ENABLE(CMAC_ID), 0);
		ys_wr32(addr, CMAC_OFFSET_RSFEC_CONF_IND_CORRECTION(CMAC_ID),
			0);
		ndev_priv->fec_cfg = ETHTOOL_FEC_OFF;
		return 0;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

void ys_cmac_get_mac_stats(struct net_device *ndev,
			   struct ethtool_eth_mac_stats *mac_stats)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u16 func_id;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[CMAC_REGS_BAR];
	func_id = PCI_FUNC(ndev_priv->pdev->devfn);

	if (func_id == 0)
		ys_wr32(addr, CMAC_OFFSET_TICK(0), 1);
	else
		ys_wr32(addr, CMAC_OFFSET_TICK(1), 1);

	mac_stats->FramesTransmittedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_TX_TOTAL_GOOD_PKTS(0));
	mac_stats->FramesReceivedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_RX_TOTAL_GOOD_PKTS(0));
	mac_stats->FrameCheckSequenceErrors =
		ys_rd32(addr, CMAC_OFFSET_STAT_TX_BAD_FCS(0)) +
		ys_rd32(addr, CMAC_OFFSET_STAT_RX_BAD_FCS(0));
	mac_stats->OctetsTransmittedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_TX_TOTAL_GOOD_BYTES(0));
	mac_stats->OctetsReceivedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_RX_TOTAL_GOOD_BYTES(0));
	mac_stats->MulticastFramesXmittedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_TX_MULTICAST(0));
	mac_stats->BroadcastFramesXmittedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_TX_BROADCAST(0));
	mac_stats->MulticastFramesReceivedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_RX_MULTICAST(0));
	mac_stats->BroadcastFramesReceivedOK =
		ys_rd32(addr, CMAC_OFFSET_STAT_RX_BROADCAST(0));
	mac_stats->InRangeLengthErrors = 0;
	mac_stats->OutOfRangeLengthField = 0;
	mac_stats->FrameTooLongErrors = 0;
}

static int ys_cmac_init(struct net_device *ndev, int cmac_id)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[CMAC_REGS_BAR];

	if (cmac_id != 0 && cmac_id != 1)
		return -EINVAL;

	if (ndev_priv->fec_cfg) {
		ys_wr32(addr, CMAC_OFFSET_RSFEC_CONF_ENABLE(cmac_id), 0x3);
		ys_wr32(addr, CMAC_OFFSET_RSFEC_CONF_IND_CORRECTION(cmac_id),
			0x7);
	}

	if (cmac_id == 0) {
		ys_wr32(addr, SYSCFG_OFFSET_SHELL_RESET, 0x2);
		if ((ys_rd32(addr, SYSCFG_OFFSET_SHELL_STATUS) & 0x2) != 0x2)
			mdelay(CMAC_RESET_WAIT_MS);
	} else {
		ys_wr32(addr, SYSCFG_OFFSET_SHELL_RESET, 0x4);
		if ((ys_rd32(addr, SYSCFG_OFFSET_SHELL_STATUS) & 0x4) != 0x4)
			mdelay(CMAC_RESET_WAIT_MS);
	}

	ys_wr32(addr, CMAC_OFFSET_CONF_RX_1(cmac_id), 0x1);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_1(cmac_id), 0x10);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_1(cmac_id), 0x1);

	/* RX flow control */
	ys_wr32(addr, CMAC_OFFSET_CONF_RX_FC_CTRL_1(cmac_id), 0x00003DFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_RX_FC_CTRL_2(cmac_id), 0x0001C631);

	/* TX flow control */
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_QNTA_1(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_QNTA_2(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_QNTA_3(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_QNTA_4(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_QNTA_5(cmac_id), 0x0000FFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_RFRH_1(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_RFRH_2(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_RFRH_3(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_RFRH_4(cmac_id), 0xFFFFFFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_RFRH_5(cmac_id), 0x0000FFFF);
	ys_wr32(addr, CMAC_OFFSET_CONF_TX_FC_CTRL_1(cmac_id), 0x000001FF);

	return 0;
}

int ys_cmac_enable(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	int val = 0;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[CMAC_REGS_BAR];

	if (!pdev_priv->pdev->is_virtfn) {
		val = ys_rd32(addr, CMAC_OFFSET_CORE_VERSION(pdev_priv->pf_id));
		if (val != CMAC_CORE_VERSION)
			return -1;
		ys_cmac_init(ndev, pdev_priv->pf_id);
	}

	return pdev_priv->pf_id;
}

int ys_cmac_eth_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw))
		CMAC_ETH_FUNC(ndev_priv->ys_eth_hw);

	return 0;
}

int ys_cmac_ndev_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw)) {
		CMAC_NDEV_FUNC(ndev_priv->ys_ndev_hw);
		(void)ndev_priv;
	}

	return 0;
}
