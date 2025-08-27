// SPDX-License-Identifier: GPL-2.0

#include "ys_xmac.h"
#include "../../../platform/ysif_linux.h"

static const char ys_xmac_stats_strings[][ETH_GSTRING_LEN] = {
	"cycle_count_phy",
	"rx_framing_err_phy",
	"rx_bad_code_phy",
	"rx_error_phy",
	"rx_rsfec_corrected_cw_inc_phy",
	"rx_rsfec_uncorrected_cw_inc_phy",
	"rx_rsfec_err_count0_inc_phy",
	"rx_rsfec_uncorrected_cw_inc_phy",

	"tx_framing_error_phy",
	"tx_total_packets_phy",
	"tx_total_good_packets_phy",
	"tx_total_bytes_phy",
	"tx_total_good_bytes_phy",
	"tx_packet_64_bytes_phy",
	"tx_packet_65_127_bytes_phy",
	"tx_packet_128_255_bytes_phy",
	"tx_packet_256_511_bytes_phy",
	"tx_packet_512_1023_bytes_phy",
	"tx_packet_1024_1518_bytes_phy",
	"tx_packet_1519_1522_bytes_phy",
	"tx_packet_1523_1548_bytes_phy",
	"tx_packet_1549_2047_bytes_phy",
	"tx_packet_2048_4095_bytes_phy",
	"tx_packet_4096_8191_bytes_phy",
	"tx_packet_8192_9215_bytes_phy",
	"tx_packet_large_phy",
	"tx_packet_small_phy",
	"tx_bad_fcs_phy",
	"tx_unicast_phy",
	"tx_multicast_phy",
	"tx_broadcast_phy",
	"tx_vlan_phy",
	"tx_pause_phy",
	"tx_user_pause_phy",

	"rx_total_packets_phy",
	"rx_total_good_packets_phy",
	"rx_total_bytes_phy",
	"rx_total_good_bytes_phy",
	"rx_packet_64_bytes_phy",
	"rx_packet_65_127_bytes_phy",
	"rx_packet_128_255_bytes_phy",
	"rx_packet_256_511_bytes_phy",
	"rx_packet_512_1023_bytes_phy",
	"rx_packet_1024_1518_bytes_phy",
	"rx_packet_1519_1022_bytes_phy",
	"rx_packet_1523_1548_bytes_phy",
	"rx_packet_1549_2047_bytes_phy",
	"rx_packet_2048_4095_bytes_phy",
	"rx_packet_4096_8191_bytes_phy",
	"rx_packet_8192_9215_bytes_phy",
	"rx_packet_large_phy",
	"rx_packet_small_phy",
	"rx_undersize_phy",
	"rx_fragment_phy",
	"rx_oversize_phy",
	"rx_toolong_phy",
	"rx_jabber_phy",
	"rx_bad_fcs_phy",
	"rx_packet_bad_fcs_phy",
	"rx_stomped_bad_fcs_phy",
	"rx_unicast_phy",
	"rx_multicast_phy",
	"rx_broadcast_phy",
	"rx_vlan_phy",
	"rx_pause_phy",
	"rx_user_pause_phy",
	"rx_inrangeerr_phy",
	"rx_truncated_phy",
	"rx_test_pattern_mismatch_phy",
	"fec_inc_correct_count_phy",
	"fec_inc_cant_correct_count_phy",
};

int ys_xmac_enable(struct net_device *ndev)
{
	return 0;
}

void ys_xmac_netdev_check_link(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32 reg;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	reg = ys_rd32(pdev_priv->bar_addr[YS_XMAC_REGS_BAR],
		      XMAC_LINK_STATUS(pdev_priv->pf_id));

	if (reg & XMAC_PORT_STATUS_ENABLED) {
		if (!netif_carrier_ok(ndev)) {
			netif_carrier_on(ndev);
			ys_net_info("Link up");
		}
	} else if (netif_carrier_ok(ndev)) {
		netif_carrier_off(ndev);
		ys_net_info("Link down");
	}
}

void ys_xmac_get_stats(struct net_device *ndev, u64 *data)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32 pf_id;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_XMAC_REGS_BAR];
	pf_id = pdev_priv->pf_id % 2;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return;

	/* trigger count */
	ys_wr32(pdev_priv->bar_addr[YS_XMAC_REGS_BAR],
		XMAC_TICK(pf_id), 1);

	data[XMAC_STATUS_CYCLE_COUNT] += ys_rd64(addr, XMAC_STATUS_CYCLE_COUNT(pf_id));
	data[XMAC_STAT_RX_FRAMING_ERR] += ys_rd64(addr, XMAC_STAT_RX_FRAMING_ERR(pf_id));
	data[XMAC_STAT_RX_BAD_CODE] += ys_rd64(addr, XMAC_STAT_RX_BAD_CODE(pf_id));
	data[XMAC_STAT_RX_ERROR] += ys_rd64(addr, XMAC_STAT_RX_ERROR(pf_id));
	data[XMAC_STAT_RX_RSFEC_CORRECTED_CW_INC] +=
		ys_rd64(addr, XMAC_STAT_RX_RSFEC_CORRECTED_CW_INC(pf_id));
	data[XMAC_STAT_RX_RSFEC_UNCORRECTED_CW_INC] +=
		ys_rd64(addr, XMAC_STAT_RX_RSFEC_UNCORRECTED_CW_INC(pf_id));
	data[XMAC_STAT_RX_RSFEC_ERR_COUNT0_INC] +=
		ys_rd64(addr, XMAC_STAT_RX_RSFEC_ERR_COUNT0_INC(pf_id));

	data[XMAC_STAT_TX_FRAMING_ERROR] +=
		ys_rd64(addr, XMAC_STAT_TX_FRAMING_ERROR(pf_id));
	data[XMAC_STAT_TX_TOTAL_PACKETS] +=
		ys_rd64(addr, XMAC_STAT_TX_TOTAL_PACKETS(pf_id));
	data[XMAC_STAT_TX_TOTAL_GOOD_PACKETS] +=
		ys_rd64(addr, XMAC_STAT_TX_TOTAL_GOOD_PACKETS(pf_id));
	data[XMAC_STAT_TX_TOTAL_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_TOTAL_BYTES(pf_id));
	data[XMAC_STAT_TX_TOTAL_GOOD_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_TOTAL_GOOD_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_64_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_64_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_65_127_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_65_127_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_128_255_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_128_255_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_256_511_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_256_511_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_512_1023_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_512_1023_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_1024_1518_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_1024_1518_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_1519_1522_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_1519_1522_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_1523_1548_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_1523_1548_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_1549_2047_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_1549_2047_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_2048_4095_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_2048_4095_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_4096_8191_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_4096_8191_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_8192_9215_BYTES] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_8192_9215_BYTES(pf_id));
	data[XMAC_STAT_TX_PACKET_LARGE] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_LARGE(pf_id));
	data[XMAC_STAT_TX_PACKET_SMALL] +=
		ys_rd64(addr, XMAC_STAT_TX_PACKET_SMALL(pf_id));
	data[XMAC_STAT_TX_BAD_FCS] +=
		ys_rd64(addr, XMAC_STAT_TX_BAD_FCS(pf_id));
	data[XMAC_STAT_TX_UNICAST] +=
		ys_rd64(addr, XMAC_STAT_TX_UNICAST(pf_id));
	data[XMAC_STAT_TX_MULTICAST] +=
		ys_rd64(addr, XMAC_STAT_TX_MULTICAST(pf_id));
	data[XMAC_STAT_TX_BROADCAST] +=
		ys_rd64(addr, XMAC_STAT_TX_BROADCAST(pf_id));
	data[XMAC_STAT_TX_VLAN] += ys_rd64(addr, XMAC_STAT_TX_VLAN(pf_id));
	data[XMAC_STAT_TX_PAUSE] += ys_rd64(addr, XMAC_STAT_TX_PAUSE(pf_id));
	data[XMAC_STAT_TX_USER_PAUSE] +=
		ys_rd64(addr, XMAC_STAT_TX_USER_PAUSE(pf_id));

	data[XMAC_STAT_RX_TOTAL_PACKETS] +=
		ys_rd64(addr, XMAC_STAT_RX_TOTAL_PACKETS(pf_id));
	data[XMAC_STAT_RX_TOTAL_GOOD_PACKETS] +=
		ys_rd64(addr, XMAC_STAT_RX_TOTAL_GOOD_PACKETS(pf_id));
	data[XMAC_STAT_RX_TOTAL_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_TOTAL_BYTES(pf_id));
	data[XMAC_STAT_RX_TOTAL_GOOD_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_TOTAL_GOOD_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_64_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_64_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_65_127_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_65_127_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_128_255_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_128_255_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_256_511_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_256_511_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_512_1023_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_512_1023_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_1024_1518_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_1024_1518_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_1519_1022_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_1519_1022_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_1523_1548_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_1523_1548_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_1549_2047_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_1549_2047_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_2048_4095_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_2048_4095_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_4096_8191_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_4096_8191_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_8192_9215_BYTES] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_8192_9215_BYTES(pf_id));
	data[XMAC_STAT_RX_PACKET_LARGE] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_LARGE(pf_id));
	data[XMAC_STAT_RX_PACKET_SMALL] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_SMALL(pf_id));

	data[XMAC_STAT_RX_UNDERSIZE] += ys_rd64(addr, XMAC_STAT_RX_UNDERSIZE(pf_id));
	data[XMAC_STAT_RX_FRAGMENT] += ys_rd64(addr, XMAC_STAT_RX_FRAGMENT(pf_id));
	data[XMAC_STAT_RX_OVERSIZE] += ys_rd64(addr, XMAC_STAT_RX_OVERSIZE(pf_id));
	data[XMAC_STAT_RX_TOOLONG] += ys_rd64(addr, XMAC_STAT_RX_TOOLONG(pf_id));
	data[XMAC_STAT_RX_JABBER] += ys_rd64(addr, XMAC_STAT_RX_JABBER(pf_id));
	data[XMAC_STAT_RX_BAD_FCS] += ys_rd64(addr, XMAC_STAT_RX_BAD_FCS(pf_id));
	data[XMAC_STAT_RX_PACKET_BAD_FCS] +=
		ys_rd64(addr, XMAC_STAT_RX_PACKET_BAD_FCS(pf_id));
	data[XMAC_STAT_RX_STOMPED_BAD_FCS] +=
		ys_rd64(addr, XMAC_STAT_RX_STOMPED_BAD_FCS(pf_id));
	data[XMAC_STAT_RX_UNICAST] += ys_rd64(addr, XMAC_STAT_RX_UNICAST(pf_id));
	data[XMAC_STAT_RX_MULTICAST] += ys_rd64(addr, XMAC_STAT_RX_MULTICAST(pf_id));
	data[XMAC_STAT_RX_BROADCAST] += ys_rd64(addr, XMAC_STAT_RX_BROADCAST(pf_id));
	data[XMAC_STAT_RX_VLAN] += ys_rd64(addr, XMAC_STAT_RX_VLAN(pf_id));
	data[XMAC_STAT_RX_PAUSE] += ys_rd64(addr, XMAC_STAT_RX_PAUSE(pf_id));
	data[XMAC_STAT_RX_USER_PAUSE] += ys_rd64(addr, XMAC_STAT_RX_USER_PAUSE(pf_id));

	data[XMAC_STAT_RX_INRANGEERR] += ys_rd64(addr, XMAC_STAT_RX_INRANGEERR(pf_id));
	data[XMAC_STAT_RX_TRUNCATED] += ys_rd64(addr, XMAC_STAT_RX_TRUNCATED(pf_id));
	data[XMAC_STAT_RX_TEST_PATTERN_MISMATCH] +=
		ys_rd64(addr, XMAC_STAT_RX_TEST_PATTERN_MISMATCH(pf_id));
	data[XMAC_STAT_FEC_INC_CORRECT_COUNT] +=
		ys_rd64(addr, XMAC_STAT_FEC_INC_CORRECT_COUNT(pf_id));
	data[XMAC_STAT_FEC_INC_CANT_CORRECT_COUNT] +=
		ys_rd64(addr, XMAC_STAT_FEC_INC_CANT_CORRECT_COUNT(pf_id));
}

void ys_xmac_get_stats_strings(struct net_device *ndev, u8 *data)
{
	struct ys_ndev_priv *ndev_priv;
	u8 *p = data;
	int i;

	ndev_priv = netdev_priv(ndev);
	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return;

	for (i = 0; i < ARRAY_SIZE(ys_xmac_stats_strings); i++) {
		memcpy(p, ys_xmac_stats_strings[i], ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
	}
}

int ys_xmac_get_stats_count(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);
	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return 0;

	return ARRAY_SIZE(ys_xmac_stats_strings);
}

static void ys_xmac_get_mac_stats(struct net_device *ndev,
				  struct ethtool_eth_mac_stats *mac_stats)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u8 pf_id;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_XMAC_REGS_BAR];
	pf_id = pdev_priv->pf_id;

	mac_stats->FramesTransmittedOK =
		ys_rd64(addr, XMAC_STAT_TX_TOTAL_PACKETS(pf_id));

	mac_stats->FramesReceivedOK =
		ys_rd64(addr, XMAC_STAT_RX_TOTAL_PACKETS(pf_id));

	mac_stats->FrameCheckSequenceErrors = 0;

	mac_stats->OctetsTransmittedOK =
		ys_rd64(addr, XMAC_STAT_TX_TOTAL_GOOD_BYTES(pf_id));

	mac_stats->OctetsReceivedOK =
		ys_rd64(addr, XMAC_STAT_RX_TOTAL_GOOD_BYTES(pf_id));

	mac_stats->MulticastFramesXmittedOK =
		ys_rd64(addr, XMAC_STAT_TX_MULTICAST(pf_id));

	mac_stats->BroadcastFramesXmittedOK =
		ys_rd64(addr, XMAC_STAT_TX_BROADCAST(pf_id));

	mac_stats->MulticastFramesReceivedOK =
		ys_rd64(addr, XMAC_STAT_RX_MULTICAST(pf_id));

	mac_stats->BroadcastFramesReceivedOK =
		ys_rd64(addr, XMAC_STAT_RX_BROADCAST(pf_id));

	mac_stats->InRangeLengthErrors = 0;
	mac_stats->OutOfRangeLengthField = 0;
	mac_stats->FrameTooLongErrors = 0;
}

void ys_xmac_get_supported_advertising(struct net_device *ndev,
				       struct ys_ethtool_ksetting *cmd)
{
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_25000baseKR_Full_BIT);
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FEC_RS_BIT);
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FIBRE_BIT);
	ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FEC_NONE_BIT);

	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_25000baseKR_Full_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FEC_RS_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FIBRE_BIT);
	ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FEC_NONE_BIT);

	/* hw not support yet */
	/* ys_build_ehtool_ksetting(cmd, ETHTOOL_LINK_MODE_10000baseKR_Full_BIT); */
	/* ys_build_ehtool_ksetting(cmd, ETHTOOL_LINK_MODE_Autoneg_BIT); */
}

u32 ys_xmac_get_link_speed(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	u32 speed_reg;

	speed_reg = ys_rd32(pdev_priv->bar_addr[YS_XMAC_REGS_BAR],
			    XMAC_STAT_SPEED(pdev_priv->pf_id));

	switch (speed_reg) {
	case XMAC_STANDALONE_25G:
	case XMAC_RUNTIME_SWITCHABLE_25G:
		return SPEED_25G;
	case XMAC_STANDALONE_10G:
	case XMAC_RUNTIME_SWITCHABLE_10G:
		return SPEED_10G;
	}

	return SPEED_UNKNOWN;
}

static int ys_xmac_set_link_speed(struct net_device *ndev, u32 speed)
{
	/* Operation not supported */
	return -EOPNOTSUPP;
}

u32 ys_xmac_get_link_duplex(struct net_device *ndev)
{
	u32 duplex;

	duplex = DUPLEX_FULL;
	return duplex;
}

static int ys_xmac_set_link_duplex(struct net_device *ndev, u32 duplex_mode)
{
	/* Operation not supported */
	return -EOPNOTSUPP;
}

u32 ys_xmac_get_link_port_type(struct net_device *ndev)
{
	u32 port_type;

	port_type = PORT_FIBRE;
	return port_type;
}

u8 ys_xmac_get_link_autoneg(struct net_device *ndev)
{
	u8 autoneg;

	autoneg = AUTONEG_DISABLE;
	return autoneg;
}

int ys_xmac_set_link_autoneg(struct net_device *ndev, bool autoneg)
{
	/* Operation not supported */
	return -EOPNOTSUPP;
}

int ys_xmac_get_fec_mode(struct net_device *ndev,
			 struct ethtool_fecparam *fp)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	u32 fec_mode;

	fec_mode = ys_rd32(pdev_priv->bar_addr[YS_XMAC_REGS_BAR],
			   XMAC_RSFEC_CONF_ENABLE(pdev_priv->pf_id));

	if (fec_mode == XMAC_RSFEC_25G || fec_mode == XMAC_RSFEC_10G)
		fp->active_fec = ETHTOOL_FEC_RS;
	else
		fp->active_fec = ETHTOOL_FEC_OFF;
	return 0;
}

int ys_xmac_set_fec_mode(struct net_device *ndev, u32 fec)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	u32  speed;
	u32 fec_mode = 0;

	speed = ys_rd32(pdev_priv->bar_addr[YS_XMAC_REGS_BAR],
			XMAC_STAT_SPEED(pdev_priv->pf_id));

	switch (fec) {
	case ETHTOOL_FEC_RS:
		if ((speed & XMAC_STAT_CORE_SPEED) == STAT_CORE_SPEED(0))
			fec_mode = XMAC_RSFEC_25G;
		else
			fec_mode = XMAC_RSFEC_10G;
		ndev_priv->fec_cfg = ETHTOOL_FEC_RS;
		break;
	case ETHTOOL_FEC_OFF:
		fec_mode = XMAC_RSFEC_OFF;
		ndev_priv->fec_cfg = ETHTOOL_FEC_OFF;
		break;
	default:
		/* Operation not supported */
		return -EOPNOTSUPP;
	}

	ys_wr32(pdev_priv->bar_addr[YS_XMAC_REGS_BAR],
		XMAC_RSFEC_CONF_ENABLE(pdev_priv->pf_id),
		fec_mode);

	return 0;
}

int ys_xmac_eth_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw))
		XMAC_ETH_FUNC(ndev_priv->ys_eth_hw);
	return 0;
}

static void ys_xmac_ndev_check_link(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *hw_addr;
	u32 reg = 0;
	int i = 3;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hw_addr = pdev_priv->bar_addr[YS_XMAC_REGS_BAR];

	if (!pdev_priv->nic_type->is_vf) {
		switch (pdev_priv->pf_id) {
		case 0 ... 3:
			while (i--) {
				reg = ys_rd32(hw_addr, XMAC_CHX_STATUS_REG(0, pdev_priv->pf_id));
				udelay(10);
			}
			break;
		default:
			break;
		}
	}

	if ((reg & XMAC_STATUS_MASK) == XMAC_STATUS_EN) {
		netif_carrier_on(ndev);
		pdev_priv->link_status = 1;
	} else {
		netif_carrier_off(ndev);
		pdev_priv->link_status = 0;
	}
}

int ys_xmac_ndev_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_mac *mac;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mac_ndev *ys_mac_ndev;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw))
		XMAC_NDEV_FUNC(ndev_priv->ys_ndev_hw);

	mac = ys_aux_match_mac_dev(ndev_priv->pdev);
	if (IS_ERR_OR_NULL(mac))
		return -EOPNOTSUPP;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (IS_ERR_OR_NULL(pdev_priv))
		return -EOPNOTSUPP;

	ys_mac_ndev = kzalloc(sizeof(*ys_mac_ndev), GFP_KERNEL);
	if (IS_ERR_OR_NULL(ys_mac_ndev))
		return -ENOMEM;

	spin_lock(&mac->list_lock);
	if (!IS_ERR_OR_NULL(pdev_priv->ops->ndev_has_mac_link_status)) {
		if (pdev_priv->ops->ndev_has_mac_link_status(ndev)) {
			ys_mac_ndev->ndev = ndev;
			ys_xmac_ndev_check_link(ndev);
			list_add(&ys_mac_ndev->list, &mac->ndev_list);
		}
	}
	spin_unlock(&mac->list_lock);

	/* alloc irq failed, switch to timer mode deteck link status */
	if (mac->irq_vector >= 0)
		ndev_priv->mac_intr_en = 1;
	ndev_priv->ys_eth_hw->et_check_link = ys_xmac_ndev_check_link;

	return 0;
}

void ys_xmac_ndev_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_mac *mac;
	struct ys_mac_ndev *ys_mac_ndev, *temp;

	mac = ys_aux_match_mac_dev(ndev_priv->pdev);
	if (IS_ERR_OR_NULL(mac))
		return;

	spin_lock(&mac->list_lock);
	list_for_each_entry_safe(ys_mac_ndev, temp,
				 &mac->ndev_list, list) {
		list_del(&ys_mac_ndev->list);
		kfree(ys_mac_ndev);
	}
	spin_unlock(&mac->list_lock);
}

static int ys_xmac_intr(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ys_mac *mac = container_of(nb, struct ys_mac, irq_nb);
	struct ys_mac_ndev *ys_mac_ndev, *temp;

	spin_lock(&mac->list_lock);
	list_for_each_entry_safe(ys_mac_ndev, temp, &mac->ndev_list, list)
		if (ys_mac_ndev->ndev)
			ys_xmac_ndev_check_link(ys_mac_ndev->ndev);
	spin_unlock(&mac->list_lock);

	return NOTIFY_DONE;
}

int ys_xmac_init(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_mac *mac = adev->adev_priv;
	void __iomem *hw_addr;
	u32 val;
	int ret;
	const struct ysif_ops *ops = ysif_get_ops();

	INIT_LIST_HEAD(&mac->ndev_list);
	spin_lock_init(&mac->list_lock);

	hw_addr = (void __iomem *)pdev_priv->bar_addr[YS_XMAC_REGS_BAR];

	/* request mac interrupt */
	mac->irq_nb.notifier_call = ys_xmac_intr;
	/* get misc irq vector position */
	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_get_init_qnum))
		mac->irq_vector = pdev_priv->ops->hw_adp_get_init_qnum(adev->pdev);
	else
		mac->irq_vector = 0;

	ret = ({
		int ret;
		do {
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(0, pdev_priv->pdev, YS_IRQ_TYPE_MAC, NULL, NULL, "xmac");
			irq_nb.sub.bh_type = YS_IRQ_BH_NOTIFIER;
			irq_nb.sub.bh.nb = &mac->irq_nb;
			ret = ops->blocking_notifier_call_chain(&pdev_priv->irq_table.nh, YS_IRQ_NB_REGISTER_ANY, &irq_nb);
		} while (0);
		ret;
	});

	if (ret < 0) {
		ys_dev_err("ys_xmac alloc irq failed for xmac\n");
		return -ENOMEM;
	}
	mac->irq_vector = ret;

	ys_wr32(hw_addr, XMAC_INTER_JITTER_CTL(0), XMAC_INTER_JITTER_CTL_DEF);
	ys_dev_debug("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, XMAC_INTER_JITTER_CTL(0), XMAC_INTER_JITTER_CTL_DEF);

	ys_wr32(hw_addr, XMAC_INTER_ENABLE_REG(0), XMAC_INTER_ENABLE_ALL);
	ys_dev_debug("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, XMAC_INTER_ENABLE_REG(0), XMAC_INTER_ENABLE_ALL);

	if (!pdev_priv->nic_type->is_vf) {
		if (pdev_priv->pf_id < 4) {
			switch (pdev_priv->pf_id) {
			case 0:
				val = FIELD_PREP(XMAC_INTER_VECTOR_LAN02_MASK, mac->irq_vector);
				ys_wr32(hw_addr, XMAC_INTER_VECTOR_HOST_LAN01(0), val);
				ys_dev_debug("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, XMAC_INTER_VECTOR_HOST_LAN01(0), val);
				break;
			case 1:
				val = ys_rd32(hw_addr, XMAC_INTER_VECTOR_HOST_LAN01(0));
				val |= FIELD_PREP(XMAC_INTER_VECTOR_LAN13_MASK, mac->irq_vector);
				ys_wr32(hw_addr, XMAC_INTER_VECTOR_HOST_LAN01(0), val);
				ys_dev_debug("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, XMAC_INTER_VECTOR_HOST_LAN01(0), val);
				break;
			case 2:
				val = FIELD_PREP(XMAC_INTER_VECTOR_LAN02_MASK, mac->irq_vector);
				ys_wr32(hw_addr, XMAC_INTER_VECTOR_HOST_LAN23(0), val);
				ys_dev_debug("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, XMAC_INTER_VECTOR_HOST_LAN23(0), val);
				break;
			case 3:
				val = ys_rd32(hw_addr, XMAC_INTER_VECTOR_HOST_LAN23(0));
				val |= FIELD_PREP(XMAC_INTER_VECTOR_LAN13_MASK, mac->irq_vector);
				ys_wr32(hw_addr, XMAC_INTER_VECTOR_HOST_LAN23(0), val);
				ys_dev_debug("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, XMAC_INTER_VECTOR_HOST_LAN23(0), val);
				break;
			default:
				ys_dev_debug("pf_id %u\n", pdev_priv->pf_id);
				break;
			}

			val = FIELD_PREP(XMAC_INTER_CHX_F_VALUE_HOST_MASK, pdev_priv->pf_id);
			ys_wr32(hw_addr, XMAC_INTER_CHX_F_VALUE(0, pdev_priv->pf_id), val);
			ys_dev_debug("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, XMAC_INTER_CHX_F_VALUE(0, pdev_priv->pf_id), val);
		}
	}

	ys_dev_debug("hw_addr 0x%p pf_id %u irq %u\n", hw_addr, pdev_priv->pf_id, mac->irq_vector);

	return 0;
}

void ys_xmac_uninit(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_mac *mac = (struct ys_mac *)adev->adev_priv;

	if (mac->irq_vector >= 0) {
		YS_UNREGISTER_IRQ(&pdev_priv->irq_table.nh, mac->irq_vector,
				  pdev_priv->pdev, &mac->irq_nb);
	}
}
