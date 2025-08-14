// SPDX-License-Identifier: GPL-2.0

#include "ys_umac.h"

static const char ys_umac_stats_strings[][ETH_GSTRING_LEN] = {
	"tx_crc_error_packets_phy",
	"tx_less_than_64_bytes_phy",
	"tx_equal_to_64_bytes_phy",
	"tx_65_to_127_bytes_phy",
	"tx_128_to_255_bytes_phy",
	"tx_256_to_511_bytes_phy",
	"tx_512_to_1023_bytes_phy",
	"tx_1024_to_1518_bytes_phy",
	"tx_1519_to_2047_bytes_phy",
	"tx_2048_to_4095_bytes_phy",
	"tx_4096_to_8191_bytes_phy",
	"tx_8192_to_9215_bytes_phy",
	"tx_greater_than_9216_bytes_phy",

	"rx_crc_error_packets_phy",
	"rx_less_than_64_bytes_phy",
	"rx_equal_to_64_bytes_phy",
	"rx_65_to_127_bytes_phy",
	"rx_128_to_255_bytes_phy",
	"rx_256_to_511_bytes_phy",
	"rx_512_to_1023_bytes_phy",
	"rx_1024_to_1518_bytes_phy",
	"rx_1519_to_2047_bytes_phy",
	"rx_2048_to_4095_bytes_phy",
	"rx_4096_to_8191_bytes_phy",
	"rx_8192_to_9215_bytes_phy",
	"rx_greater_than_9216_bytes_phy",

	"tx_discard_phy",
	"rx_discard_phy",
};

#define VALUE_RECOMPUTE(old_val, set_val, vmask, shift) \
({ \
	u32 __old_val = (old_val); \
	u16 __set_val = (set_val); \
	u16 __vmask = (vmask); \
	u32 __shift = (shift); \
	u32 set_val32 = ((u32)__set_val) << (__shift); \
	u32 mask32 = ((u32)__vmask) << (__shift); \
	(__old_val & ~mask32) | (set_val32 & mask32); \
})

__weak void
ysk2_shr0_port_autonego(struct ys_mbox *mbox, u32 pf_id, u32 speed)
{}

__weak void
ysk2_shr0_port_speed(struct ys_mbox *mbox, u32 pf_id, u32 speed)
{}

__weak u32
ysk2_get_shr0_port_autonego(struct ys_mbox *mbox)
{ return 0x0; }

__weak u32
ysk2_get_shr0_port_speed(struct ys_mbox *mbox)
{ return 0x0; }

static u32 ys_umac_get_link_speed(struct net_device *ndev);

static void ys_umac_set_d2m_command(void __iomem *hw_addr, u32 d2m_cmd)
{
	ys_wr32(hw_addr, UMAC_SFP_TRANS_D2M_CMD, d2m_cmd);
}

static int ys_umac_get_fec_mode(struct net_device *ndev,
				struct ethtool_fecparam *fp);

static int ys_umac_wait_m3_get_command(void __iomem *hw_addr)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(1000);
	u32 d2m_cmd = 0;

	while (time_before(jiffies, timeout)) {
		d2m_cmd = ys_rd32(hw_addr, UMAC_SFP_TRANS_D2M_CMD);
		if (d2m_cmd == 0)
			return 0;

		cpu_relax();
		usleep_range(100, 500);
	}
	ys_err("m3 clear d2m_cmd faild:%02x", d2m_cmd);

	return -ETIMEDOUT;
}

static void ys_umac_clear_m2d_command(void __iomem *hw_addr)
{
	ys_wr32(hw_addr, UMAC_SFP_TRANS_M2D_CMD, 0);
}

static int ys_umac_wait_m2d_command(void __iomem *hw_addr)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(1000);
	u32 m2d_cmd = 0;

	while (time_before(jiffies, timeout)) {
		m2d_cmd = ys_rd32(hw_addr, UMAC_SFP_TRANS_M2D_CMD);
		if (m2d_cmd >= UMAC_M2D_SET_SPEED10G &&
		    m2d_cmd <= UMAC_M2D_SET_PORT1_LIGHT_NORMAL)
			return 0;

		cpu_relax();
		usleep_range(100, 500);
	}
	ys_err("m2d_cmd is illegal:%02x", m2d_cmd);

	return -ETIMEDOUT;
}

int ys_umac_get_sfp_data(struct net_device *ndev, u32 pf_id, u8 *data,
			 u32 data_type)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (!pdev_priv->hw_info)
		return -EINVAL;

	/* Waiting for M3 to return data */
	memcpy_fromio(data, (void __iomem *)pdev_priv->hw_info->env_info.mod_info,
		      MODULE_INFO_LEN_MAX);
	ys_info("mode:%u\r\n", pdev_priv->hw_info->nic_info.mode);
	ys_info("temperature_l:%u\r\n", pdev_priv->hw_info->env_info.temperature_l);

	return 0;
}

int ys_umac_vf_link_state(struct net_device *ndev, int vf_id, int link_state)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	struct ys_mbox_msg mbox_msg;
	u32 vf_link_state;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);

	vf_link_state = pdev_priv->sriov_info.vfinfo[vf_id].link_state;
	if (vf_link_state != link_state) {
		pdev_priv->sriov_info.vfinfo[vf_id].link_state = link_state;
		memset(&mbox_msg, 0, sizeof(mbox_msg));
		mbox_msg.opcode = YS_MBOX_OPCODE_SET_PORT_STATUS;
		mbox_msg.data[0] = pdev_priv->sriov_info.vfinfo[vf_id].link_state;
		ys_mbox_send_msg(mbox, &mbox_msg, vf_id + 1, MB_NO_REPLY, 0, NULL);
	}

	return 0;
}

static int ys_umac_enable_10gbase(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B10G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B10G_CHMODE_0_CFG0_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), B10G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), B10G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), B10G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), B10G_TXFIFOCFG_0_CFG_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B10G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B10G_CHMODE_0_CFG1_H);

	return 0;
}

int ys_umac_enable_25gbase(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B25G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B25G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		B25G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		B25G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), B25G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), B25G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), B25G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), B25G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), B25G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), B25G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), B25G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), B25G_CHCONFIG4_0_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), B25G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), B25G_SDCFG0_CFG0_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B25G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B25G_CHMODE_0_CFG1_H);

	ys_rd32(addr, UMAC_CHSTS_L(pdev_priv->pf_id, UMAC_CH0));
	ys_wr32(addr, UMAC_BIGENDIAN_CONVERTE(pdev_priv->pf_id), 1);

	return 0;
}

static int ys_umac_enable_40gbase(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B40G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B40G_CHMODE_0_CFG0_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), B40G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), B40G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), B40G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), B40G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), B40G_CHCONFIG31_0_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHMODE_1_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHMODE_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), B40G_MACCFG_1_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), B40G_MACCFG_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), B40G_MACCFG_1_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), B40G_MACCFG_1_CFG1_H);

	/* txfifocfg_1 registers offset_addr 0x04c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH1), B40G_TXFIFOCFG_1_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH1), B40G_TXFIFOCFG_1_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHMODE_1_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHMODE_1_CFG1_H);

	/* chconfig3_1 registers offset_addr 0x0418 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG3_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG3_1_CFG_H);

	/* chconfig4_1 registers offset_addr 0x0420 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG4_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG4_1_CFG_H);

	/* chconfig5_1 registers offset_addr 0x0428 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG5_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG5_1_CFG_H);

	/* chconfig8_1 registers offset_addr 0x0440 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG8_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG8_1_CFG_H);

	/* chconfig12_1 registers offset_addr 0x0460 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG12_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG12_1_CFG_H);

	/* chconfig31_1 registers offset_addr 0x04f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG31_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH1), B40G_CHCONFIG31_1_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHMODE_2_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHMODE_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), B40G_MACCFG_2_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), B40G_MACCFG_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), B40G_MACCFG_2_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), B40G_MACCFG_2_CFG1_H);

	/* txfifocfg_2 registers offset_addr 0x08c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH2), B40G_TXFIFOCFG_2_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH2), B40G_TXFIFOCFG_2_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHMODE_2_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHMODE_2_CFG1_H);

	/* chconfig3_2 registers offset_addr 0x0818 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG3_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG3_2_CFG_H);

	/* chconfig4_2 registers offset_addr 0x0820 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG4_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG4_2_CFG_H);

	/* chconfig5_2 registers offset_addr 0x0828 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG5_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG5_2_CFG_H);

	/* chconfig8_2 registers offset_addr 0x0840 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG8_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG8_2_CFG_H);

	/* chconfig12_2 registers offset_addr 0x0860 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG12_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG12_2_CFG_H);

	/* chconfig31_2 registers offset_addr 0x08f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG31_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH2), B40G_CHCONFIG31_2_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHMODE_3_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHMODE_3_CFG0_H);

	/* chconfig6_3 registers offset_addr 0x0c30 */
	ys_wr32(addr, UMAC_CHCONFIG6_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG6_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG6_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG6_3_CFG_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), B40G_MACCFG_3_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), B40G_MACCFG_3_CFG0_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), B40G_MACCFG_3_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), B40G_MACCFG_3_CFG1_H);

	/* txfifocfg_3 registers offset_addr 0x0cc0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH3), B40G_TXFIFOCFG_3_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH3), B40G_TXFIFOCFG_3_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHMODE_3_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHMODE_3_CFG1_H);

	/* chconfig3_3 registers offset_addr 0x0c18 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG3_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG3_3_CFG_H);

	/* chconfig4_3 registers offset_addr 0x0c20 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG4_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG4_3_CFG_H);

	/* chconfig5_3 registers offset_addr 0x0c28 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG5_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG5_3_CFG_H);

	/* chconfig8_3 registers offset_addr 0x0c40 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG8_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG8_3_CFG_H);

	/* chconfig12_3 registers offset_addr 0x0c60 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG12_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG12_3_CFG_H);

	/* chconfig33_3 registers offset_addr 0x3c08 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG33_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG33_3_CFG_H);

	/* chconfig31_3 registers offset_addr 0x0cf8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG31_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH3), B40G_CHCONFIG31_3_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		B40G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		B40G_PCSRXOVERRIDE0_0_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG0_CFG0_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG1_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG1_CFG0_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG2_CFG0_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B40G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B40G_CHMODE_0_CFG1_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG1_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG1_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG0_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG0_CFG1_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG2_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG2_CFG1_H);

	/* pcsrxoverride0_1 registers offset_addr 0x04e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH1),
		B40G_PCSRXOVERRIDE0_1_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH1),
		B40G_PCSRXOVERRIDE0_1_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x08e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH2),
		B40G_PCSRXOVERRIDE0_2_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH2),
		B40G_PCSRXOVERRIDE0_2_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x0ce0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH3),
		B40G_PCSRXOVERRIDE0_3_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH3),
		B40G_PCSRXOVERRIDE0_3_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG0_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG0_CFG2_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG1_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG1_CFG2_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG2_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), B40G_SDCFG2_CFG2_H);

	return 0;
}

static int ys_umac_enable_50gbase(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B50G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B50G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		B50G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		B50G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), B50G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), B50G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), B50G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), B50G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG8_0_CFG_H);

	/* chconfig33 registers offset_addr 0x03008 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG33_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG33_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), B50G_CHCONFIG31_0_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), B50G_CHMODE_2_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), B50G_CHMODE_2_CFG0_H);

	/* pcstxoverride1_2 registers offset_addr 0x08c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH2),
		B50G_PCSTXOVERRIDE1_2_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH2),
		B50G_PCSTXOVERRIDE1_2_CFG_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), B50G_MACCFG_2_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), B50G_MACCFG_2_CFG_H);

	/* txfifocfg_2 registers offset_addr 0x08c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH2), B50G_TXFIFOCFG_2_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH2), B50G_TXFIFOCFG_2_CFG_H);

	/* chconfig3_2 registers offset_addr 0x0818 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG3_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG3_2_CFG_H);

	/* chconfig4_2 registers offset_addr 0x0820 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG4_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG4_2_CFG_H);

	/* chconfig8_2 registers offset_addr 0x0840 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG8_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG8_2_CFG_H);

	/* chconfig33 registers offset_addr 0x03808 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG33_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG33_2_CFG_H);

	/* chconfig31_2 registers offset_addr 0x08f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG31_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH2), B50G_CHCONFIG31_2_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		B50G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		B50G_PCSRXOVERRIDE0_0_CFG_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B50G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B50G_CHMODE_0_CFG1_H);

	/* pcsrxoverride0_2 registers offset_addr 0x08e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH2),
		B50G_PCSRXOVERRIDE0_2_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH2),
		B50G_PCSRXOVERRIDE0_2_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), B50G_CHMODE_2_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), B50G_CHMODE_2_CFG1_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), B50G_SDCFG1_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), B50G_SDCFG1_CFG0_H);

	return 0;
}

static int ys_umac_enable_100gbase(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B100G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B100G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		B100G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		B100G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), B100G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), B100G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), B100G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), B100G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), B100G_CHCONFIG31_0_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHMODE_1_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHMODE_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), B100G_MACCFG_1_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), B100G_MACCFG_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), B100G_MACCFG_1_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), B100G_MACCFG_1_CFG1_H);

	/* txfifocfg_1 registers offset_addr 0x04c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH1), B100G_TXFIFOCFG_1_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH1), B100G_TXFIFOCFG_1_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHMODE_1_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHMODE_1_CFG1_H);

	/* chconfig3_1 registers offset_addr 0x0418 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG3_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG3_1_CFG_H);

	/* chconfig4_1 registers offset_addr 0x0420 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG4_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG4_1_CFG_H);

	/* chconfig5_1 registers offset_addr 0x0428 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG5_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG5_1_CFG_H);

	/* chconfig8_1 registers offset_addr 0x0440 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG8_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG8_1_CFG_H);

	/* chconfig12_1 registers offset_addr 0x0460 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG12_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG12_1_CFG_H);

	/* chconfig31_1 registers offset_addr 0x04f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG31_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH1), B100G_CHCONFIG31_1_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHMODE_2_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHMODE_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), B100G_MACCFG_2_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), B100G_MACCFG_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), B100G_MACCFG_2_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), B100G_MACCFG_2_CFG1_H);

	/* txfifocfg_2 registers offset_addr 0x08c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH2), B100G_TXFIFOCFG_2_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH2), B100G_TXFIFOCFG_2_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHMODE_2_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHMODE_2_CFG1_H);

	/* chconfig3_2 registers offset_addr 0x0818 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG3_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG3_2_CFG_H);

	/* chconfig4_2 registers offset_addr 0x0820 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG4_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG4_2_CFG_H);

	/* chconfig5_2 registers offset_addr 0x0828 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG5_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG5_2_CFG_H);

	/* chconfig8_2 registers offset_addr 0x0840 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG8_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG8_2_CFG_H);

	/* chconfig12_2 registers offset_addr 0x0860 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG12_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG12_2_CFG_H);

	/* chconfig31_2 registers offset_addr 0x08f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG31_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH2), B100G_CHCONFIG31_2_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHMODE_3_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHMODE_3_CFG0_H);

	/* chconfig6_3 registers offset_addr 0x0c30 */
	ys_wr32(addr, UMAC_CHCONFIG6_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG6_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG6_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG6_3_CFG_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), B100G_MACCFG_3_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), B100G_MACCFG_3_CFG0_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), B100G_MACCFG_3_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), B100G_MACCFG_3_CFG1_H);

	/* txfifocfg_3 registers offset_addr 0x0cc0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH3), B100G_TXFIFOCFG_3_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH3), B100G_TXFIFOCFG_3_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHMODE_3_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHMODE_3_CFG1_H);

	/* chconfig3_3 registers offset_addr 0x0c18 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG3_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG3_3_CFG_H);

	/* chconfig4_3 registers offset_addr 0x0c20 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG4_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG4_3_CFG_H);

	/* chconfig5_3 registers offset_addr 0x0c28 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG5_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG5_3_CFG_H);

	/* chconfig8_3 registers offset_addr 0x0c40 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG8_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG8_3_CFG_H);

	/* chconfig12_3 registers offset_addr 0x0c60 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG12_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG12_3_CFG_H);

	/* chconfig33_3 registers offset_addr 0x3c08 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG33_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG33_3_CFG_H);

	/* chconfig31_3 registers offset_addr 0x0cf8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG31_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH3), B100G_CHCONFIG31_3_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		B100G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		B100G_PCSRXOVERRIDE0_0_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG0_CFG0_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG1_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG1_CFG0_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG2_CFG0_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), B100G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), B100G_CHMODE_0_CFG1_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG1_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG1_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG0_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG0_CFG1_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG2_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG2_CFG1_H);

	/* pcsrxoverride0_1 registers offset_addr 0x04e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH1),
		B100G_PCSRXOVERRIDE0_1_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH1),
		B100G_PCSRXOVERRIDE0_1_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x08e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH2),
		B100G_PCSRXOVERRIDE0_2_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH2),
		B100G_PCSRXOVERRIDE0_2_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x0ce0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH3),
		B100G_PCSRXOVERRIDE0_3_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH3),
		B100G_PCSRXOVERRIDE0_3_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG0_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG0_CFG2_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG1_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG1_CFG2_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG2_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), B100G_SDCFG2_CFG2_H);

	return 0;
}

static int ys_umac_enable_10gbase_fc(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHMODE_0_CFG0_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHCONFIG31_0_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		FC_10G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		FC_10G_PCSRXOVERRIDE0_0_CFG_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_CHMODE_0_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG0_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG1_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG1_CFG0_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG2_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG2_CFG0_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG3_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG0_CFG3_H);

	/* sdcfg3 registers offset_addr 0x1180 */
	ys_wr32(addr, UMAC_SDCFG3_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG3_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG3_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG3_CFG0_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG2_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG2_CFG1_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG2_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG2_CFG2_H);

	/* sdcfg3 registers offset_addr 0x1180 */
	ys_wr32(addr, UMAC_SDCFG3_L(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG3_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG3_H(pdev_priv->pf_id, UMAC_CH0), FC_10G_SDCFG3_CFG1_H);

	return 0;
}

static int ys_umac_enable_25gbase_fc(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		FC_25G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		FC_25G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHCONFIG31_0_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		FC_25G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		FC_25G_PCSRXOVERRIDE0_0_CFG_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_CHMODE_0_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_25G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_25G_SDCFG0_CFG0_H);

	return 0;
}

static int ys_umac_enable_40gbase_fc(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHMODE_0_CFG0_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHCONFIG31_0_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHMODE_1_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHMODE_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_MACCFG_1_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_MACCFG_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_MACCFG_1_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_MACCFG_1_CFG1_H);

	/* txfifocfg_1 registers offset_addr 0x04c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_TXFIFOCFG_1_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_TXFIFOCFG_1_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHMODE_1_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHMODE_1_CFG1_H);

	/* chconfig3_1 registers offset_addr 0x0418 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG3_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG3_1_CFG_H);

	/* chconfig4_1 registers offset_addr 0x0420 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG4_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG4_1_CFG_H);

	/* chconfig5_1 registers offset_addr 0x0428 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG5_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG5_1_CFG_H);

	/* chconfig8_1 registers offset_addr 0x0440 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG8_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG8_1_CFG_H);

	/* chconfig12_1 registers offset_addr 0x0460 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG12_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG12_1_CFG_H);

	/* chconfig31_1 registers offset_addr 0x04f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG31_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH1), FC_40G_CHCONFIG31_1_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHMODE_2_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHMODE_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_MACCFG_2_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_MACCFG_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_MACCFG_2_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_MACCFG_2_CFG1_H);

	/* txfifocfg_2 registers offset_addr 0x08c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_TXFIFOCFG_2_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_TXFIFOCFG_2_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHMODE_2_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHMODE_2_CFG1_H);

	/* chconfig3_2 registers offset_addr 0x0818 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG3_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG3_2_CFG_H);

	/* chconfig4_2 registers offset_addr 0x0820 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG4_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG4_2_CFG_H);

	/* chconfig5_2 registers offset_addr 0x0828 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG5_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG5_2_CFG_H);

	/* chconfig8_2 registers offset_addr 0x0840 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG8_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG8_2_CFG_H);

	/* chconfig12_2 registers offset_addr 0x0860 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG12_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG12_2_CFG_H);

	/* chconfig31_2 registers offset_addr 0x08f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG31_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH2), FC_40G_CHCONFIG31_2_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHMODE_3_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHMODE_3_CFG0_H);

	/* chconfig6_3 registers offset_addr 0x0c30 */
	ys_wr32(addr, UMAC_CHCONFIG6_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG6_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG6_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG6_3_CFG_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_MACCFG_3_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_MACCFG_3_CFG0_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_MACCFG_3_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_MACCFG_3_CFG1_H);

	/* txfifocfg_3 registers offset_addr 0x0cc0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_TXFIFOCFG_3_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_TXFIFOCFG_3_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHMODE_3_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHMODE_3_CFG1_H);

	/* chconfig3_3 registers offset_addr 0x0c18 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG3_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG3_3_CFG_H);

	/* chconfig4_3 registers offset_addr 0x0c20 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG4_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG4_3_CFG_H);

	/* chconfig5_3 registers offset_addr 0x0c28 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG5_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG5_3_CFG_H);

	/* chconfig8_3 registers offset_addr 0x0c40 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG8_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG8_3_CFG_H);

	/* chconfig12_3 registers offset_addr 0x0c60 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG12_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG12_3_CFG_H);

	/* chconfig33_3 registers offset_addr 0x3c08 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG33_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG33_3_CFG_H);

	/* chconfig31_3 registers offset_addr 0x0cf8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG31_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH3), FC_40G_CHCONFIG31_3_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		FC_40G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		FC_40G_PCSRXOVERRIDE0_0_CFG_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_CHMODE_0_CFG1_H);

	/* pcsrxoverride0_1 registers offset_addr 0x04e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH1),
		FC_40G_PCSRXOVERRIDE0_1_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH1),
		FC_40G_PCSRXOVERRIDE0_1_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x08e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH2),
		FC_40G_PCSRXOVERRIDE0_2_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH2),
		FC_40G_PCSRXOVERRIDE0_2_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x0ce0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH3),
		FC_40G_PCSRXOVERRIDE0_3_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH3),
		FC_40G_PCSRXOVERRIDE0_3_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG0_CFG0_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG1_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG1_CFG0_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG2_CFG0_H);

	/* sdcfg3 registers offset_addr 0x1180 */
	ys_wr32(addr, UMAC_SDCFG3_L(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG3_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG3_H(pdev_priv->pf_id, UMAC_CH0), FC_40G_SDCFG3_CFG0_H);

	return 0;
}

static int ys_umac_enable_50gbase_fc(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		FC_50G_PCSTXOVERRIDE1_0_CFG0_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		FC_50G_PCSTXOVERRIDE1_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		FC_50G_PCSTXOVERRIDE1_0_CFG1_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		FC_50G_PCSTXOVERRIDE1_0_CFG1_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG8_0_CFG_H);

	/* chconfig33 registers offset_addr 0x03008 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG33_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG33_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHCONFIG31_0_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHMODE_2_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHMODE_2_CFG0_H);

	/* pcstxoverride1_2 registers offset_addr 0x08c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH2),
		FC_50G_PCSTXOVERRIDE1_2_CFG0_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH2),
		FC_50G_PCSTXOVERRIDE1_2_CFG0_H);

	/* pcstxoverride1_2 registers offset_addr 0x08c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH2),
		FC_50G_PCSTXOVERRIDE1_2_CFG1_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH2),
		FC_50G_PCSTXOVERRIDE1_2_CFG1_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_MACCFG_2_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_MACCFG_2_CFG_H);

	/* txfifocfg_2 registers offset_addr 0x08c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_TXFIFOCFG_2_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_TXFIFOCFG_2_CFG_H);

	/* chconfig3_2 registers offset_addr 0x0818 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG3_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG3_2_CFG_H);

	/* chconfig4_2 registers offset_addr 0x0820 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG4_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG4_2_CFG_H);

	/* chconfig8_2 registers offset_addr 0x0840 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG8_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG8_2_CFG_H);

	/* chconfig33 registers offset_addr 0x03808 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG33_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG33_2_CFG_H);

	/* chconfig31_2 registers offset_addr 0x08f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG31_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHCONFIG31_2_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		FC_50G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		FC_50G_PCSRXOVERRIDE0_0_CFG_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_CHMODE_0_CFG1_H);

	/* pcsrxoverride0_2 registers offset_addr 0x08e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH2),
		FC_50G_PCSRXOVERRIDE0_2_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH2),
		FC_50G_PCSRXOVERRIDE0_2_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHMODE_2_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), FC_50G_CHMODE_2_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG0_CFG0_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG1_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG1_CFG0_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG0_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG0_CFG1_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG2_CFG0_H);

	/* sdcfg3 registers offset_addr 0x1180 */
	ys_wr32(addr, UMAC_SDCFG3_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG3_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG3_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG3_CFG0_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG2_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), FC_50G_SDCFG2_CFG1_H);

	return 0;
}

int ys_umac_enable_25gbase_rs_cons(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];
	ndev_priv->fec_cfg = UMAC_MODE_SPEED_25GBASE_RS_CONS;

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		RSCONS_25G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		RSCONS_25G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHCONFIG31_0_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		RSCONS_25G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		RSCONS_25G_PCSRXOVERRIDE0_0_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG0_CFG0_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_CHMODE_0_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG0_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG0_CFG1_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG2_CFG0_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG2_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG2_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG0_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG0_CFG2_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG2_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RSCONS_25G_SDCFG2_CFG2_H);

	return 0;
}

static int ys_umac_enable_25gbase_rs_ieee(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		RSIEEE_25G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		RSIEEE_25G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHCONFIG8_0_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_SDCFG0_CFG0_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RSIEEE_25G_CHMODE_0_CFG1_H);

	return 0;
}

static int ys_umac_enable_50gbase_rs(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		RS_50G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		RS_50G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHCONFIG31_0_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHMODE_2_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHMODE_2_CFG0_H);

	/* pcstxoverride1_2 registers offset_addr 0x08c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH2),
		RS_50G_PCSTXOVERRIDE1_2_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH2),
		RS_50G_PCSTXOVERRIDE1_2_CFG_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_MACCFG_2_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_MACCFG_2_CFG_H);

	/* txfifocfg_2 registers offset_addr 0x08c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_TXFIFOCFG_2_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_TXFIFOCFG_2_CFG_H);

	/* chconfig3_2 registers offset_addr 0x0818 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG3_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG3_2_CFG_H);

	/* chconfig4_2 registers offset_addr 0x0820 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG4_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG4_2_CFG_H);

	/* chconfig8_2 registers offset_addr 0x0840 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG8_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG8_2_CFG_H);

	/* chconfig31_2 registers offset_addr 0x08f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG31_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHCONFIG31_2_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		RS_50G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		RS_50G_PCSRXOVERRIDE0_0_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG0_CFG0_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_CHMODE_0_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG0_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG0_CFG1_H);

	/* pcsrxoverride0_2 registers offset_addr 0x08e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH2),
		RS_50G_PCSRXOVERRIDE0_2_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH2),
		RS_50G_PCSRXOVERRIDE0_2_CFG_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG2_CFG0_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHMODE_2_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), RS_50G_CHMODE_2_CFG1_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG2_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG2_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG0_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG0_CFG2_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG2_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RS_50G_SDCFG2_CFG2_H);

	return 0;
}

static int ys_umac_enable_100gbase_rs(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHMODE_0_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHMODE_0_CFG0_H);

	/* pcstxoverride1 registers offset_addr 0x00c8 */
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_L(pdev_priv->pf_id, UMAC_CH0),
		RS_100G_PCSTXOVERRIDE1_0_CFG_L);
	ys_wr32(addr, UMAC_PCSTXOVERRIDE1_H(pdev_priv->pf_id, UMAC_CH0),
		RS_100G_PCSTXOVERRIDE1_0_CFG_H);

	/* maccfg_0 registers offset_addr 0x0008 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_MACCFG_0_CFG_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_MACCFG_0_CFG_H);

	/* txfifocfg_0 registers offset_addr 0x00c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_TXFIFOCFG_0_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_TXFIFOCFG_0_CFG_H);

	/* chconfig3_0 registers offset_addr 0x0018 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG3_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG3_0_CFG_H);

	/* chconfig4_0 registers offset_addr 0x0020 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG4_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG4_0_CFG_H);

	/* chconfig8_0 registers offset_addr 0x0040 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG8_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG8_0_CFG_H);

	/* chconfig31_0 registers offset_addr 0x00f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG31_0_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHCONFIG31_0_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHMODE_1_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHMODE_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_MACCFG_1_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_MACCFG_1_CFG0_H);

	/* maccfg_1 registers offset_addr 0x0408 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_MACCFG_1_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_MACCFG_1_CFG1_H);

	/* txfifocfg_1 registers offset_addr 0x04c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_TXFIFOCFG_1_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_TXFIFOCFG_1_CFG_H);

	/* chmode_1 registers offset_addr 0x0400 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHMODE_1_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHMODE_1_CFG1_H);

	/* chconfig3_1 registers offset_addr 0x0418 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG3_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG3_1_CFG_H);

	/* chconfig4_1 registers offset_addr 0x0420 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG4_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG4_1_CFG_H);

	/* chconfig5_1 registers offset_addr 0x0428 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG5_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG5_1_CFG_H);

	/* chconfig8_1 registers offset_addr 0x0440 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG8_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG8_1_CFG_H);

	/* chconfig12_1 registers offset_addr 0x0460 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG12_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG12_1_CFG_H);

	/* chconfig31_1 registers offset_addr 0x04f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG31_1_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH1), RS_100G_CHCONFIG31_1_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHMODE_2_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHMODE_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_MACCFG_2_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_MACCFG_2_CFG0_H);

	/* maccfg_2 registers offset_addr 0x0808 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_MACCFG_2_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_MACCFG_2_CFG1_H);

	/* txfifocfg_2 registers offset_addr 0x08c0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_TXFIFOCFG_2_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_TXFIFOCFG_2_CFG_H);

	/* chmode_2 registers offset_addr 0x0800 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHMODE_2_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHMODE_2_CFG1_H);

	/* chconfig3_2 registers offset_addr 0x0818 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG3_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG3_2_CFG_H);

	/* chconfig4_2 registers offset_addr 0x0820 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG4_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG4_2_CFG_H);

	/* chconfig5_2 registers offset_addr 0x0828 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG5_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG5_2_CFG_H);

	/* chconfig8_2 registers offset_addr 0x0840 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG8_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG8_2_CFG_H);

	/* chconfig12_2 registers offset_addr 0x0860 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG12_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG12_2_CFG_H);

	/* chconfig31_2 registers offset_addr 0x08f8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG31_2_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH2), RS_100G_CHCONFIG31_2_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHMODE_3_CFG0_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHMODE_3_CFG0_H);

	/* chconfig6_3 registers offset_addr 0x0c30 */
	ys_wr32(addr, UMAC_CHCONFIG6_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG6_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG6_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG6_3_CFG_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_MACCFG_3_CFG0_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_MACCFG_3_CFG0_H);

	/* maccfg_3 registers offset_addr 0x0c08 */
	ys_wr32(addr, UMAC_MACCFG_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_MACCFG_3_CFG1_L);
	ys_wr32(addr, UMAC_MACCFG_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_MACCFG_3_CFG1_H);

	/* txfifocfg_3 registers offset_addr 0x0cc0 */
	ys_wr32(addr, UMAC_TXFIFOCFG_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_TXFIFOCFG_3_CFG_L);
	ys_wr32(addr, UMAC_TXFIFOCFG_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_TXFIFOCFG_3_CFG_H);

	/* chmode_3 registers offset_addr 0x0c00 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHMODE_3_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHMODE_3_CFG1_H);

	/* chconfig3_3 registers offset_addr 0x0c18 */
	ys_wr32(addr, UMAC_CHCONFIG3_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG3_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG3_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG3_3_CFG_H);

	/* chconfig4_3 registers offset_addr 0x0c20 */
	ys_wr32(addr, UMAC_CHCONFIG4_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG4_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG4_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG4_3_CFG_H);

	/* chconfig5_3 registers offset_addr 0x0c28 */
	ys_wr32(addr, UMAC_CHCONFIG5_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG5_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG5_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG5_3_CFG_H);

	/* chconfig8_3 registers offset_addr 0x0c40 */
	ys_wr32(addr, UMAC_CHCONFIG8_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG8_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG8_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG8_3_CFG_H);

	/* chconfig12_3 registers offset_addr 0x0c60 */
	ys_wr32(addr, UMAC_CHCONFIG12_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG12_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG12_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG12_3_CFG_H);

	/* chconfig33_3 registers offset_addr 0x3c08 */
	ys_wr32(addr, UMAC_CHCONFIG33_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG33_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG33_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG33_3_CFG_H);

	/* chconfig31_3 registers offset_addr 0x0cf8 */
	ys_wr32(addr, UMAC_CHCONFIG31_L(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG31_3_CFG_L);
	ys_wr32(addr, UMAC_CHCONFIG31_H(pdev_priv->pf_id, UMAC_CH3), RS_100G_CHCONFIG31_3_CFG_H);

	/* pcsrxoverride0_0 registers offset_addr 0x00e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH0),
		RS_100G_PCSRXOVERRIDE0_0_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH0),
		RS_100G_PCSRXOVERRIDE0_0_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG0_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG0_CFG0_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG1_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG1_CFG0_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG2_CFG0_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG2_CFG0_H);

	/* chmode_0 registers offset_addr 0x0000 */
	ys_wr32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHMODE_0_CFG1_L);
	ys_wr32(addr, UMAC_CHMODE_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_CHMODE_0_CFG1_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG1_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG1_CFG1_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG0_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG0_CFG1_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG2_CFG1_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG2_CFG1_H);

	/* pcsrxoverride0_1 registers offset_addr 0x04e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH1),
		RS_100G_PCSRXOVERRIDE0_1_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH1),
		RS_100G_PCSRXOVERRIDE0_1_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x08e0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH2),
		RS_100G_PCSRXOVERRIDE0_2_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH2),
		RS_100G_PCSRXOVERRIDE0_2_CFG_H);

	/* pcsrxoverride0_2 registers offset_addr 0x0ce0 */
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_L(pdev_priv->pf_id, UMAC_CH3),
		RS_100G_PCSRXOVERRIDE0_3_CFG_L);
	ys_wr32(addr, UMAC_PCSRXOVERRIDE0_H(pdev_priv->pf_id, UMAC_CH3),
		RS_100G_PCSRXOVERRIDE0_3_CFG_H);

	/* sdcfg0 registers offset_addr 0x1000 */
	ys_wr32(addr, UMAC_SDCFG0_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG0_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG0_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG0_CFG2_H);

	/* sdcfg1 registers offset_addr 0x1080 */
	ys_wr32(addr, UMAC_SDCFG1_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG1_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG1_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG1_CFG2_H);

	/* sdcfg2 registers offset_addr 0x1100 */
	ys_wr32(addr, UMAC_SDCFG2_L(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG2_CFG2_L);
	ys_wr32(addr, UMAC_SDCFG2_H(pdev_priv->pf_id, UMAC_CH0), RS_100G_SDCFG2_CFG2_H);

	return 0;
}

void ys_umac_get_stats(struct net_device *ndev, u64 *data)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32 pf_id;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];
	pf_id = pdev_priv->switch_mac ?
		(pdev_priv->pf_id ? 0x0 : 0x1) :
		pdev_priv->pf_id;

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return;

	data[UMAC_FRAMES_XMIT_ERROR] = ys_rd64(addr, UMAC_FRAMES_XMIT_ERROR(pf_id));
	data[UMAC_FRAMES_XMIT_SIZELT64] = ys_rd64(addr, UMAC_FRAMES_XMIT_SIZELT64(pf_id));
	data[UMAC_FRAMES_XMIT_SIZEEQ64] = ys_rd64(addr, UMAC_FRAMES_XMIT_SIZEEQ64(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE65TO127] = ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE65TO127(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE128TO255] = ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE128TO255(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE256TO511] = ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE256TO511(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE512TO1023] = ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE512TO1023(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE1024TO1518] =
		ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE1024TO1518(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE1519TO2047] =
		ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE1519TO2047(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE2048TO4095] =
		ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE2048TO4095(pf_id));
	data[UMAC_FRAMES_XMIT_SIZE4096TO8191] =
		ys_rd64(addr, UMAC_FRAMES_XMIT_SIZE4096TO8191(pf_id));
	data[UMAC_FRAMES_SMIT_SIZE8192TO9215] =
		ys_rd64(addr, UMAC_FRAMES_SMIT_SIZE8192TO9215(pf_id));
	data[UMAC_FRAMES_XMIT_SIZEGT9216] = ys_rd64(addr, UMAC_FRAMES_XMIT_SIZEGT9216(pf_id));

	data[UMAC_FRAMES_RCVD_CRCERROR] = ys_rd64(addr, UMAC_FRAMES_RCVD_CRCERROR(pf_id));
	data[UMAC_FRAMES_RCVD_SIZELT64] = ys_rd64(addr, UMAC_FRAMES_RCVD_SIZELT64(pf_id));
	data[UMAC_FRAMES_RCVD_SIZEEQ64] = ys_rd64(addr, UMAC_FRAMES_RCVD_SIZEEQ64(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE65TO127] = ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE65TO127(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE128TO255] = ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE128TO255(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE256TO511] = ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE256TO511(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE512TO1023] = ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE512TO1023(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE1024TO1518] =
		ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE1024TO1518(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE1419TO2047] =
		ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE1419TO2047(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE2048TO4095] =
		ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE2048TO4095(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE4096TO8191] =
		ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE4096TO8191(pf_id));
	data[UMAC_FRAMES_RCVD_SIZE8192TO9215] =
		ys_rd64(addr, UMAC_FRAMES_RCVD_SIZE8192TO9215(pf_id));
	data[UMAC_FRAMES_RCVD_SIZEGT9216] = ys_rd64(addr, UMAC_FRAMES_RCVD_SIZEGT9216(pf_id));

	/* Generate a dummy counter. Simulate discarding packet by phy layer */
	data[UMAC_DUMMY_TX_DISCARD_PHY] = 0;
	data[UMAC_DUMMY_RX_DISCARD_PHY] = 0;
}

void ys_umac_get_stats_strings(struct net_device *ndev, u8 *data)
{
	struct ys_ndev_priv *ndev_priv;
	u8 *p = data;
	int i;

	ndev_priv = netdev_priv(ndev);

	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return;

	for (i = 0; i < ARRAY_SIZE(ys_umac_stats_strings); i++) {
		memcpy(p, ys_umac_stats_strings[i], ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
	}
}

int ys_umac_get_stats_count(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);
	if (ys_ndev_check_permission(ndev_priv, AUX_TYPE_ETH))
		return 0;

	return ARRAY_SIZE(ys_umac_stats_strings);
}

#ifdef YS_HAVE_ETHTOOL_MAC_STATS
static void ys_umac_get_mac_stats(struct net_device *ndev,
				  struct ethtool_eth_mac_stats *mac_stats)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u8 pf_id;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];
	pf_id = pdev_priv->pf_id;

	mac_stats->FramesTransmittedOK =
		ys_rd64(addr, UMAC_FRAMES_XMIT_OK(pf_id));

	mac_stats->FramesReceivedOK =
		ys_rd64(addr, UMAC_FRAMES_RCVD_OK(pf_id));

	mac_stats->FrameCheckSequenceErrors =
		ys_rd64(addr, UMAC_FRAMES_RCVD_CRCERROR(pf_id));

	mac_stats->OctetsTransmittedOK =
		ys_rd64(addr, UMAC_OCTETS_XMIT_OK(pf_id));

	mac_stats->OctetsReceivedOK =
		ys_rd64(addr, UMAC_OCTETS_RCVD_OK(pf_id));

	mac_stats->MulticastFramesXmittedOK =
		ys_rd64(addr, UMAC_FRAMES_XMIT_MULTICAST(pf_id));

	mac_stats->BroadcastFramesXmittedOK =
		ys_rd64(addr, UMAC_FRAMES_XMIT_BROADCAST(pf_id));

	mac_stats->MulticastFramesReceivedOK =
		ys_rd64(addr, UMAC_FRAMES_RCVD_MULTICAST(pf_id));

	mac_stats->BroadcastFramesReceivedOK =
		ys_rd64(addr, UMAC_FRAMES_RCVD_BROADCAST(pf_id));

	mac_stats->InRangeLengthErrors = 0;
	mac_stats->OutOfRangeLengthField = 0;
	mac_stats->FrameTooLongErrors = 0;
}
#endif /* YS_HAVE_ETHTOOL_MAC_STATS */

static void ys_umac_get_supported_advertising(struct net_device *ndev,
					      struct ys_ethtool_ksetting *cmd)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32  speed_reg;
	u32 speed;
	struct ys_mbox *mbox;
	struct ethtool_fecparam fp;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	speed = ysk2_get_shr0_port_speed(mbox);
	speed_reg = pdev_priv->hw_info->nic_info.port_type;
	ys_net_debug("speed_reg: 0x%x", speed_reg);

	ys_umac_get_fec_mode(ndev, &fp);
	switch (speed_reg) {
	case UMAC_MODE_SPEEDM_10GBASE:
		ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_10000baseSR_Full_BIT);
		ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FEC_NONE_BIT);
		ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FIBRE_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_10000baseSR_Full_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FEC_NONE_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FIBRE_BIT);
		break;
	case UMAC_MODE_SPEEDM_25GBASE:
		if (speed == SPEED_25G) {
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_25000baseSR_Full_BIT);
		} else if (speed == SPEED_10G) {
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_10000baseSR_Full_BIT);
		} else if (speed == SPEED_AUTO) {
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_Autoneg_BIT);
		} else {
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_10000baseSR_Full_BIT);
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_25000baseSR_Full_BIT);
		}
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_10000baseSR_Full_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_25000baseSR_Full_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FEC_NONE_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FEC_RS_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FEC_BASER_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_FIBRE_BIT);
		ys_build_ehtool_ksetting_supported(cmd, ETHTOOL_LINK_MODE_Autoneg_BIT);
		switch (fp.active_fec) {
		case ETHTOOL_FEC_OFF:
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FEC_NONE_BIT);
			break;
		case ETHTOOL_FEC_BASER:
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FEC_BASER_BIT);
			break;
		case ETHTOOL_FEC_RS:
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FEC_RS_BIT);
			break;
		default:
			ys_build_ehtool_ksetting_advertising(cmd, ETHTOOL_LINK_MODE_FEC_NONE_BIT);
			break;
		}
		break;
	default:
		break;
	}
}

static u32 ys_umac_get_link_speed(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32  speed_reg;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	if (!netif_carrier_ok(ndev))
		return SPEED_UNKNOWN;

	speed_reg = ys_rd32(addr, UMAC_CHMODE_L(pdev_priv->switch_mac ?
						(pdev_priv->pf_id ? 0x0 : 0x1) :
						pdev_priv->pf_id, UMAC_CH0));
	speed_reg &= CHMODE_MODE_MASK;
	switch (speed_reg) {
	case UMAC_MODE_SPEED_10GBASE:
	case UMAC_MODE_SPEED_10GBASE_FC:
		return SPEED_10G;
	case UMAC_MODE_SPEED_25GBASE:
	case UMAC_MODE_SPEED_25GBASE_FC:
	case UMAC_MODE_SPEED_25GBASE_RS_IEEE:
	case UMAC_MODE_SPEED_25GBASE_RS_CONS:
		return SPEED_25G;
	default:
		return SPEED_UNKNOWN;
	}

	return SPEED_UNKNOWN;
}

int ys_umac_set_link_speed(struct net_device *ndev, u32 speed)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32  speed_mode;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	speed_mode = ys_rd32(addr, UMAC_CHMODE_L(pdev_priv->pf_id, UMAC_CH0));
	speed_mode &= CHMODE_MODE_MASK;

	switch (speed) {
	case SPEED_10G:
		if (speed_mode == UMAC_MODE_SPEED_10GBASE ||
		    speed_mode == UMAC_MODE_SPEED_10GBASE_FC) {
			return 0;
		} else if (speed_mode == UMAC_MODE_SPEED_25GBASE ||
			   speed_mode == UMAC_MODE_SPEED_40GBASE ||
			   speed_mode == UMAC_MODE_SPEED_50GBASE ||
			   speed_mode == UMAC_MODE_SPEED_100GBASE) {
			return ys_umac_enable_10gbase(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_25GBASE_FC ||
			   speed_mode == UMAC_MODE_SPEED_40GBASE_FC ||
			   speed_mode == UMAC_MODE_SPEED_50GBASE_FC) {
			return ys_umac_enable_10gbase_fc(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_25GBASE_RS_IEEE ||
			   speed_mode == UMAC_MODE_SPEED_25GBASE_RS_CONS ||
			   speed_mode == UMAC_MODE_SPEED_50GBASE_RS ||
			   speed_mode == UMAC_MODE_SPEED_100GBASE_RS) {
			ys_net_warn("The current RS fec mode does not support 10G speed");
			return -EINVAL;
		} else if (speed_mode == UMAC_MODE_SPEED_DISABLED) {
			ys_net_warn("Channel is shut down and held in reset");
			return ys_umac_enable_10gbase(ndev);
		}
		break;
	case SPEED_25G:
		if (speed_mode == UMAC_MODE_SPEED_25GBASE ||
		    speed_mode == UMAC_MODE_SPEED_25GBASE_FC ||
		    speed_mode == UMAC_MODE_SPEED_25GBASE_RS_IEEE ||
		    speed_mode == UMAC_MODE_SPEED_25GBASE_RS_CONS) {
			return 0;
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE ||
			   speed_mode == UMAC_MODE_SPEED_40GBASE ||
			   speed_mode == UMAC_MODE_SPEED_50GBASE ||
			   speed_mode == UMAC_MODE_SPEED_100GBASE) {
			return ys_umac_enable_25gbase(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE_FC ||
			   speed_mode == UMAC_MODE_SPEED_40GBASE_FC ||
			   speed_mode == UMAC_MODE_SPEED_50GBASE_FC) {
			return ys_umac_enable_25gbase_fc(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_50GBASE_RS ||
			   speed_mode == UMAC_MODE_SPEED_100GBASE_RS) {
			return ys_umac_enable_25gbase_rs_ieee(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_DISABLED) {
			ys_net_warn("Channel is shut down and held in reset");
			return ys_umac_enable_25gbase(ndev);
		}
		break;
	case SPEED_40G:
		if (speed_mode == UMAC_MODE_SPEED_40GBASE ||
		    speed_mode == UMAC_MODE_SPEED_40GBASE_FC) {
			return 0;
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE ||
			speed_mode == UMAC_MODE_SPEED_25GBASE ||
			speed_mode == UMAC_MODE_SPEED_50GBASE ||
			speed_mode == UMAC_MODE_SPEED_100GBASE) {
			return ys_umac_enable_40gbase(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE_FC ||
			speed_mode == UMAC_MODE_SPEED_25GBASE_FC ||
			speed_mode == UMAC_MODE_SPEED_50GBASE_FC) {
			return ys_umac_enable_40gbase_fc(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_25GBASE_RS_IEEE ||
			speed_mode == UMAC_MODE_SPEED_25GBASE_RS_CONS ||
			speed_mode == UMAC_MODE_SPEED_50GBASE_RS ||
			speed_mode == UMAC_MODE_SPEED_100GBASE_RS) {
			ys_net_warn("The current RS fec mode does not support 40G speed");
			return -EINVAL;
		} else if (speed_mode == UMAC_MODE_SPEED_DISABLED) {
			ys_net_warn("Channel is shut down and held in reset");
			return ys_umac_enable_40gbase(ndev);
		}
		break;
	case SPEED_50G:
		if (speed_mode == UMAC_MODE_SPEED_50GBASE ||
		    speed_mode == UMAC_MODE_SPEED_50GBASE_FC ||
		    speed_mode == UMAC_MODE_SPEED_50GBASE_RS) {
			return 0;
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE ||
			   speed_mode == UMAC_MODE_SPEED_25GBASE ||
			   speed_mode == UMAC_MODE_SPEED_40GBASE ||
			   speed_mode == UMAC_MODE_SPEED_100GBASE) {
			return ys_umac_enable_50gbase(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE_FC ||
			   speed_mode == UMAC_MODE_SPEED_25GBASE_FC ||
			   speed_mode == UMAC_MODE_SPEED_50GBASE_FC) {
			return ys_umac_enable_50gbase_fc(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_25GBASE_RS_IEEE ||
			   speed_mode == UMAC_MODE_SPEED_25GBASE_RS_CONS ||
			   speed_mode == UMAC_MODE_SPEED_100GBASE_RS) {
			return ys_umac_enable_50gbase_rs(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_DISABLED) {
			ys_net_warn("Channel is shut down and held in reset");
			return ys_umac_enable_50gbase(ndev);
		}
		break;
	case SPEED_100G:
		if (speed_mode == UMAC_MODE_SPEED_100GBASE ||
		    speed_mode == UMAC_MODE_SPEED_100GBASE_RS) {
			return 0;
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE ||
			speed_mode == UMAC_MODE_SPEED_25GBASE ||
			speed_mode == UMAC_MODE_SPEED_40GBASE ||
			speed_mode == UMAC_MODE_SPEED_50GBASE) {
			return ys_umac_enable_100gbase(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_10GBASE_FC ||
			speed_mode == UMAC_MODE_SPEED_25GBASE_FC ||
			speed_mode == UMAC_MODE_SPEED_40GBASE_FC ||
			speed_mode == UMAC_MODE_SPEED_50GBASE_FC) {
			ys_net_warn("The current FC fec mode does not support 100G speed");
			return -EINVAL;
		} else if (speed_mode == UMAC_MODE_SPEED_25GBASE_RS_IEEE ||
			speed_mode == UMAC_MODE_SPEED_25GBASE_RS_CONS ||
			speed_mode == UMAC_MODE_SPEED_50GBASE_RS) {
			return ys_umac_enable_100gbase_rs(ndev);
		} else if (speed_mode == UMAC_MODE_SPEED_DISABLED) {
			ys_net_warn("Channel is shut down and held in reset");
			return ys_umac_enable_100gbase(ndev);
		}
		break;
	default:
		ys_net_warn("This speed %d is not supported", speed);
		return -EINVAL;
	}

	return -EINVAL;
}

static int ys_umac_send_cmd_to_m3(struct net_device *ndev, void __iomem *hw_addr, u32 d2m_cmd, u32 m2d_rep_cmd)
{
	int ret = 0;
	u32 m2d_cmd = 0;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	unsigned long timeout = jiffies + msecs_to_jiffies(5000); /* 5s */

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ys_dev_info("driver to m3 cmd: %02x", d2m_cmd);
	/* Clear m2d command first */
	ys_umac_clear_m2d_command(hw_addr);

	/* Set driver command */
	ys_umac_set_d2m_command(hw_addr, d2m_cmd);

	/* M3 receive the command and clear the command register */
	ret = ys_umac_wait_m3_get_command(hw_addr);
	if (ret)
		return ret;

	while (time_before(jiffies, timeout)) {
		if (ys_umac_wait_m2d_command(hw_addr))
			return -ETIMEDOUT;

		m2d_cmd = ys_rd32(hw_addr, UMAC_SFP_TRANS_M2D_CMD);
		if (m2d_cmd == m2d_rep_cmd) {
			ys_dev_info("send_cmd_to_m3 success m2d_cmd:%02x,m2d_rep_cmd:%02x",
				    m2d_cmd, m2d_rep_cmd);
			return 0;
		}
	}
	ys_dev_info("send_cmd_to_m3 faild, m2d_cmd:%02x, m2d_rep_cmd:%02x",
		    m2d_cmd, m2d_rep_cmd);

	return -EINVAL;
}

static int ys_umac_set_m3_link_speed(struct net_device *ndev, u32 speed)
{
	void __iomem *hw_addr;
	u32 d2m_cmd = 0, m2d_rep_cmd = 0;
	int ret = 0;
	struct ys_mbox *mbox;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);

	switch (speed) {
	case SPEED_10G:
		d2m_cmd = UMAC_D2M_SET_SPEED10G;
		m2d_rep_cmd = UMAC_M2D_SET_SPEED10G;
		ysk2_shr0_port_speed(mbox, pdev_priv->pf_id, SPEED_10G);
		break;
	case SPEED_25G:
		d2m_cmd = UMAC_D2M_SET_SPEED25G;
		m2d_rep_cmd = UMAC_M2D_SET_SPEED25G;
		ysk2_shr0_port_speed(mbox, pdev_priv->pf_id, SPEED_25G);
		break;
	case SPEED_AUTO:
		d2m_cmd = UMAC_D2M_SET_SPEED_AUTONEGO;
		m2d_rep_cmd = UMAC_M2D_SET_SPEED_AUTONEGO;
		ysk2_shr0_port_autonego(mbox, pdev_priv->pf_id, SPEED_AUTO);
		ysk2_shr0_port_speed(mbox, pdev_priv->pf_id, SPEED_AUTO);
		break;
	default:
		return -EINVAL;
	}

	if (d2m_cmd < UMAC_D2M_SET_SPEED10G || d2m_cmd > UMAC_D2M_CMD_MAX)
		return -EINVAL;

	hw_addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	ret = ys_umac_send_cmd_to_m3(ndev, hw_addr, d2m_cmd, m2d_rep_cmd);
	if (ret)
		return ret;

	return 0;
}

int ys_umac_set_speed_autonego(struct net_device *ndev, bool on)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	u32 speed = SPEED_AUTO;
	int ret;
	struct ys_mbox *mbox;

	if (!pdev_priv->hw_info)
		return -EINVAL;

	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);

	if (on)
		speed = SPEED_AUTO;
	else if (pdev_priv->hw_info->nic_info.port_type == UMAC_MODE_SPEEDM_10GBASE)
		speed = SPEED_10G;
	else if (pdev_priv->hw_info->nic_info.port_type == UMAC_MODE_SPEEDM_25GBASE)
		speed = SPEED_25G;

	ys_dev_info("speed autonego:%s", on ? "on" : "off");
	ret = ys_umac_set_m3_link_speed(ndev, speed);
	if (!ret)
		ysk2_shr0_port_autonego(mbox, pdev_priv->pf_id, speed);

	return ret;
}

u8 ys_umac_get_speed_autonego(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	u32 speed;
	struct ys_mbox *mbox;

	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	speed = ysk2_get_shr0_port_autonego(mbox);
	if (speed == SPEED_AUTO)
		return AUTONEG_ENABLE;
	else
		return AUTONEG_DISABLE;
}

static int ys_umac_set_phys_id(struct net_device *ndev,
			enum ethtool_phys_id_state state)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	u32 led_state = 0, m2d_rep_cmd = 0;
	int ret = 0;
	void __iomem *hw_addr;
	u8 pf_id;

	pf_id = pdev_priv->switch_mac ?
		(pdev_priv->pf_id ? 0x0 : 0x1) :
		pdev_priv->pf_id;

	switch (state) {
	case ETHTOOL_ID_INACTIVE:
		led_state = pf_id + UMAC_D2M_SET_PORT0_LIGHT_NORMAL;
		m2d_rep_cmd = pf_id ? UMAC_M2D_SET_PORT1_LIGHT_NORMAL :
			      UMAC_M2D_SET_PORT0_LIGHT_NORMAL;
		break;
	case ETHTOOL_ID_ACTIVE:
		led_state = pf_id + UMAC_D2M_SET_PORT0_LIGHT_BLINK;
		m2d_rep_cmd = pf_id ? UMAC_M2D_SET_PORT1_LIGHT_BLINK :
			      UMAC_M2D_SET_PORT0_LIGHT_BLINK;
		break;
	default:
		break;
	}

	hw_addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];
	ret = ys_umac_send_cmd_to_m3(ndev, hw_addr, led_state, m2d_rep_cmd);
	if (ret)
		return ret;

	return 0;
}

static u32 ys_umac_get_link_duplex(struct net_device *ndev)
{
	u32 duplex;

	duplex = DUPLEX_FULL;
	return duplex;
}

static u32 ys_umac_get_link_port_type(struct net_device *ndev)
{
	u32 port_type;

	if (!netif_carrier_ok(ndev))
		return PORT_NONE;

	port_type = PORT_FIBRE;
	return port_type;
}

static int ys_umac_get_fec_mode(struct net_device *ndev,
				struct ethtool_fecparam *fp)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32  fec_mode;
	void __iomem *addr;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	fec_mode = ys_rd32(addr, UMAC_CHMODE_L(pdev_priv->switch_mac ?
					       (pdev_priv->pf_id ? 0x0 : 0x1) :
					       pdev_priv->pf_id, UMAC_CH0));
	fec_mode &= CHMODE_MODE_MASK;

	switch (fec_mode) {
	case UMAC_MODE_SPEED_10GBASE:
	case UMAC_MODE_SPEED_25GBASE:
	case UMAC_MODE_SPEED_40GBASE:
	case UMAC_MODE_SPEED_50GBASE:
	case UMAC_MODE_SPEED_100GBASE:
		fp->active_fec = ETHTOOL_FEC_OFF;
		break;
	case UMAC_MODE_SPEED_10GBASE_FC:
	case UMAC_MODE_SPEED_25GBASE_FC:
	case UMAC_MODE_SPEED_40GBASE_FC:
	case UMAC_MODE_SPEED_50GBASE_FC:
		fp->active_fec = ETHTOOL_FEC_BASER;
		break;
	case UMAC_MODE_SPEED_25GBASE_RS_IEEE:
	case UMAC_MODE_SPEED_25GBASE_RS_CONS:
	case UMAC_MODE_SPEED_50GBASE_RS:
	case UMAC_MODE_SPEED_100GBASE_RS:
		fp->active_fec = ETHTOOL_FEC_RS;
		break;
	default:
		fp->active_fec = ETHTOOL_FEC_OFF;
		ys_net_warn("fec mode unknown");
		return -EINVAL;
	}
	return 0;
}

int ys_umac_set_fec_mode(struct net_device *ndev, u32 fec)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	u32  port_flags;
	int ret;
	void __iomem *hw_addr;
	u32 m2d_rep_cmd;

	switch (fec) {
	case ETHTOOL_FEC_RS:
		port_flags = UMAC_D2M_SET_FEC_RS;
		m2d_rep_cmd = UMAC_M2D_SET_FEC_RS;
		ndev_priv->fec_cfg = ETHTOOL_FEC_RS;
		break;
	case ETHTOOL_FEC_BASER:
		port_flags = UMAC_D2M_SET_FEC_BASER;
		m2d_rep_cmd = UMAC_M2D_SET_FEC_BASER;
		ndev_priv->fec_cfg = ETHTOOL_FEC_BASER;
		break;
	case ETHTOOL_FEC_OFF:
		port_flags = UMAC_D2M_SET_FEC_NONE;
		m2d_rep_cmd = UMAC_M2D_SET_FEC_NONE;
		ndev_priv->fec_cfg = ETHTOOL_FEC_OFF;
		break;
	case ETHTOOL_FEC_AUTO:
		port_flags = UMAC_D2M_SET_FEC_AUTONEGO;
		m2d_rep_cmd = UMAC_M2D_SET_FEC_AUTONEGO;
		ndev_priv->fec_cfg = ETHTOOL_FEC_AUTO;
		break;
	default:
		return -EOPNOTSUPP;
	}
	hw_addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];
	ret = ys_umac_send_cmd_to_m3(ndev, hw_addr, port_flags, m2d_rep_cmd);

	if (ret)
		return ret;
	return 0;
}

static void ys_umac_get_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *pause)
{
	void __iomem *hw_addr;
	u32 tx_pause_mode = 0, rx_pause_mode = 0;
	u32 value = 0, value_bit8 = 0, value_bit10 = 0;

	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	hw_addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];
	if (pdev_priv->pf_id == 0) {
		//read rx pause(mac addr)
		value = ys_rd32(hw_addr, UMAC_PAUSE_RX_MAC0);
		value_bit8 = (value >> 8) & 0x1;
		value_bit10 = (value >> 10) & 0x1;
		if (1 ==  value_bit8 && 1 == value_bit10)
			rx_pause_mode = 1;

		//read tx pause(mac addr)
		tx_pause_mode = ys_rd32(hw_addr, UMAC_PAUSE_TX_TM0);
	} else {
		//read rx pause(mac addr)
		value = ys_rd32(hw_addr, UMAC_PAUSE_RX_MAC1);
		value_bit8 = (value >> 8) & 0x1;
		value_bit10 = (value >> 10) & 0x1;

		if (1 ==  value_bit8 && 1 == value_bit10)
			rx_pause_mode = 1;

		//read tx pause(mac addr)
		tx_pause_mode = ys_rd32(hw_addr, UMAC_PAUSE_TX_TM1);
	}

	pause->rx_pause = !!(rx_pause_mode > 0);
	pause->tx_pause = !!(tx_pause_mode > 0);
	pause->autoneg = 0;

	ys_net_info("getting pause");
}
static int ys_umac_set_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *pause)
{
	int ret = 0;
	void __iomem *hw_addr;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	u32 d2m_cmd;
	u32 m2d_rep_cmd;

	if (pause->autoneg)
		return -EINVAL;

	hw_addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];
	if (pdev_priv->pf_id == 0) {
		if (pause->rx_pause || pause->tx_pause) {
			d2m_cmd = UMAC_D2M_SET_PF0_FC_PAUSE;
			m2d_rep_cmd = UMAC_M2D_SET_PF0_FC_PAUSE;
			ys_net_info("setting pause rx:%d, tx:%d", pause->rx_pause, pause->tx_pause);
			ret = ys_umac_send_cmd_to_m3(ndev, hw_addr, d2m_cmd, m2d_rep_cmd);
		} else {
			d2m_cmd = UMAC_D2M_SET_PF0_FC_PAUSE_OFF;
			m2d_rep_cmd = UMAC_M2D_SET_PF0_FC_PAUSE_OFF;
			ys_net_info("setting pause rx:%d, tx:%d", pause->rx_pause, pause->tx_pause);
			ret = ys_umac_send_cmd_to_m3(ndev, hw_addr, d2m_cmd, m2d_rep_cmd);
		}
	} else {
		if (pause->rx_pause || pause->tx_pause) {
			d2m_cmd = UMAC_D2M_SET_PFN_FC_PAUSE;
			m2d_rep_cmd = UMAC_M2D_SET_PFN_FC_PAUSE;
			ys_net_info("setting pause rx:%d, tx:%d", pause->rx_pause, pause->tx_pause);
			ret = ys_umac_send_cmd_to_m3(ndev, hw_addr, d2m_cmd, m2d_rep_cmd);
		} else {
			d2m_cmd = UMAC_D2M_SET_PFN_FC_PAUSE_OFF;
			m2d_rep_cmd = UMAC_M2D_SET_PFN_FC_PAUSE_OFF;
			ys_net_info("setting pause rx:%d, tx:%d", pause->rx_pause, pause->tx_pause);
			ret = ys_umac_send_cmd_to_m3(ndev, hw_addr, d2m_cmd, m2d_rep_cmd);
		}
	}
	if (ret) {
		ys_net_info("M3 set fc pause failed , setting pause rx:%d, tx:%d",
			pause->rx_pause, pause->tx_pause);
		return ret;
	}
	return 0;
}

int ys_umac_eth_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw))
		UMAC_ETH_FUNC(ndev_priv->ys_eth_hw);

	return 0;
}

static void ys_umac_ndev_check_link(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *hw_addr;
	u32 reg = 0;
	int i = 3;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hw_addr = pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	if (!pdev_priv->nic_type->is_vf) {
		switch (pdev_priv->pf_id) {
		case 0 ... 3:
			while (i--) {
				reg = ys_rd32(hw_addr, UMAC_CHX_STATUS_REG(0, pdev_priv->pf_id));
				udelay(10);
			}
			break;
		default:
			break;
		}
	}

	if ((reg & UMAC_STATUS_MASK) == UMAC_STATUS_EN) {
		netif_carrier_on(ndev);
		pdev_priv->link_status = 1;
	} else {
		netif_carrier_off(ndev);
		pdev_priv->link_status = 0;
	}
}

int ys_umac_ndev_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_mac *mac;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mac_ndev *ys_mac_ndev;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw))
		UMAC_NDEV_FUNC(ndev_priv->ys_ndev_hw);

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
			ys_umac_ndev_check_link(ndev);
			list_add(&ys_mac_ndev->list, &mac->ndev_list);
		}
	}
	spin_unlock(&mac->list_lock);

	/* alloc irq failed, switch to timer mode deteck link status */
	if (mac->irq_vector >= 0)
		ndev_priv->mac_intr_en = 1;
	ndev_priv->ys_eth_hw->et_check_link = ys_umac_ndev_check_link;

	ys_umac_set_fec_mode(ndev, ETHTOOL_FEC_AUTO);
	ys_umac_set_m3_link_speed(ndev, SPEED_AUTO);

	return 0;
}

void ys_umac_ndev_uninit(struct net_device *ndev)
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

static int ys_umac_intr(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ys_mac *mac = container_of(nb, struct ys_mac, irq_nb);
	struct ys_mac_ndev *ys_mac_ndev, *temp;

	spin_lock(&mac->list_lock);
	list_for_each_entry_safe(ys_mac_ndev, temp, &mac->ndev_list, list)
		if (ys_mac_ndev->ndev)
			ys_umac_ndev_check_link(ys_mac_ndev->ndev);
	spin_unlock(&mac->list_lock);

	return NOTIFY_DONE;
}

int ys_umac_init(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_mac *mac = adev->adev_priv;
	void __iomem *hw_addr;
	u32 val;
	int ret;

	INIT_LIST_HEAD(&mac->ndev_list);
	spin_lock_init(&mac->list_lock);

	hw_addr = (void __iomem *)pdev_priv->bar_addr[YS_UMAC_REGS_BAR];

	/* request mac interrupt */
	mac->irq_nb.notifier_call = ys_umac_intr;
	/* get misc irq vector position */
	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_get_init_qnum))
		mac->irq_vector = pdev_priv->ops->hw_adp_get_init_qnum(adev->pdev);
	else
		mac->irq_vector = 0;

	ret = YS_REGISTER_NOTIFIER_IRQ(&pdev_priv->irq_table.nh, YS_IRQ_NB_REGISTER_ANY,
		0, pdev_priv->pdev, YS_IRQ_TYPE_MAC,
		NULL, &mac->irq_nb, "xmac");
	if (ret < 0) {
		ys_dev_err("ys_umac alloc irq failed for umac\n");
		return -ENOMEM;
	}
	mac->irq_vector = ret;

	ys_wr32(hw_addr, UMAC_INTER_JITTER_CTL(0), UMAC_INTER_JITTER_CTL_DEF);
	ys_dev_info("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, UMAC_INTER_JITTER_CTL(0), UMAC_INTER_JITTER_CTL_DEF);

	ys_wr32(hw_addr, UMAC_INTER_ENABLE_REG(0), UMAC_INTER_ENABLE_ALL);
	ys_dev_info("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, UMAC_INTER_ENABLE_REG(0), UMAC_INTER_ENABLE_ALL);

	if (!pdev_priv->nic_type->is_vf) {
		if (pdev_priv->pf_id < 4) {
			switch (pdev_priv->pf_id) {
			case 0:
				val = FIELD_PREP(UMAC_INTER_VECTOR_LAN02_MASK, mac->irq_vector);
				ys_wr32(hw_addr, UMAC_INTER_VECTOR_HOST_LAN01(0), val);
				ys_dev_info("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, UMAC_INTER_VECTOR_HOST_LAN01(0), val);
				break;
			case 1:
				val = ys_rd32(hw_addr, UMAC_INTER_VECTOR_HOST_LAN01(0));
				val |= FIELD_PREP(UMAC_INTER_VECTOR_LAN13_MASK, mac->irq_vector);
				ys_wr32(hw_addr, UMAC_INTER_VECTOR_HOST_LAN01(0), val);
				ys_dev_info("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, UMAC_INTER_VECTOR_HOST_LAN01(0), val);
				break;
			case 2:
				val = FIELD_PREP(UMAC_INTER_VECTOR_LAN02_MASK, mac->irq_vector);
				ys_wr32(hw_addr, UMAC_INTER_VECTOR_HOST_LAN23(0), val);
				ys_dev_info("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, UMAC_INTER_VECTOR_HOST_LAN23(0), val);
				break;
			case 3:
				val = ys_rd32(hw_addr, UMAC_INTER_VECTOR_HOST_LAN23(0));
				val |= FIELD_PREP(UMAC_INTER_VECTOR_LAN13_MASK, mac->irq_vector);
				ys_wr32(hw_addr, UMAC_INTER_VECTOR_HOST_LAN23(0), val);
				ys_dev_info("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, UMAC_INTER_VECTOR_HOST_LAN23(0), val);
				break;
			default:
				ys_dev_info("pf_id %u\n", pdev_priv->pf_id);
				break;
			}

			val = FIELD_PREP(UMAC_INTER_CHX_F_VALUE_HOST_MASK, pdev_priv->pf_id);
			ys_wr32(hw_addr, UMAC_INTER_CHX_F_VALUE(0, pdev_priv->pf_id), val);
			ys_dev_info("wr32 hw_addr 0x%p reg 0x%x val 0x%x\n", hw_addr, UMAC_INTER_CHX_F_VALUE(0, pdev_priv->pf_id), val);
		}
	}

	ys_dev_info("hw_addr 0x%p pf_id %u irq %u\n", hw_addr, pdev_priv->pf_id, mac->irq_vector);

	return 0;
}

void ys_umac_uninit(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_mac *mac = (struct ys_mac *)adev->adev_priv;

	if (mac->irq_vector >= 0) {
		YS_UNREGISTER_IRQ(&pdev_priv->irq_table.nh, mac->irq_vector,
				  pdev_priv->pdev, &mac->irq_nb);
	}
}

