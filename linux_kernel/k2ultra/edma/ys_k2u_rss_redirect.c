// SPDX-License-Identifier: GPL-2.0
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include "ys_k2u_new_ndev.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_rss_redirect.h"

static u8 k2u_default_hash_key[] = {0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e,
	0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
	0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae,
	0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
	0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7,
	0x3b, 0xbe, 0xac, 0x01, 0xfa
};

void ys_k2u_pf_rss_redirect_table_default(void __iomem *hw_addr, u16 qstart, u16 qnb)
{
	u32 i = 0, tmp = 0, val = 0;

	for (i = 0; i < 4 * qnb; i++) {
		if (tmp == qnb)
			tmp = 0;
		val = val + (tmp << (8 * (i & 0x03)));
		tmp++;
		if ((i & 0x03) == 0x03) {
			ys_wr32(hw_addr, YS_K2U_RSS_REDIRECT_BASE + 4 * qstart + 4 * (i >> 2),
				val);
			val = 0;
		}
	}
}

void ys_k2u_pf_rss_redirect_table_set(void __iomem *hw_addr, u16 qstart, u16 qnb, u8 *data)
{
	u32 i = 0, val = 0;

	for (i = 0; i < 4 * qnb; i += 4) {
		val = ((data[i + 3] & 0xff) << 24) | ((data[i + 2] & 0xff) << 16)
			| ((data[i + 1] & 0xff) << 8) | (data[i] & 0xff);
		ys_wr32(hw_addr, YS_K2U_RSS_REDIRECT_BASE + 4 * qstart + i, val);
	}
}

void ys_k2u_pf_rss_redirect_table_get(void __iomem *hw_addr, u16 qstart, u16 qnb, u8 *out)
{
	u32 i = 0, j = 0, val = 0;

	for (i = 0; i < qnb; i++) {
		val = ys_rd32(hw_addr, YS_K2U_RSS_REDIRECT_BASE + 4 * qstart + 4 * i);
		out[j++] = val & 0xff;
		out[j++] = (val >> 8) & 0xff;
		out[j++] = (val >> 16) & 0xff;
		out[j++] = (val >> 24) & 0xff;
	}
}

void ys_k2u_pf_hash_key_set(void __iomem *hw_addr, const u8 *key)
{
	u32 i, val;

	for (i = 0; i <= YS_K2U_RSS_HASH_KEY_SIZE - 4; i += 4) {
		val = *((u32 *)(key + i));
		ys_wr32(hw_addr, YS_K2U_RSS_KEY_ADDR + YS_K2U_RSS_HASH_KEY_SIZE - 4 - i,
			htonl(val));
	}
}

void ys_k2u_pf_hash_key_get(void __iomem *hw_addr, u8 *out)
{
	u32 i, val;

	for (i = 0; i <= YS_K2U_RSS_HASH_KEY_SIZE - 4; i += 4) {
		val = ys_rd32(hw_addr, YS_K2U_RSS_KEY_ADDR + YS_K2U_RSS_HASH_KEY_SIZE - 4 - i);
		*((u32 *)(out + i)) = htonl(val);
	}
}

void ys_k2u_rss_redirect_table_init(struct net_device *ndev, u16 rxqnum)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_mbox *mbox;
	struct ys_mbox_msg mbox_msg = {0};
	struct ys_k2u_mbox_rss_redirect_cmd *cmd;
	void __iomem *hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv);
	u16 qstart = k2u_ndev->g_qbase.start;

	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf hash*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("rss redirect mbox not support!\n");
			return;
		}
		cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)mbox_msg.data;
		cmd->cmd_type = YS_K2U_CMD_RSS_REDIRECT_TABLE_INIT;
		cmd->qstart = qstart;
		cmd->qnb = rxqnum;
		mbox_msg.opcode = YS_MBOX_OPCODE_RSS_REDIRECT;
		ys_mbox_send_msg(mbox, &mbox_msg, pdev_priv->vf_id, MB_NO_REPLY, 0, NULL);
	} else {
		ys_k2u_pf_rss_redirect_table_default(hw_addr, qstart, rxqnum);
	}
}

void ys_k2u_mbox_rss_redirect_proc(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	struct ys_k2u_mbox_rss_redirect_cmd *cmd, *ack_cmd;
	struct ys_mbox_msg ack_msg = {0};
	void __iomem *hw_addr = func->hw_addr;

	cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)msg->data;
	switch (cmd->cmd_type) {
	case YS_K2U_CMD_RSS_REDIRECT_TABLE_INIT:
		ys_k2u_pf_rss_redirect_table_default(hw_addr, cmd->qstart, cmd->qnb);
		break;
	case YS_K2U_CMD_RSS_REDIRECT_GET:
		ack_cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)ack_msg.data;
		ys_k2u_pf_rss_redirect_table_get(hw_addr, cmd->qstart, cmd->qnb,
						 ack_cmd->cmd_data);
		ack_cmd->cmd_status = 0;
		ack_msg.opcode = msg->opcode | (1 << YS_MBOX_OPCODE_MASK_ACK);
		ack_msg.seqno = msg->seqno;
		ys_mbox_send_msg(mbox, &ack_msg, channel, MB_NO_REPLY, 0, NULL);
		break;
	case YS_K2U_CMD_RSS_REDIRECT_TABLE_SET:
		ys_k2u_pf_rss_redirect_table_set(hw_addr, cmd->qstart, cmd->qnb,
						 cmd->cmd_data);
		break;
	case YS_K2U_CMD_RSS_REDIRECT_KEY_SET:
		ys_k2u_pf_hash_key_set(hw_addr, cmd->cmd_data);
		break;
	case YS_K2U_CMD_RSS_REDIRECT_KEY_GET:
		ack_cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)ack_msg.data;
		ack_cmd->cmd_status = 0;
		ack_msg.opcode = msg->opcode | (1 << YS_MBOX_OPCODE_MASK_ACK);
		ack_msg.seqno = msg->seqno;
		ys_k2u_pf_hash_key_get(hw_addr, ack_cmd->cmd_data);
		ys_mbox_send_msg(mbox, &ack_msg, channel, MB_NO_REPLY, 0, NULL);
		break;
	default:
		break;
	}
}

void ys_k2u_rss_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	void __iomem *hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv);
	struct ys_mbox *mbox;
	u32 val, i;

	if (!pdev_priv->nic_type->is_vf &&
	    (ndev_priv->adev_type & AUX_TYPE_ETH) &&
	    pdev_priv->pf_id == 0) {
		/* set rss default key */
		for (i = 0; i <= YS_K2U_RSS_HASH_KEY_SIZE - 4; i += 4) {
			val = *((u32 *)(k2u_default_hash_key + i));
			ys_wr32(hw_addr, YS_K2U_RSS_KEY_ADDR + YS_K2U_RSS_HASH_KEY_SIZE - 4 - i,
				htonl(val));
		}

		/* set rss redirect scale & bias & sw_fr */
		val = ys_rd32(hw_addr, YS_K2U_RSS_REDIRECT_SCALE_BIAS_ADDR);
		val &= ~(YS_K2U_RSS_REDIRECT_SCALE | YS_K2U_RSS_REDIRECT_BIAS
			| YS_K2U_RSS_REDIRECT_SW_FR);
		val |= FIELD_PREP(YS_K2U_RSS_REDIRECT_SCALE,
				  YS_K2U_RSS_REDIRECT_SCALE_POWER_VALUE);
		val |= FIELD_PREP(YS_K2U_RSS_REDIRECT_BIAS, YS_K2U_RSS_REDIRECT_BIAS_VALUE);
		val |= FIELD_PREP(YS_K2U_RSS_REDIRECT_SW_FR, YS_K2U_RSS_REDIRECT_SW_FR_VALUE);
		ys_wr32(hw_addr, YS_K2U_RSS_REDIRECT_SCALE_BIAS_ADDR, val);
	}
	ys_k2u_rss_redirect_table_init(ndev, (u16)ndev->real_num_rx_queues);
	k2u_ndev->rss_redirect_en = 1;

	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(mbox))
		return;

	mbox->mbox_vf_to_pf_set_rss_redirect = ys_k2u_mbox_rss_redirect_proc;
}
