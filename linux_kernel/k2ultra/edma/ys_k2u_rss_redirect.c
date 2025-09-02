// SPDX-License-Identifier: GPL-2.0
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/hashtable.h>
#include "ys_k2u_new_ndev.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_new_base.h"
#include "ys_k2u_rss_redirect.h"
#include "../mbox/ys_k2u_mbox.h"

#define YS_K2U_N_RSS_REDIR_MAXQNUM	(4 * YS_K2U_N_PF_MAXQNUM)

static u8 k2u_default_hash_key[] = {0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e,
	0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
	0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae,
	0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
	0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7,
	0x3b, 0xbe, 0xac, 0x01, 0xfa
};

static DEFINE_HASHTABLE(rss_redir_adjust_htable, 7);
static DEFINE_SPINLOCK(rss_redir_adjust_lock);

struct ys_k2u_rss_redir_status {
	struct hlist_node hlist;
	int ifindex;
	u64 rss_redir_pkts_last[YS_K2U_N_RSS_REDIR_MAXQNUM];
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

void ys_k2u_rss_redirect_table_set(struct net_device *ndev, const u32 *indir)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_mbox *mbox;
	struct ys_mbox_msg mbox_msg = {0};
	struct ys_k2u_mbox_rss_redirect_cmd *cmd;
	void __iomem *hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv);
	u32 send_id = 0;
	u32 i = 0, val = 0;
	struct ys_k2u_mbox_ctx *ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	u16 qstart = k2u_ndev->g_qbase.start;
	u32 qcount = ndev->real_num_rx_queues;

	if (pdev_priv->nic_type->is_vf) {
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("rss redirect set mbox not support!\n");
			return;
		}
		cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)mbox_msg.data;
		cmd->cmd_type = YS_K2U_CMD_RSS_REDIRECT_TABLE_SET;
		cmd->qstart = qstart;
		cmd->qnb = (u16)(qcount);
		mbox_msg.opcode = YS_MBOX_OPCODE_RSS_REDIRECT;
		ctx->type = MB_PF;
		for (i = 0; i < 4 * qcount; i++)
			cmd->cmd_data[i] = (u8)(indir[i] & 0xff);
		ys_mbox_send_msg(mbox, &mbox_msg, pdev_priv->vf_id,
				 MB_NO_REPLY, 0, NULL);
	} else {
		for (i = 0; i < 4 * qcount; i += 4) {
			val = ((indir[i + 3] & 0xff) << 24) | ((indir[i + 2] & 0xff) << 16)
				| ((indir[i + 1] & 0xff) << 8) | (indir[i] & 0xff);
			ys_wr32(hw_addr, YS_K2U_RSS_REDIRECT_BASE + 4 * qstart + i, val);
		}
	}
}

void ys_k2u_rss_redirect_table_get(struct net_device *ndev, u32 *indir)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_mbox *mbox;
	struct ys_mbox_msg mbox_msg = {0}, ack_msg = {0};
	struct ys_k2u_mbox_rss_redirect_cmd *cmd, *ack_cmd;
	void __iomem *hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv);
	u32 send_id = 0;
	u32 i = 0, j = 0, val = 0;
	struct ys_k2u_mbox_ctx *ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	u32 real_tbl_size;
	u16 qstart = k2u_ndev->g_qbase.start;
	u32 qcount = ndev->real_num_rx_queues;

	real_tbl_size = 4 * qcount;
	if (pdev_priv->nic_type->is_vf) {
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("rss redirect get mbox not support!\n");
			return;
		}
		cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)mbox_msg.data;
		cmd->cmd_type = YS_K2U_CMD_RSS_REDIRECT_GET;
		cmd->qstart = qstart;
		cmd->qnb = (u16)(qcount);
		mbox_msg.opcode = YS_MBOX_OPCODE_RSS_REDIRECT;
		ctx->type = MB_PF;
		if (!ys_mbox_send_msg(mbox, &mbox_msg, send_id,
				      MB_WAIT_REPLY, 1000, &ack_msg)) {
			ack_cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)
					   ack_msg.data;
			for (i = 0; i < real_tbl_size; i++)
				indir[i] = ack_cmd->cmd_data[i];
		}
	} else {
		for (i = 0; i < qcount; i++) {
			val = ys_rd32(hw_addr,
				      YS_K2U_RSS_REDIRECT_BASE + 4 * qstart + 4 * i);
			indir[j++] = val & 0xff;
			indir[j++] = (val >> 8) & 0xff;
			indir[j++] = (val >> 16) & 0xff;
			indir[j++] = (val >> 24) & 0xff;
		}
	}
}

void ys_k2u_rss_key_set(struct net_device *ndev, const u8 *key)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_mbox *mbox;
	struct ys_mbox_msg mbox_msg = {0};
	struct ys_k2u_mbox_rss_redirect_cmd *cmd;
	void __iomem *hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv);
	u32 send_id = 0;
	struct ys_k2u_mbox_ctx *ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	u16 qstart = k2u_ndev->g_qbase.start;
	u32 qcount = ndev->real_num_rx_queues;

	if (pdev_priv->nic_type->is_vf) {
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("rss key-set mbox not support!\n");
			return;
		}
		cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)mbox_msg.data;
		cmd->cmd_type = YS_K2U_CMD_RSS_REDIRECT_KEY_SET;
		cmd->qstart = qstart;
		cmd->qnb = (u16)(qcount);
		mbox_msg.opcode = YS_MBOX_OPCODE_RSS_REDIRECT;
		ctx->type = MB_PF;
		memcpy(cmd->cmd_data, key, YS_K2U_RSS_HASH_KEY_SIZE);
		ys_mbox_send_msg(mbox, &mbox_msg, pdev_priv->vf_id,
				 MB_NO_REPLY, 0, NULL);
	} else {
		ys_k2u_pf_hash_key_set(hw_addr, key);
	}
}

void ys_k2u_rss_key_get(struct net_device *ndev, u8 *key)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_mbox *mbox;
	struct ys_mbox_msg mbox_msg = {0}, ack_msg = {0};
	struct ys_k2u_mbox_rss_redirect_cmd *cmd, *ack_cmd;
	void __iomem *hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv);
	u32 send_id = 0;
	struct ys_k2u_mbox_ctx *ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	u16 qstart = k2u_ndev->g_qbase.start;
	u32 qcount = ndev->real_num_rx_queues;

	if (pdev_priv->nic_type->is_vf) {
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("rss key-get mbox not support!\n");
			return;
		}
		cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)mbox_msg.data;
		cmd->cmd_type = YS_K2U_CMD_RSS_REDIRECT_KEY_GET;
		cmd->qstart = qstart;
		cmd->qnb = (u16)(qcount);
		mbox_msg.opcode = YS_MBOX_OPCODE_RSS_REDIRECT;
		ctx->type = MB_PF;
		if (!ys_mbox_send_msg(mbox, &mbox_msg, send_id,
				      MB_WAIT_REPLY, 1000, &ack_msg)) {
			ack_cmd = (struct ys_k2u_mbox_rss_redirect_cmd *)
					   ack_msg.data;
			memcpy(key, ack_cmd->cmd_data, YS_K2U_RSS_HASH_KEY_SIZE);
		}
	} else {
		ys_k2u_pf_hash_key_get(hw_addr, key);
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

static void ys_k2u_rss_adjust_dynamic(struct timer_list *t)
{
	struct ys_k2u_ndev *k2u_ndev = container_of(t, struct ys_k2u_ndev, rss_redir_timer);
	struct net_device *ndev = k2u_ndev->ndev;
	struct ys_k2u_rss_redir_status *node;
	struct hlist_node *tmp;
	int bkt;
	u64 rxq_num = ndev->real_num_rx_queues;
	u64 rx_pkts_diff[YS_K2U_N_PF_MAXQNUM] = {0};
	u32 rss_redir_table[YS_K2U_N_RSS_REDIR_MAXQNUM] = {0};
	u64 rss_redir_pkts_diff[YS_K2U_N_RSS_REDIR_MAXQNUM] = {0};
	u64 pkts_total = 0, avg_pkts, threshold;
	u16 i, rxq_id;
	u16 max_q = 0, min_q = 0, diff_not_zero_num = 0;
	u64 max_load, min_load, pkts_now;
	u64 moved, can_move, need_to_move;
	bool rss_table_changed = false;
	bool node_find = false;

	mod_timer(&k2u_ndev->rss_redir_timer, jiffies + YS_K2U_RSS_REDIR_TIMER_PERIOD * HZ);

	if (!k2u_ndev->rss_redirect_dynamic_adjust || rxq_num <= 1)
		return;

	spin_lock(&rss_redir_adjust_lock);

	hash_for_each_safe(rss_redir_adjust_htable, bkt, tmp, node, hlist) {
		if (node->ifindex == ndev->ifindex) {
			node_find = true;
			break;
		}
	}

	if (!node_find) {
		spin_unlock(&rss_redir_adjust_lock);
		return;
	}

	for (i = 0; i < 4 * rxq_num; i++) {
		pkts_now = 0;
		for (rxq_id = 0; rxq_id < rxq_num; rxq_id++)
			pkts_now += READ_ONCE(k2u_ndev->qps[rxq_id]
					      .rxcq->stats_rss_redir
					      .num_rss_redir_idx[i]);
		rss_redir_pkts_diff[i] = pkts_now - node->rss_redir_pkts_last[i];
		if (rss_redir_pkts_diff[i])
			diff_not_zero_num++;
		node->rss_redir_pkts_last[i] = pkts_now;
	}
	spin_unlock(&rss_redir_adjust_lock);

	if (diff_not_zero_num <= rxq_num)
		return;

	ys_k2u_rss_redirect_table_get(ndev, rss_redir_table);
	for (i = 0; i < 4 * rxq_num; i++) {
		if (rss_redir_table[i] < rxq_num) {
			rx_pkts_diff[rss_redir_table[i]] += rss_redir_pkts_diff[i];
			pkts_total += rss_redir_pkts_diff[i];
		}
	}

	for (i = 0; i < 4 * rxq_num; i++) {
		if (rss_redir_pkts_diff[i] >= pkts_total / 2)
			return;
	}

	if (pkts_total == 0)
		return;

	/* calculate total load and average */
	avg_pkts = pkts_total / rxq_num;
	threshold = avg_pkts / 10;
	max_load = rx_pkts_diff[0];
	min_load = rx_pkts_diff[0];
	for (i = 1; i < rxq_num; i++) {
		if (rx_pkts_diff[i] > max_load) {
			max_load = rx_pkts_diff[i];
			max_q = i;
		}
		if (rx_pkts_diff[i] < min_load) {
			min_load = rx_pkts_diff[i];
			min_q = i;
		}
	}
	/* check if balancing is needed */
	if (max_load - min_load <= threshold || min_q == max_q)
		return;

	/* how many ptks to move */
	need_to_move = (max_load - min_load) / 2;
	/* Move at least 1 unit */
	if (need_to_move == 0)
		need_to_move = 1;

	/* reassign mappings */
	for (i = 0, moved = 0; i < 4 * rxq_num && moved < need_to_move; i++) {
		if (rss_redir_table[i] == max_q && rss_redir_pkts_diff[i] > 0) {
			can_move = rss_redir_pkts_diff[i];
			if (moved + can_move > need_to_move)
				can_move = need_to_move - moved;
			/* reassign to the lowest loaded queue */
			rss_redir_table[i] = min_q;
			rss_table_changed = true;
			moved += can_move;
		}
	}

	if (rss_table_changed)
		ys_k2u_rss_redirect_table_set(ndev, rss_redir_table);
}

void ys_k2u_rss_redir_timer_setup(struct ys_k2u_ndev *k2u_ndev)
{
	struct ys_k2u_rss_redir_status *node;
	struct net_device *ndev = k2u_ndev->ndev;
	u64 rxq_num = ndev->real_num_rx_queues;
	int i, rxq_id;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return;

	node->ifindex = ndev->ifindex;
	for (i = 0; i < 4 * rxq_num; i++) {
		for (rxq_id = 0; rxq_id < rxq_num; rxq_id++)
			node->rss_redir_pkts_last[i] += READ_ONCE(k2u_ndev->qps[rxq_id]
								  .rxcq->stats_rss_redir
								  .num_rss_redir_idx[i]);
	}
	spin_lock(&rss_redir_adjust_lock);
	hash_add(rss_redir_adjust_htable, &node->hlist, node->ifindex);
	spin_unlock(&rss_redir_adjust_lock);
	timer_setup(&k2u_ndev->rss_redir_timer, ys_k2u_rss_adjust_dynamic, 0);
	mod_timer(&k2u_ndev->rss_redir_timer, jiffies + YS_K2U_RSS_REDIR_TIMER_PERIOD * HZ);
}

void ys_k2u_rss_redir_timer_delete(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_k2u_rss_redir_status *node;
	struct hlist_node *tmp;
	int bkt;

	if (k2u_ndev->rss_redir_timer.function)
		del_timer_sync(&k2u_ndev->rss_redir_timer);

	spin_lock(&rss_redir_adjust_lock);
	hash_for_each_safe(rss_redir_adjust_htable, bkt, tmp, node, hlist) {
		if (node->ifindex == ndev->ifindex) {
			hash_del(&node->hlist);
			kfree(node);
			node = NULL;
		}
	}
	spin_unlock(&rss_redir_adjust_lock);
}

static u8 ys_k2u_rss_redir_adjust_get(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	return k2u_ndev->rss_redirect_dynamic_adjust;
}

static int ys_k2u_rss_redir_adjust_set(struct net_device *ndev, u8 enable)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	if (enable == k2u_ndev->rss_redirect_dynamic_adjust)
		return 0;

	if (enable && ndev->real_num_rx_queues == 1)
		return -EOPNOTSUPP;

	k2u_ndev->rss_redirect_dynamic_adjust = enable;
	if (enable)
		ys_k2u_rss_redir_timer_setup(k2u_ndev);
	else
		ys_k2u_rss_redir_timer_delete(ndev);
	return 0;
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
	k2u_ndev->rss_redirect_dynamic_adjust = 0;
	pdev_priv->ops->hw_adp_rss_redir_dynamic_adjust_get = ys_k2u_rss_redir_adjust_get;
	pdev_priv->ops->hw_adp_rss_redir_dynamic_adjust_set = ys_k2u_rss_redir_adjust_set;

	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(mbox))
		return;

#ifndef CONFIG_YSHW_K2ULTRA_U200
	mbox->mbox_vf_to_pf_set_rss_redirect = ys_k2u_mbox_rss_redirect_proc;
#endif
}
