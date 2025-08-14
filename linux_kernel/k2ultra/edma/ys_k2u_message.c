// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_base.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_new_qset.h"

#include "ys_k2u_message.h"
#include "../mbox/ys_k2u_mbox.h"

static void ys_k2u_message_handler(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 msg_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_k2u_mbox_ctx *ctx = (struct ys_k2u_mbox_ctx *)(&msg_id);
	struct ys_mbox_msg ack_msg = {0};
	struct ys_k2u_msg_cmd *req, *rsp;
	u16 vf_id;
	struct ys_k2u_queuebase qbase;
	enum ys_k2u_queue_type qtype;
	u16 irqnum;
	struct ys_vf_info *vf_info;

	req = (struct ys_k2u_msg_cmd *)msg->data;
	rsp = (struct ys_k2u_msg_cmd *)ack_msg.data;
	rsp->id = req->id;
	vf_id = ctx->func_id;

	switch (req->id) {
	case FUNC_GET_QBASE:
		qtype = req->func_qbase.req.type;
		qbase = ys_k2u_func_get_funcx_qbase(pdev_priv, vf_id + 1, qtype);
		rsp->func_qbase.rsp.qbase = qbase;
		break;
	case FUNC_GET_IRQNUM:
		irqnum = ys_k2u_func_get_funcx_irqnum(pdev_priv, vf_id + 1);
		rsp->func_irqnum.rsp.irqnum = irqnum;
		break;
	case QSET_ALLOC:
		vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
		rsp->qset_alloc.rsp.qsetid = vf_info->qset;
		break;
	case QSET_FREE:
		return;
	case QSET_START:
		qtype = YS_K2U_QUEUE_GLOBAL;
		qbase = ys_k2u_func_get_funcx_qbase(pdev_priv, vf_id + 1, qtype);
		qbase.num = min_t(u16, req->qset_start.req.rxqbase.num, qbase.num);
		ys_k2u_qset_set_qset2q(pdev_priv, req->qset_start.req.qsetid, &qbase);

		qbase = ys_k2u_func_get_funcx_qbase(pdev_priv, vf_id + 1, qtype);
		qbase.num = min_t(u16, req->qset_start.req.txqbase.num, qbase.num);
		ys_k2u_qset_set_q2qset(pdev_priv, req->qset_start.req.qsetid, &qbase);
		return;
	case QSET_STOP:
		qtype = YS_K2U_QUEUE_GLOBAL;
		qbase = ys_k2u_func_get_funcx_qbase(pdev_priv, vf_id + 1, qtype);

		ys_k2u_qset_set_qset2q(pdev_priv, req->qset_stop.req.qsetid, NULL);
		ys_k2u_qset_set_q2qset(pdev_priv, 0, &qbase);
		return;
	default:
		ys_dev_err("unknown message id %d\n", req->id);
		return;
	}

	ack_msg.opcode = msg->opcode | (1 << YS_MBOX_OPCODE_MASK_ACK);
	ack_msg.seqno = msg->seqno;

	ys_mbox_send_msg(mbox, &ack_msg, msg_id, MB_NO_REPLY, 0, NULL);
}

int ys_k2u_msg_send(struct ys_pdev_priv *pdev_priv, struct ys_k2u_msg_cmd *req,
		    struct ys_k2u_msg_cmd *rsp)
{
	u32 send_id = 0;
	struct ys_k2u_mbox_ctx *ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	struct ys_mbox *mbox;
	struct ys_mbox_msg req_msg = {0};
	struct ys_mbox_msg rsp_msg = {0};
	int ret;
	enum ys_mbox_mode reply;

	if (!pdev_priv->nic_type->is_vf) {
		ys_dev_err("edma send msg pf not support");
		return -EOPNOTSUPP;
	}

	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (!mbox) {
		ys_dev_err("edma send msg mbox not found");
		return -ENODEV;
	}

	ctx->func_id = 0;
	ctx->type = MB_PF;

	req_msg.opcode = YS_MBOX_OPCODE_GET_QSET;
	memcpy(req_msg.data, req, sizeof(struct ys_k2u_msg_cmd));

	reply = rsp ? MB_WAIT_REPLY : MB_NO_REPLY;
	ret = ys_mbox_send_msg(mbox, &req_msg, send_id, reply, 1000, &rsp_msg);
	if (ret) {
		ys_dev_err("edma send msg failed, ret %d", ret);
		return ret;
	}

	if (rsp)
		memcpy(rsp, rsp_msg.data, sizeof(struct ys_k2u_msg_cmd));

	return ret;
}

int ys_k2u_message_init(struct ys_ndev_priv *ndev_priv)
{
	struct ys_mbox *mbox;

	if (!(ndev_priv->adev_type & AUX_TYPE_ETH))
		return 0;

	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	if (!mbox) {
		ys_net_err("%s mbox not found", __func__);
		return -ENODEV;
	}

	mbox->mbox_vf_to_pf_get_qset = ys_k2u_message_handler;
	return 0;
}

void ys_k2u_message_uninit(struct ys_ndev_priv *ndev_priv)
{
}
