// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_core.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_debugfs.h"
#include "ys_k2u_new_ndev.h"
#include "ys_k2u_new_vfsf.h"
#include "ys_k2u_new_qset.h"
#include "ys_k2u_message.h"
#include "../../platform/ysif_linux.h"

struct ys_k2u_qset_manager {
	struct idr idr;
	struct idr rep_idr;
	spinlock_t idr_slock;	/* for idr */
	u16 idr_start;
	u16 idr_end;
	u16 rep_idr_start;
	u16 rep_idr_end;
	refcount_t refcnt;
	struct ys_pdev_priv *pdev_priv[9];
};

static DEFINE_IDR(ys_k2u_qset_manager_idr);

static int k2u_qsetid_alloc(struct ys_pdev_priv *pdev_priv, enum ys_k2u_ndev_type type)
{
	int card_id;
	struct ys_k2u_qset_manager *qset_mgr;
	int ret;

	if (type == YS_K2U_NDEV_UPLINK)
		return pdev_priv->pf_id;

	card_id = pdev_priv->pdev->bus->number;
	qset_mgr = idr_find(&ys_k2u_qset_manager_idr, card_id);
	if (!qset_mgr) {
		ys_dev_err("k2u: qset manager not found");
		return -ENODEV;
	}

	spin_lock(&qset_mgr->idr_slock);
	if (pdev_priv->dpu_mode == MODE_SMART_NIC && type == YS_K2U_NDEV_REP)
		ret = idr_alloc(&qset_mgr->rep_idr, qset_mgr, qset_mgr->rep_idr_start,
				qset_mgr->rep_idr_end, GFP_ATOMIC);
	else
		ret = idr_alloc(&qset_mgr->idr, qset_mgr, qset_mgr->idr_start,
				qset_mgr->idr_end, GFP_ATOMIC);
	spin_unlock(&qset_mgr->idr_slock);
	if (ret < 0) {
		ys_dev_err("k2u: failed to allocate qset id");
		return ret;
	}

	return ret;
}

static void k2u_qsetid_free(struct ys_pdev_priv *pdev_priv, u16 qset_id)
{
	int card_id;
	struct ys_k2u_qset_manager *qset_mgr;

	card_id = pdev_priv->pdev->bus->number;
	qset_mgr = idr_find(&ys_k2u_qset_manager_idr, card_id);
	if (!qset_mgr) {
		ys_dev_err("k2u: qset manager not found");
		return;
	}

	spin_lock(&qset_mgr->idr_slock);
	if (idr_find(&qset_mgr->idr, qset_id))
		idr_remove(&qset_mgr->idr, qset_id);
	else if (idr_find(&qset_mgr->rep_idr, qset_id))
		idr_remove(&qset_mgr->rep_idr, qset_id);
	spin_unlock(&qset_mgr->idr_slock);
}

int ys_k2u_qsetid_alloc(struct ys_pdev_priv *pdev_priv, enum ys_k2u_ndev_type type,
			u16 *qsetid, u16 num)
{
	int i;
	int ret;

	for (i = 0; i < num; i++) {
		ret = k2u_qsetid_alloc(pdev_priv, type);
		if (ret < 0) {
			ys_dev_err("k2u: failed to allocate qset id");
			break;
		}
		qsetid[i] = (u16)ret;
	}

	if (i < num)
		goto failed;

	return 0;

failed:
	for (; i > 0; i--)
		k2u_qsetid_free(pdev_priv, qsetid[i - 1]);

	return -ENOMEM;
}

void ys_k2u_qsetid_free(struct ys_pdev_priv *pdev_priv, u16 *qsetid, u16 num)
{
	int i;

	for (i = 0; i < num; i++)
		k2u_qsetid_free(pdev_priv, qsetid[i]);
}

struct ys_k2u_qset *
ys_k2u_qset_alloc(struct ys_pdev_priv *pdev_priv, struct ys_ndev_priv *ndev_priv)
{
	struct ys_k2u_qset *qset;
	int ret;
	struct ys_adev *adev;
	struct ys_k2u_msg_cmd req = {0};
	struct ys_k2u_msg_cmd rsp = {0};

	qset = kzalloc(sizeof(*qset), GFP_KERNEL);
	if (!qset)
		return NULL;

	qset->pdev_priv = pdev_priv;
	qset->ndev_priv = ndev_priv;

	/* alloc id from mbox */
	if (!pdev_priv->nic_type->is_vf) {
		adev = ys_aux_get_adev(ndev_priv->pdev, ndev_priv->adev_type, ndev_priv->ndev);
		if (!adev) {
			ys_dev_err("k2u: adev not found");
			kfree(qset);
			return NULL;
		}

		if (adev->adev_type == AUX_TYPE_ETH)
			ret = k2u_qsetid_alloc(pdev_priv, YS_K2U_NDEV_PF);
		else if (adev->adev_type == AUX_TYPE_SF)
			ret = k2u_qsetid_alloc(pdev_priv, YS_K2U_NDEV_SF);
		else if (adev->adev_type == AUX_TYPE_REP && adev->idx == YS_K2U_ID_NDEV_UPLINK)
			ret = k2u_qsetid_alloc(pdev_priv, YS_K2U_NDEV_UPLINK);
		else
			ret = k2u_qsetid_alloc(pdev_priv, YS_K2U_NDEV_REP);

		if (ret < 0) {
			ys_dev_err("k2u: failed to allocate qset id");
			kfree(qset);
			return NULL;
		}

		qset->id = (u16)ret;
	} else {
		req.id = QSET_ALLOC;

		ret = ys_k2u_msg_send(pdev_priv, &req, &rsp);
		if (ret < 0) {
			ys_dev_err("k2u: failed to allocate qset id");
			kfree(qset);
			return NULL;
		}

		qset->id = rsp.qset_alloc.rsp.qsetid;
	}

	return qset;
}

void ys_k2u_qset_free(struct ys_k2u_qset *qset)
{
	struct ys_pdev_priv *pdev_priv;
	int ret = 0;
	struct ys_k2u_msg_cmd req = {0};

	if (!qset)
		return;

	pdev_priv = qset->pdev_priv;

	if (!pdev_priv->nic_type->is_vf) {
		k2u_qsetid_free(qset->pdev_priv, qset->id);
	} else {
		req.id = QSET_FREE;
		req.qset_free.req.qsetid = qset->id;
		ret = ys_k2u_msg_send(qset->pdev_priv, &req, NULL);
		if (ret < 0)
			ys_dev_err("k2u: failed to free qset id %d", qset->id);
	}

	kfree(qset);
}

void ys_k2u_qset_set_qset2q(struct ys_pdev_priv *pdev_priv, u16 qset_id,
			    struct ys_k2u_queuebase *qbase)
{
	u32 val = 0;

	if (qbase) {
		val = FIELD_PREP(YS_K2U_RE_QSET2Q_QSTART_GMASK, qbase->start);
		val |= FIELD_PREP(YS_K2U_RE_QSET2Q_QNUM_GMASK, qbase->num);
	}

	if (qbase && qbase->num != 0)
		val |= FIELD_PREP(YS_K2U_RE_QSET2Q_VALID_GMASK, 1)
		       | YS_K2U_RE_QSET2Q_RSS_REDIRECT_EN;
	else
		val |= FIELD_PREP(YS_K2U_RE_QSET2Q_VALID_GMASK, 0);

	ys_wr32(ys_k2u_func_get_hwaddr(pdev_priv), YS_K2U_RE_QSET2Q(qset_id), val);
}

void ys_k2u_qset_set_q2qset(struct ys_pdev_priv *pdev_priv, u16 qset_id,
			    struct ys_k2u_queuebase *qbase)
{
	u32 val;
	u16 i;

	for (i = qbase->start; i < (qbase->start + qbase->num); i++) {
		val = FIELD_PREP(YS_K2U_RE_Q2QSET_QSETID_GMASK, qset_id);
		ys_wr32(ys_k2u_func_get_hwaddr(pdev_priv), YS_K2U_RE_Q2QSET(i), val);
	}
}

int ys_k2u_qset_start(struct ys_k2u_qset *qset, u16 txqnum, u16 rxqnum)
{
	struct ys_pdev_priv *pdev_priv = qset->pdev_priv;
	struct ys_k2u_queuebase qbase;
	int ret = 0;
	struct ys_k2u_msg_cmd req = {0};

	if (!pdev_priv->nic_type->is_vf) {
		qbase = ys_k2u_ndev_get_qbase(qset->ndev_priv, YS_K2U_QUEUE_GLOBAL);
		qbase.num = min_t(u16, qbase.num, rxqnum);
		ys_k2u_qset_set_qset2q(pdev_priv, qset->id, &qbase);

		qbase = ys_k2u_ndev_get_qbase(qset->ndev_priv, YS_K2U_QUEUE_GLOBAL);
		qbase.num = min_t(u16, qbase.num, txqnum);
		ys_k2u_qset_set_q2qset(pdev_priv, qset->id, &qbase);
	} else {
		req.id = QSET_START;
		req.qset_start.req.qsetid = qset->id;
		req.qset_start.req.rxqbase.num = rxqnum;
		req.qset_start.req.txqbase.num = txqnum;

		ret = ys_k2u_msg_send(pdev_priv, &req, NULL);
		if (ret < 0)
			ys_dev_err("k2u: failed to start qset %d", qset->id);
	}

	return ret;
}

void ys_k2u_qset_stop(struct ys_k2u_qset *qset)
{
	struct ys_pdev_priv *pdev_priv = qset->pdev_priv;
	struct net_device *ndev = qset->ndev_priv->ndev;
	struct ys_k2u_queuebase qbase;
	int ret;
	struct ys_k2u_msg_cmd req = {0};

	if (!pdev_priv->nic_type->is_vf) {
		qbase = ys_k2u_ndev_get_qbase(qset->ndev_priv, YS_K2U_QUEUE_GLOBAL);
		qbase.num = ndev->real_num_tx_queues;

		ys_k2u_qset_set_qset2q(pdev_priv, qset->id, NULL);
		ys_k2u_qset_set_q2qset(pdev_priv, 0, &qbase);
	} else {
		req.id = QSET_STOP;
		req.qset_stop.req.qsetid = qset->id;
		req.qset_start.req.txqbase.num = ndev->real_num_tx_queues;

		ret = ys_k2u_msg_send(pdev_priv, &req, NULL);
		if (ret < 0)
			ys_dev_err("k2u: failed to stop qset %d", qset->id);
	}
}

int ys_k2u_pdev_qset_init(struct ys_pdev_priv *pdev_priv)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_qset_manager *qset_mgr;
	struct ys_k2u_new_func *func;
	int ret;
	int card_id;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	card_id = pdev_priv->pdev->bus->number;
	qset_mgr = ops->idr_find(&ys_k2u_qset_manager_idr, card_id);
	if (qset_mgr) {
		qset_mgr->pdev_priv[pdev_priv->pf_id] = pdev_priv;
		ops->refcount_inc(&qset_mgr->refcnt);
		return 0;
	}

	qset_mgr = kzalloc(sizeof(*qset_mgr), GFP_KERNEL);
	if (!qset_mgr)
		return -ENOMEM;

	ops->yspin_lock_init(&qset_mgr->idr_slock);
	ops->idr_init(&qset_mgr->idr);
	ops->idr_init(&qset_mgr->rep_idr);

	func = ys_k2u_func_get_priv(pdev_priv);

	if (pdev_priv->dpu_mode == MODE_SMART_NIC) {
		qset_mgr->rep_idr_start = func->dma_qset_offset ?: YS_K2U_N_MAX_PF;
		qset_mgr->rep_idr_end = func->dma_qset_offset + func->dma_max_qsetnum / 2 - 1;
		qset_mgr->idr_start = qset_mgr->rep_idr_end + 1;
		qset_mgr->idr_end = func->dma_qset_offset + func->dma_max_qsetnum - 1;

		ys_dev_debug("k2u: qset repidr start %d to end %d", qset_mgr->rep_idr_start,
			    qset_mgr->rep_idr_end);
	} else {
		qset_mgr->idr_start = func->dma_qset_offset ?: YS_K2U_N_MAX_PF;
		qset_mgr->idr_end = func->dma_qset_offset + func->dma_max_qsetnum - 1;
	}
	ys_dev_debug("k2u: qset idr start %d to end %d", qset_mgr->idr_start, qset_mgr->idr_end);

	ops->refcount_set(&qset_mgr->refcnt, 1);
	qset_mgr->pdev_priv[pdev_priv->pf_id] = pdev_priv;

	ret = ops->idr_alloc(&ys_k2u_qset_manager_idr, qset_mgr, card_id, card_id + 1, GFP_ATOMIC);
	if (ret < 0) {
		ys_dev_err("k2u: failed to allocate qset manager idr");
		kfree(qset_mgr);
		return ret;
	}

	ys_dev_debug("qset manage id start %d to end %d", qset_mgr->idr_start, qset_mgr->idr_end);

	return 0;
}

void ys_k2u_pdev_qset_uninit(struct ys_pdev_priv *pdev_priv)
{
	int card_id;
	struct ys_k2u_qset_manager *qset_mgr;

	if (pdev_priv->nic_type->is_vf)
		return;

	card_id = pdev_priv->pdev->bus->number;
	qset_mgr = idr_find(&ys_k2u_qset_manager_idr, card_id);
	if (!qset_mgr)
		return;

	if (!qset_mgr->pdev_priv[pdev_priv->pf_id])
		return;

	if (refcount_dec_and_test(&qset_mgr->refcnt)) {
		idr_remove(&ys_k2u_qset_manager_idr, card_id);
		kfree(qset_mgr);
	}
}
