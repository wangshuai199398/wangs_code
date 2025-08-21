// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_core.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_new_vfsf.h"
#include "ys_k2u_debugfs.h"
#include "ys_k2u_message.h"
#include "../../platform/ysif_linux.h"

static void *func_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	return NULL;
}

static void *func_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void func_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int func_debugfs_show(struct seq_file *seq, void *v)
{
	struct ys_k2u_new_func *func = seq->private;
	int i;
	struct ys_k2u_funcbase *fbase;
	struct ys_k2u_queuebase *qbase;
	u16 irqnum;

	if (v != SEQ_START_TOKEN)
		return 0;
	if (!func)
		return 0;

	/* 1. basic */
	seq_printf(seq, "\t%-16s : %-16d\n", "pf_id", func->pdev_priv->pf_id);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_id", func->pdev_priv->vf_id);
	seq_printf(seq, "\t%-16s : %-16d\n", "l qbase start", func->func_l_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "l qbase num", func->func_l_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "f qbase start", func->func_f_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "f qbase num", func->func_f_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "p qbase start", func->func_p_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "p qbase num", func->func_p_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "g qbase start", func->func_g_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "g qbase num", func->func_g_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "irq_user_max", func->pdev_priv->irq_table.user_max);
	seq_printf(seq, "\t%-16s : %-16d\n", "irq_max", func->pdev_priv->irq_table.max);

	/* 2. pf */
	if (func->pdev_priv->nic_type->is_vf)
		return 0;

	seq_printf(seq, "\t%-16s : %-16d\n", "dma_id", func->dma_id);
	seq_printf(seq, "\t%-16s : %-16d\n", "dma_inst", func->dma_inst);
	seq_printf(seq, "\t%-16s : %-16d\n", "dma_qmaxnum", func->dma_qmaxnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "dma_max_qsetnum", func->dma_max_qsetnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "dma_qset_offset", func->dma_qset_offset);
	seq_printf(seq, "\t%-16s : %-16d\n", "dma_qset_qmaxnum", func->dma_qset_qmaxnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "dma_irq_maxnum", func->dma_irq_maxnum);

	for (i = 0; i < YS_K2U_N_MAX_PF; i++) {
		fbase = &func->func_pf->pfx_fbase[i];
		if (fbase->top == 0 && fbase->base == 0)
			continue;
		seq_printf(seq, "\tpf%-d_%-12s : %-16d\n", i, "fbase", fbase->base);
		seq_printf(seq, "\tpf%-d_%-12s : %-16d\n", i, "ftop", fbase->top);
	}

	for (i = 0; i < YS_K2U_N_MAX_PF; i++) {
		qbase = &func->func_pf->pfx_qbase[i];
		if (qbase->start == 0 && qbase->num == 0)
			continue;
		seq_printf(seq, "\tpf%d_%-12s : %-16d\n", i, "qstart", qbase->start);
		seq_printf(seq, "\tpf%d_%-12s : %-16d\n", i, "qnum", qbase->num);
	}

	for (i = 0; i < YS_K2U_N_PF_MAX_FUNC; i++) {
		qbase = &func->func_pf->funcx_p_qbase[i];
		if (qbase->start == 0 && qbase->num == 0)
			continue;
		seq_printf(seq, "\tfunc%d_%-9s : %-16d\n", i, "qstart", qbase->start);
		seq_printf(seq, "\tfunc%d_%-9s : %-16d\n", i, "qnum", qbase->num);
	}

	for (i = 0; i < YS_K2U_N_PF_MAX_FUNC; i++) {
		qbase = &func->func_pf->funcx_g_qbase[i];
		if (qbase->start == 0 && qbase->num == 0)
			continue;
		seq_printf(seq, "\tfunc%d_%-9s : %-16d\n", i, "g_qstart", qbase->start);
		seq_printf(seq, "\tfunc%d_%-9s : %-16d\n", i, "g_qnum", qbase->num);
	}

	for (i = 0; i < YS_K2U_N_PF_MAX_FUNC; i++) {
		irqnum = func->func_pf->funcx_irqnum[i];
		if (irqnum == 0)
			continue;
		seq_printf(seq, "\tfunc%d_%-9s : %-16d\n", i, "irqnum", irqnum);
	}

	return 0;
}

static const struct seq_operations func_debugfs_sops = {
	.start = func_debugfs_start,
	.next = func_debugfs_next,
	.stop = func_debugfs_stop,
	.show = func_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(func_debugfs);

struct ys_k2u_queuebase
ys_k2u_func_get_qbase(struct ys_pdev_priv *pdev_priv, enum ys_k2u_queue_type type)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	struct ys_k2u_queuebase qbase = {0};

	switch (type) {
	case YS_K2U_QUEUE_LOCAL:
		qbase = func->func_l_qbase;
		break;
	case YS_K2U_QUEUE_FUNC:
		qbase = func->func_f_qbase;
		break;
	case YS_K2U_QUEUE_PF:
		qbase = func->func_p_qbase;
		break;
	case YS_K2U_QUEUE_GLOBAL:
		qbase = func->func_g_qbase;
		break;
	default:
		ys_dev_err("%s : invalid queue type %d\n", __func__, type);
		break;
	}
	return qbase;
}

void ys_k2u_func_set_qbase(struct ys_pdev_priv *pdev_priv, enum ys_k2u_queue_type type,
			   struct ys_k2u_queuebase qbase)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	switch (type) {
	case YS_K2U_QUEUE_LOCAL:
		func->func_l_qbase = qbase;
		break;
	case YS_K2U_QUEUE_FUNC:
		func->func_f_qbase = qbase;
		break;
	case YS_K2U_QUEUE_PF:
		func->func_p_qbase = qbase;
		break;
	case YS_K2U_QUEUE_GLOBAL:
		func->func_g_qbase = qbase;
		break;
	default:
		ys_dev_err("%s : invalid queue type %d\n", __func__, type);
		break;
	}
}

void ys_k2u_func_change_qnum(struct ys_pdev_priv *pdev_priv, u16 qnum, bool is_add)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	if (is_add) {
		func->func_l_qbase.num += qnum;
		func->func_f_qbase.num += qnum;
		func->func_p_qbase.num += qnum;
		func->func_g_qbase.num += qnum;
	} else {
		func->func_l_qbase.num -= qnum;
		func->func_f_qbase.num -= qnum;
		func->func_p_qbase.num -= qnum;
		func->func_g_qbase.num -= qnum;
	}
}

struct ys_k2u_queuebase
ys_k2u_func_get_funcx_qbase(struct ys_pdev_priv *pdev_priv, u16 func_id,
			    enum ys_k2u_queue_type type)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	struct ys_k2u_queuebase qbase = {0};

	if (pdev_priv->nic_type->is_vf)
		return qbase;

	switch (type) {
	case YS_K2U_QUEUE_PF:
		qbase = func->func_pf->funcx_p_qbase[func_id];
		break;
	case YS_K2U_QUEUE_GLOBAL:
		qbase = func->func_pf->funcx_g_qbase[func_id];
		break;
	default:
		ys_dev_err("%s : invalid queue type %d\n", __func__, type);
		break;
	}

	return qbase;
}

void ys_k2u_func_set_funcx_qbase(struct ys_pdev_priv *pdev_priv, u16 func_id,
				 enum ys_k2u_queue_type type, struct ys_k2u_queuebase qbase)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	u32 val;

	if (pdev_priv->nic_type->is_vf)
		return;

	switch (type) {
	case YS_K2U_QUEUE_PF:
		func->func_pf->funcx_p_qbase[func_id] = qbase;

		val = FIELD_PREP(YS_K2U_RE_DMA_FUNC_QSTART_GMASK, qbase.start);
		val |= FIELD_PREP(YS_K2U_RE_DMA_FUNC_QNUM_GMASK, qbase.num);

		ys_wr32(func->hw_dma_addr, YS_K2U_RE_DMA_FUNCX_QBASE(func_id), val);

		qbase.start = func->func_pf->pfx_qbase[pdev_priv->pf_id].start + qbase.start;
		func->func_pf->funcx_g_qbase[func_id] = qbase;
		break;
	default:
		ys_dev_err("%s : invalid queue type %d\n", __func__, type);
		break;
	}
}

void ys_k2u_func_change_funcx_qnum(struct ys_pdev_priv *pdev_priv, u16 func_id,
				   u16 qnum, bool is_add)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	u32 val;
	struct ys_k2u_queuebase qbase;

	if (pdev_priv->nic_type->is_vf)
		return;

	if (is_add) {
		func->func_pf->funcx_p_qbase[func_id].num += qnum;
		func->func_pf->funcx_g_qbase[func_id].num += qnum;
	} else {
		func->func_pf->funcx_p_qbase[func_id].num -= qnum;
		func->func_pf->funcx_g_qbase[func_id].num -= qnum;
	}

	qbase = func->func_pf->funcx_p_qbase[func_id];
	val = FIELD_PREP(YS_K2U_RE_DMA_FUNC_QSTART_GMASK, qbase.start);
	val |= FIELD_PREP(YS_K2U_RE_DMA_FUNC_QNUM_GMASK, qbase.num);

	ys_wr32(func->hw_dma_addr, YS_K2U_RE_DMA_FUNCX_QBASE(func_id), val);
}

static int
ys_k2u_func_get_qbase_remote(struct ys_pdev_priv *pdev_priv, enum ys_k2u_queue_type type,
			     struct ys_k2u_queuebase *qbase)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	int ret = 0;
	struct ys_k2u_msg_cmd req = {0};
	struct ys_k2u_msg_cmd rsp = {0};

	if (!pdev_priv->nic_type->is_vf) {
		switch (type) {
		case YS_K2U_QUEUE_LOCAL:
			*qbase = func->func_pf->funcx_p_qbase[pdev_priv->vf_id];
			qbase->start = 0;
			break;
		case YS_K2U_QUEUE_FUNC:
			*qbase = func->func_pf->funcx_p_qbase[pdev_priv->vf_id];
			qbase->start = 0;
			break;
		case YS_K2U_QUEUE_PF:
			*qbase = func->func_pf->funcx_p_qbase[pdev_priv->vf_id];
			break;
		case YS_K2U_QUEUE_GLOBAL:
			*qbase = func->func_pf->funcx_g_qbase[pdev_priv->vf_id];
			break;
		default:
			ret = -EINVAL;
			ys_dev_err("%s: invalid queue type %d\n", __func__, type);
			break;
		}

		return ret;
	}

	req.id = FUNC_GET_QBASE;
	switch (type) {
	case YS_K2U_QUEUE_LOCAL:
		req.func_qbase.req.type = YS_K2U_QUEUE_PF;
		break;
	case YS_K2U_QUEUE_FUNC:
		req.func_qbase.req.type = YS_K2U_QUEUE_PF;
		break;
	case YS_K2U_QUEUE_PF:
		req.func_qbase.req.type = YS_K2U_QUEUE_PF;
		break;
	case YS_K2U_QUEUE_GLOBAL:
		req.func_qbase.req.type = YS_K2U_QUEUE_GLOBAL;
		break;
	default:
		ret = -EINVAL;
		ys_dev_err("%s : invalid queue type %d\n", __func__, type);
		return ret;
	}

	ret = ys_k2u_msg_send(pdev_priv, &req, &rsp);
	if (ret) {
		ys_dev_err("%s : msg send failed, ret=%d\n", __func__, ret);
		return ret;
	}

	switch (type) {
	case YS_K2U_QUEUE_PF:
	case YS_K2U_QUEUE_GLOBAL:
		*qbase = rsp.func_qbase.rsp.qbase;
		break;
	default:
		*qbase = rsp.func_qbase.rsp.qbase;
		qbase->start = 0;
		break;
	}

	return ret;
}

u16 ys_k2u_func_get_irqnum(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	return func->func_irqnum;
}

void ys_k2u_func_set_irqnum(struct ys_pdev_priv *pdev_priv, u16 irqnum)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	func->func_irqnum = irqnum;
}

void ys_k2u_func_change_irqnum(struct ys_pdev_priv *pdev_priv, u16 irqnum, bool is_add)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	if (is_add)
		func->func_irqnum += irqnum;
	else
		func->func_irqnum -= irqnum;
}

u16 ys_k2u_func_get_funcx_irqnum(struct ys_pdev_priv *pdev_priv, u16 func_id)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	return func->func_pf->funcx_irqnum[func_id];
}

void ys_k2u_func_set_funcx_irqnum(struct ys_pdev_priv *pdev_priv, u16 func_id, u16 irqnum)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	u32 val;

	if (pdev_priv->nic_type->is_vf)
		return;

	func->func_pf->funcx_irqnum[func_id] = irqnum;

	val = FIELD_PREP(YS_K2U_RP_VFX_IRQNUM_GMASK, irqnum);
	ys_wr32(func->hw_dma_addr, YS_K2U_RP_VFX_IRQNUM(func_id), val);
}

void ys_k2u_func_change_funcx_irqnum(struct ys_pdev_priv *pdev_priv, u16 func_id,
				     u16 irqnum, bool is_add)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	u32 val;

	if (pdev_priv->nic_type->is_vf)
		return;

	if (is_add)
		func->func_pf->funcx_irqnum[func_id] += irqnum;
	else
		func->func_pf->funcx_irqnum[func_id] -= irqnum;

	irqnum = func->func_pf->funcx_irqnum[func_id];
	val = FIELD_PREP(YS_K2U_RP_VFX_IRQNUM_GMASK, irqnum);
	ys_wr32(func->hw_dma_addr, YS_K2U_RP_VFX_IRQNUM(func_id), val);
}

static int ys_k2u_func_get_irqnum_remote(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	int ret = 0;
	struct ys_k2u_msg_cmd req = {0};
	struct ys_k2u_msg_cmd rsp = {0};

	if (!pdev_priv->nic_type->is_vf)
		return func->func_pf->funcx_irqnum[pdev_priv->vf_id];

	req.id = FUNC_GET_IRQNUM;

	ret = ys_k2u_msg_send(pdev_priv, &req, &rsp);
	if (ret) {
		ys_dev_err("%s: msg send failed, ret=%d\n", __func__, ret);
		return ret;
	}

	return rsp.func_irqnum.rsp.irqnum;
}

u16 ys_k2u_func_get_vfnum(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	struct ys_k2u_funcbase *fbase;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	fbase = &func->func_pf->pfx_fbase[pdev_priv->pf_id];

	return fbase->top - fbase->base;
}

int ys_k2u_pdev_get_init_qbase(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	return func->func_p_qbase.start;
}

int ys_k2u_pdev_get_init_qnum(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;
	u16 qnum = ys_k2u_vfsf_get_minqnum(pdev_priv, YS_K2U_NDEV_PF);

	if (qnum)
		qnum = min_t(u16, qnum, func->func_l_qbase.num);
	else
		qnum = func->func_l_qbase.num;

	if (pdev_priv->nic_type->is_vf)
		return min_t(u16, qnum, YS_K2U_N_VF_MAXQNUM);
	else
		return min_t(u16, qnum, YS_K2U_N_PF_MAXQNUM);
}

int ys_k2u_pdev_func_init(struct ys_pdev_priv *pdev_priv)
{
	struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_new_func *func;
	void __iomem *hw_addr;
	size_t size;
	u32 val;
	int i;
	struct ys_k2u_funcbase *fbase;
	struct ys_k2u_queuebase *qbase_ptr;
	struct ys_k2u_queuebase *qbase_ptr2;
	struct ys_k2u_queuebase pf_qbase;
	struct ys_k2u_queuebase tmp_qbase;
	char name[32];
	int ret;

	hw_addr = pdev_priv->bar_addr[0];

	if (pdev_priv->nic_type->is_vf)
		size = sizeof(struct ys_k2u_new_func);
	else
		size = sizeof(struct ys_k2u_new_func) + sizeof(struct ys_k2u_func_pf);
	func = kzalloc(size, GFP_KERNEL);
	if (!func)
		return -ENOMEM;

	pdev_priv->padp_priv = func;

	func->pdev = pdev_priv->pdev;
	func->pdev_priv = pdev_priv;
	func->hw_addr = hw_addr;
	func->hw_dma_addr = func->hw_addr + YS_K2U_RE_DMA_BASE;

	func->dma_id = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_ID);
	func->dma_inst = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_INST);
	func->dma_qmaxnum = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_QNUM);
	func->dma_max_qsetnum = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_QSETNUM);

	/* bug : will delete */
	func->dma_max_qsetnum = 256;

	val = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_QSET_OFFSET);
	func->dma_qset_offset = FIELD_GET(YS_K2U_RE_DMA_QSET_OFFSET_GMASK, val);
	func->dma_qset_qmaxnum = FIELD_GET(YS_K2U_RE_DMA_QSET_QMAXNUM_GMASK, val);
	func->dma_qset_qmaxnum = (1 << func->dma_qset_qmaxnum) - 1;

	val = ys_rd32(func->hw_dma_addr, YS_K2U_RP_VFX_IRQNUM(pdev_priv->vf_id));
	func->dma_irq_maxnum = FIELD_GET(YS_K2U_RP_VFX_IRQNUM_GMASK, val);

	if (!pdev_priv->nic_type->is_vf) {
		for (i = 0; i < YS_K2U_N_MAX_PF; i++) {
			val = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_PFX_FNUM(i));
			fbase = &func->func_pf->pfx_fbase[i];
			fbase->top = FIELD_GET(YS_K2U_RE_DMA_PF_FTOP_GMASK, val);
			fbase->base = FIELD_GET(YS_K2U_RE_DMA_PF_FBASE_GMASK, val);
		}

		for (i = 0; i < YS_K2U_N_MAX_PF; i++) {
			val = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_PFX_QBASE(i));
			qbase_ptr = &func->func_pf->pfx_qbase[i];
			qbase_ptr->start = FIELD_GET(YS_K2U_RE_DMA_PF_QSTART_GMASK, val);
			qbase_ptr->num = FIELD_GET(YS_K2U_RE_DMA_PF_QNUM_GMASK, val);
		}

		pf_qbase.start = func->func_pf->pfx_qbase[pdev_priv->pf_id].start;
		for (i = 0; i < YS_K2U_N_PF_MAX_FUNC; i++) {
			val = ys_rd32(func->hw_dma_addr, YS_K2U_RE_DMA_FUNCX_QBASE(i));
			if (ys_k2u_reg_err(val))
				continue;
			qbase_ptr = &func->func_pf->funcx_p_qbase[i];
			qbase_ptr->start = FIELD_GET(YS_K2U_RE_DMA_FUNC_QSTART_GMASK, val);
			qbase_ptr->num = FIELD_GET(YS_K2U_RE_DMA_FUNC_QNUM_GMASK, val);

			if (qbase_ptr->start || qbase_ptr->num) {
				qbase_ptr2 = &func->func_pf->funcx_g_qbase[i];
				qbase_ptr2->start = qbase_ptr->start + pf_qbase.start;
				qbase_ptr2->num = qbase_ptr->num;
			}
		}

		for (i = 0; i < YS_K2U_N_PF_MAX_FUNC; i++) {
			val = ys_rd32(func->hw_dma_addr, YS_K2U_RP_VFX_IRQNUM(i));
			if (ys_k2u_reg_err(val))
				continue;
			func->func_pf->funcx_irqnum[i] = FIELD_GET(YS_K2U_RP_VFX_IRQNUM_GMASK, val);
		}

		tmp_qbase = func->func_pf->pfx_qbase[pdev_priv->pf_id];
		tmp_qbase.start = 0;

		ys_k2u_func_set_funcx_qbase(pdev_priv, 0, YS_K2U_QUEUE_PF, tmp_qbase);

		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_LOCAL, tmp_qbase);
		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_FUNC, tmp_qbase);
		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_PF, tmp_qbase);

		tmp_qbase = func->func_pf->pfx_qbase[pdev_priv->pf_id];
		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_GLOBAL, tmp_qbase);

		ys_k2u_func_set_irqnum(pdev_priv, func->func_pf->funcx_irqnum[0]);
	} else {
		ret = ys_k2u_func_get_qbase_remote(pdev_priv, YS_K2U_QUEUE_LOCAL, &tmp_qbase);
		if (ret) {
			ys_dev_err("get qbase remote YS_K2U_QUEUE_LOCAL failed\n");
			return ret;
		}
		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_LOCAL, tmp_qbase);

		ret = ys_k2u_func_get_qbase_remote(pdev_priv, YS_K2U_QUEUE_FUNC, &tmp_qbase);
		if (ret) {
			ys_dev_err("get qbase remote YS_K2U_QUEUE_FUNC failed\n");
			return ret;
		}
		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_FUNC, tmp_qbase);

		ret = ys_k2u_func_get_qbase_remote(pdev_priv, YS_K2U_QUEUE_PF, &tmp_qbase);
		if (ret) {
			ys_dev_err("get qbase remote YS_K2U_QUEUE_PF failed\n");
			return ret;
		}
		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_PF, tmp_qbase);

		ret = ys_k2u_func_get_qbase_remote(pdev_priv, YS_K2U_QUEUE_GLOBAL, &tmp_qbase);
		if (ret) {
			ys_dev_err("get qbase remote YS_K2U_QUEUE_GLOBAL failed\n");
			return ret;
		}
		ys_k2u_func_set_qbase(pdev_priv, YS_K2U_QUEUE_GLOBAL, tmp_qbase);

		ret = ys_k2u_func_get_irqnum_remote(pdev_priv);
		if (ret <= 0) {
			ys_dev_err("get irqnum remote failed\n");
			return ret;
		}
		ys_k2u_func_set_irqnum(pdev_priv, (u16)ret);
	}

	tmp_qbase = ys_k2u_func_get_qbase(pdev_priv, YS_K2U_QUEUE_GLOBAL);
	if (!tmp_qbase.num) {
		ys_dev_err("no queue and check firmware\n");
		return -EINVAL;
	}

	ret = ys_k2u_func_get_irqnum(pdev_priv);
	if (ret <= 0) {
		ys_dev_err("no irq and check firmware\n");
		return -EINVAL;
	}

	ys_k2u_debugfs_init(pdev_priv, &func->debugfs_root);

	if (func->debugfs_root) {
		snprintf(name, sizeof(name), "info");
		func->debugfs_info_file = ops->debugfs_create_file(name, 0400, func->debugfs_root, func,
							      &func_debugfs_fops);
		if (IS_ERR(func->debugfs_info_file))
			ys_dev_err("func_info debugfs file create failed");
	}

	return 0;
}

void ys_k2u_pdev_func_uninit(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_new_func *func = pdev_priv->padp_priv;

	if (!func)
		return;

	debugfs_remove(func->debugfs_info_file);
	debugfs_remove_recursive(func->debugfs_root);

	kfree(func);
	pdev_priv->padp_priv = NULL;
}
