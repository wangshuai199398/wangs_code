// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_core.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_debugfs.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_new_vfsf.h"
#include "ys_k2u_new_qset.h"

struct ys_k2u_vfsf_priv {
	struct ys_pdev_priv *pdev_priv;
	/* pf */
	u16 pf_qnum;
	u16 pf_irqnum;
	u16 uplink_qnum;
	/* vf */
	u16 vf_maxnum;
	u16 vf_curnum;

	u16 vf_maxqnum;
	u16 vf_minqnum;
	u16 vf_curqnum;

	u16 vf_max_irqnum;
	u16 vf_min_irqnum;
	u16 vf_cur_irqnum;
	/* rep */
	u16 rep_maxqnum;
	u16 rep_minqnum;
	/* sf */
	u16 sf_maxnum;
	u16 sf_curnum;

	u16 sf_maxqnum;
	u16 sf_minqnum;

	u16 irq_ratio;

	u16 vfx_qsetid[YS_K2U_N_MAX_VF];
	struct ys_k2u_queuebase vfx_qbase[YS_K2U_N_MAX_VF];
	struct dentry *debugfs_vfsf_file;
};

/* debug */
static void *vfsf_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	return NULL;
}

static void *vfsf_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void vfsf_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int vfsf_debugfs_show(struct seq_file *seq, void *v)
{
	struct ys_k2u_vfsf_priv *vfsf_priv = seq->private;
	int i;
	struct ys_k2u_queuebase *qbase;

	if (v != SEQ_START_TOKEN)
		return 0;

	/* pf */
	seq_printf(seq, "\t%-16s : %-16d\n", "pf_qnum", vfsf_priv->pf_qnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "pf_irqnum", vfsf_priv->pf_irqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "uplink_qnum", vfsf_priv->uplink_qnum);

	/* vf */
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_maxnum", vfsf_priv->vf_maxnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_curnum", vfsf_priv->vf_curnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_maxqnum", vfsf_priv->vf_maxqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_minqnum", vfsf_priv->vf_minqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_curqnum", vfsf_priv->vf_curqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_max_irqnum", vfsf_priv->vf_max_irqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_min_irqnum", vfsf_priv->vf_min_irqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "vf_cur_irqnum", vfsf_priv->vf_cur_irqnum);

	/* rep */
	seq_printf(seq, "\t%-16s : %-16d\n", "rep_maxqnum", vfsf_priv->rep_maxqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "rep_minqnum", vfsf_priv->rep_minqnum);

	/* sf */
	seq_printf(seq, "\t%-16s : %-16d\n", "sf_maxnum", vfsf_priv->sf_maxnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "sf_curnum", vfsf_priv->sf_curnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "sf_maxqnum", vfsf_priv->sf_maxqnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "sf_minqnum", vfsf_priv->sf_minqnum);

	/* vf qset */
	for (i = 0; i < vfsf_priv->vf_curnum; i++) {
		if (!vfsf_priv->vfx_qsetid[i])
			continue;
		seq_printf(seq, "\tvf%d_%-12s : %-16d\n", i, "qsetid", vfsf_priv->vfx_qsetid[i]);
	}

	for (i = 0; i < vfsf_priv->vf_curnum; i++) {
		qbase = &vfsf_priv->vfx_qbase[i];
		if (!qbase->start && !qbase->num)
			continue;
		seq_printf(seq, "\tvf%d_%-12s : %-16d\n", i, "start", qbase->start);
		seq_printf(seq, "\tvf%d_%-12s : %-16d\n", i, "num", qbase->num);
	}

	return 0;
}

static const struct seq_operations vfsf_debugfs_sops = {
	.start = vfsf_debugfs_start,
	.next = vfsf_debugfs_next,
	.stop = vfsf_debugfs_stop,
	.show = vfsf_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(vfsf_debugfs);

static struct ys_k2u_vfsf_priv *ys_k2u_vfsf_get_priv(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_new_func *func = ys_k2u_func_get_priv(pdev_priv);

	if (!func)
		return NULL;

	return func->vfsf_priv;
}

void ys_k2u_vfsf_set_qsetid(struct ys_pdev_priv *pdev_priv, u16 vf_idx, u16 qsetid)
{
	struct ys_k2u_vfsf_priv *vfsf_priv;

	if (pdev_priv->nic_type->is_vf)
		return;

	vfsf_priv = ys_k2u_vfsf_get_priv(pdev_priv);
	if (vfsf_priv)
		vfsf_priv->vfx_qsetid[vf_idx] = qsetid;
}

u16 ys_k2u_vfsf_get_qsetid(struct ys_pdev_priv *pdev_priv, u16 vf_idx)
{
	struct ys_k2u_vfsf_priv *vfsf_priv;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	vfsf_priv = ys_k2u_vfsf_get_priv(pdev_priv);
	/* TODO: Is it good to return 0? */
	if (!vfsf_priv)
		return 0;

	return vfsf_priv->vfx_qsetid[vf_idx];
}

u16 ys_k2u_vfsf_get_maxqnum(struct ys_pdev_priv *pdev_priv, enum ys_k2u_ndev_type type)
{
	struct ys_k2u_vfsf_priv *vfsf_priv;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	vfsf_priv = ys_k2u_vfsf_get_priv(pdev_priv);
	if (!vfsf_priv)
		return 0;

	switch (type) {
	case YS_K2U_NDEV_PF:
		return vfsf_priv->pf_qnum;
	case YS_K2U_NDEV_VF:
		return vfsf_priv->vf_maxqnum;
	case YS_K2U_NDEV_REP:
		return vfsf_priv->rep_maxqnum;
	case YS_K2U_NDEV_UPLINK:
		return vfsf_priv->uplink_qnum;
	case YS_K2U_NDEV_SF:
		return vfsf_priv->sf_maxqnum;
	default:
		return 0;
	}
}

u16 ys_k2u_vfsf_get_minqnum(struct ys_pdev_priv *pdev_priv, enum ys_k2u_ndev_type type)
{
	struct ys_k2u_vfsf_priv *vfsf_priv;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	vfsf_priv = ys_k2u_vfsf_get_priv(pdev_priv);
	if (!vfsf_priv)
		return 0;

	switch (type) {
	case YS_K2U_NDEV_PF:
		return vfsf_priv->pf_qnum;
	case YS_K2U_NDEV_VF:
		return vfsf_priv->vf_minqnum;
	case YS_K2U_NDEV_REP:
		return vfsf_priv->rep_minqnum;
	case YS_K2U_NDEV_UPLINK:
		return vfsf_priv->uplink_qnum;
	case YS_K2U_NDEV_SF:
		return vfsf_priv->sf_minqnum;
	default:
		return 0;
	}
}

static void
k2u_vfsf_set_qbase(struct ys_k2u_vfsf_priv *vfsf_priv, u16 vf_idx, struct ys_k2u_queuebase qbase)
{
	vfsf_priv->vfx_qbase[vf_idx] = qbase;
}

int ys_k2u_sriov_enable(struct pci_dev *pdev, u32 num_vfs)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_k2u_vfsf_priv *vfsf_priv = ys_k2u_vfsf_get_priv(pdev_priv);
	struct ys_k2u_queuebase qbase;
	int i, ret;
	struct ys_vf_info *vf_info;
	struct ys_queue_params qi;
	u16 *vfs_qsetid;

	if (!vfsf_priv)
		return -EINVAL;
	vfsf_priv->vf_curnum = num_vfs;

	pdev_priv->func_qnum -= pdev_priv->sriov_info.vfs_total_qnum;

	vfs_qsetid = kcalloc(num_vfs, sizeof(u16), GFP_KERNEL);
	if (!vfs_qsetid)
		return -ENOMEM;

	ret = ys_k2u_qsetid_alloc(pdev_priv, YS_K2U_NDEV_VF, vfs_qsetid, num_vfs);
	if (ret) {
		ys_dev_err("failed to allocate qsetid for vfs\n");
		return ret;
	}

	for (i = 0; i < num_vfs; i++) {
		vf_info = &pdev_priv->sriov_info.vfinfo[i];
		qbase.start = vf_info->qbase;
		qbase.num = vf_info->func_qnum;
		vf_info->qset = vfs_qsetid[i];

		ys_dev_info("vf%d qsetid %d, qbase %d, qnum %d", i, vf_info->qset, qbase.start,
			    qbase.num);

		k2u_vfsf_set_qbase(vfsf_priv, i, qbase);
		ys_k2u_vfsf_set_qsetid(pdev_priv, i, vfs_qsetid[i]);

		ys_k2u_func_change_qnum(pdev_priv, qbase.num, false);
		ys_k2u_func_change_funcx_qnum(pdev_priv, 0, qbase.num, false);
		ys_k2u_func_set_funcx_qbase(pdev_priv, i + 1, YS_K2U_QUEUE_PF, qbase);

		ys_k2u_func_change_irqnum(pdev_priv, qbase.num * vfsf_priv->irq_ratio, false);
		ys_k2u_func_change_funcx_irqnum(pdev_priv, 0, qbase.num * vfsf_priv->irq_ratio,
						false);
		ys_k2u_func_set_funcx_irqnum(pdev_priv, i + 1, qbase.num * vfsf_priv->irq_ratio);
	}

	kfree(vfs_qsetid);

	if (pdev_priv->dpu_mode == MODE_SMART_NIC) {
		vf_info = &pdev_priv->sriov_info.vfinfo[0];
		qbase.start = pdev_priv->total_qnum - pdev_priv->sriov_info.vfs_total_qnum;
		qbase.num = vf_info->func_qnum / (pdev_priv->sriov_info.rep_ratio + 1);
		qbase.num = qbase.num ?: 1;
		qbase.num = min_t(u16, qbase.num, YS_K2U_N_REP_MAXQNUM);
		qbase.start -= (qbase.num * num_vfs);

		ys_dev_info("total_qnum %d, vfs_total_qnum %d, func_qnum %d, rep_ratio %d",
			    pdev_priv->total_qnum, pdev_priv->sriov_info.vfs_total_qnum,
			    vf_info->func_qnum, pdev_priv->sriov_info.rep_ratio);

		for (i = 0; i < num_vfs; i++) {
			qi.ndev_qnum = qbase.num;
			qi.qbase = qbase.start;
			qbase.start += qbase.num;

			ys_aux_add_adev(pdev, YS_K2U_ID_NDEV_VFREP(i), AUX_NAME_REP, &qi);
		}
	}

	return 0;
}

int ys_k2u_sriov_config_change(struct pci_dev *pdev)
{
	return 0;
}

int ys_k2u_sriov_disable(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_k2u_vfsf_priv *vfsf_priv = ys_k2u_vfsf_get_priv(pdev_priv);
	int i;
	struct net_device *ndev;
	struct ys_k2u_queuebase qbase;
	u16 *vfs_qsetid;
	struct ys_vf_info *vf_info;
	u16 irqnum;

	vfs_qsetid = kcalloc(pdev_priv->sriov_info.num_vfs, sizeof(u16), GFP_KERNEL);
	if (!vfs_qsetid)
		return -ENOMEM;

	for (i = 0; i < pdev_priv->sriov_info.num_vfs; i++) {
		vf_info = &pdev_priv->sriov_info.vfinfo[i];
		vfs_qsetid[i] = vf_info->qset;

		ndev = ys_aux_match_rep(pdev, YS_K2U_ID_NDEV_VFREP(i));
		if (ndev)
			ys_aux_del_match_adev(pdev, YS_K2U_ID_NDEV_VFREP(i), AUX_NAME_REP);

		qbase.start = 0;
		qbase.num = 0;

		k2u_vfsf_set_qbase(vfsf_priv, i, qbase);
		ys_k2u_vfsf_set_qsetid(pdev_priv, i, 0);

		ys_k2u_func_set_funcx_qbase(pdev_priv, i + 1, YS_K2U_QUEUE_PF, qbase);
		ys_k2u_func_change_qnum(pdev_priv, vf_info->func_qnum, true);
		ys_k2u_func_change_funcx_qnum(pdev_priv, 0, vf_info->func_qnum, true);

		irqnum = ys_k2u_func_get_funcx_irqnum(pdev_priv, i + 1);
		ys_k2u_func_set_funcx_irqnum(pdev_priv, i + 1, 0);
		ys_k2u_func_change_irqnum(pdev_priv, irqnum, true);
		ys_k2u_func_change_funcx_irqnum(pdev_priv, 0, irqnum, true);
	}

	ys_k2u_qsetid_free(pdev_priv, vfs_qsetid, pdev_priv->sriov_info.num_vfs);

	pdev_priv->func_qnum = pdev_priv->total_qnum;
	if (vfsf_priv)
		vfsf_priv->vf_curnum = 0;

	return 0;
}

static int k2u_vfsf_calc_qnum(struct ys_k2u_vfsf_priv *vfsf_priv)
{
	struct ys_pdev_priv *pdev_priv = vfsf_priv->pdev_priv;
	u16 vfs_num = ys_k2u_func_get_vfnum(vfsf_priv->pdev_priv);
	u16 total_irqnum = ys_k2u_func_get_irqnum(vfsf_priv->pdev_priv);
	u16 total_qnum = ys_k2u_func_get_qbase(pdev_priv, YS_K2U_QUEUE_FUNC).num;
	u16 irq_ratio;

	u16 pf_qnum, vf_qnum, uplink_qnum, rep_qnum, need_qnum, need_vfnum;

	vfsf_priv->vf_maxnum = vfs_num;
	vfsf_priv->vf_curnum = 0;

	/* 0. irq ratio */
	vfsf_priv->irq_ratio = total_irqnum / total_qnum;
	vfsf_priv->irq_ratio = vfsf_priv->irq_ratio ?: 1;
	irq_ratio = vfsf_priv->irq_ratio;

	if (vfsf_priv->pdev_priv->dpu_mode == MODE_LEGACY ||
	    vfsf_priv->pdev_priv->dpu_mode == MODE_DPU_HOST) {
		/* 1. pf */
		if (total_qnum >= (YS_K2U_N_PF_MAXQNUM + vfs_num)) {
			vfsf_priv->pf_qnum = YS_K2U_N_PF_MAXQNUM;
			total_qnum -= YS_K2U_N_PF_MAXQNUM;
		} else {
			vfsf_priv->pf_qnum = 1;
			total_qnum -= 1;
		}

		/* 2. vf */
		vfsf_priv->vf_maxnum = vfs_num;
		if (total_qnum >= YS_K2U_N_VF_MAXQNUM)
			vfsf_priv->vf_maxqnum = YS_K2U_N_VF_MAXQNUM;
		else
			vfsf_priv->vf_maxqnum = total_qnum;
		vfsf_priv->vf_minqnum = total_qnum / vfs_num;
		if (vfsf_priv->vf_minqnum > vfsf_priv->vf_maxqnum)
			vfsf_priv->vf_minqnum = vfsf_priv->vf_maxqnum;

		total_qnum -= vfsf_priv->vf_minqnum * vfs_num;

		/* 3. sf */
		if (total_qnum > 0) {
			vfsf_priv->sf_maxnum = total_qnum;
			vfsf_priv->sf_maxqnum = total_qnum;
			vfsf_priv->sf_minqnum = 1;
		}

		/* 4. vf irq */
		vfsf_priv->vf_max_irqnum = vfsf_priv->vf_maxqnum * irq_ratio;
		vfsf_priv->vf_min_irqnum = vfsf_priv->vf_minqnum * irq_ratio;
		total_irqnum -= vfsf_priv->vf_minqnum * vfsf_priv->vf_maxnum;

		/* 5. pf irq */
		vfsf_priv->pf_irqnum = total_irqnum;
	} else if (vfsf_priv->pdev_priv->dpu_mode == MODE_SMART_NIC) {
		pf_qnum = YS_K2U_N_PF_MAXQNUM;
		vf_qnum = YS_K2U_N_VF_MAXQNUM;
		uplink_qnum = YS_K2U_N_UPLINK_MAXQNUM;
		rep_qnum = YS_K2U_N_REP_MAXQNUM;
		need_vfnum = vfs_num;

		for (; (pf_qnum != 1 || vf_qnum != 1 || uplink_qnum != 1 || rep_qnum != 1 ||
			!need_vfnum);) {
			need_qnum = (vf_qnum + rep_qnum) * vfs_num;
			need_qnum += pf_qnum + rep_qnum + uplink_qnum;
			if (total_qnum >= need_qnum)
				break;

			if (pf_qnum > 1)
				pf_qnum--;
			if (vf_qnum > 1)
				vf_qnum--;
			if (uplink_qnum > 1)
				uplink_qnum--;
			if (rep_qnum > 1)
				rep_qnum--;
			if (pf_qnum == 1 && vf_qnum == 1)
				need_vfnum--;
		}

		/* 1. pf */
		vfsf_priv->pf_qnum = pf_qnum;
		vfsf_priv->uplink_qnum = uplink_qnum;
		total_qnum -= pf_qnum + uplink_qnum + rep_qnum;

		/* 2. vf */
		vfsf_priv->vf_maxnum = need_vfnum;
		if (total_qnum >= YS_K2U_N_VF_MAXQNUM + YS_K2U_N_REP_MAXQNUM) {
			vfsf_priv->vf_maxqnum = YS_K2U_N_VF_MAXQNUM;
			vfsf_priv->rep_maxqnum = YS_K2U_N_REP_MAXQNUM;
		} else {
			vfsf_priv->rep_maxqnum = rep_qnum;
			vfsf_priv->vf_maxqnum = total_qnum - rep_qnum;
		}
		vfsf_priv->vf_minqnum = vf_qnum;
		vfsf_priv->rep_minqnum = rep_qnum;

		total_qnum -= (vf_qnum + rep_qnum) * need_vfnum;

		/* 3. sf */
		if (total_qnum > 0) {
			vfsf_priv->sf_maxnum = total_qnum;
			vfsf_priv->sf_maxqnum = total_qnum;
			vfsf_priv->sf_minqnum = 1;
		}

		/* 4. vf irq */
		vfsf_priv->vf_max_irqnum = vfsf_priv->vf_maxqnum * irq_ratio;
		vfsf_priv->vf_min_irqnum = vfsf_priv->vf_minqnum * irq_ratio;
		total_irqnum -= vfsf_priv->vf_minqnum * vfsf_priv->vf_maxnum;

		/* 5. pf irq */
		vfsf_priv->pf_irqnum = total_irqnum;
	} else {
		if (vfsf_priv->pdev_priv->dpu_mode != MODE_DPU_SOC) {
			ys_dev_err("invalid dpu mode %d\n", vfsf_priv->pdev_priv->dpu_mode);
			return -EINVAL;
		}
	}

	return 0;
}

int ys_k2u_pdev_vfsf_init(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_queuebase qbase;
	struct ys_k2u_new_func *func = ys_k2u_func_get_priv(pdev_priv);
	struct ys_k2u_vfsf_priv *vfsf_priv;
	struct dentry *entry;
	u16 irq_num;
	u16 rep_ratio;

	qbase = ys_k2u_func_get_qbase(pdev_priv, YS_K2U_QUEUE_FUNC);

	pdev_priv->total_qnum = qbase.num;
	pdev_priv->func_qnum = qbase.num;

	irq_num = ys_k2u_func_get_irqnum(pdev_priv);
	pdev_priv->irq_table.user_max = irq_num;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	vfsf_priv = kzalloc(sizeof(*vfsf_priv), GFP_KERNEL);
	if (!vfsf_priv)
		return -ENOMEM;

	func->vfsf_priv = vfsf_priv;
	vfsf_priv->pdev_priv = pdev_priv;

	pdev_priv->sriov_info.vf_min_qnum = 1;
	pdev_priv->sriov_info.vf_max_qnum = YS_K2U_N_VF_MAXQNUM;
	pdev_priv->sriov_info.rep_ratio = 0;

	if (k2u_vfsf_calc_qnum(vfsf_priv) < 0)
		return -EINVAL;

	switch (pdev_priv->dpu_mode) {
	case MODE_LEGACY:
	case MODE_DPU_HOST:
		pdev_priv->sriov_info.max_vfs = vfsf_priv->vf_maxnum * vfsf_priv->vf_minqnum;
		break;
	case MODE_SMART_NIC:
		pdev_priv->sriov_info.max_vfs = vfsf_priv->vf_maxnum * vfsf_priv->vf_minqnum;
		pdev_priv->sriov_info.max_vfs += vfsf_priv->vf_maxnum * vfsf_priv->rep_minqnum;
		rep_ratio = (u16)(vfsf_priv->vf_minqnum / vfsf_priv->rep_minqnum);
		pdev_priv->sriov_info.rep_ratio = rep_ratio;
		break;
	case MODE_DPU_SOC:
		break;
	default:
		ys_dev_err("invalid dpu mode %d\n", pdev_priv->dpu_mode);
		return -EINVAL;
	}

	if (func->debugfs_root) {
		entry = debugfs_create_file("vfsf", 0400, func->debugfs_root, vfsf_priv,
					    &vfsf_debugfs_fops);
		if (!entry)
			ys_dev_err("vfsf debugfs create file failed");
		else
			vfsf_priv->debugfs_vfsf_file = entry;
	}

	pdev_priv->irq_table.user_max = vfsf_priv->pf_irqnum;

	return 0;
}

void ys_k2u_pdev_vfsf_uninit(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_vfsf_priv *vfsf_priv;

	if (pdev_priv->nic_type->is_vf)
		return;

	vfsf_priv = ys_k2u_vfsf_get_priv(pdev_priv);
	if (!vfsf_priv)
		return;

	debugfs_remove(vfsf_priv->debugfs_vfsf_file);
	kfree(vfsf_priv);
}
