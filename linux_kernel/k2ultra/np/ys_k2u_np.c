// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_np_priv.h"
#include "ys_k2u_np.h"
#include "ys_k2u_np_lag.h"
#include "../include/ys_doe.h"
#include "../net/tc/ys_tc.h"
#include "../platform/ys_if.h"

static DEFINE_IDR(ys_k2u_np_dev_idr);
static DEFINE_MUTEX(ys_k2u_np_dev_lock);

struct ys_k2u_np_mbox_cmd {
	u8 cmd_type;
	s8 cmd_status;
	u8 cmd_len;
	u8 cmd_key;
	u32 cmd_data[];
};

struct ys_k2u_np_mbox_channel {
	u16 rsv : 10;
	u16 dst : 6;
};

static int ys_np_set_doe_access(struct ys_pdev_priv *pdev_priv, bool access)
{
	int ret = 0;
	bool protect = !access;
	bool ready = access;

	ret = ys_np_set_doe_protect(pdev_priv, protect);
	if (ret) {
		ys_np_err("np doe protect failed, ret = %d", ret);
		return ret;
	}

	ret = ys_np_set_tbl_ready(pdev_priv, ready);
	if (ret) {
		ys_np_err("np set table ready failed, ret = %d", ret);
		return ret;
	}

	return 0;
}

static int ys_k2u_np_base_init(struct ys_np *np)
{
	int ret = 0;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);

	ret = ys_np_set_doe_access(pdev_priv, false);
	if (ret) {
		ys_np_err("disable doe access, ret = %d.\n", ret);
		return ret;
	}

	ret = ys_k2u_np_doe_init(np);
	if (ret) {
		ys_np_err("doe init failed, ret = %d.\n", ret);
		return ret;
	}

	// table create
	ret = ys_k2u_np_doe_tbl_init(np);
	if (ret) {
		ys_np_err("doe table init failed, ret = %d.\n", ret);
		return ret;
	}

	ret = ys_np_set_doe_access(pdev_priv, true);
	if (ret) {
		ys_np_err("Enable doe access failed, ret = %d.\n", ret);
		return ret;
	}

	return ret;
}

static void ys_k2u_np_base_fini(struct ys_np *np)
{
	int ret = 0;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);

	ret = ys_np_set_doe_access(pdev_priv, false);
	if (ret)
		ys_np_err("disable doe access, ret = %d.\n", ret);

	ys_k2u_np_doe_tbl_fini(np);
}

static int ys_k2u_np_legacy_init(struct ys_np *np)
{
	return ys_k2u_np_base_init(np);
}

static int ys_k2u_np_switchdev_init(struct ys_np *np)
{
	int ret = 0;
	bool cache_miss = true;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);

	ret = ys_k2u_np_base_init(np);
	if (ret) {
		ys_np_err("Base init failed, ret = %d.\n", ret);
		return ret;
	}

	ret = ys_np_set_ign_frag_l4_port(pdev_priv, true);
	if (ret) {
		ys_np_err("Set ignore fragment l4 port failed, ret = %d.\n", ret);
		return ret;
	}

	// TODO: For BNIC, enable cache miss; for DPU, disable cache miss
	ret = ys_np_set_tbl_cache_miss(pdev_priv, cache_miss);
	if (ret) {
		ys_np_err("Set cache miss failed, ret = %d.\n", ret);
		return ret;
	}

	return ret;
}

static const struct ys_np_ops ys_np_legacy_ops = {
	.init = ys_k2u_np_legacy_init,
	.fini = ys_k2u_np_base_fini,
};

static const struct ys_np_ops ys_np_switchdev_ops = {
	.init = ys_k2u_np_switchdev_init,
	.fini = ys_k2u_np_base_fini,
};

enum {
	YS_NP_REG_CFG_SET     = 0,
};

static inline u32 ys_k2u_value_recompute(u32 old_val, u16 set_val, u16 mask, u32 shift)
{
	u32 set_val32 = set_val;
	u32 mask32 = mask;

	set_val32 <<= shift;
	mask32 <<= shift;

	return ((old_val & ~mask32) | (set_val32 & mask32));
}

struct ys_k2u_np_cfg {
	const char *name;
	const enum ysc_np_cfg_type type;
	const u16 mask;
	const u8 val_shift;
	const u8 reg_shift;
	const u32 offset;
	const u32 mode_bitmap;
	const u32 cls_bitmap;
};

static struct ys_k2u_np_cfg ys_np_cfg_list[] = {
	{
		.name = "Doe table ready",
		.type = YS_NP_CFG_DOE_TBL_READY,
		.mask = 1,
		.val_shift = 0,
		.reg_shift = 0,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_LEGACY) | BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP,
	},
	{
		.name = "Fcs error drop",
		.type = YS_NP_CFG_FCS_ERR_DROP,
		.mask = (1 << 1),
		.val_shift = 1,
		.reg_shift = 0,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_LEGACY) | BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP_LOW,
	},
	{
		.name = "TM trust priority",
		.type = YS_NP_CFG_TM_TRUST_PRI,
		.mask = (1 << 2),
		.val_shift = 2,
		.reg_shift = 0,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_LEGACY) | BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP,
	},
	{
		.name = "LRO",
		.type = YS_NP_CFG_LRO,
		.mask = (1 << 3),
		.val_shift = 3,
		.reg_shift = 0,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_LEGACY) | BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP_LOW,
	},
	{
		.name = "Ignore PPP",
		.type = YS_NP_CFG_IGN_PPP,
		.mask = (1 << 14),
		.val_shift = 14,
		.reg_shift = 0,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP_LOW,
	},
	{
		.name = "Trust PPP",
		.type = YS_NP_CFG_TRUST_PPP,
		.mask = (1 << 15),
		.val_shift = 15,
		.reg_shift = 0,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP_LOW,
	},
	{
		.name = "Bypass offload",
		.type = YS_NP_CFG_BYPASS_OFFLOAD,
		.mask = 1,
		.val_shift = 0,
		.reg_shift = 16,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP_LOW,
	},
	{
		.name = "Ignore tunnel ipv4 identify",
		.type = YS_NP_CFG_IGN_TNL_V4_ID,
		.mask = (1 << 1),
		.val_shift = 1,
		.reg_shift = 16,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP_HIGH,
	},
	{
		.name = "Ignore first fragment L4 port",
		.type = YS_NP_CFG_IGN_FRAG_L4_PORT,
		.mask = (1 << 2),
		.val_shift = 2,
		.reg_shift = 16,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP,
	},
	{
		.name = "Table cache miss",
		.type = YS_NP_CFG_TBL_CACHE_MISS,
		.mask = (1 << 3),
		.val_shift = 3,
		.reg_shift = 16,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP,
	},
	{
		.name = "MA dispatch policy",
		.type = YS_NP_CFG_MA_DISPATCH_POLICY,
		.mask = (3 << 4),
		.val_shift = 4,
		.reg_shift = 16,
		.offset = YS_NP_HOST_FW_MSG1_L_OFFSET,
		.mode_bitmap = BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
		.cls_bitmap = YS_K2U_NP_VALID_CLS_BITMAP_LOW,
	}
};

static const struct ys_k2u_np_cfg *ys_k2u_np_get_cfg(enum ysc_np_cfg_type type,
						     int mode)
{
	size_t i = 0;
	const struct ys_k2u_np_cfg *cfg = NULL;

	for (i = 0; i < ARRAY_SIZE(ys_np_cfg_list); i++) {
		cfg = &ys_np_cfg_list[i];
		if (cfg->type == type) {
			if (cfg->mode_bitmap & BIT(mode))
				return cfg;
			else
				return NULL;
		}
	}

	return NULL;
}

static int ys_k2u_np_do_set_cfg(struct ys_pdev_priv *pdev_priv,
				enum ysc_np_cfg_type type, u16 val)
{
	void  __iomem *baddr = pdev_priv->bar_addr[YS_K2U_NP_REGS_BAR];

	size_t i = 0;
	u32 offset;
	u32 value = 0;
	u32 reg_val = 0;
	const struct ys_k2u_np_cfg *cfg = NULL;
	struct ys_np *np = NULL;
	struct ys_np_sw *np_sw = NULL;
	int ret = 0;

	cfg = ys_k2u_np_get_cfg(type, pdev_priv->dpu_mode);
	if (!cfg) {
		ys_np_err("Got unknown cfg type: %d for mode %d.\n", type, pdev_priv->dpu_mode);
		return -EINVAL;
	}

	np = ys_aux_match_np_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(np)) {
		ys_np_err("np not found for set cfg, probe might failed.");
		return -EFAULT;
	}

	np_sw = np->sw;
	mutex_lock(&np_sw->cfg_lock);
	for (i = 0; i < YS_K2U_NP_PPE_CLUSTE_NUM; i++) {
		/* Got valid cluster id */
		if (!(YS_K2U_NP_VALID_CLS_BITMAP & BIT(i)))
			continue;
		if (!(cfg->cls_bitmap & BIT(i)))
			continue;

		offset = YS_K2U_NP_BASE + YS_K2U_NP_CLUSTER_SIZE * i;
		offset += cfg->offset;

		value = ys_rd32(baddr, offset);
		if (value == YS_K2U_NP_REG_MAGIC) {
			ys_np_err("Invalid reg found for cluster %lu.", i);
			ret = -EINVAL;
			goto out;
		}

		reg_val = ys_k2u_value_recompute(value, (val << cfg->val_shift),
						 cfg->mask, cfg->reg_shift);
		ys_wr32(baddr, offset, reg_val);
		np_sw->cfg[i][type] = val;
	}
out:
	mutex_unlock(&np_sw->cfg_lock);
	return ret;
}

int ys_np_set_doe_protect(struct ys_pdev_priv *pdev_priv, bool protect)
{
	struct ys_np *np = NULL;

	np = ys_aux_match_np_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(np)) {
		ys_np_err("np not found for set protect, probe might failed.");
		return -EFAULT;
	}

	return ys_k2u_np_doe_set_protect(np, protect);
}

static void ys_k2u_np_mbox_cmd_handler(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 msg_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_k2u_np_mbox_cmd *cmd = NULL;
	struct ys_k2u_np_mbox_cmd *cmd_ack = NULL;
	struct ys_mbox_msg ack_msg = {0};

	int ret = 0;
	int cfg_type = 0;
	u16 cfg_val = 0;

	cmd = (struct ys_k2u_np_mbox_cmd *)msg->data;
	cmd_ack = (struct ys_k2u_np_mbox_cmd *)ack_msg.data;
	cmd_ack->cmd_type = cmd->cmd_type; // is it neccessery ?
	ys_np_info("mailbox cmd handler:%x, cmd type:%d", msg_id, cmd->cmd_type);

	switch (cmd->cmd_type) {
	case YS_NP_REG_CFG_SET:
		cfg_type = cmd->cmd_data[0];
		cfg_val =  cmd->cmd_data[1];
		ret = ys_k2u_np_do_set_cfg(pdev_priv, cfg_type, cfg_val);
		if (ret) {
			ys_np_err("set reg cfg failed, ret %d, type %x, value %x",
				  ret, cfg_type, cfg_val);
			cmd_ack->cmd_status = -1;
		}
		break;
	default:
		ys_np_err("mailbox unknown cmd type:0x%x", cmd->cmd_type);
		cmd_ack->cmd_status = -2;
		break;
	}

	ack_msg.opcode = msg->opcode | (1 << YS_MBOX_OPCODE_MASK_ACK);
	ack_msg.seqno = msg->seqno;
	/* response message */
	ys_mbox_send_msg(mbox, &ack_msg, msg_id, MB_NO_REPLY, 0, NULL);
}

static int ys_np_cfg_debugfs_show(struct seq_file *seq, void *data)
{
	struct ys_np_sw *np_sw = seq->private;
	int cls = 0;
	int type = 0;
	u16 val = 0;
	const struct ys_k2u_np_cfg *cfg = NULL;

	seq_puts(seq, "NP config show by cluster.\n");
	mutex_lock(&np_sw->cfg_lock);
	for (cls = 0; cls < YS_K2U_NP_PPE_CLUSTE_NUM; cls++) {
		/* Got valid cluster id */
		if (!(YS_K2U_NP_VALID_CLS_BITMAP & BIT(cls)))
			continue;

		seq_printf(seq, "Cluster %d:\n", cls);
		for (type = 0; type < YS_NP_CFG_MAX; type++) {
			cfg = ys_k2u_np_get_cfg(type, np_sw->mode);
			if (!cfg)
				continue;
			if (!(cfg->cls_bitmap & BIT(cls)))
				continue;

			val = np_sw->cfg[cls][type];
			seq_printf(seq, "%-36s : %u\n", cfg->name, val);
		}
		seq_puts(seq, "\n");
	}
	mutex_unlock(&np_sw->cfg_lock);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ys_np_cfg_debugfs);

static int ys_np_sw_get(struct ys_np *np, int np_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	struct ys_doe_ops *doe_ops = pdev_priv->pdev_manager->doe_ops;
	struct ys_np_sw *np_sw = NULL;
	char work_q_name[32] = {0};
	char fs_name[16] = {0};
	int ret = 0;

	mutex_lock(&ys_k2u_np_dev_lock);
	np_sw = idr_find(&ys_k2u_np_dev_idr, np_id);
	if (np_sw) {
		if (refcount_inc_not_zero(&np_sw->refcnt)) {
			np->sw = np_sw;
			goto out;
		}
		ret = -EINVAL;
		goto fail;
	}

	np_sw = kzalloc(sizeof(*np_sw), GFP_KERNEL);
	if (!np_sw) {
		ret = -ENOMEM;
		goto fail;
	}

	np_sw->doe_ops = doe_ops;
	np_sw->bus_id = pdev_priv->pdev->bus->number;
	np_sw->id = np_id;
	refcount_set(&np_sw->refcnt, 1);
	INIT_LIST_HEAD(&np_sw->table_head);
	mutex_init(&np_sw->cfg_lock);

	np_sw->mode = pdev_priv->dpu_mode;
	if (pdev_priv->dpu_mode == MODE_LEGACY)
		np_sw->ops = &ys_np_legacy_ops;
	else
		np_sw->ops = &ys_np_switchdev_ops;

	ret = idr_alloc(&ys_k2u_np_dev_idr, np_sw, np_id, np_id + 1, GFP_ATOMIC);
	if (ret != np_id) {
		ys_np_err("failed to allocate np id %d\n", np_id);
		ret = -EINVAL;
		goto fail_with_alloc;
	}

	/* workqueue. */
	snprintf(work_q_name, sizeof(work_q_name), "ys_np_sw_work_%d", np_sw->id);
	np_sw->wq = create_singlethread_workqueue(work_q_name);
	if (!np_sw->wq) {
		ys_np_err("Failed to create workqueue %s.\n", work_q_name);
		ret = -EINVAL;
		goto fail_with_dir;
	}

	/* debugfs */
	snprintf(fs_name, sizeof(fs_name), "ys_np_%d", np_sw->id);
	np_sw->debugfs_root = debugfs_create_dir(fs_name, ys_debugfs_root);
	if (IS_ERR(np_sw->debugfs_root)) {
		ys_np_err("Failed to create debugfs node %s.\n", fs_name);
		ret = -EINVAL;
		np_sw->debugfs_root = NULL;
	} else if (!(np_sw->debugfs_root)) {
		ys_np_err("The debugfs node %s exists.\n", fs_name);
		ret = -EEXIST;
	} else {
		ret = 0;
	}
	if (ret)
		goto fail_with_wq;

	/* np cfg debugfs, no need to check return code. */
	debugfs_create_file("cfg", 0400, np_sw->debugfs_root, np_sw, &ys_np_cfg_debugfs_fops);

	/* hw init, needs adev_priv and np_sw. */
	np->sw = np_sw;
	ret = np_sw->ops->init(np);
	if (ret) {
		ys_np_err("Failed to run np init, ret = %d.\n", ret);
		goto fail_with_fs;
	}

	if ((pdev_priv->dpu_mode == MODE_DPU_SOC ||
	     pdev_priv->dpu_mode == MODE_SMART_NIC) &&
	    ys_tc_flow_enable)
		ys_k2u_init_lag(np);

out:
	mutex_unlock(&ys_k2u_np_dev_lock);
	return 0;

fail_with_fs:
	debugfs_remove_recursive(np_sw->debugfs_root);
fail_with_wq:
	destroy_workqueue(np_sw->wq);
fail_with_dir:
	idr_remove(&ys_k2u_np_dev_idr, np_id);
fail_with_alloc:
	kfree(np_sw);
fail:
	np->sw = NULL;
	mutex_unlock(&ys_k2u_np_dev_lock);
	return ret;
}

int ys_k2u_np_aux_probe(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_doe_ops *doe_ops = pdev_priv->pdev_manager->doe_ops;

	struct ys_mbox *mbox = NULL;
	struct ys_np *np = NULL;
	int ret = 0;
	const int np_id = pdev_priv->pdev->bus->number;

	switch (pdev_priv->dpu_mode) {
	case MODE_LEGACY:
	case MODE_SMART_NIC:
	case MODE_DPU_SOC:
		break;
	case MODE_DPU_HOST:
		return 0;
	default:
		ys_np_err("Unknown dpu mode %d found.", pdev_priv->dpu_mode);
		return -EINVAL;
	}

	if (!doe_ops ||
	    !doe_ops->hw_init ||
	    !doe_ops->protect_status ||
	    !doe_ops->set_protect_status ||
	    !doe_ops->tbl_valid ||
	    !doe_ops->create_arraytbl ||
	    !doe_ops->delete_arraytbl ||
	    !doe_ops->array_store ||
	    !doe_ops->array_load ||
	    !doe_ops->counter_enable ||
	    !doe_ops->counter_load) {
		ys_np_err("Doe is invalid.");
		return -EINVAL;
	}

	if (!pdev_priv->nic_type->is_vf) {
		mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
		if (!IS_ERR_OR_NULL(mbox))
			mbox->mbox_np_opt = ys_k2u_np_mbox_cmd_handler;
	}

	np = kzalloc(sizeof(*np), GFP_KERNEL);
	if (!np) {
		ret = -ENOMEM;
		goto fail;
	}

	np->pdev = adev->pdev;
	adev->adev_priv = np;
	ret = ys_np_sw_get(np, np_id);
	if (ret) {
		ys_np_err("Failed to get np sw.\n");
		goto fail;
	}

	pdev_priv->ops->hw_adp_np_set_cfg = ys_k2u_np_ops_set_cfg;
	pdev_priv->ops->hw_adp_np_bond_set_cfg = ys_k2u_np_set_lag_cfg;
	pdev_priv->ops->hw_adp_np_bond_linkstatus_set_cfg = ys_k2u_np_set_lag_linkstatus_cfg;
	ys_np_info("np dev probe success.\n");
	return 0;

fail:
	kfree(np);
	adev->adev_priv = NULL;
	ys_np_err("Failed to init np, ret = %d.\n", ret);
	return ret;
}

static void ys_np_sw_put(struct ys_np *np)
{
	struct ys_np_sw *np_sw = NULL;
	struct ys_pdev_priv *pdev_priv = NULL;

	if (!np)
		return;

	pdev_priv = pci_get_drvdata(np->pdev);
	np_sw = np->sw;
	if (!np_sw)
		return;

	mutex_lock(&ys_k2u_np_dev_lock);
	if (refcount_dec_and_test(&np_sw->refcnt)) {
		np_sw->ops->fini(np);

		debugfs_remove_recursive(np_sw->debugfs_root);
		destroy_workqueue(np_sw->wq);
		idr_remove(&ys_k2u_np_dev_idr, np_sw->id);

		if ((pdev_priv->dpu_mode == MODE_DPU_SOC ||
		     pdev_priv->dpu_mode == MODE_SMART_NIC) &&
		    ys_tc_flow_enable)
			ys_k2u_deinit_lag(np);

		kfree(np_sw);
	}
	mutex_unlock(&ys_k2u_np_dev_lock);
}

void ys_k2u_np_aux_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_np *np = (struct ys_np *)adev->adev_priv;

	ys_np_sw_put(np);
	kfree(np);
	adev->adev_priv = NULL;
	ys_np_info("np dev remove.\n");
}

static int ys_k2u_np_mbox_set_cfg(struct ys_pdev_priv *pdev_priv,
				  enum ysc_np_cfg_type type, u16 val)
{
	struct ys_mbox *mbox = NULL;
	struct ys_mbox_msg msg = {0};
	struct ys_mbox_msg ack_msg = {0};
	struct ys_k2u_np_mbox_cmd *cmd = NULL;
	struct ys_k2u_np_mbox_cmd *cmd_ack = NULL;
	u32 channel = 0;
	struct ys_k2u_np_mbox_channel *chl = (struct ys_k2u_np_mbox_channel *)&channel;
	int ret = 0;

	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(mbox))
		return -EFAULT;

	cmd = (struct ys_k2u_np_mbox_cmd *)msg.data;
	cmd->cmd_data[0] = type;
	cmd->cmd_data[1] = val;
	cmd->cmd_type = YS_NP_REG_CFG_SET;

	/* TODO: For now, VF only access to its PF. The dst should be MB_M3 in next stage. */
	chl->dst = MB_PF;
	msg.opcode = YS_MBOX_OPCODE_NP_OPT;
	ret = ys_mbox_send_msg(mbox, &msg, channel, MB_WAIT_REPLY, 1000, &ack_msg);
	cmd_ack = (struct ys_k2u_np_mbox_cmd *)ack_msg.data;
	if (ret) {
		ys_np_err("Set np reg cfg failed, ret = %d, status:%d", ret, cmd_ack->cmd_status);
		return -EINVAL;
	}
	return cmd_ack->cmd_status;
}

static int ys_k2u_np_set_cfg(struct ys_pdev_priv *pdev_priv, enum ysc_np_cfg_type type, u16 val)
{
	int ret = 0;

	if (!pdev_priv->nic_type->is_vf)
		ret = ys_k2u_np_do_set_cfg(pdev_priv, type, val);
	else
		ret = ys_k2u_np_mbox_set_cfg(pdev_priv, type, val);
	return ret;
}

int ys_np_set_tbl_ready(struct ys_pdev_priv *pdev_priv, bool ready)
{
	u16 val = ready ? 1 : 0;

	return ys_k2u_np_set_cfg(pdev_priv, YS_NP_CFG_DOE_TBL_READY, val);
}

int ys_np_set_fcs_err_drop(struct ys_pdev_priv *pdev_priv, bool drop)
{
	u16 val = drop ? 1 : 0;

	return ys_k2u_np_set_cfg(pdev_priv, YS_NP_CFG_FCS_ERR_DROP, val);
}

int ys_np_set_tm_trust_pri(struct ys_pdev_priv *pdev_priv, bool val)
{
	//TODO
	return 0;
}

int ys_np_set_LRO(struct ys_pdev_priv *pdev_priv, bool val)
{
	//TODO
	return 0;
}

int ys_np_set_ignore_PPP(struct ys_pdev_priv *pdev_priv, bool val)
{
	//TODO
	return 0;
}

int ys_np_set_trust_PPP(struct ys_pdev_priv *pdev_priv, bool val)
{
	//TODO
	return 0;
}

int ys_np_set_bypass_offload(struct ys_pdev_priv *pdev_priv, bool val)
{
	//TODO
	return 0;
}

int ys_np_set_ign_tnl_v4_id(struct ys_pdev_priv *pdev_priv, bool val)
{
	//TODO
	return 0;
}

int ys_np_set_ign_frag_l4_port(struct ys_pdev_priv *pdev_priv, bool ignore)
{
	u16 val = ignore ? 1 : 0;

	return ys_k2u_np_set_cfg(pdev_priv, YS_NP_CFG_IGN_FRAG_L4_PORT, val);
}

int ys_np_set_tbl_cache_miss(struct ys_pdev_priv *pdev_priv, bool cache_miss)
{
	u16 val = cache_miss ? 1 : 0;

	return ys_k2u_np_set_cfg(pdev_priv, YS_NP_CFG_TBL_CACHE_MISS, val);
}

int ys_np_set_MA_dispatch_policy(struct ys_pdev_priv *pdev_priv, u16 val)
{
	//TODO
	return 0;
}

struct ys_np_sw *ys_get_np_by_bus_id(int bus_id)
{
	return idr_find(&ys_k2u_np_dev_idr, bus_id);
}

int ys_k2u_np_ops_set_cfg(struct pci_dev *pdev, u16 type, u16 val)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	return ys_k2u_np_set_cfg(pdev_priv, type, val);
}
