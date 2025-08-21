// SPDX-License-Identifier: GPL-2.0
#include <asm/barrier.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/llist.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "ys_k2u_doe_core.h"
#include "ys_k2u_doe_mm.h"
#include "../include/ys_platform.h"
#include "../include/ys_doe.h"
#include "../platform/ys_cdev.h"

dev_t ys_k2u_doe_devt;
LIST_HEAD(ys_k2u_doe_list);

/*
 * This registers is used for clean cache.
 * The index is standed for table type.
 */
const u64 ys_k2u_doe_tbl_del_offset[] = {
	YS_K2U_DOE_TBL_DEL_ARRAY,   YS_K2U_DOE_TBL_DEL_BIG_HASH,
	YS_K2U_DOE_TBL_DEL_COUNTER, YS_K2U_DOE_TBL_DEL_METER,
	YS_K2U_DOE_TBL_DEL_LOCK,    YS_K2U_DOE_TBL_DEL_SMALL_HASH
};

const u64 ys_k2u_doe_reset_offset[] = {
	YS_K2U_DOE_RESET_AIE, YS_K2U_DOE_RESET_HIE, YS_K2U_DOE_RESET_CIE,
	YS_K2U_DOE_RESET_MIE, YS_K2U_DOE_RESET_LHIE
};

/*
 * Table location support feature.
 * The row stands for table type. The column stands for location.
 */
static u8 ys_k2u_doe_loc_valid[7][4] = {
	{ 1, 0, 1, 1 },
	{ 1, 0, 1, 1 },
	{ 1, 0, 1, 1 },
	{ 1, 0, 1, 1 },
	{ 1, 0, 1, 1 },
	{ 1, 0, 1, 1 },
	{ 0, 1, 0, 0 },
};

/*
 * Table specification limit of table type
 * The row stands for table type. The column stands for key_len and dov_len
 */
static u8 ys_k2u_doe_len_limit[7][2] = {
	{ 0, 128 }, { 96, 128 }, { 0, 16 }, { 0, 32 }, { 0, 128 }, { 16, 16 }, { 0, 128 },
};

static struct ys_doe_ops g_auxdev_ops;

static int ys_k2u_doe_get_ddr_channel(struct ys_k2u_doe_device *ys_k2u_doe,
				      struct ys_doe_table_param *param);

static int ys_k2u_doe_irq_handler(struct notifier_block *nb,
				  unsigned long action, void *data)
{
	int ret;
	struct ys_k2u_doe_interface *doe_if =
		container_of(nb, struct ys_k2u_doe_interface, irq_nb);
	struct ys_pdev_priv *pdev_priv =
		pci_get_drvdata(doe_if->ys_k2u_doe->pdev);

	ret = ys_k2u_doe_check_irq(doe_if);
	if (ret)
		return IRQ_NONE;

	ys_dev_debug("%s IRQ Recived!\n", doe_if->name);
	ys_k2u_desc_completed(doe_if);

	return IRQ_HANDLED;
}

#define DOE_IRQ_BASE_VAL(pf_id) ((pf_id) << 21)

static int ys_k2u_doe_register_irqs(struct ys_k2u_doe_device *ys_k2u_doe)
{
	int ret, i, pf_id = 0;
	struct pci_dev *pdev = ys_k2u_doe->pdev;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_k2u_doe_interface *doe_if[2] = { ys_k2u_doe->doe_write_if,
						   ys_k2u_doe->doe_read_if };
	char *name[2] = { "ys_doe_write", "ys_doe_read" };
	u32 offset[2] = { YS_K2U_DOE_IRQ_WRITE, YS_K2U_DOE_IRQ_READ };

	if (pdev->vendor == 0x10ee && pdev->device == 0x9338)
		pf_id = 3;
	else if (pdev->vendor == 0x1f47 && pdev->device == 0x1001)
		pf_id = 0;
	else
		pf_id = pdev_priv->pf_id;

	/* write pf num register */
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PF_NUM, (pf_id << 9));

	/* write irq register */
	for (i = 0; i < 2; ++i) {
		doe_if[i]->irq_nb.notifier_call = ys_k2u_doe_irq_handler;
		ret = YS_REGISTER_NOTIFIER_IRQ(&pdev_priv->irq_table.nh,
					       YS_IRQ_NB_REGISTER_ANY, 0,
					       pdev_priv->pdev,
					       YS_IRQ_TYPE_QUEUE, NULL,
					       &doe_if[i]->irq_nb, name[i]);

		doe_if[i]->irq_vector = ret;
		ys_wr32(ys_k2u_doe->doe_base, offset[i],
			DOE_IRQ_BASE_VAL(pf_id) + ret);
	}

	return 0;
}

static int ys_k2u_doe_unregister_irqs(struct ys_k2u_doe_device *ys_k2u_doe)
{
	int i;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct ys_k2u_doe_interface *doe_if[2] = { ys_k2u_doe->doe_write_if,
						   ys_k2u_doe->doe_read_if };

	for (i = 0; i < 2; ++i) {
		YS_UNREGISTER_IRQ(&pdev_priv->irq_table.nh,
				  doe_if[i]->irq_vector, pdev_priv->pdev,
				  &doe_if[i]->irq_nb);
	}

	return 0;
}

static int ys_k2u_doe_get_table_lock(struct ys_k2u_doe_device *ys_k2u_doe,
				     struct ys_doe_sw_cmd *sw_cmd)
{
	int ret = 0;

	if (sw_cmd->opcode == YS_DOE_SW_RAW_CMD)
		return 0;

	if (sw_cmd->opcode == YS_DOE_SW_CREATE_ARRAY ||
	    sw_cmd->opcode == YS_DOE_SW_CREATE_HASH ||
	    sw_cmd->opcode == YS_DOE_SW_DELETE_ARRAY ||
	    sw_cmd->opcode == YS_DOE_SW_DELETE_HASH) {
		down_write(&ys_k2u_doe->mutex);
	} else if (sw_cmd->opcode == YS_DOE_SW_HW_INIT) {
		ret = 0;
	} else {
		down_read(&ys_k2u_doe->mutex);
	}

	return ret;
}

static long ys_k2u_doe_fops_ioctl(struct file *filep, unsigned int cmd,
				  unsigned long arg)
{
	int ret;
	struct ys_k2u_doe_device *ys_k2u_doe;
	struct ys_doe_sw_cmd *sw_cmd;
	struct ys_pdev_priv *pdev_priv;
	struct ys_cdev *ys_cdev =
		container_of(filep->private_data, struct ys_cdev, mdev);

	if (IS_ERR_OR_NULL(ys_cdev))
		return -EFAULT;

	pdev_priv = pci_get_drvdata(ys_cdev->pdev);
	if (!pdev_priv)
		return -EFAULT;

	ys_k2u_doe = ys_aux_match_doe_dev(ys_cdev->pdev);

	switch (cmd) {
	case YS_DOE_SEND_CMD:
		sw_cmd = ys_k2u_doe_sw_cmd_prepare(ys_k2u_doe, arg);
		if (IS_ERR(sw_cmd))
			return PTR_ERR(sw_cmd);

		/* The `HW_INIT` command is executed once */
		if (sw_cmd->opcode == YS_DOE_SW_HW_INIT && ys_k2u_doe->init) {
			ret = 0;
			goto out;
		}

		ret = ys_k2u_doe_user_cmd_context(ys_k2u_doe, sw_cmd);
		if (ret)
			goto out;
		/* if (ret && sw_cmd->succeed != sw_cmd->cnt) */

		ret = copy_to_user((void *)arg, sw_cmd, sizeof(*sw_cmd));
		if (ret)
			ret = -EFAULT;
out:
		ret = ys_k2u_doe_sw_cmd_unprepare(ys_k2u_doe, sw_cmd, ret, 0);

		return ret;
	default:
		ys_dev_err("ioctl: Failed cmd %u\n", cmd);
		return -EIO;
	}
}

int ys_k2u_doe_kernel_call(u32 card_id, struct ys_doe_sw_cmd *sw_cmd,
			   u8 poll_wait)
{
	int ret;
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);

	ys_dev_debug("Recive cmd opc 0x%x tbl %d\n", sw_cmd->opcode,
		     sw_cmd->tbl_id);

	if (sw_cmd->opcode == YS_DOE_SW_HW_INIT && ys_k2u_doe->init)
		return 0;

	ret = ys_k2u_doe_sw_cmd_valid(ys_k2u_doe, sw_cmd);
	if (ret)
		return ret;

	if (sw_cmd->opcode == YS_DOE_SW_CREATE_ARRAY || sw_cmd->opcode == YS_DOE_SW_CREATE_HASH) {
		ret = ys_k2u_doe_get_ddr_channel(ys_k2u_doe, &sw_cmd->tbl_param);
		sw_cmd->tbl_param.ddr_channel = ret;
	}
	ys_k2u_doe_get_table_lock(ys_k2u_doe, sw_cmd);

	INIT_LIST_HEAD(&sw_cmd->cache_list);
	if (poll_wait)
		ret = ys_k2u_doe_user_cmd_context_poll_wait(ys_k2u_doe, sw_cmd);
	else
		ret = ys_k2u_doe_user_cmd_context(ys_k2u_doe, sw_cmd);

	ret = ys_k2u_doe_sw_cmd_unprepare(ys_k2u_doe, sw_cmd, ret, 1);

	if (!ret && sw_cmd->cnt != sw_cmd->succeed)
		return 100 + sw_cmd->err;

	return -ret;
}

static const struct file_operations ys_k2u_doe_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ys_k2u_doe_fops_ioctl,
};

int ys_k2u_doe_module_add_cdev(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (pdev_priv->doe_schedule.doe_master &&
	    (pdev_priv->dpu_mode == MODE_SMART_NIC ||
	    pdev_priv->dpu_mode == MODE_DPU_SOC ||
	    pdev_priv->dpu_mode == MODE_LEGACY))
		return ys_k2u_doe_add_cdev(pdev);

	return 0;
}

int ys_k2u_doe_add_cdev(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	char misc_dev_name[MAX_MISC_DEV_NAME_BYTES];
	int ret;

	snprintf(misc_dev_name, MAX_MISC_DEV_NAME_BYTES, "ys_doe-%d",
		 pdev->bus->number);
	ret = ys_add_cdev(pdev, misc_dev_name, &ys_k2u_doe_fops);
	if (ret) {
		ys_dev_err("Failed to register ldma3 misc device: %d\n", ret);
		return ret;
	}

	return 0;
}

struct ys_k2u_doe_device *ys_k2u_doe_get_device(u32 card_id)
{
	struct ys_k2u_doe_device *ys_k2u_doe;

	list_for_each_entry(ys_k2u_doe, &ys_k2u_doe_list, list) {
		if (ys_k2u_doe->pdev->bus->number == card_id)
			return ys_k2u_doe;
	}

	return NULL;
}

static struct ys_k2u_doe_interface *
ys_k2u_doe_alloc_interface(struct ys_k2u_doe_device *ys_k2u_doe,
			   const char *name, u32 cmd_buffer_size,
			   u8 cmd_buffer_cnt, u8 msi_index, u32 eq_entry_size,
			   u32 eq_depth)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct device *dev = &pdev_priv->pdev->dev;
	struct ys_k2u_doe_interface *doe_if;
	struct ys_k2u_doe_cmd_buffer *cb;
	struct ys_k2u_doe_event_queue *eq;
	struct ys_doe_sw_cmd *sw_cmd;
	struct ys_k2u_doe_desc *desc;
	int i;

	/* alloc interface structure */
	doe_if = devm_kzalloc(dev, sizeof(*doe_if), GFP_KERNEL);
	if (!doe_if)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&doe_if->work_list);
	INIT_LIST_HEAD(&doe_if->cache_list);
	init_llist_head(&doe_if->cmd_mpool);
	init_llist_head(&doe_if->des_mpool);
	spin_lock_init(&doe_if->work_lock);
	spin_lock_init(&doe_if->transaction_lock);
	doe_if->name = name;
	doe_if->msi_index = msi_index;
	doe_if->ys_k2u_doe = ys_k2u_doe;

	/* alloc cmd buffer */
	doe_if->cb_depth = cmd_buffer_cnt;
	atomic_set(&doe_if->cmdbuffer_count, cmd_buffer_cnt);
	atomic_set(&doe_if->hw_buffer_count, cmd_buffer_cnt);
	doe_if->cb = devm_kzalloc(dev, sizeof(*doe_if->cb) * cmd_buffer_cnt, GFP_KERNEL);
	if (!doe_if->cb)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < cmd_buffer_cnt; i++) {
		cb = doe_if->cb + i;
		cb->end_ptr = 0;
		cb->cmd_cnt = 0;
		cb->id = i;
		cb->size = cmd_buffer_size;
		cb->base = dma_alloc_coherent(dev, cmd_buffer_size,
					      &cb->dma_base, GFP_KERNEL);
		if (!cb->base)
			return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < cmd_buffer_cnt; i++) {
		sw_cmd = kzalloc(sizeof(*sw_cmd), GFP_KERNEL);
		if (!sw_cmd)
			return ERR_PTR(-ENOMEM);
		llist_add(&sw_cmd->mp_node, &doe_if->cmd_mpool);

		desc = kzalloc(sizeof(*desc), GFP_KERNEL);
		if (!desc)
			return ERR_PTR(-ENOMEM);
		llist_add(&desc->llnode, &doe_if->des_mpool);
	}

	/* alloc event buffer */
	eq = &doe_if->eq;
	eq->depth = eq_depth;
	eq->entry_size = eq_entry_size;
	eq->entry_bit = ys_k2u_doe_get_order(eq_entry_size);
	eq->base = dma_alloc_coherent(dev, eq->depth * eq->entry_size,
				      &eq->dma_base, GFP_KERNEL);
	if (!eq->base)
		return ERR_PTR(-ENOMEM);

	/* alloc event pointer */
	eq->hw_tail_ptr = dma_alloc_coherent(dev, sizeof(u64),
					     &eq->dma_hw_tail, GFP_KERNEL);
	if (!eq->hw_tail_ptr)
		return ERR_PTR(-ENOMEM);

	*(u64 *)eq->hw_tail_ptr = (u64)eq->dma_base;

	ys_dev_debug("Init %s-if.\n", name);
	ys_dev_debug("eq 0x%p(0x%016llx) eq_ptr 0x%p(0x%016llx)\n", eq->base,
		     eq->dma_base, eq->hw_tail_ptr, eq->dma_hw_tail);
	return doe_if;
}

static void ys_k2u_doe_destroy_interface(struct ys_k2u_doe_interface *doe_if)
{
	struct ys_k2u_doe_device *ys_k2u_doe = NULL;
	struct ys_pdev_priv *pdev_priv = NULL;
	struct device *dev = NULL;
	struct ys_k2u_doe_event_queue *eq;
	struct ys_k2u_doe_cmd_buffer *cb;
	struct llist_node *node;
	struct ys_doe_sw_cmd *sw_cmd;
	struct ys_k2u_doe_desc *desc;
	int i = 0;

	if (!doe_if)
		return;

	ys_k2u_doe = doe_if->ys_k2u_doe;
	pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	dev = &pdev_priv->pdev->dev;
	ys_dev_info("Exit doe %s-if.\n", doe_if->name);

	for (i = 0; i < doe_if->cb_depth; i++) {
		cb = doe_if->cb + i;
		if (cb->base)
			dma_free_coherent(dev, cb->size, cb->base, cb->dma_base);
	}

	/* free cmd buffer */
	if (doe_if->cb)
		devm_kfree(dev, doe_if->cb);

	while (!llist_empty(&doe_if->cmd_mpool)) {
		node = llist_del_first(&doe_if->cmd_mpool);
		sw_cmd = llist_entry(node, struct ys_doe_sw_cmd, mp_node);
		kfree(sw_cmd);
	}

	while (!llist_empty(&doe_if->des_mpool)) {
		node = llist_del_first(&doe_if->des_mpool);
		desc = llist_entry(node, struct ys_k2u_doe_desc, llnode);
		kfree(desc);
	}

	/* free event buffer */
	eq = &doe_if->eq;
	if (eq->base)
		dma_free_coherent(dev, eq->depth * eq->entry_size, eq->base, eq->dma_base);

	/* free event pointer */
	if (eq->hw_tail_ptr)
		dma_free_coherent(dev, sizeof(u64), eq->hw_tail_ptr, eq->dma_hw_tail);

	if (doe_if)
		devm_kfree(dev, doe_if);
}

static int ys_k2u_doe_hw_resources_init(struct ys_k2u_doe_device *ys_k2u_doe)
{
	int ret = 0;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct device *dev = &pdev_priv->pdev->dev;
	struct ys_doe_table_param *param;
	struct ys_k2u_doe_table_spec *spec;
	u32 val = 0;
	u64 ddr_size = 0;
	u32 host_ddr_channel = 0;
	u32 dpu_ddr_channel = 0;
	u32 soc_ddr_channel = 0;
	int ddr_channel = 0;

	init_waitqueue_head(&ys_k2u_doe->wait);
	init_rwsem(&ys_k2u_doe->mutex);
	mutex_init(&ys_k2u_doe->mtx_init);
	ys_k2u_doe->tbl_bitmap = devm_kzalloc(dev, ((YS_K2U_DOE_USER_TBL_NUM - 1) /
					      sizeof(unsigned long) + 1) *
					      sizeof(unsigned long),
					      GFP_KERNEL);
	if (!ys_k2u_doe->tbl_bitmap)
		return -ENOMEM;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_SYS_INFO);
	ys_k2u_doe->hash_tbl_max = FIELD_GET(YS_K2U_HASH_TLB_NUM, val);
	host_ddr_channel = FIELD_GET(YS_K2U_DDR_VALID, val) & YS_K2U_HOST_VALID_MASK;
	ys_k2u_doe->enble_host_ddr = host_ddr_channel;
	ys_k2u_doe->non_ddr_mode = (FIELD_GET(YS_K2U_DDR_VALID, val) == 0);
	dpu_ddr_channel = FIELD_GET(YS_K2U_DDR_VALID, val) & YS_K2U_DDR_VALID_MASK;
	ys_k2u_doe->enble_dpu_ddr = dpu_ddr_channel;
	soc_ddr_channel = FIELD_GET(YS_K2U_DDR_VALID, val) & YS_K2U_SOC_VALID_MASK;
	ys_k2u_doe->enble_soc_ddr = soc_ddr_channel;
	ys_k2u_doe->channel_0_size = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_CHANNEL0_LIMIT);
	ys_k2u_doe->channel_1_size = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_CHANNEL1_LIMIT);
	ys_k2u_doe->channel_0_size = ys_k2u_doe->channel_0_size * YS_K2U_DOE_DDR_SLICE;
	ys_k2u_doe->channel_1_size = ys_k2u_doe->channel_1_size * YS_K2U_DOE_DDR_SLICE;
	ys_k2u_doe->index_sram_size = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_INDEX_SRAM_LIMIT);
	if (pdev_priv->dpu_mode == MODE_LEGACY && ys_k2u_doe->non_ddr_mode == false) {
		ys_dev_err("DOE MODE_LEGACY must work in NON-DDR mode\n");
		return -EDOM;
	}
	if (ys_k2u_doe->enble_host_ddr && ys_k2u_doe->enble_soc_ddr) {
		ys_dev_err("DOE work in enble_host_ddr&enble_soc_ddr both true mode\n");
		return -EDOM;
	}
	if (!host_ddr_channel && !dpu_ddr_channel && !soc_ddr_channel)
		ys_dev_err("DOE host_ddr&dpu_ddr&soc_ddr both not enable\n");

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_DMA_MODE);
	if (!val) {
		ys_k2u_doe->enble_faster_mode = false;
		ys_k2u_doe->doe_read_if->mod_reg_base_shfit = 0;
		ys_k2u_doe->doe_write_if->mod_reg_base_shfit = 0;
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_RD_CHANNEL_SPACE, 1);
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_WR_CHANNEL_SPACE, 1);
		atomic_set(&ys_k2u_doe->doe_read_if->hw_buffer_count, 1);
		atomic_set(&ys_k2u_doe->doe_write_if->hw_buffer_count, 1);
	} else {
		ys_k2u_doe->enble_faster_mode = true;
		ys_k2u_doe->doe_read_if->mod_reg_base_shfit = YS_K2U_DOE_RD_BASE_SHIFT;
		ys_k2u_doe->doe_write_if->mod_reg_base_shfit = YS_K2U_DOE_WR_BASE_SHIFT;
	}

	/* init param of special table in sram */
	param = &ys_k2u_doe->param[YS_K2U_DOE_MIU_PARAM_TABLE];
	param->depth = YS_K2U_DOE_USER_TBL_NUM + 1;
	param->dov_len = sizeof(struct ys_k2u_doe_miu_param);

	param = &ys_k2u_doe->param[YS_K2U_DOE_HIE_PARAM_TABLE];
	param->depth = YS_K2U_DOE_USER_TBL_NUM - 1;
	param->dov_len = sizeof(struct ys_k2u_doe_hie_param);

	param = &ys_k2u_doe->param[YS_K2U_DOE_AIE_PARAM_TABLE];
	param->depth = YS_K2U_DOE_USER_TBL_NUM + 1;
	param->dov_len = sizeof(struct ys_k2u_doe_aie_param);

	param = &ys_k2u_doe->param[YS_K2U_DOE_CACHE_CONFIG_TABLE];
	param->depth = YS_K2U_DOE_USER_TBL_NUM - 1;
	param->dov_len = sizeof(struct ys_k2u_doe_cache_param);

	param = &ys_k2u_doe->param[YS_K2U_DOE_INDEX_MANAGE_TABLE];
	param->depth = YS_K2U_DOE_USER_TBL_NUM - 1;
	param->dov_len = sizeof(struct ys_k2u_doe_index_param);

	param = &ys_k2u_doe->param[YS_K2U_DOE_BATCH_OP_TABLE];
	param->depth = YS_K2U_DOE_USER_TBL_NUM + 1;
	param->dov_len = sizeof(struct ys_k2u_doe_flush_param);

	/* init param of special table in ddr */
	param = &ys_k2u_doe->param[YS_K2U_DOE_INDEX_RES_TABLE];
	ddr_size = ys_k2u_doe->channel_0_size + ys_k2u_doe->channel_1_size;
	param->depth = ddr_size / YS_K2U_DOE_INDEX_ITEM_SIZE - 1;
	param->dov_len = YS_K2U_DOE_INDEX_ITEM_SIZE;

	param->location = DOE_LOCATION_DDR;
	ddr_channel = ys_k2u_doe_get_ddr_channel(ys_k2u_doe, param);
	if (ddr_channel < 0) {
		param->location = DOE_LOCATION_HOST_DDR;
		ddr_channel = ys_k2u_doe_get_ddr_channel(ys_k2u_doe, param);
	}
	if (ddr_channel < 0) {
		param->location = DOE_LOCATION_SOC_DDR;
		ddr_channel = ys_k2u_doe_get_ddr_channel(ys_k2u_doe, param);
	}

	spec = &ys_k2u_doe->spec[YS_K2U_DOE_INDEX_RES_TABLE];
	spec->miu_param.item_len = cpu_to_le16(YS_K2U_DOE_INDEX_ITEM_SIZE);
	spec->miu_param.item_size = ys_k2u_doe_get_order(param->dov_len);
	spec->miu_param.ddr_channel = ddr_channel;

	spec->aie_param.item_size = spec->miu_param.item_size;
	spec->aie_param.data_len = spec->miu_param.item_len;
	spec->aie_param.depth = cpu_to_le32(param->depth);
	spec->aie_param.tbl_type = 0;
	spec->aie_param.valid = 1;
	spec->aie_param.ddr_mode = 0;
	spec->aie_param.endian = 0;
	spec->aie_param.ddr_channel = ddr_channel;
	spec->cache_param.ddr_mode = 0;
	spec->cache_param.big_mode = 0;
	spec->cache_param.ddr_channel = ddr_channel;
	spec->cache_param.tbl_type = 0;
	spec->cache_param.valid = 1;
	spec->cache_param.data_len = spec->miu_param.item_len;
	spec->cache_param.key_len = 0;
	spec->cache_param.depth = spec->aie_param.depth;
	spec->cache_param.item_size = spec->miu_param.item_size;

	if (ys_k2u_doe->enble_host_ddr || ys_k2u_doe->enble_soc_ddr)
		ret = ys_k2u_doe_addrmap_init(ys_k2u_doe);
	if (ret)
		goto err_with_host_ddr;

	/* init memory resources */
	if (ys_k2u_doe->non_ddr_mode)
		ys_k2u_doe->ddr0 = ys_k2u_doe_mm_init(dev, 0, YS_K2U_DOE_LEGACY_SIZE, false,
						      YS_K2U_DOE_LEGACY_ALIGN, "non_ddr_mode");
	else if (ys_k2u_doe->enble_host_ddr && host_ddr_channel & 0xf)
		ys_k2u_doe->ddr0 = ys_k2u_doe_mm_init(dev, 0, ys_k2u_doe->host_ddr_size, false,
						      YS_K2U_DOE_DDR_ALIGN, "host_ddr");
	else if (ys_k2u_doe->enble_dpu_ddr && dpu_ddr_channel & 0xf)
		ys_k2u_doe->ddr0 = ys_k2u_doe_mm_init(dev, 0, ys_k2u_doe->channel_0_size, false,
						      YS_K2U_DOE_DDR_ALIGN, "dpu_ddr");
	else if (ys_k2u_doe->enble_soc_ddr && soc_ddr_channel & 0xf)
		ys_k2u_doe->ddr0 = ys_k2u_doe_mm_init(dev, 0, ys_k2u_doe->host_ddr_size, false,
						      YS_K2U_DOE_DDR_ALIGN, "soc_ddr");
	if (IS_ERR(ys_k2u_doe->ddr0)) {
		ret = PTR_ERR(ys_k2u_doe->ddr0);
		goto err_with_ddr0;
	}

	if (ys_k2u_doe->enble_host_ddr && host_ddr_channel & 0xf0)
		ys_k2u_doe->ddr1 = ys_k2u_doe_mm_init(dev, 0, ys_k2u_doe->host_ddr_size, false,
						      YS_K2U_DOE_DDR_ALIGN, "host_ddr");
	else if (ys_k2u_doe->enble_dpu_ddr && dpu_ddr_channel & 0xf0)
		ys_k2u_doe->ddr1 = ys_k2u_doe_mm_init(dev, 0, ys_k2u_doe->channel_1_size, false,
						      YS_K2U_DOE_DDR_ALIGN, "dpu_ddr");
	else if (ys_k2u_doe->enble_soc_ddr && soc_ddr_channel & 0xf0)
		ys_k2u_doe->ddr1 = ys_k2u_doe_mm_init(dev, 0, ys_k2u_doe->host_ddr_size, false,
						      YS_K2U_DOE_DDR_ALIGN, "soc_ddr");
	if (IS_ERR(ys_k2u_doe->ddr1)) {
		ret = PTR_ERR(ys_k2u_doe->ddr1);
		goto err_with_ddr1;
	}

	ys_k2u_doe->ram = ys_k2u_doe_mm_init(dev, 0, YS_K2U_DOE_RAM_SIZE, false,
					     YS_K2U_DOE_RAM_ALIGN, "ram");
	if (IS_ERR(ys_k2u_doe->ram)) {
		ret = PTR_ERR(ys_k2u_doe->ram);
		goto err_with_ram;
	}

	ys_k2u_doe->index_sram =
		ys_k2u_doe_mm_init(dev, 0, ys_k2u_doe->index_sram_size, false,
				   YS_K2U_DOE_INDEX_SRAM_ALIGN, "index_sram");
	if (IS_ERR(ys_k2u_doe->index_sram)) {
		ret = PTR_ERR(ys_k2u_doe->index_sram);
		goto err_with_index_sram;
	}

	return 0;

err_with_index_sram:
	ys_k2u_doe_mm_uninit(ys_k2u_doe->ram);
err_with_ram:
	ys_k2u_doe_mm_uninit(ys_k2u_doe->ddr1);
err_with_ddr1:
	ys_k2u_doe_mm_uninit(ys_k2u_doe->ddr0);
err_with_ddr0:
	devm_kfree(dev, ys_k2u_doe->tbl_bitmap);
err_with_host_ddr:
	if (ys_k2u_doe->enble_host_ddr || ys_k2u_doe->enble_soc_ddr)
		ys_k2u_doe_addrmap_uninit(ys_k2u_doe);

	return ret;
}

static void ys_k2u_doe_hw_resources_uninit(struct ys_k2u_doe_device *ys_k2u_doe)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct device *dev = &pdev_priv->pdev->dev;

	if (ys_k2u_doe->tbl_bitmap)
		devm_kfree(dev, ys_k2u_doe->tbl_bitmap);

	if (ys_k2u_doe->index_sram) {
		ys_k2u_doe_mm_uninit(ys_k2u_doe->index_sram);
		ys_k2u_doe->index_sram = NULL;
	}

	if (ys_k2u_doe->ram) {
		ys_k2u_doe_mm_uninit(ys_k2u_doe->ram);
		ys_k2u_doe->ram = NULL;
	}

	if (ys_k2u_doe->ddr1) {
		ys_k2u_doe_mm_uninit(ys_k2u_doe->ddr1);
		ys_k2u_doe->ddr1 = NULL;
	}

	if (ys_k2u_doe->ddr0) {
		ys_k2u_doe_mm_uninit(ys_k2u_doe->ddr0);
		ys_k2u_doe->ddr0 = NULL;
	}

	if (ys_k2u_doe->enble_host_ddr || ys_k2u_doe->enble_soc_ddr)
		ys_k2u_doe_addrmap_uninit(ys_k2u_doe);
}

static int ys_k2u_doe_hw_resources_move(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_k2u_doe_device *doe_from = pdev_priv->doe_schedule.schedule_buf;
	struct ys_k2u_doe_device *doe_to = ys_aux_match_adev(pdev, AUX_TYPE_DOE, 0);
	u32 len = 0;
	u32 i = 0;

	ys_wr32(doe_from->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x3);
	ys_wr32(doe_to->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x3);

	doe_from->enble_doe_schedule = true;
	doe_to->enble_doe_schedule = true;
	if (doe_from->tbl_bitmap) {
		len = YS_K2U_DOE_TBL_NUM / sizeof(unsigned long);
		memcpy(doe_to->tbl_bitmap, doe_from->tbl_bitmap, len);
	}

	if (doe_from->index_sram)
		ys_k2u_doe_mm_move(doe_to->index_sram, doe_from->index_sram);

	if (doe_from->ram)
		ys_k2u_doe_mm_move(doe_to->ram, doe_from->ram);

	if (doe_from->ddr1)
		ys_k2u_doe_mm_move(doe_to->ddr1, doe_from->ddr1);

	if (doe_from->ddr0)
		ys_k2u_doe_mm_move(doe_to->ddr0, doe_from->ddr0);

	if (doe_from->enble_host_ddr || doe_from->enble_soc_ddr) {
		for (i = 0; i < doe_from->ddrh_array_max && i < doe_to->ddrh_array_max; i++)
			ys_k2u_doe_mm_move(doe_to->ddrh[i], doe_from->ddrh[i]);
	}

	len = sizeof(struct ys_doe_table_param) * YS_K2U_DOE_TBL_NUM;
	memcpy(doe_to->param, doe_from->param, len);
	len = sizeof(struct ys_k2u_doe_table_spec) * (YS_K2U_DOE_USER_TBL_NUM + 2);
	memcpy(doe_to->spec, doe_from->spec, len);
	doe_to->hash_tbl_cnt = doe_from->hash_tbl_cnt;
	doe_to->user_tbl_used = doe_from->user_tbl_used;

	ys_k2u_doe_unfix_mode(doe_from);
	ys_k2u_doe_destroy_interface(doe_from->doe_read_if);
	ys_k2u_doe_destroy_interface(doe_from->doe_write_if);

	list_del(&doe_from->list);
	ys_k2u_doe_hw_resources_uninit(doe_from);
	ys_wr32(doe_to->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x0);
	ys_wr32(doe_from->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x0);

	doe_from->enble_doe_schedule = false;
	doe_to->enble_doe_schedule = false;
	kfree(doe_from);

	return ys_k2u_doe_add_cdev(pdev);
}

int ys_k2u_doe_aux_probe(struct auxiliary_device *auxdev)
{
	int ret;
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct pci_dev *pdev = adev->pdev;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_k2u_doe_device *ys_k2u_doe;
	struct ys_doe_ops *auxdev_ops;
	u32 val;

	ys_k2u_doe = kzalloc(sizeof(*ys_k2u_doe), GFP_KERNEL);
	if (!ys_k2u_doe)
		return -ENOMEM;

	/* yusur device */
	if (pdev_priv->pdev->vendor == 0x1f47)
		ys_k2u_doe->doe_base = pdev_priv->bar_addr[0] + YS_K2U_DOE_REG_BASE;
	/* u200 */
	else if (pdev_priv->pdev->vendor == 0x10ee)
		ys_k2u_doe->doe_base = pdev_priv->bar_addr[0] + 0x800000;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_VERSION);
	if (val != YS_K2U_DOE_VERSION_NUM) {
		ys_dev_err("DOE hardware version:%x not match software version:%x.\n",
			   val, YS_K2U_DOE_VERSION_NUM);
		return -EDOM;
	}

	adev->adev_priv = ys_k2u_doe;
	ys_k2u_doe->pdev = pdev;
	auxdev_ops = &g_auxdev_ops;

	/* Interface buffer init, include cmd buffer and event queue buffer */
	ys_k2u_doe->doe_write_if =
		ys_k2u_doe_alloc_interface(ys_k2u_doe, "write", YS_K2U_DOE_WRITE_CMD_BUFFER_SIZE,
					   YS_K2U_DOE_WRITE_CMD_BUFFER_CNT, YS_K2U_DOE_IRQ_WRITE_EQ,
					   YS_K2U_DOE_WRITE_EVENTQ_ENTRY_SIZE,
					   YS_K2U_DOE_WRITE_EVENTQ_DEPTH);
	if (IS_ERR(ys_k2u_doe->doe_write_if))
		return PTR_ERR(ys_k2u_doe->doe_write_if);

	ys_k2u_doe->doe_read_if =
		ys_k2u_doe_alloc_interface(ys_k2u_doe, "read", YS_K2U_DOE_READ_CMD_BUFFER_SIZE,
					   YS_K2U_DOE_READ_CMD_BUFFER_CNT, YS_K2U_DOE_IRQ_READ_EQ,
					   YS_K2U_DOE_READ_EVENTQ_ENTRY_SIZE,
					   YS_K2U_DOE_READ_EVENTQ_DEPTH);
	if (IS_ERR(ys_k2u_doe->doe_read_if))
		return PTR_ERR(ys_k2u_doe->doe_read_if);
	ys_k2u_doe->doe_read_if->is_read = 1;

	/* DOE hardware resources init */
	ret = ys_k2u_doe_hw_resources_init(ys_k2u_doe);
	if (ret)
		return ret;

	list_add(&ys_k2u_doe->list, &ys_k2u_doe_list);

	/* init doe event and dma config */
	ret = ys_k2u_doe_reg_init(ys_k2u_doe);
	if (ret) {
		ys_dev_err("DOE register init fail %d!\n", ret);
		goto err_with_reg_init;
	}

	/* init adev ops */
	ys_k2u_doe_init_adev_ops(auxdev_ops);

	ys_dev_debug("Install DOE successfully, version %08x\n",
		    readl(ys_k2u_doe->doe_base + YS_K2U_DOE_VERSION));

	/* Set doe aux ops to adev data */
	ys_k2u_doe->auxdev_ops = auxdev_ops;
	adev->adev_extern_ops = auxdev_ops;
	pdev_priv->doe_schedule.ys_doe_schedule = ys_k2u_doe_hw_resources_move;

	/* register irq */
	ys_k2u_doe_fix_mode(ys_k2u_doe);

	return 0;

err_with_reg_init:
	list_del(&ys_k2u_doe->list);
	ys_k2u_doe_hw_resources_uninit(ys_k2u_doe);
	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_read_if);
	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_write_if);
	kfree(ys_k2u_doe);
	ys_dev_err("Install DOE fail!\n");
	return ret;
}

void ys_k2u_doe_aux_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_k2u_doe_device *ys_k2u_doe = adev->adev_priv;

	if (!ys_k2u_doe)
		return;

	ys_k2u_doe_unfix_mode(ys_k2u_doe);
	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_read_if);
	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_write_if);

	list_del(&ys_k2u_doe->list);
	ys_k2u_doe_hw_resources_uninit(ys_k2u_doe);
	kfree(ys_k2u_doe);
}

static struct hw_adapter_ops ys_k2u_doe_ops = {
	.hw_adp_add_cdev = ys_k2u_doe_add_cdev,
};

int ys_k2u_doe_pdev_init(struct ys_pdev_priv *pdev_priv)
{
	int ret;
	u32 val;
	struct ys_k2u_doe_device *ys_k2u_doe;
	struct ys_doe_ops *auxdev_ops;

	ys_k2u_doe = kzalloc(sizeof(*ys_k2u_doe), GFP_KERNEL);
	if (!ys_k2u_doe)
		return -ENOMEM;

	/* yusur device */
	if (pdev_priv->pdev->vendor == 0x1f47)
		ys_k2u_doe->doe_base = pdev_priv->bar_addr[0] + YS_K2U_DOE_REG_BASE;
	/* u200 */
	else if (pdev_priv->pdev->vendor == 0x10ee)
		ys_k2u_doe->doe_base = pdev_priv->bar_addr[0] + 0x800000;

	/* default mode is legacy */
	pdev_priv->dpu_mode = MODE_LEGACY;
	if (smart_nic)
		pdev_priv->dpu_mode = MODE_SMART_NIC;
	else if (dpu_host)
		pdev_priv->dpu_mode = MODE_DPU_HOST;
	else if (dpu_soc)
		pdev_priv->dpu_mode = MODE_DPU_SOC;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_VERSION);
	if (val != YS_K2U_DOE_VERSION_NUM) {
		ys_dev_err("DOE hardware version:%x not match software version:%x.\n",
			   val, YS_K2U_DOE_VERSION_NUM);
		return -EDOM;
	}

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_WORK_MODE);
	ys_k2u_doe->non_ddr_mode = (val != 0);
	if (pdev_priv->dpu_mode == MODE_LEGACY && ys_k2u_doe->non_ddr_mode == false) {
		ys_dev_err("DOE MODE_LEGACY must work in NON-DDR mode\n");
		return -EDOM;
	}

	//val = ys_rd32(pdev_priv->bar_addr[0], YS_K2U_FUNC_ID);
	//pdev_priv->pf_id = FIELD_GET(YS_K2U_FID_PF, val);
	//pdev_priv->vf_id = FIELD_GET(YS_K2U_FID_VF, val);

	pdev_priv->padp_priv = ys_k2u_doe;
	pdev_priv->ops = &ys_k2u_doe_ops;
	ys_k2u_doe->pdev = pdev_priv->pdev;
	auxdev_ops = &g_auxdev_ops;

	/* Interface buffer init, include cmd buffer and event queue buffer */
	ys_k2u_doe->doe_write_if =
		ys_k2u_doe_alloc_interface(ys_k2u_doe, "write", YS_K2U_DOE_WRITE_CMD_BUFFER_SIZE,
					   YS_K2U_DOE_WRITE_CMD_BUFFER_CNT, YS_K2U_DOE_IRQ_WRITE_EQ,
					   YS_K2U_DOE_WRITE_EVENTQ_ENTRY_SIZE,
					   YS_K2U_DOE_WRITE_EVENTQ_DEPTH);
	if (IS_ERR(ys_k2u_doe->doe_write_if))
		return PTR_ERR(ys_k2u_doe->doe_write_if);

	ys_k2u_doe->doe_read_if =
		ys_k2u_doe_alloc_interface(ys_k2u_doe, "read", YS_K2U_DOE_READ_CMD_BUFFER_SIZE,
					   YS_K2U_DOE_READ_CMD_BUFFER_CNT, YS_K2U_DOE_IRQ_READ_EQ,
					   YS_K2U_DOE_READ_EVENTQ_ENTRY_SIZE,
					   YS_K2U_DOE_READ_EVENTQ_DEPTH);
	if (IS_ERR(ys_k2u_doe->doe_read_if))
		return PTR_ERR(ys_k2u_doe->doe_read_if);
	ys_k2u_doe->doe_read_if->is_read = 1;

	/* DOE hardware resources init */
	ret = ys_k2u_doe_hw_resources_init(ys_k2u_doe);
	if (ret)
		return ret;

	list_add(&ys_k2u_doe->list, &ys_k2u_doe_list);

	/* init doe event and dma config */
	ret = ys_k2u_doe_reg_init(ys_k2u_doe);
	if (ret) {
		ys_dev_err("DOE register init fail %d!\n", ret);
		goto err_with_reg_init;
	}

	/* init adev ops */
	ys_k2u_doe_init_adev_ops(auxdev_ops);
	ys_k2u_doe->auxdev_ops = auxdev_ops;

	ys_dev_debug("Install DOE successfully, version %08x\n",
		    readl(ys_k2u_doe->doe_base + YS_K2U_DOE_VERSION));

	pdev_priv->doe_schedule.ys_doe_schedule = ys_k2u_doe_hw_resources_move;

	return 0;

err_with_reg_init:
	list_del(&ys_k2u_doe->list);
	ys_k2u_doe_hw_resources_uninit(ys_k2u_doe);
	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_read_if);
	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_write_if);
	kfree(ys_k2u_doe);
	ys_dev_err("Install DOE fail!\n");
	return ret;
}

void ys_k2u_doe_pdev_uninit(struct ys_pdev_priv *pdev_priv)
{
	struct ys_k2u_doe_device *ys_k2u_doe = pdev_priv->padp_priv;

	if (!ys_k2u_doe)
		return;

	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_read_if);
	ys_k2u_doe_destroy_interface(ys_k2u_doe->doe_write_if);

	list_del(&ys_k2u_doe->list);
	ys_k2u_doe_hw_resources_uninit(ys_k2u_doe);
	kfree(ys_k2u_doe);
}

static int ys_k2u_doe_get_ddr_channel(struct ys_k2u_doe_device *ys_k2u_doe,
				      struct ys_doe_table_param *param)
{
	u32 val = 0;
	u8 location = param->location;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_SYS_INFO);
	val = FIELD_GET(YS_K2U_DDR_VALID, val);

	if (ys_k2u_doe->non_ddr_mode && location == DOE_LOCATION_RAM)
		return DOE_CHANNEL_DDR0;

	if (param->tbl_type == DOE_TABLE_SMALL_ARRAY) {
		param->ddr_channel = DOE_CHANNEL_RAM;
		param->tbl_type = DOE_TABLE_NORMAL_ARRAY;
		param->is_small_array = 1;
	}

	switch (location) {
	case DOE_LOCATION_DDR:
		val &= YS_K2U_DDR_VALID_MASK;
		break;
	case DOE_LOCATION_RAM:
		return DOE_CHANNEL_RAM;
	case DOE_LOCATION_HOST_DDR:
		val &= YS_K2U_HOST_VALID_MASK;
		break;
	case DOE_LOCATION_SOC_DDR:
		val &= YS_K2U_SOC_VALID_MASK;
		break;
	}

	if (val & 0xf)
		return DOE_CHANNEL_DDR0;
	if (val & 0xf0)
		return DOE_CHANNEL_DDR1;

	return -1;
}

static void ys_k2u_doe_param_check_prepare(struct ys_k2u_doe_device *ys_k2u_doe)
{
	u32 val = 0;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_WORK_MODE);
	if (val & YS_K2U_DOE_WORKMODE_AIE) {
		ys_k2u_doe_loc_valid[DOE_TABLE_NORMAL_ARRAY][DOE_LOCATION_RAM] = 1;
		ys_k2u_doe_loc_valid[DOE_TABLE_LOCK][DOE_LOCATION_RAM] = 1;
	}
	if (val & YS_K2U_DOE_WORKMODE_LAIE)
		ys_k2u_doe_loc_valid[DOE_TABLE_SMALL_ARRAY][DOE_LOCATION_RAM] = 1;
	if (val & YS_K2U_DOE_WORKMODE_CIE)
		ys_k2u_doe_loc_valid[DOE_TABLE_COUNTER][DOE_LOCATION_RAM] = 1;
	if (val & YS_K2U_DOE_WORKMODE_MIE)
		ys_k2u_doe_loc_valid[DOE_TABLE_METER][DOE_LOCATION_RAM] = 1;
	if (val & YS_K2U_DOE_WORKMODE_HIE)
		ys_k2u_doe_loc_valid[DOE_TABLE_BIG_HASH][DOE_LOCATION_RAM] = 1;
	if (val & YS_K2U_DOE_WORKMODE_LHIE)
		ys_k2u_doe_loc_valid[DOE_TABLE_SMALL_HASH][DOE_LOCATION_RAM] = 1;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_AIE_DLEN_LIMIT);
	ys_k2u_doe_len_limit[DOE_TABLE_NORMAL_ARRAY][1] = (val & 0x1) ? 64 : 128;
	ys_k2u_doe_len_limit[DOE_TABLE_LOCK][1] = (val & 0x1) ? 64 : 128;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_HIE_DLEN_LIMIT);
	ys_k2u_doe_len_limit[DOE_TABLE_BIG_HASH][0] = (val & 0x1) ? 64 : 96;
	ys_k2u_doe_len_limit[DOE_TABLE_BIG_HASH][1] = (val & 0x1) ? 64 : 128;
}

/* doe business function */
static int ys_k2u_doe_check_create_param(struct ys_k2u_doe_device *ys_k2u_doe,
					 u8 table_id,
					 struct ys_doe_table_param *param)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	u32 val = 0;
	int channel = 0;

	/* check table id */
	if (table_id > YS_K2U_DOE_USER_TBL_NUM) {
		ys_dev_err("Invalid table ID %d!\n", table_id);
		return -EINVAL;
	}

	if (ys_k2u_doe->user_tbl_used >= YS_K2U_DOE_TBL_USED_MAX) {
		ys_dev_err("Invalid used_table:%d over limit!\n", ys_k2u_doe->user_tbl_used);
		return -EINVAL;
	}

	ys_k2u_doe_param_check_prepare(ys_k2u_doe);

	if (ys_k2u_doe->non_ddr_mode) {
		if (param->location != DOE_LOCATION_RAM) {
			ys_dev_err("Invalid table location(%d) at non ddr mode\n",
				   param->location);
			return -EINVAL;
		}
	} else if (!ys_k2u_doe_loc_valid[param->tbl_type][param->location]) {
		ys_dev_err("Invalid table type(%d) with location(%d)\n",
			   param->tbl_type, param->location);
		return -EINVAL;
	}

	if (param->key_len > ys_k2u_doe_len_limit[param->tbl_type][0] ||
	    param->dov_len > ys_k2u_doe_len_limit[param->tbl_type][1]) {
		ys_dev_err("Invalid tbl spec. type:%d, key_len=%d, dov_len=%d",
			   param->tbl_type, param->key_len, param->dov_len);
		return -EINVAL;
	}

	if ((param->tbl_type == DOE_TABLE_BIG_HASH || param->tbl_type == DOE_TABLE_SMALL_HASH) &&
	    !param->sdepth) {
		ys_dev_err("Invalid tbl spec. sdepth must greater than 0 when create hash table!");
		return -EINVAL;
	}

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_SYS_INFO);
	val = FIELD_GET(YS_K2U_DDR_VALID, val);

	if (!(val & YS_K2U_DDR_VALID_MASK) && param->location == YS_DOE_LOCATION_DDR) {
		ys_dev_err("Invalid ddr channel. board ddr is not exits, error!");
		return -EINVAL;
	}

	if (param->ddr_mode == 1 && (!(val & 0xf) || !(val & 0xf0))) {
		ys_dev_err("Invalid ddr channel. load balancer enable but not set 2 ddr channel!");
		return -EINVAL;
	}

	if (!(val & YS_K2U_HOST_VALID_MASK) && param->location == DOE_LOCATION_HOST_DDR) {
		ys_dev_err("Invalid ddr channel. host ddr is not exits, error!");
		return -EINVAL;
	}

	if (!(val & YS_K2U_SOC_VALID_MASK) && param->location == DOE_LOCATION_SOC_DDR) {
		ys_dev_err("Invalid ddr channel. host ddr is not exits, error!");
		return -EINVAL;
	}

	if (val != 0 && ys_k2u_doe->non_ddr_mode) {
		ys_dev_err("Invalid ddr channel. have ddr channel but non_ddr_mode is enable!");
		return -EINVAL;
	}

	channel = ys_k2u_doe_get_ddr_channel(ys_k2u_doe, param);
	if (channel < 0) {
		ys_dev_err("Invalid channel(%d) with location(%d)\n",
			   channel, param->location);
		return -EINVAL;
	}

	return 0;
}

static int ys_k2u_doe_check_delete_param(struct ys_k2u_doe_device *ys_k2u_doe,
					 u8 table_id, struct ys_doe_sw_cmd *sw_cmd)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct ys_doe_table_param *param = NULL;

	if (table_id >= YS_K2U_DOE_USER_TBL_NUM ||
	    !test_and_clear_bit(table_id, ys_k2u_doe->tbl_bitmap)) {
		ys_dev_info("Delete table ID %d is unavailable!\n", table_id);
		return -EINVAL;
	}

	param = &ys_k2u_doe->param[table_id];
	if (sw_cmd->opcode == YS_DOE_SW_DELETE_ARRAY &&
	    (param->tbl_type == DOE_TABLE_BIG_HASH || param->tbl_type == DOE_TABLE_SMALL_HASH)) {
		ys_dev_info("DELETE_ARRAY Instruction, but table %d is HASH table!\n", table_id);
		return -EINVAL;
	}

	if (sw_cmd->opcode == YS_DOE_SW_DELETE_HASH &&
	    (param->tbl_type != DOE_TABLE_BIG_HASH && param->tbl_type != DOE_TABLE_SMALL_HASH)) {
		ys_dev_info("DELETE_HASH Instruction, but table %d is ARRAY table!\n", table_id);
		return -EINVAL;
	}

	return 0;
}

int ys_k2u_doe_sw_cmd_valid(struct ys_k2u_doe_device *ys_k2u_doe,
			    struct ys_doe_sw_cmd *sw_cmd)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	u8 tbl_id = sw_cmd->tbl_id;
	bool is_hash;

	is_hash = false;

	switch (sw_cmd->opcode) {
	case YS_DOE_SW_RAW_CMD:
		return 0;

	/* create table */
	case YS_DOE_SW_CREATE_ARRAY:
	case YS_DOE_SW_CREATE_HASH:
		return ys_k2u_doe_check_create_param(ys_k2u_doe, tbl_id, &sw_cmd->tbl_param);

	/* delete table */
	case YS_DOE_SW_DELETE_ARRAY:
	case YS_DOE_SW_DELETE_HASH:
		return ys_k2u_doe_check_delete_param(ys_k2u_doe, tbl_id, sw_cmd);

	/* hash operation for table type check */
	case YS_DOE_SW_HASH_INSERT:
	case YS_DOE_SW_HASH_DELETE:
	case YS_DOE_SW_HASH_QUERY:
	case YS_DOE_SW_HASH_UPDATE:
	case YS_DOE_SW_HASH_SAVE:
	case YS_DOE_SW_HASH_INSERT_BATCH:
	case YS_DOE_SW_HASH_DELETE_BATCH:
	case YS_DOE_SW_HASH_QUERY_BATCH:
		is_hash = true;
		break;

	case YS_DOE_SW_ARRAY_LOAD:
	case YS_DOE_SW_ARRAY_STORE:
	case YS_DOE_SW_ARRAY_WRITE:
	case YS_DOE_SW_ARRAY_READ:
		if (ys_k2u_doe->param[tbl_id].depth &&
		    sw_cmd->index >= ys_k2u_doe->param[tbl_id].depth)
			return -EINVAL;
		break;

	case YS_DOE_SW_HW_INIT:
	case YS_DOE_SW_SET_PROTECT:
	case YS_DOE_SW_GET_PROTECT:
	case YS_DOE_SW_GET_CHANNEL_LOCATION:
		return 0;

	case YS_DOE_SW_GET_TABLE_VALID:
		if (tbl_id >= YS_K2U_DOE_USER_TBL_NUM)
			return -EINVAL;
		return 0;
	default:
		break;
	}

	if (tbl_id >= YS_K2U_DOE_USER_TBL_NUM ||
	    !test_bit(tbl_id, ys_k2u_doe->tbl_bitmap) ||
	    (is_hash != !!ys_k2u_doe->param[tbl_id].key_len)) {
		ys_dev_err("Error tbl ID %d!\n", tbl_id);
		return -EINVAL;
	}

	return 0;
}

int ys_k2u_doe_table_existed(u32 card_id, u8 table_id)
{
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);

	if (!ys_k2u_doe)
		return -ENXIO;

	return test_bit(table_id, ys_k2u_doe->tbl_bitmap);
}

static void *ys_k2u_doe_address_map(unsigned long uaddr, u32 size,
				    u32 *nr_pages_p, struct page ***pages_p)
{
	s32 nr_pages, nr_pinned;
	struct page **pages;
	unsigned long offset;
	void *addr;
	int ret, i;

	/* get the page offset and number */
	offset = uaddr & (PAGE_SIZE - 1);
	nr_pages = (size + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;

	pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	/* get physical pages */
	nr_pinned = get_user_pages_fast(uaddr - offset, nr_pages, 0, pages);
	if (nr_pinned != nr_pages) {
		ret = -EFAULT;
		goto err_with_get_pages;
	}

	/* vmap to kernel */
	addr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!addr) {
		ret = -ENOMEM;
		goto err_with_vmap;
	}
	addr += offset;

	*pages_p = pages;
	*nr_pages_p = nr_pages;

	return addr;

err_with_vmap:
err_with_get_pages:
	if (pages && nr_pinned > 0) {
		for (i = 0; i < nr_pinned; i++)
			put_page((pages)[i]);
	}
	kfree(pages);

	return ERR_PTR(ret);
}

static void ys_k2u_doe_address_unmap(void *addr, u32 nr_pages,
				     struct page **pages)
{
	int i;
	unsigned long offset;

	offset = (u64)addr & (PAGE_SIZE - 1);
	addr -= offset;

	vunmap(addr);
	for (i = 0; i < nr_pages; i++)
		put_page((pages)[i]);
	kfree(pages);
}

struct ys_doe_sw_cmd *
ys_k2u_doe_sw_cmd_prepare(struct ys_k2u_doe_device *ys_k2u_doe,
			  unsigned long arg)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct ys_doe_sw_cmd *sw_cmd;
	struct ys_doe_sw_cmd temp_cmd = {0};
	const void *raw_cmd;
	u32 batch_koi_len = 0;
	u32 batch_pair_len = 0;
	u8 key_len, dov_len;
	int ret;
	struct page ***pages;
	struct ys_k2u_doe_interface *doe_if;

	if (copy_from_user(&temp_cmd, (const void *)arg, sizeof(temp_cmd))) {
		ret = -EIO;
		goto err_with_io_cmd;
	}

	if (temp_cmd.is_read)
		doe_if = ys_k2u_doe->doe_read_if;
	else
		doe_if = ys_k2u_doe->doe_write_if;

	sw_cmd = ys_k2u_doe_alloc_cmd(doe_if);
	if (!sw_cmd)
		return ERR_PTR(-ENOMEM);
	memcpy(sw_cmd, &temp_cmd, sizeof(temp_cmd));

	ret = ys_k2u_doe_sw_cmd_valid(ys_k2u_doe, sw_cmd);
	if (ret)
		goto err_with_sw_cmd;

	key_len = ys_k2u_doe->param[sw_cmd->tbl_id].key_len;
	dov_len = ys_k2u_doe->param[sw_cmd->tbl_id].dov_len;
	INIT_LIST_HEAD(&sw_cmd->cache_list);

	/* Init number of pages to zero. set when batch operations */
	sw_cmd->koi_nr_pages = 0;
	sw_cmd->pair_nr_pages = 0;

	switch (sw_cmd->opcode) {
	case YS_DOE_SW_CREATE_ARRAY:
	case YS_DOE_SW_CREATE_HASH:
		ret = ys_k2u_doe_get_ddr_channel(ys_k2u_doe, &sw_cmd->tbl_param);
		sw_cmd->tbl_param.ddr_channel = ret;
		break;
	/* user raw cmd */
	case YS_DOE_SW_RAW_CMD:
		raw_cmd = (const void *)(sw_cmd->cmd);
		sw_cmd->cmd = kzalloc(sw_cmd->cmd_size, GFP_KERNEL);
		if (!sw_cmd->cmd) {
			ret = -ENOMEM;
			goto err_with_sw_cmd;
		}

		if (copy_from_user(sw_cmd->cmd, raw_cmd, sw_cmd->cmd_size)) {
			ret = -EIO;
			goto err_with_raw_cmd;
		}
		ys_dev_debug("Recive raw cmd opc 0x%x tbl %d\n",
			     *(u8 *)sw_cmd->cmd, *(u8 *)(sw_cmd->cmd + 1));
		return sw_cmd;

	/* batch operations */
	case YS_DOE_SW_ARRAY_STORE_BATCH:
	case YS_DOE_SW_HASH_INSERT_BATCH:
	case YS_DOE_SW_COUNTER_LOAD:
		batch_pair_len =
			sw_cmd->cnt * ((key_len ? key_len : 4) + dov_len);
		break;

	case YS_DOE_SW_HASH_DELETE_BATCH:
		batch_koi_len = sw_cmd->cnt * (key_len ? key_len : 4);
		break;

	case YS_DOE_SW_ARRAY_LOAD_BATCH:
	case YS_DOE_SW_HASH_QUERY_BATCH:
		batch_koi_len = sw_cmd->cnt * (key_len ? key_len : 4);
		batch_pair_len =
			sw_cmd->cnt * ((key_len ? key_len : 4) + dov_len);
		break;

	default:
		break;
	}

	if (batch_koi_len) {
		pages = (struct page ***)&sw_cmd->koi_pages;
		sw_cmd->koi_list = ys_k2u_doe_address_map((unsigned long)sw_cmd->koi_list,
							  batch_koi_len,
							  &sw_cmd->koi_nr_pages,
							  pages);
		if (IS_ERR(sw_cmd->koi_list)) {
			ret = PTR_ERR(sw_cmd->koi_list);
			goto err_with_koi_map;
		}
	}

	if (batch_pair_len) {
		pages = (struct page ***)&sw_cmd->pair_pages;
		sw_cmd->pair_list = ys_k2u_doe_address_map((unsigned long)sw_cmd->pair_list,
							   batch_pair_len,
							   &sw_cmd->pair_nr_pages,
							   pages);
		if (IS_ERR(sw_cmd->pair_list)) {
			ret = PTR_ERR(sw_cmd->pair_list);
			goto err_with_pair_map;
		}
	}

	ys_k2u_doe_get_table_lock(ys_k2u_doe, sw_cmd);

	ys_dev_debug("Recive cmd opc 0x%x tbl %d\n", sw_cmd->opcode,
		     sw_cmd->tbl_id);

	return sw_cmd;

err_with_pair_map:
	if (sw_cmd->pair_nr_pages)
		ys_k2u_doe_address_unmap(sw_cmd->pair_list,
					 sw_cmd->pair_nr_pages,
					 (struct page **)sw_cmd->pair_pages);
err_with_koi_map:
err_with_raw_cmd:
	if (sw_cmd->opcode == YS_DOE_SW_RAW_CMD)
		kfree(sw_cmd->cmd);
err_with_sw_cmd:
	ys_k2u_doe_free_cmd(doe_if, sw_cmd);
err_with_io_cmd:
	return ERR_PTR(ret);
}

static int ys_k2u_doe_clean_cache_data(struct ys_k2u_doe_device *ys_k2u_doe,
				       u8 tbl_id,
				       struct ys_doe_table_param *param)
{
	u32 val;
	void __iomem *addr;

	addr = ys_k2u_doe->doe_base +
	       ys_k2u_doe_tbl_del_offset[param->tbl_type];
	ys_k2u_doe_writel(ys_k2u_doe, (tbl_id << 8) | 1, addr);

	return readl_poll_timeout_atomic(addr, val, !(val & 0x1), 100, 100000);
}

static int ys_k2u_doe_cache_reset(struct ys_k2u_doe_device *ys_k2u_doe)
{
	int i, ret;
	u32 val;
	void __iomem *addr;

	for (i = 0; i < ARRAY_SIZE(ys_k2u_doe_reset_offset); ++i) {
		addr = ys_k2u_doe->doe_base + ys_k2u_doe_reset_offset[i];
		ys_k2u_doe_writel(ys_k2u_doe, 1, addr);

		pr_debug("DOE reset. doe_base=%p, offset=%llx, value:%u\n", ys_k2u_doe->doe_base, ys_k2u_doe_reset_offset[i], 1);
		ret = readl_poll_timeout_atomic(addr, val, !(val & 0x1), 100, 500000);
		if (ret) {
			pr_debug("DOE reset failed. doe_base=%p, offset=%llx\n",
				ys_k2u_doe->doe_base,
				ys_k2u_doe_reset_offset[i]);
			return ret;
		}
	}

	return 0;
}

int ys_k2u_doe_sw_cmd_unprepare(struct ys_k2u_doe_device *ys_k2u_doe,
				struct ys_doe_sw_cmd *sw_cmd, int err, int kc)
{
	int ret = 0;
	struct ys_k2u_doe_interface *doe_if;

	if (sw_cmd->is_read)
		doe_if = ys_k2u_doe->doe_read_if;
	else
		doe_if = ys_k2u_doe->doe_write_if;

	switch (sw_cmd->opcode) {
	case YS_DOE_SW_HW_INIT:
	case YS_DOE_SW_RAW_CMD:
		break;
	case YS_DOE_SW_CREATE_ARRAY:
	case YS_DOE_SW_CREATE_HASH:
	case YS_DOE_SW_DELETE_ARRAY:
	case YS_DOE_SW_DELETE_HASH:
		up_write(&ys_k2u_doe->mutex);
		ret = err;
		break;
	default:
		up_read(&ys_k2u_doe->mutex);
		ret = err;
		break;
	}

	if (kc)
		return ret;

	if (sw_cmd->pair_nr_pages)
		ys_k2u_doe_address_unmap(sw_cmd->pair_list,
					 sw_cmd->pair_nr_pages,
					 (struct page **)sw_cmd->pair_pages);
	if (sw_cmd->koi_nr_pages)
		ys_k2u_doe_address_unmap(sw_cmd->koi_list, sw_cmd->koi_nr_pages,
					 (struct page **)sw_cmd->koi_pages);
	if (sw_cmd->opcode == YS_DOE_SW_RAW_CMD)
		kfree(sw_cmd->cmd);
	ys_k2u_doe_free_cmd(doe_if, sw_cmd);

	return ret;
}

static struct ys_k2u_doe_mm *
ys_k2u_doe_get_mm(struct ys_k2u_doe_device *ys_k2u_doe, u8 ddr_channel)
{
	if (ddr_channel == DOE_CHANNEL_DDR0)
		return ys_k2u_doe->ddr0;
	else if (ddr_channel == DOE_CHANNEL_DDR1)
		return ys_k2u_doe->ddr1;
	else if (ddr_channel == DOE_CHANNEL_RAM)
		return ys_k2u_doe->ram;

	return NULL;
}

static int ys_k2u_doe_create_hashtbl(struct ys_k2u_doe_device *ys_k2u_doe,
				     u8 table_id,
				     struct ys_doe_table_param *param)
{
	struct ys_k2u_doe_table_spec *spec;
	struct ys_k2u_doe_table_spec *flush_spec =
		&ys_k2u_doe->spec[YS_K2U_DOE_HASH_FLUSH_TABLE];
	struct ys_doe_table_param *flush_param =
		&ys_k2u_doe->param[YS_K2U_DOE_HASH_FLUSH_TABLE];
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	int ret = 0;
	u64 tbl_len;
	u32 size, index_mask, ddr_channel, total_depth;
	s64 addr;
	u32 index_ddr_channel;
	struct ys_k2u_doe_mm *hash_index_mm, *hash_data_mm;

	if (ys_k2u_doe->hash_tbl_cnt >= ys_k2u_doe->hash_tbl_max) {
		ys_dev_err("Hash table count exceeded the upper limit!\n");
		return -EINVAL;
	}

	if (test_and_set_bit(table_id, ys_k2u_doe->tbl_bitmap)) {
		ys_dev_err("Create hash table ID %d is unavailable!\n", table_id);
		return -EINVAL;
	}

	spec = &ys_k2u_doe->spec[table_id];
	hash_data_mm = ys_k2u_doe_get_mm(ys_k2u_doe, param->ddr_channel);
	if (!hash_data_mm) {
		ret = -EINVAL;
		goto err_with_table_bit;
	}

	index_ddr_channel = ys_k2u_doe->spec[YS_K2U_DOE_INDEX_RES_TABLE].miu_param.ddr_channel;
	hash_index_mm = ys_k2u_doe_get_mm(ys_k2u_doe, index_ddr_channel);
	ddr_channel = param->ddr_channel;

	ys_k2u_doe->hash_tbl_cnt++;
	ys_k2u_doe->user_tbl_used++;

	/* calculate item size */
	size = param->key_len + param->dov_len + 32;

	index_mask = roundup_pow_of_two(param->depth) - 1;

	/* init hie_param special table */
	spec->miu_param.item_len = cpu_to_le16(size);
	spec->miu_param.item_size = ys_k2u_doe_get_order(size);
	spec->miu_param.ddr_channel = ddr_channel;
	spec->miu_param.endian = param->endian;
	spec->miu_param.ddr_mode = param->ddr_mode;
	spec->hie_param.item_size = spec->miu_param.item_size;

	spec->hie_param.key_len = cpu_to_le16(param->key_len);
	spec->hie_param.value_len = cpu_to_le16(param->dov_len);
	spec->hie_param.index_mask = cpu_to_le32(index_mask);
	spec->hie_param.ddr_channel = ddr_channel;
	spec->hie_param.valid = 1;
	spec->hie_param.tbl_type = param->tbl_type;
	spec->hie_param.endian = param->endian;
	spec->hie_param.ddr_mode = param->ddr_mode;
	spec->hie_param.mdepth = param->depth;
	spec->hie_param.sdepth = param->sdepth;
	spec->hie_param.chain_limit = param->chain_limit;
	/* set hash seed */
	if (!param->hash_seed)
		param->hash_seed = 0xffff;
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_AIE_HASH_SEED, param->hash_seed);
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_HIE_HASH_SEED, param->hash_seed);
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_LHIE_HASH_SEED, param->hash_seed);
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_CIE_HASH_SEED, param->hash_seed);
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_MIE_HASH_SEED, param->hash_seed);

	/* calculate table size, include main and sub table */
	total_depth = param->depth + param->sdepth;
	if (param->ddr_mode == 0) {
		tbl_len = total_depth * (1 << spec->hie_param.item_size);
		addr = ys_k2u_doe_malloc(hash_data_mm, tbl_len);
		if (addr == -ENOMEM) {
			ys_dev_info("Insufficient ddr0 for 0x%llx Bytes!\n", tbl_len);
			ret = -ENOMEM;
			goto err_with_table;
		}

		/* init miu_param special table */
		spec->miu_param.ddr_base_high = (u8)(addr >> 32);
		spec->miu_param.ddr_base_low = cpu_to_le32((u32)addr);

		spec->miu_param.ddr_base_high1 = 0;
		spec->miu_param.ddr_base_low1 = 0;
	} else if (param->ddr_mode == 1) {
		tbl_len = DIV_ROUND_UP(total_depth, 2) *
		       (1 << spec->hie_param.item_size);
		addr = ys_k2u_doe_malloc(ys_k2u_doe->ddr0, tbl_len);
		if (addr == -ENOMEM) {
			ys_dev_info("Insufficient ddr0 for 0x%llx Bytes!\n", tbl_len);
			ret = -ENOMEM;
			goto err_with_table;
		}

		/* init miu_param special table */
		spec->miu_param.ddr_base_high = (u8)(addr >> 32);
		spec->miu_param.ddr_base_low = cpu_to_le32((u32)addr);

		tbl_len = (total_depth >> 1) * (1 << spec->hie_param.item_size);
		addr = ys_k2u_doe_malloc(ys_k2u_doe->ddr1, tbl_len);
		if (addr == -ENOMEM) {
			ys_dev_info("Insufficient ddr1 for 0x%llx Bytes!\n", tbl_len);
			ret = -ENOMEM;
			goto err_with_table1;
		}

		/* init miu_param special table */
		spec->miu_param.ddr_base_high1 = (u8)(addr >> 32);
		spec->miu_param.ddr_base_low1 = cpu_to_le32((u32)addr);
	}

	/* Resetting table parameters for each initialization */
	/* TODO: add lock to protect flush table */
	//flush_param->depth = (param->index_mask << 1) + 1;
	flush_param->dov_len = param->key_len + param->dov_len + 32;
	flush_spec->miu_param.item_len = spec->miu_param.item_len;
	flush_spec->miu_param.item_size = spec->miu_param.item_size;
	flush_spec->miu_param.ddr_base_high = spec->miu_param.ddr_base_high;
	flush_spec->miu_param.ddr_base_low = spec->miu_param.ddr_base_low;
	flush_spec->miu_param.ddr_channel = ddr_channel;
	flush_spec->miu_param.endian = param->endian;
	flush_spec->miu_param.ddr_mode = param->ddr_mode;
	flush_spec->miu_param.ddr_base_high1 = spec->miu_param.ddr_base_high1;
	flush_spec->miu_param.ddr_base_low1 = spec->miu_param.ddr_base_low1;

	flush_spec->aie_param.item_size = spec->miu_param.item_size;
	flush_spec->aie_param.data_len = spec->miu_param.item_len;
	flush_spec->aie_param.valid = 1;
	flush_spec->aie_param.depth =
		spec->hie_param.mdepth + spec->hie_param.sdepth;
	flush_spec->aie_param.tbl_type = 0;
	flush_spec->aie_param.ddr_mode = param->ddr_mode;
	flush_spec->aie_param.endian = param->endian;
	flush_spec->aie_param.ddr_channel = ddr_channel;

	flush_spec->cache_param.ddr_mode = param->ddr_mode;
	flush_spec->cache_param.big_mode = param->endian;
	flush_spec->cache_param.ddr_channel = ddr_channel;
	flush_spec->cache_param.tbl_type = 0;
	flush_spec->cache_param.valid = 1;
	flush_spec->cache_param.data_len = param->key_len + param->dov_len + 32;
	flush_spec->cache_param.key_len = 0;
	flush_spec->cache_param.depth =
		spec->hie_param.mdepth + spec->hie_param.sdepth;
	flush_spec->cache_param.item_size = spec->miu_param.item_size;

	/* alloc index sram resources */
	tbl_len = param->index_sram_size;
	addr = ys_k2u_doe_malloc(ys_k2u_doe->index_sram, tbl_len);
	if (addr == -ENOMEM) {
		ys_dev_info("Insufficient index sram for 0x%llx Bytes!\n", tbl_len);
		ret = -ENOMEM;
		goto err_with_index_sram;
	}
	spec->index_param.ram_physic_base = cpu_to_le16((u16)addr);

	/* alloc index ddr resources in array_ddr1 */
	tbl_len = param->sdepth * 4;
	addr = ys_k2u_doe_malloc(hash_index_mm, tbl_len);
	if (addr == -ENOMEM) {
		ys_dev_info("Insufficient hash_index_mm for 0x%llx Bytes!\n", tbl_len);
		ret = -ENOMEM;
		goto err_with_index_ddr;
	}

	/* Init index_param special table */
	spec->index_param.ddr_physic_base = cpu_to_le32((u32)(addr >> 8));
	spec->index_param.ram_point = 0;
	spec->index_param.ddr_point = 0;
	spec->index_param.ddr_state = 0;

	/* init cache_param special table */
	spec->cache_param.ddr_mode = param->ddr_mode;
	spec->cache_param.big_mode = param->endian;
	spec->cache_param.ddr_channel = ddr_channel;
	spec->cache_param.tbl_type = param->tbl_type;
	spec->cache_param.valid = 1;
	spec->cache_param.data_len = spec->hie_param.value_len;
	spec->cache_param.key_len = spec->hie_param.key_len;
	spec->cache_param.depth = 0;
	spec->cache_param.item_size = spec->miu_param.item_size;

	spec->flush_param.start = 0;
	spec->flush_param.total =
		spec->hie_param.mdepth + spec->hie_param.sdepth;
	spec->flush_param.debug = 0;

	memcpy(&ys_k2u_doe->param[table_id], param, sizeof(*param));

	ys_dev_debug("Create hash table %d: %d+%d(2^%d) * 0x%x\n", table_id,
		     param->key_len, param->dov_len, spec->hie_param.item_size,
		     param->depth);
	return 0;

err_with_index_ddr:
	addr = le16_to_cpu(spec->index_param.ram_physic_base);
	ys_k2u_doe_free(ys_k2u_doe->index_sram, addr);
err_with_index_sram:
	addr = (s64)spec->miu_param.ddr_base_high << 32;
	addr |= le32_to_cpu(spec->miu_param.ddr_base_low);
	ys_k2u_doe_free(hash_data_mm, addr);
err_with_table1:
	if (param->ddr_mode == 1) {
		addr = (s64)spec->miu_param.ddr_base_high1 << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low1);
		ys_k2u_doe_free(hash_data_mm, addr);
	}
err_with_table:
	ys_k2u_doe->hash_tbl_cnt--;
	ys_k2u_doe->user_tbl_used--;

err_with_table_bit:
	clear_bit(table_id, ys_k2u_doe->tbl_bitmap);

	return ret;
}

static int ys_k2u_doe_delete_hashtbl(struct ys_k2u_doe_device *ys_k2u_doe,
				     u8 table_id,
				     struct ys_doe_table_param *param)
{
	struct ys_k2u_doe_table_spec *spec;
	s64 addr;
	u32 index_ddr_channel;
	struct ys_k2u_doe_mm *index_mm, *data_mm;

	spec = &ys_k2u_doe->spec[table_id];

	ys_k2u_doe->hash_tbl_cnt--;
	ys_k2u_doe->user_tbl_used--;
	data_mm = ys_k2u_doe_get_mm(ys_k2u_doe, param->ddr_channel);
	index_ddr_channel = ys_k2u_doe->spec[YS_K2U_DOE_INDEX_RES_TABLE].miu_param.ddr_channel;
	index_mm = ys_k2u_doe_get_mm(ys_k2u_doe, index_ddr_channel);
	spec->hie_param.valid = 0;
	spec->aie_param.valid = 0;
	spec->cache_param.valid = 0;

	/* free index ddr */
	addr = (s64)le32_to_cpu(spec->index_param.ddr_physic_base) << 8;
	ys_k2u_doe_free(index_mm, addr);

	/* free index sram */
	addr = le16_to_cpu(spec->index_param.ram_physic_base);
	ys_k2u_doe_free(ys_k2u_doe->index_sram, addr);

	if (param->ddr_mode) {
		addr = (s64)spec->miu_param.ddr_base_high << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low);
		ys_k2u_doe_free(ys_k2u_doe->ddr0, addr);

		addr = (s64)spec->miu_param.ddr_base_high1 << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low1);
		ys_k2u_doe_free(ys_k2u_doe->ddr1, addr);
	} else {
		addr = (s64)spec->miu_param.ddr_base_high << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low);
		ys_k2u_doe_free(data_mm, addr);
	}
	memset(&spec->miu_param, 0, sizeof(spec->miu_param));
	memset(&spec->hie_param, 0, sizeof(spec->hie_param));
	memset(&spec->aie_param, 0, sizeof(spec->aie_param));
	memset(&spec->cache_param, 0, sizeof(spec->cache_param));

	return 0;
}

static int ys_k2u_doe_create_arraytbl(struct ys_k2u_doe_device *ys_k2u_doe,
				      u8 table_id,
				      struct ys_doe_table_param *param)
{
	struct ys_k2u_doe_table_spec *spec;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	int ret = 0;
	s64 tbl_len;
	u32 item_len, align_size, item_size;
	u32 size, ddr_channel;
	s64 addr;
	struct ys_k2u_doe_mm *array_mm;

	if (test_and_set_bit(table_id, ys_k2u_doe->tbl_bitmap)) {
		ys_dev_err("Create array table ID %d is unavailable!\n", table_id);
		return -EINVAL;
	}

	spec = &ys_k2u_doe->spec[table_id];

	/* calculate item size */
	size = param->dov_len;
	array_mm = ys_k2u_doe_get_mm(ys_k2u_doe, param->ddr_channel);
	if (!array_mm) {
		ret = -EINVAL;
		goto err_with_table_bit;
	}

	ys_k2u_doe->user_tbl_used++;
	item_len = param->dov_len;

	if (param->ddr_channel == DOE_CHANNEL_RAM) {
		align_size = ALIGN(item_len, 8);
		tbl_len = param->depth * align_size;
	} else {
		align_size = ALIGN(item_len, 64);
		tbl_len = param->depth * align_size;
	}

	item_size = ilog2(roundup_pow_of_two(align_size));

	if (param->ddr_channel == DOE_CHANNEL_RAM)
		item_size = item_size < 3 ? 3 : item_size;
	else
		item_size = item_size < 6 ? 6 : item_size;

	ddr_channel = param->ddr_channel;

	/* init aie_param special table */
	spec->miu_param.item_len = cpu_to_le16(size);
	spec->miu_param.item_size = item_size;
	spec->miu_param.ddr_channel = ddr_channel;
	spec->miu_param.endian = param->endian;
	spec->miu_param.ddr_mode = param->ddr_mode;
	spec->aie_param.item_size = spec->miu_param.item_size;
	spec->aie_param.data_len = spec->miu_param.item_len;
	spec->aie_param.ddr_channel = ddr_channel;
	spec->aie_param.valid = 1;

	spec->aie_param.depth = param->depth;
	spec->aie_param.tbl_type = param->tbl_type;
	spec->aie_param.endian = param->endian;
	spec->aie_param.ddr_mode = param->ddr_mode;

	if (param->ddr_mode == 1) {
		tbl_len = DIV_ROUND_UP(param->depth, 2) * align_size;
		addr = ys_k2u_doe_malloc(ys_k2u_doe->ddr0, tbl_len);
		if (addr == -ENOMEM) {
			ys_dev_info("Insufficient ddr0 dor 0x%llx bytes!\n",
				    tbl_len);
			ret = -ENOMEM;
			goto err_with_table;
		}
		ys_dev_debug("Alloc 0x%llx DDR0 at 0x%llx for array table %d\n",
			     tbl_len, addr, table_id);

		/* init miu_param special table */
		spec->miu_param.ddr_base_high = (u8)(addr >> 32);
		spec->miu_param.ddr_base_low = cpu_to_le32((u32)addr);

		tbl_len = (param->depth >> 1) * align_size;
		addr = ys_k2u_doe_malloc(ys_k2u_doe->ddr1, tbl_len);
		if (addr == -ENOMEM) {
			ys_dev_info("Insufficient ddr1 for 0x%llx bytes!\n",
				    tbl_len);
			ret = -ENOMEM;
			goto err_with_table1;
		}
		ys_dev_debug("Alloc 0x%llx DDR1 at 0x%llx for array table %d\n",
			     tbl_len, addr, table_id);

		spec->miu_param.ddr_base_high1 = (u8)(addr >> 32);
		spec->miu_param.ddr_base_low1 = cpu_to_le32((u32)addr);
	} else if (param->ddr_mode == 0) {
		addr = ys_k2u_doe_malloc(array_mm, tbl_len);
		if (addr == -ENOMEM) {
			ys_dev_info("Insufficient %s for 0x%llx bytes!\n",
				    array_mm->name, tbl_len);
			ret = -ENOMEM;
			goto err_with_table;
		}
		ys_dev_debug("Alloc 0x%llx %s at 0x%llx for array table %d\n",
			     tbl_len, array_mm->name, addr, table_id);

		spec->miu_param.ddr_base_high = (u8)(addr >> 32);
		spec->miu_param.ddr_base_low = cpu_to_le32((u32)addr);
		spec->miu_param.ddr_base_high1 = 0;
		spec->miu_param.ddr_base_low1 = 0;
	}

	/* init cache_param special table */
	spec->cache_param.ddr_channel = ddr_channel;
	spec->cache_param.big_mode = param->endian;
	spec->cache_param.tbl_type = param->tbl_type;
	spec->cache_param.valid = 1;
	spec->cache_param.ddr_mode = param->ddr_mode;
	spec->cache_param.data_len = spec->miu_param.item_len;
	spec->cache_param.key_len = 0;
	spec->cache_param.depth = param->depth;
	spec->cache_param.item_size = spec->miu_param.item_size;

	spec->flush_param.start = 0;
	spec->flush_param.total = param->depth;

	memcpy(&ys_k2u_doe->param[table_id], param, sizeof(*param));

	ys_dev_debug("Create array table %d: %d(2^%d) * 0x%x\n", table_id,
		     param->dov_len, spec->aie_param.item_size,
		     param->depth + 1);

	return 0;

err_with_table1:
	if (param->ddr_mode == 0) {
		addr = (s64)spec->miu_param.ddr_base_high << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low);
		ys_k2u_doe_free(array_mm, addr);
	} else if (param->ddr_mode == 1) {
		addr = (s64)spec->miu_param.ddr_base_high << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low);
		ys_k2u_doe_free(ys_k2u_doe->ddr0, addr);
	}
err_with_table:
	ys_k2u_doe->user_tbl_used--;

err_with_table_bit:
	clear_bit(table_id, ys_k2u_doe->tbl_bitmap);

	return ret;
}

static int ys_k2u_doe_delete_arraytbl(struct ys_k2u_doe_device *ys_k2u_doe,
				      u8 table_id,
				      struct ys_doe_table_param *param)
{
	struct ys_k2u_doe_table_spec *spec;
	s64 addr;
	struct ys_k2u_doe_mm *array_mm;

	array_mm = ys_k2u_doe_get_mm(ys_k2u_doe, param->ddr_channel);

	ys_k2u_doe->user_tbl_used--;
	spec = &ys_k2u_doe->spec[table_id];
	spec->hie_param.valid = 0;
	spec->aie_param.valid = 0;
	spec->cache_param.valid = 0;

	if (param->ddr_mode) {
		addr = (s64)spec->miu_param.ddr_base_high << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low);
		ys_k2u_doe_free(ys_k2u_doe->ddr0, addr);

		addr = (s64)spec->miu_param.ddr_base_high1 << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low1);
		ys_k2u_doe_free(ys_k2u_doe->ddr1, addr);
	} else {
		addr = (s64)spec->miu_param.ddr_base_high << 32;
		addr |= le32_to_cpu(spec->miu_param.ddr_base_low);
		ys_k2u_doe_free(array_mm, addr);
	}
	memset(&spec->miu_param, 0, sizeof(spec->miu_param));
	memset(&spec->hie_param, 0, sizeof(spec->hie_param));
	memset(&spec->aie_param, 0, sizeof(spec->aie_param));
	memset(&spec->cache_param, 0, sizeof(spec->cache_param));

	return 0;
}

static int ys_k2u_doe_complete_desc(struct ys_k2u_doe_desc *desc,
				    struct ys_k2u_doe_event *event)
{
	struct ys_k2u_doe_device *ys_k2u_doe = desc->ys_k2u_doe;
	struct ys_doe_sw_cmd *parent = desc->parent;
	struct ys_doe_sw_cmd *cmd = desc->cmd;
	bool hash_read = false, array_read = false, counter_read = false;
	u16 dov_len, key_len, item_len;
	void *base, *event_data;
	struct ys_k2u_doe_interface *doe_if;
	int i;
	u32 opcode = cmd->opcode;

	if (opcode == YS_DOE_SW_RAW_CMD)
		opcode = *(u8 *)cmd->cmd;
	/* TODO: add NULL pointer judgement */
	if (opcode == YS_DOE_SW_ARRAY_LOAD ||
	    opcode == YS_DOE_SW_ARRAY_READ)
		array_read = true;
	else if (opcode == YS_DOE_SW_HASH_QUERY)
		hash_read = true;
	else if (opcode == YS_DOE_SW_COUNTER_LOAD)
		counter_read = true;

	if (desc->is_read)
		doe_if = ys_k2u_doe->doe_read_if;
	else
		doe_if = ys_k2u_doe->doe_write_if;

	dov_len = ys_k2u_doe->param[cmd->tbl_id].dov_len;
	key_len = ys_k2u_doe->param[cmd->tbl_id].key_len;

	/* If the desc is one of the batch operation */
	if (parent) {
		if (event->status != YS_K2U_DOE_STATUS_SUCCESS) {
			parent->failed++;
			if (parent->err == 0)
				parent->err = event->status;
		} else {
			base = parent->pair_list;
			if (hash_read) {
				base += parent->succeed * (dov_len + key_len);
				memcpy(base, cmd->key, key_len);
				memcpy(base + key_len, event + 1, dov_len);
			} else if (array_read) {
				base += parent->succeed * (dov_len + 4);
				*(u32 *)base = cmd->index;
				memcpy(base + 4, event + 1, dov_len);
			}

			parent->succeed++;
		}

		/* All cmd excuated, wakeup user */
		if (parent->cnt == parent->succeed + parent->failed)
			atomic_sub(1, (atomic_t *)&parent->wait_lock);

		ys_k2u_doe_free_cmd(doe_if, cmd);
	} else {
		if (event->status != YS_K2U_DOE_STATUS_SUCCESS) {
			cmd->failed++;
			if (cmd->err == 0)
				cmd->err = event->status;
		} else {
			/* For user raw debug cmd, dov-len is uninitialized */
			if (!dov_len)
				dov_len = 128;

			if (hash_read) {
				memset(cmd->value, 0, sizeof(cmd->value));
				memcpy(cmd->value, event + 1, dov_len);
			} else if (array_read) {
				memset(cmd->data, 0, sizeof(cmd->data));
				memcpy(cmd->data, event + 1, dov_len);
			} else if (counter_read) {
				item_len = dov_len + 4;
				base = cmd->pair_list;
				event_data = event + 1;

				for (i = 0; i < event->nb; i++) {
					memcpy(base, event_data, item_len);
					base += item_len;
					event_data +=
						YS_K2U_DOE_COUNTER_LOAD_STRIDE;
				}
				cmd->number = event->nb;
			}

			cmd->succeed++;
		}
		atomic_sub(1, (atomic_t *)&cmd->wait_lock);
	}

	ys_k2u_doe_free_dsc(doe_if, desc);

	return 0;
}

static int ys_k2u_doe_push_submit(struct ys_k2u_doe_device *ys_k2u_doe,
				  struct ys_doe_sw_cmd *parent)
{
	struct ys_doe_sw_cmd *cmd;
	int ret;

	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = YS_DOE_SW_CMD_PUSH;
	cmd->tbl_id = parent->tbl_id;
	cmd->index = parent->tbl_id;

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent, NULL);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}

	return 0;
}

int ys_k2u_doe_clean_push(struct ys_k2u_doe_interface *doe_if,
			  struct ys_k2u_doe_desc *desc)
{
	struct ys_doe_sw_cmd *cmd = desc->cmd;

	/* return true when opcode == YS_DOE_SW_CMD_PUSH */
	if (cmd->opcode != YS_DOE_SW_CMD_PUSH)
		return 0;

	ys_k2u_doe_free_cmd(doe_if, cmd);
	ys_k2u_doe_free_dsc(doe_if, desc);

	return 1;
}

static int ys_k2u_doe_submit_spec(struct ys_k2u_doe_device *ys_k2u_doe,
				  u8 spec_tbl, struct ys_doe_sw_cmd *parent);
int ys_k2u_doe_reset(struct ys_k2u_doe_device *ys_k2u_doe,
		     struct ys_doe_sw_cmd *parent)
{
	int i;

	ys_k2u_doe->hash_tbl_cnt = 0;
	for (i = 0; i < 0xee; ++i) {
		parent->tbl_id = CACHE_ITEM_ID(i, 0, 0);
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_CACHE_CONFIG_TABLE, parent);
		parent->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_AIE_PARAM_TABLE, parent);
		parent->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_HIE_PARAM_TABLE, parent);
		parent->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_MIU_PARAM_TABLE, parent);
		parent->cnt += 1;
	}

	return 0;
}

static int ys_k2u_doe_flush_table(struct ys_k2u_doe_device *ys_k2u_doe,
				  u32 depth, bool is_hash,
				  struct ys_doe_sw_cmd *parent)
{
	int ret;
	struct ys_doe_sw_cmd *cmd;
	struct ys_k2u_doe_table_spec *spec = &ys_k2u_doe->spec[parent->tbl_id];

	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = YS_K2U_DOE_BATCH_OP_TABLE;
	cmd->total = depth;
	cmd->independent = 1;
	if (is_hash)
		cmd->index = YS_K2U_DOE_HASH_FLUSH_TABLE;
	else
		cmd->index = parent->tbl_id;

	memcpy(cmd->data, &spec->flush_param, sizeof(spec->flush_param));

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent,
				    ys_k2u_doe_complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}

	return 0;
}

static int ys_k2u_doe_init_hash_index(struct ys_k2u_doe_device *ys_k2u_doe,
				      u32 depth, u32 sdepth,
				      struct ys_doe_sw_cmd *parent)
{
	struct ys_doe_sw_cmd *cmd;
	int ret;
	u32 i, j, index;
	u32 stride = YS_K2U_DOE_INDEX_ITEM_SIZE / 4;
	struct ys_k2u_doe_table_spec *spec = &ys_k2u_doe->spec[parent->tbl_id];
	u32 hash_index_base;

	hash_index_base = spec->index_param.ddr_physic_base;
	index = 0;

	for (i = 0; i < sdepth; i += stride) {
		cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
		if (!cmd)
			return -ENOMEM;

		cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
		cmd->tbl_id = YS_K2U_DOE_INDEX_RES_TABLE;
		cmd->index = hash_index_base + index;

		/* fill array data as index of sub-table */
		for (j = 0; j < stride; j++)
			*((u32 *)cmd->data + j) = depth + index * stride + j;

		index++;

		ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent,
					    ys_k2u_doe_complete_desc);
		if (ret) {
			ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
			return ret;
		}
	}

	return 0;
}

int ys_k2u_doe_submit_ddr_spec(struct ys_k2u_doe_device *ys_k2u_doe,
			       u8 spec_tbl, struct ys_doe_sw_cmd *parent,
			       int (*complete_desc)(struct ys_k2u_doe_desc *,
						    struct ys_k2u_doe_event *))
{
	struct ys_doe_sw_cmd *cmd;
	struct ys_k2u_doe_table_spec *spec = &ys_k2u_doe->spec[spec_tbl];
	int ret;

	/* submit miu table */
	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = YS_K2U_DOE_MIU_PARAM_TABLE;
	cmd->index = spec_tbl;
	memcpy(cmd->data, &spec->miu_param,
	       sizeof(struct ys_k2u_doe_miu_param));

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent, complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}
	ys_k2u_doe_push_submit(ys_k2u_doe, parent);

	/* submit aie table */
	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = YS_K2U_DOE_AIE_PARAM_TABLE;
	cmd->index = spec_tbl;
	memcpy(cmd->data, &spec->aie_param,
	       sizeof(struct ys_k2u_doe_aie_param));

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent, complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}
	ys_k2u_doe_push_submit(ys_k2u_doe, parent);

	/* submit internal cache table */
	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = YS_K2U_DOE_CACHE_CONFIG_TABLE;
	cmd->index = CACHE_ITEM_ID(spec_tbl, 0, 0);
	memcpy(cmd->data, &spec->cache_param,
	       sizeof(struct ys_k2u_doe_cache_param));

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent, complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}

	return 0;
}

static int ys_k2u_doe_submit_hash_flush_spec(struct ys_k2u_doe_device *ys_k2u_doe,
					     u8 spec_tbl,
					     struct ys_doe_sw_cmd *parent,
					     int (*complete_desc)(struct ys_k2u_doe_desc *,
								  struct ys_k2u_doe_event *))
{
	struct ys_doe_sw_cmd *cmd;
	struct ys_k2u_doe_table_spec *spec = &ys_k2u_doe->spec[spec_tbl];
	int ret;

	/* submit miu table */
	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = YS_K2U_DOE_MIU_PARAM_TABLE;
	cmd->index = spec_tbl;
	memcpy(cmd->data, &spec->miu_param,
	       sizeof(struct ys_k2u_doe_miu_param));

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent, complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}
	ys_k2u_doe_push_submit(ys_k2u_doe, parent);

	/* submit aie table */
	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = YS_K2U_DOE_AIE_PARAM_TABLE;
	cmd->index = spec_tbl;
	memcpy(cmd->data, &spec->aie_param,
	       sizeof(struct ys_k2u_doe_aie_param));

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent, complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}
	ys_k2u_doe_push_submit(ys_k2u_doe, parent);

	/* submit cache table */
	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = YS_K2U_DOE_CACHE_CONFIG_TABLE;
	cmd->index = CACHE_ITEM_ID(spec_tbl, 0, 0);
	memcpy(cmd->data, &spec->cache_param,
	       sizeof(struct ys_k2u_doe_cache_param));

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent, complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}

	return 0;
}

/*
 * Update spec table when creating user table
 *  @ys_k2u_doe: doe device
 *  @spec_tbl: the special table id to be updated
 *  @parent: software cmd to creat user table
 */
static int ys_k2u_doe_submit_spec(struct ys_k2u_doe_device *ys_k2u_doe,
				  u8 spec_tbl, struct ys_doe_sw_cmd *parent)
{
	struct ys_doe_sw_cmd *cmd;
	struct ys_k2u_doe_table_spec *spec = &ys_k2u_doe->spec[parent->tbl_id];
	void *data;
	u32 size, index;
	int ret;

	index = parent->tbl_id;

	switch (spec_tbl) {
	case YS_K2U_DOE_INDEX_MANAGE_TABLE:
		data = &spec->index_param;
		size = sizeof(struct ys_k2u_doe_index_param);
		break;

	case YS_K2U_DOE_AIE_PARAM_TABLE:
		data = &spec->aie_param;
		size = sizeof(struct ys_k2u_doe_aie_param);
		break;

	case YS_K2U_DOE_HIE_PARAM_TABLE:
		data = &spec->hie_param;
		size = sizeof(struct ys_k2u_doe_hie_param);
		break;

	case YS_K2U_DOE_MIU_PARAM_TABLE:
		data = &spec->miu_param;
		size = sizeof(struct ys_k2u_doe_miu_param);
		break;

	case YS_K2U_DOE_CACHE_CONFIG_TABLE:
		data = &spec->cache_param;
		size = sizeof(struct ys_k2u_doe_cache_param);
		index = CACHE_ITEM_ID(index, 0, 0);
		break;

	case YS_K2U_DOE_HASH_FLUSH_TABLE:
		return ys_k2u_doe_submit_hash_flush_spec(ys_k2u_doe,
							 YS_K2U_DOE_HASH_FLUSH_TABLE,
							 parent, ys_k2u_doe_complete_desc);
	default:
		return -EINVAL;
	}

	cmd = ys_k2u_doe_alloc_cmd(ys_k2u_doe->doe_write_if);
	if (!cmd)
		return -ENOMEM;

	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = YS_DOE_SW_ARRAY_WRITE;
	cmd->tbl_id = spec_tbl;
	cmd->index = index;
	memcpy(cmd->data, data, size);

	ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent,
				    ys_k2u_doe_complete_desc);
	if (ret) {
		ys_k2u_doe_free_cmd(ys_k2u_doe->doe_write_if, cmd);
		return ret;
	}

	return 0;
}

static int ys_k2u_doe_batch_ops(struct ys_k2u_doe_device *ys_k2u_doe,
				struct ys_doe_sw_cmd *parent)
{
	u8 opcode;
	u8 tbl_id = parent->tbl_id;
	u8 key_len, dov_len;
	u16 stride = 0;
	void *input;
	struct ys_doe_sw_cmd *cmd;
	struct ys_k2u_doe_interface *doe_if;
	int i, ret;

	if (parent->is_read)
		doe_if = ys_k2u_doe->doe_read_if;
	else
		doe_if = ys_k2u_doe->doe_write_if;

	key_len = ys_k2u_doe->param[tbl_id].key_len;
	dov_len = ys_k2u_doe->param[tbl_id].dov_len;

	/* change opcode to sub cmd */
	switch (parent->opcode) {
	case YS_DOE_SW_ARRAY_LOAD_BATCH:
		opcode = YS_DOE_SW_ARRAY_LOAD;
		input = parent->koi_list;
		break;
	case YS_DOE_SW_ARRAY_STORE_BATCH:
		opcode = YS_DOE_SW_ARRAY_STORE;
		input = parent->pair_list;
		stride = dov_len;
		break;
	case YS_DOE_SW_HASH_INSERT_BATCH:
		opcode = YS_DOE_SW_HASH_INSERT;
		input = parent->pair_list;
		stride = dov_len;
		break;
	case YS_DOE_SW_HASH_DELETE_BATCH:
		opcode = YS_DOE_SW_HASH_DELETE;
		input = parent->koi_list;
		break;
	case YS_DOE_SW_HASH_QUERY_BATCH:
		opcode = YS_DOE_SW_HASH_QUERY;
		input = parent->koi_list;
		break;
	case YS_DOE_SW_COUNTER_ENABLE_BATCH:
		opcode = YS_DOE_SW_COUNTER_ENABLE;
		input = parent->koi_list;
		break;
	default:
		return -EINVAL;
	}

	stride += key_len ? key_len : 4;

	for (i = 0; i < parent->cnt; i++) {
		/* alloc sub cmd */
		cmd = ys_k2u_doe_alloc_cmd(doe_if);
		if (!cmd)
			return -ENOMEM;

		cmd->opcode = opcode;
		cmd->tbl_id = parent->tbl_id;
		cmd->is_read = parent->is_read;

		if (opcode == YS_DOE_SW_COUNTER_ENABLE) {
			cmd->opcode = YS_K2U_DOE_ARRAY_STORE;
			cmd->enable = parent->enable;
		}

		if (!key_len)
			cmd->index = cpu_to_le32(*(u32 *)(input + i * stride));
		else
			memcpy(cmd->key, input + i * stride, key_len);

		if (opcode == YS_DOE_SW_ARRAY_STORE)
			memcpy(cmd->data, input + i * stride + 4, dov_len);

		if (opcode == YS_DOE_SW_HASH_INSERT)
			memcpy(cmd->value, input + i * stride + key_len,
			       dov_len);

		ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, parent,
					    ys_k2u_doe_complete_desc);
		if (ret) {
			ys_k2u_doe_free_cmd(doe_if, cmd);
			return ret;
		}
	}

	return 0;
}

int ys_k2u_doe_process_cmd(struct ys_k2u_doe_device *ys_k2u_doe,
			   struct ys_doe_sw_cmd *cmd)
{
	int ret;
	u32 depth, sdepth;
	u32 status;
	size_t i = 0;
	u32 card_id = ys_k2u_doe->pdev->bus->number;

	switch (cmd->opcode) {
	case YS_DOE_SW_CREATE_ARRAY:
		ret = ys_k2u_doe_create_arraytbl(ys_k2u_doe, cmd->tbl_id,
						 &cmd->tbl_param);
		if (ret)
			return ret;

		/* submit spec table */
		cmd->cnt = 0;
		if (!ys_k2u_doe->non_ddr_mode || cmd->tbl_param.is_small_array) {
			cmd->cnt += 1;
			ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_MIU_PARAM_TABLE, cmd);
			ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		}

		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_AIE_PARAM_TABLE, cmd);
		ys_k2u_doe_push_submit(ys_k2u_doe, cmd);

		/* flush tbl */
		if (!ys_k2u_doe->non_ddr_mode || cmd->tbl_param.is_small_array) {
			cmd->cnt += 1;
			depth = roundup_pow_of_two(ys_k2u_doe->param[cmd->tbl_id].depth);
			ys_k2u_doe_flush_table(ys_k2u_doe, depth, false, cmd);
			ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		}

		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe,
				       YS_K2U_DOE_CACHE_CONFIG_TABLE, cmd);
		ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		break;

	case YS_DOE_SW_DELETE_ARRAY:
		ys_k2u_doe_delete_arraytbl(ys_k2u_doe, cmd->tbl_id,
					   &ys_k2u_doe->param[cmd->tbl_id]);

		status = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG);
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x3);

		ret = ys_k2u_doe_clean_cache_data(ys_k2u_doe, cmd->tbl_id,
						  &ys_k2u_doe->param[cmd->tbl_id]);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_CACHE_CONFIG_TABLE, cmd);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_AIE_PARAM_TABLE, cmd);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_HIE_PARAM_TABLE, cmd);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_MIU_PARAM_TABLE, cmd);
		ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG, status);
		break;

	case YS_DOE_SW_CREATE_HASH:
		ret = ys_k2u_doe_create_hashtbl(ys_k2u_doe, cmd->tbl_id, &cmd->tbl_param);
		if (ret)
			return ret;

		/* calculate total sub command for this operation */
		depth = roundup_pow_of_two(ys_k2u_doe->param[cmd->tbl_id].depth);

		/*
		 * calculate total cmd number of create hash table.
		 * submit MIU、CACHE_CONFIG、INDEX_MANAGE spec table use 1 cmd.
		 * submit HASH_FLUSH spec use 3 commands.
		 * flush hash data use 1 commands.
		 * init hash index use (sdepth -1) / 64 + 1 commands.
		 * submit cache configs use 24 commands.
		 */
		sdepth = ALIGN(cmd->tbl_param.sdepth, 64);
		cmd->cnt = 0;

		/* flush tbl */
		if (!ys_k2u_doe->non_ddr_mode) {
			cmd->cnt += 3;
			ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_HASH_FLUSH_TABLE, cmd);
			ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		}

		/* submit spec table */
		if (!ys_k2u_doe->non_ddr_mode) {
			cmd->cnt += 1;
			ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_MIU_PARAM_TABLE, cmd);
			ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		}

		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_HIE_PARAM_TABLE, cmd);
		ys_k2u_doe_push_submit(ys_k2u_doe, cmd);

		if (!ys_k2u_doe->non_ddr_mode) {
			cmd->cnt += sdepth / 64;
			ys_k2u_doe_init_hash_index(ys_k2u_doe, cmd->tbl_param.depth, sdepth, cmd);
			ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		}

		/* flush tbl */
		if (!ys_k2u_doe->non_ddr_mode) {
			cmd->cnt += 1;
			ret = ys_k2u_doe_flush_table(ys_k2u_doe, depth * 2, true, cmd);
			ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		}

		/**
		 * Doe developer request to change the special table order.
		 * The index manage table must be submitted after index
		 * resource table. So the index resource can be read when
		 * the index manage table is submitted.
		 */
		if (!ys_k2u_doe->non_ddr_mode) {
			cmd->cnt += 1;
			ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_INDEX_MANAGE_TABLE, cmd);
			ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		}

		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_CACHE_CONFIG_TABLE, cmd);
		ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		break;

	case YS_DOE_SW_DELETE_HASH:
		ys_k2u_doe_delete_hashtbl(ys_k2u_doe, cmd->tbl_id,
					  &ys_k2u_doe->param[cmd->tbl_id]);

		status = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG);
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x3);
		ret = ys_k2u_doe_clean_cache_data(ys_k2u_doe, cmd->tbl_id,
						  &ys_k2u_doe->param[cmd->tbl_id]);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_CACHE_CONFIG_TABLE, cmd);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_AIE_PARAM_TABLE, cmd);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_HIE_PARAM_TABLE, cmd);
		cmd->cnt += 1;
		ys_k2u_doe_submit_spec(ys_k2u_doe, YS_K2U_DOE_MIU_PARAM_TABLE, cmd);
		ys_k2u_doe_push_submit(ys_k2u_doe, cmd);
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG, status);
		break;

	/* alloc the desc for single cmd */
	case YS_DOE_SW_ARRAY_LOAD:
	case YS_DOE_SW_ARRAY_STORE:
	case YS_DOE_SW_HASH_INSERT:
	case YS_DOE_SW_HASH_DELETE:
	case YS_DOE_SW_HASH_QUERY:
	case YS_DOE_SW_HASH_UPDATE:
	case YS_DOE_SW_HASH_SAVE:
	case YS_DOE_SW_RAW_CMD:
	case YS_DOE_SW_COUNTER_ENABLE:
	case YS_DOE_SW_COUNTER_LOAD:
		ret = ys_k2u_doe_submit_cmd(ys_k2u_doe, cmd, NULL,
					    ys_k2u_doe_complete_desc);
		if (ret)
			return ret;
		break;

	/* alloc the descs for batch cmd */
	case YS_DOE_SW_ARRAY_STORE_BATCH:
	case YS_DOE_SW_ARRAY_LOAD_BATCH:
	case YS_DOE_SW_HASH_INSERT_BATCH:
	case YS_DOE_SW_HASH_DELETE_BATCH:
	case YS_DOE_SW_HASH_QUERY_BATCH:
		ret = ys_k2u_doe_batch_ops(ys_k2u_doe, cmd);
		if (ret)
			return ret;
		break;
	case YS_DOE_SW_HW_INIT:
		mutex_lock(&ys_k2u_doe->mtx_init);
		if (!ys_k2u_doe->init) {
			ys_k2u_doe_reset(ys_k2u_doe, cmd);
			ys_k2u_doe->init = 1;
		}
		mutex_unlock(&ys_k2u_doe->mtx_init);
		break;

	case YS_DOE_SW_SET_PROTECT:
		ret = ys_k2u_doe_set_protect(card_id, cmd->enable);
		if (ret)
			return ret;
		break;

	case YS_DOE_SW_GET_PROTECT:
		ret = ys_k2u_doe_protect_status(card_id);
		if (ret < 0)
			return ret;
		cmd->enable = ret;
		break;

	case YS_DOE_SW_GET_CHANNEL_LOCATION:
		for (i = 0; i < ARRAY_SIZE(cmd->channel.locations); i++)
			cmd->channel.locations[i] = hados_doe_get_channel_type(card_id, i);
		break;

	case YS_DOE_SW_GET_TABLE_VALID:
		cmd->tbl_valid = hados_doe_tbl_existed(card_id, cmd->tbl_id);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

int ys_k2u_doe_pdev_fix_mode(struct ys_pdev_priv *priv)
{
	struct ys_k2u_doe_device *ys_k2u_doe = NULL;

	ys_k2u_doe = priv->padp_priv;
	return ys_k2u_doe_fix_mode(ys_k2u_doe);
}

void ys_k2u_doe_pdev_unfix_mode(struct ys_pdev_priv *priv)
{
	struct ys_k2u_doe_device *ys_k2u_doe = NULL;

	ys_k2u_doe = priv->padp_priv;
	ys_k2u_doe_unfix_mode(ys_k2u_doe);
}

int ys_k2u_doe_fix_mode(struct ys_k2u_doe_device *ys_k2u_doe)
{
	int ret;
	struct ys_doe_sw_cmd *init_cmd = NULL;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);

	ret = ys_k2u_doe_register_irqs(ys_k2u_doe);
	if (ret) {
		ys_err("doe register irq failed. ret=%d", ret);
		return ret;
	}

	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x1);
	ys_k2u_doe->init = 1;
	/* init DOE just when schedule_buf is NULL */
	if (pdev_priv->doe_schedule.schedule_buf)
		return 0;

	init_cmd = kzalloc(sizeof(*init_cmd), GFP_KERNEL);
	if (!init_cmd)
		return -ENOMEM;
	init_cmd->opcode = YS_DOE_SW_HW_INIT;
	INIT_LIST_HEAD(&init_cmd->cache_list);
	ys_k2u_doe_reset(ys_k2u_doe, init_cmd);
	ys_k2u_doe_polling_work(ys_k2u_doe->doe_write_if, init_cmd);
	dev_dbg(pdev_priv->dev, "fsffs");
	pr_debug("f==============");
	ret = ys_k2u_doe_cache_reset(ys_k2u_doe);
	/*
	 * submit air/miu_param for table 239 (hash index resource) which
	 * covers the entire array_ddr1 address space.
	 * index resource and table 238 (hash flush table) will be initialized
	 * at the stage of HashTBL Create.
	 */
	ret = ys_k2u_doe_submit_ddr_spec(ys_k2u_doe, YS_K2U_DOE_INDEX_RES_TABLE,
					 init_cmd, NULL);
	if (ret)
		return ret;

	ys_k2u_doe_polling_work(ys_k2u_doe->doe_write_if, init_cmd);

	return 0;
}

void ys_k2u_doe_unfix_mode(struct ys_k2u_doe_device *ys_k2u_doe)
{
	ys_k2u_doe_unregister_irqs(ys_k2u_doe);
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG, 0x3);
}

s32 ys_k2u_doe_protect_status(u32 card_id)
{
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);

	if (!ys_k2u_doe)
		return -ENXIO;

	return ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG) & 0x1;
}

s32 ys_k2u_doe_set_protect(u32 card_id, u8 status)
{
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);
	u32 val = 0;

	if (!ys_k2u_doe)
		return -ENXIO;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG);
	val &= 0x2;
	val |= (status ? 1 : 0);
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_PROTECT_CFG, val);
	if (status)
		readl_poll_timeout_atomic(ys_k2u_doe->doe_base + YS_K2U_DOE_PROTECT_ACK, val,
					  (val & 0x3f) == 0x3f, 100, 3000);

	return 0;
}

u32 ys_k2u_doe_hash_table_max(u32 card_id)
{
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);
	u32 val = 0;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_SYS_INFO);

	return FIELD_GET(YS_K2U_HASH_TLB_NUM, val);
}

u32 ys_k2u_doe_get_table_cache_entry_limit(u32 card_id, u32 tlb_type)
{
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);
	u32 val = 0;
	u32 ret = 0;

	switch (tlb_type) {
	case DOE_TABLE_NORMAL_ARRAY:
	case DOE_TABLE_LOCK:
		val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_AIE_DLEN_LIMIT);
		ret = val & 0x1 ? 2000 : 1000;
		break;
	case DOE_TABLE_SMALL_ARRAY:
		ret = YS_K2U_DOE_RAM_SIZE / ys_k2u_doe_len_limit[DOE_TABLE_SMALL_ARRAY][1];
		break;
	case DOE_TABLE_BIG_HASH:
		val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_HIE_DLEN_LIMIT);
		ret = val & 0x1 ? 2000 : 1000;
		break;
	case DOE_TABLE_SMALL_HASH:
		ret = 1000;
		break;
	case DOE_TABLE_COUNTER:
		ret = 2000;
		break;
	case DOE_TABLE_METER:
		ret = 1000;
		break;
	default:
		ret = 0;
	}

	return ret;
}

void ys_k2u_doe_set_table_cache_entry_limit(u32 card_id, u32 tlb_type, u32 data_len)
{
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);
	u32 val = 0;
	u32 key_limit = 0;

	if (tlb_type == DOE_TABLE_NORMAL_ARRAY) {
		data_len = data_len <= 64 ? 64 : 128;
		ys_k2u_doe_len_limit[DOE_TABLE_NORMAL_ARRAY][1] = data_len;
		ys_k2u_doe_len_limit[DOE_TABLE_LOCK][1] = data_len;
		val = data_len == 64 ? 0x1 : 0x0;
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_AIE_DLEN_LIMIT, val);
	} else if (tlb_type == DOE_TABLE_BIG_HASH) {
		data_len = data_len <= 64 ? 64 : 128;
		key_limit = data_len == 64 ? 64 : 96;
		ys_k2u_doe_len_limit[DOE_TABLE_BIG_HASH][0] = key_limit;
		ys_k2u_doe_len_limit[DOE_TABLE_BIG_HASH][1] = data_len;
		val = data_len == 64 ? 0x1 : 0x0;
		ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_HIE_DLEN_LIMIT, val);
	} else if (tlb_type == DOE_TABLE_SMALL_ARRAY) {
		data_len = (data_len + YS_K2U_DOE_RAM_ALIGN) & (~YS_K2U_DOE_RAM_ALIGN);
		data_len = data_len <= 128 ? data_len : 128;
		ys_k2u_doe_len_limit[DOE_TABLE_SMALL_ARRAY][1] = data_len;
	}
}

s32 ys_k2u_doe_get_channel_type(u32 card_id, u8 channel_id)
{
	struct ys_k2u_doe_device *ys_k2u_doe = ys_k2u_doe_get_device(card_id);
	u32 val = 0;

	val = ys_rd32(ys_k2u_doe->doe_base, YS_K2U_DOE_SYS_INFO);
	val = FIELD_GET(YS_K2U_DDR_VALID, val);

	if (channel_id == DOE_CHANNEL_DDR0)
		val = val & 0xf;
	if (channel_id == DOE_CHANNEL_DDR1)
		val = val >> 4;

	if (val & YS_K2U_DDR_VALID_MASK)
		return DOE_LOCATION_DDR;
	else if (val & YS_K2U_HOST_VALID_MASK)
		return DOE_LOCATION_HOST_DDR;
	else if (val & YS_K2U_SOC_VALID_MASK)
		return DOE_LOCATION_SOC_DDR;

	return -1;
}

void *ys_k2u_doe_alloc_cmd(struct ys_k2u_doe_interface *doe_if)
{
	struct ys_doe_sw_cmd *sw_cmd;
	void *node = NULL;

	node = llist_del_first(&doe_if->cmd_mpool);
	if (!node)
		sw_cmd = kzalloc(sizeof(*sw_cmd), GFP_KERNEL);
	else
		sw_cmd = llist_entry(node, struct ys_doe_sw_cmd, mp_node);

	if (!sw_cmd)
		return NULL;

	memset(sw_cmd, 0, sizeof(*sw_cmd));

	return sw_cmd;
}

void ys_k2u_doe_free_cmd(struct ys_k2u_doe_interface *doe_if, void *cmd)
{
	struct ys_doe_sw_cmd *sw_cmd = cmd;

	llist_add(&sw_cmd->mp_node, &doe_if->cmd_mpool);
}

void *ys_k2u_doe_alloc_dsc(struct ys_k2u_doe_interface *doe_if)
{
	struct ys_k2u_doe_desc *desc;
	void *node = NULL;

	node = llist_del_first(&doe_if->des_mpool);
	if (!node)
		desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	else
		desc = llist_entry(node, struct ys_k2u_doe_desc, llnode);

	if (!desc)
		return NULL;

	memset(desc, 0, sizeof(*desc));

	return desc;
}

void ys_k2u_doe_free_dsc(struct ys_k2u_doe_interface *doe_if, void *dsc)
{
	struct ys_k2u_doe_desc *sw_desc = dsc;

	llist_add(&sw_desc->llnode, &doe_if->des_mpool);
}
