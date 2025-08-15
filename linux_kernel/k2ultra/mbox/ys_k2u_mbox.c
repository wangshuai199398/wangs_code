// SPDX-License-Identifier: GPL-2.0

#include <linux/list.h>
#include <linux/llist.h>
#include "../edma/ys_k2u_new_base.h"
#include "../edma/ys_k2u_new_func.h"
#include "ys_k2u_mbox.h"
#include "../../platform/ys_mbox.h"

u32 ys_k2u_mbox_base;
EXPORT_SYMBOL(ys_k2u_mbox_base);

static struct spinlock ys_k2u_mbox_global_locks[MBOX_MAX_CHANNAL];

struct ys_k2u_pf_num {
	u32 resv1 : 20;
	u32 pf_num : 1;
	u32 resv2 : 7;
	u32 host_id : 2;
	u32 resv3 : 2;
};

static inline void ys_k2u_mbox_memcpy_fromio(void *buffer,
					     const void __iomem *addr,
					     size_t size)
{
	u32 i;

	for (i = 0; i < size / sizeof(u32); i++)
		*((u32 *)buffer + i) = ys_rd32(addr, i * sizeof(u32));
}

static inline void ys_k2u_mbox_memcpy_toio(void __iomem *addr,
					   const void *buffer,
					   size_t size)
{
	u32 i;

	for (i = 0; i < size / sizeof(u32); i++)
		ys_wr32(addr, i * sizeof(u32), *((u32 *)buffer + i));
}

static inline void ys_k2u_mbox_memset_io(void __iomem *addr, int value, size_t size)
{
	u32 i;

	for (i = 0; i < size / sizeof(u32); i++)
		ys_wr32(addr, i * sizeof(u32), value);
}

static u32 ys_k2u_mbox_get_irq_id(struct ys_mbox *mbox)
{
	return YS_K2U_MBOX_IRQ;
}

static void ys_k2u_mbox_get_send_offset(struct ys_mbox *mbox,
					u32 send_id,
					struct ys_k2u_mbox_offset_ctx *offset_ctx)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_k2u_mbox_ctx *ctx;
	struct ys_k2u_mbox *k2u_mbox;
	u32 offset = 0;
	u32 trigger_offset = 0;
	u32 trigger_id = 0;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	k2u_mbox = (struct ys_k2u_mbox *)mbox->mb_priv;

	if (mbox->role == MB_MASTER) {
		switch (ctx->type) {
		case MB_MASTER:
			/* master -> master */
			offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_TH;
			if (pdev_priv->dpu_mode == MODE_DPU_SOC)
				offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_BH;
			trigger_offset = YS_K2U_MBOX_H2S_IRQ_TRIGGER;
			break;
		case MB_PF:
			/* check pf id */
			if (ctx->func_id > YS_K2U_MBOX_LF_END)
				ys_dev_err("mbox dst pf id err, pf id:%u", ctx->func_id);
			/* master -> pf */
			offset = YS_K2U_MBOX_PF2PF_BUF_OFFSET(k2u_mbox->pf2lf_table[ctx->func_id]) +
				 YS_K2U_MBOX_SH_BUF_TH;
			trigger_offset = YS_K2U_MBOX_PF2PF_IRQ_TRIGGER;
			trigger_id = ctx->func_id;
			break;
		case MB_VF:
			/* check vf id */
			if (ctx->func_id > YS_K2U_MBOX_MAX_VF)
				ys_dev_err("mbox dst vf id err, vf id:%u", ctx->func_id);
			/* master -> vf */
			offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) +
				 YS_K2U_MBOX_SH_BUF_TH;
			trigger_offset = YS_K2U_MBOX_PF2VF_IRQ_TRIGGER;
			trigger_id = ctx->func_id + 1;
			break;
		case MB_M3:
			offset = YS_K2U_MBOX_M2M3_CHN + YS_K2U_MBOX_SH_BUF_TH;
			trigger_offset = YS_K2U_MBOX_H2M_IRQ_TRIGGER;
			break;
		default:
			ys_dev_err(" dst type is unknown!!");
		}
	} else if (mbox->role == MB_PF) {
		switch (ctx->type) {
		case MB_PF:
		case MB_MASTER:
			/* pf -> master */
			offset = YS_K2U_MBOX_PF2PF_BUF_BASE +
				 YS_K2U_MBOX_SH_BUF_BH;
			trigger_offset = YS_K2U_MBOX_PF2PF_IRQ_TRIGGER;
			break;
		case MB_VF:
			/* check vf id */
			if (ctx->func_id > YS_K2U_MBOX_MAX_VF)
				ys_dev_err("mbox dst vf id err, vf id:%u", ctx->func_id);
			/* pf -> vf */
			offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) +
				 YS_K2U_MBOX_SH_BUF_TH;
			trigger_offset = YS_K2U_MBOX_PF2VF_IRQ_TRIGGER;
			trigger_id = ctx->func_id + 1;
			break;
		default:
			ys_dev_err(" dst type is unknown!!");
		}
	} else if (mbox->role == MB_VF) {
		/* vf -> pf */
		offset = YS_K2U_MBOX_VF_PF_BUF_BASE + YS_K2U_MBOX_SH_BUF_BH;
		trigger_offset = YS_K2U_MBOX_VF_IRQ_TRIGGER;
	}

	offset_ctx->offset = offset;
	offset_ctx->trigger_offset = trigger_offset;
	offset_ctx->trigger_id = trigger_id;
}

static void ys_k2u_mbox_send_msg(struct ys_mbox *mbox, void *data, u32 send_id)
{
	struct ys_k2u_mbox_offset_ctx offset_ctx = {0};
	unsigned long flags;

	ys_k2u_mbox_get_send_offset(mbox, send_id, &offset_ctx);

	/* send data */
	spin_lock_irqsave(&ys_k2u_mbox_global_locks[send_id], flags);
	ys_k2u_mbox_memcpy_toio(mbox->addr + offset_ctx.offset, data, YS_K2U_MBOX_MSG_LEN);
	spin_unlock_irqrestore(&ys_k2u_mbox_global_locks[send_id], flags);

	ys_wr32(mbox->addr, offset_ctx.trigger_offset, offset_ctx.trigger_id);
}

static u32 ys_k2u_mbox_get_recv_offset(struct ys_mbox *mbox, u32 recv_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_k2u_mbox_ctx *ctx;
	struct ys_k2u_mbox *k2u_mbox;
	u32 offset = 0;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	k2u_mbox = (struct ys_k2u_mbox *)mbox->mb_priv;
	ctx = (struct ys_k2u_mbox_ctx *)&recv_id;

	if (mbox->role == MB_MASTER) {
		if (ctx->func_id == YS_K2U_MBOX_MASTER_PF_ID && ctx->type == MB_MASTER) {
			/* recv master msg */
			/* recv host/soc master msg */
			offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_BH;
			if (pdev_priv->dpu_mode == MODE_DPU_SOC) {
				/* recv soc master msg */
				offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_TH;
			}
		} else if (ctx->func_id == YS_K2U_MBOX_M3_PF_ID && ctx->type == MB_M3) {
			/* recv m3 msg */
			offset = YS_K2U_MBOX_M2M3_CHN + YS_K2U_MBOX_SH_BUF_BH;
		} else if (ctx->type == MB_VF) {
			/* master pf <- vf */
			offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) + YS_K2U_MBOX_SH_BUF_BH;
		} else if (ctx->type == MB_PF) {
			/* recv from pf,target is pf message need forward*/
			offset = YS_K2U_MBOX_PF2PF_BUF_OFFSET(k2u_mbox->pf2lf_table[ctx->func_id]) +
				 YS_K2U_MBOX_SH_BUF_BH;
		}
	} else if (mbox->role == MB_PF) {
		if (ctx->type == MB_MASTER) {
			/* pf <- master */
			/* recv local master msg */
			offset = YS_K2U_MBOX_PF2PF_BUF_BASE +
				 YS_K2U_MBOX_SH_BUF_TH;
		} else if (ctx->type == MB_VF) {
			/* pf <- vf */
			offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) +
				 YS_K2U_MBOX_SH_BUF_BH;
		}
	} else if (mbox->role == MB_VF) {
		/* vf <- pf */
		offset = YS_K2U_MBOX_VF_PF_BUF_BASE +
			 YS_K2U_MBOX_SH_BUF_TH;
	}
	return offset;
}

static void ys_k2u_mbox_recv_msg(struct ys_mbox *mbox, void *data, u32 recv_id)
{
	u32 offset;

	offset = ys_k2u_mbox_get_recv_offset(mbox, recv_id);
	spin_lock(&ys_k2u_mbox_global_locks[recv_id]);
	ys_k2u_mbox_memcpy_fromio(data, mbox->addr + offset, YS_K2U_MBOX_MSG_LEN);
	/* unlock mailbox */
	ys_k2u_mbox_memset_io(mbox->addr + offset, 0, YS_K2U_MBOX_MSG_LEN);
	spin_unlock(&ys_k2u_mbox_global_locks[recv_id]);
}

static struct ys_mbox_irq_info ys_k2u_mbox_get_irq_status(struct ys_mbox *mbox)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_k2u_mbox_ctx *ctx;
	struct ys_mbox_irq_info irq_info;
	u32 pending, id;
	u16 msg_id = 0;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	memset(&irq_info, 0, sizeof(struct ys_mbox_irq_info));
	ctx = (struct ys_k2u_mbox_ctx *)&msg_id;
	if (mbox->role == MB_MASTER) {
		pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_PENDING);
		if (FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_STATUS, pending)) {
			irq_info.irq_status = 1;
			id = FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_PF_ID, pending);
			if (id == YS_K2U_MBOX_MASTER_PF_ID) {
				/* recv master msg */
				ctx->type = MB_MASTER;
				ctx->func_id = id;
				/* recv host master msg */
				goto irq_data;
			}

			if (id == YS_K2U_MBOX_M3_PF_ID) {
				/* recv m3 msg */
				ctx->type = MB_M3;
				ctx->func_id = id;
				goto irq_data;
			}

			/* recv pf message */
			ctx->type = MB_PF;
			ctx->func_id = id;
			goto irq_data;
		}
		/* master pf <- vf */
		if (pdev_priv->sriov_info.num_vfs > 0) {
			pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_PENDING);
			if (FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_STATUS, pending)) {
				irq_info.irq_status = 1;
				id = FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_VF_ID, pending);
				ctx->type = MB_VF;
				ctx->func_id = id - 1;
				goto irq_data;
			}
		}
	} else if (mbox->role == MB_PF) {
		/* pf <- master */
		pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_PENDING);
		if (FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_STATUS, pending)) {
			irq_info.irq_status = 1;
			id = FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_PF_ID, pending);
			/* recv m3 master msg */
			/* recv local master msg */
			ctx->type = MB_MASTER;
			ctx->func_id = 0;
			goto irq_data;
		}
		/* pf <- vf */
		if (pdev_priv->sriov_info.num_vfs > 0) {
			pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_PENDING);
			if (FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_STATUS, pending)) {
				irq_info.irq_status = 1;
				id = FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_VF_ID, pending);
				ctx->type = MB_VF;
				ctx->func_id = id - 1;
				goto irq_data;
			}
		}
	} else if (mbox->role == MB_VF) {
		/* vf <- pf */
		pending = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_PENDING);
		if (FIELD_GET(YS_K2U_MBOX_VF2PF_IRQ_P_STATUS, pending)) {
			irq_info.irq_status = 1;
			id = FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_VF_ID, pending);
			ctx->type = MB_PF;
			ctx->func_id = 0;
			goto irq_data;
		}
	}
irq_data:
	irq_info.msg_id = msg_id;
	ys_dev_info("%s, type %s, func_id %d, irq_status %d\n", __func__,
		    mb_role_stringify(ctx->type), ctx->func_id, irq_info.irq_status);
	return irq_info;
}

static void ys_k2u_mbox_clear_send_mailbox(struct ys_mbox *mbox, u32 clear_id)
{
	struct ys_k2u_mbox_offset_ctx offset_ctx;

	memset(&offset_ctx, 0, sizeof(struct ys_k2u_mbox_offset_ctx));
	ys_k2u_mbox_get_send_offset(mbox, clear_id, &offset_ctx);

	ys_k2u_mbox_memset_io(mbox->addr + offset_ctx.offset, 0, YS_K2U_MBOX_MSG_LEN);
}

static void ys_k2u_mbox_clear_recv_mailbox(struct ys_mbox *mbox, u32 clear_id)
{
	u32 offset = 0;

	offset = ys_k2u_mbox_get_recv_offset(mbox, clear_id);

	ys_k2u_mbox_memset_io(mbox->addr + offset, 0, YS_K2U_MBOX_MSG_LEN);
}

static void ys_k2u_mbox_read_send_mailbox(struct ys_mbox *mbox, void *data, u32 send_id)
{
	struct ys_k2u_mbox_offset_ctx offset_ctx;

	memset(&offset_ctx, 0, sizeof(struct ys_k2u_mbox_offset_ctx));
	ys_k2u_mbox_get_send_offset(mbox, send_id, &offset_ctx);

	ys_k2u_mbox_memcpy_fromio(data, mbox->addr + offset_ctx.offset, YS_K2U_MBOX_MSG_LEN);
}

static void ys_k2u_mbox_send_ack(struct ys_mbox *mbox, struct ys_mbox_msg *msg,
				 u32 msg_id, u32 ack_type)
{
	struct ys_mbox_msg response = {0};

	memcpy(&response, msg, sizeof(*msg));
	response.opcode |= (1 << YS_MBOX_OPCODE_MASK_ACK);
	response.seqno = msg->seqno;
	ys_mbox_send_msg(mbox, &response, msg_id, MB_NO_REPLY, 0, NULL);
}

static int ys_k2u_mbox_test_reset(struct ys_mbox *mbox)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	u8 data[YS_K2U_MBOX_SH_BUF_SIZE];
	u32 init_done;
	u32 reg;
	u32 test_pass = 1;
	int num_vfs = YS_K2U_MBOX_VFS_NUM;
	u32 mem_test;
	u32 *ptr;
	u32 i = 0;
	u32 j = 0;

	ys_dev_info("== yusur mailbox reset test start ==\n");
	init_done = ys_rd32(mbox->addr, YS_K2U_MBOX_G_MAILBOX_INIT_DONE);
	if (init_done != 1) {
		ys_dev_info("yusur mailbox is not initialized\n");
		return 0;
	}

	if (mbox->role == MB_MASTER) {
		ys_dev_info("== MB_MASTER\n");
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_BUF_SIZE);
		if (reg != YS_K2U_MBOX_SH_BUF_SIZE) {
			ys_dev_warn("MAILBOX_BUF_SIZE reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE);
		if (reg != 0x00000001) {
			ys_dev_warn("MAILBOX_TIMEOUT_ENABLE reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_CNT);
		if (reg != 0x004c4b40) {
			ys_dev_warn("MAILBOX_TIMEOUT_CNT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_M3_IRQ_OUT_CNT);
		if (reg != 0x00000014) {
			ys_dev_warn("MAILBOX_M3_IRQ_OUT_CNT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("MAILBOX_PF_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MASTER_PREEMPT);
		if (reg != 1) {
			ys_dev_warn("MBOX_MASTER_PREEMPT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MASTER_OPTION);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("MAILBOX_HOST_MASTER_OPTION reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("MAILBOX_LF_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("SOC2HOST_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("M32HOST_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		for (i = 0; i < 511; i++) {
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10));
			if (reg != YS_K2U_MBOX_DEF_VAL) {
				ys_dev_warn("MAILBOX_VF_IRQ_VECTOR reg %d %s %08x\n",
					    i, YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
				test_pass = 0;
			}
		}

		for (i = 0; i < num_vfs; i++) {
			mem_test = 1;
			ys_k2u_mbox_memcpy_fromio(data,
						  mbox->addr + YS_K2U_MBOX_VF_PF_BUF_OFFSET(i),
						  YS_K2U_MBOX_SH_BUF_SIZE);
			ptr = (u32 *)data;
			for (j = 0; j < YS_K2U_MBOX_SH_BUF_SIZE / 4; j++) {
				if (ptr[j] != YS_K2U_MBOX_DEF_VAL) {
					test_pass = 0;
					mem_test = 0;
					break;
				}
			}

			if (mem_test == 0)
				ys_dev_warn("PF/VF Buffer %d %08x error 0x%08x\n",
					    i, YS_K2U_MBOX_VF_PF_BUF_OFFSET(i), ptr[0]);
		}

		for (; i < 511; i++) {
			mem_test = 1;
			ys_k2u_mbox_memcpy_fromio(data,
						  mbox->addr + YS_K2U_MBOX_VF_PF_BUF_OFFSET(i),
						  YS_K2U_MBOX_SH_BUF_SIZE);
			ptr = (u32 *)data;
			for (j = 0; j < YS_K2U_MBOX_SH_BUF_SIZE / 4; j++) {
				if (ptr[j] != YS_K2U_MBOX_ERR_VAL) {
					test_pass = 0;
					mem_test = 0;
					break;
				}
			}

			if (mem_test == 0)
				ys_dev_warn("PF/VF Buffer %d %08x error 0x%08x\n",
					    i, YS_K2U_MBOX_VF_PF_BUF_OFFSET(i), ptr[0]);
		}

		for (i = 0; i < 2; i++) {
			mem_test = 1;
			ys_k2u_mbox_memcpy_fromio(data,
						  mbox->addr + YS_K2U_MBOX_PF2PF_BUF_OFFSET(i),
						  YS_K2U_MBOX_SH_BUF_SIZE);
			for (j = 0; j < YS_K2U_MBOX_SH_BUF_SIZE; j++) {
				if (data[j] != YS_K2U_MBOX_DEF_VAL) {
					test_pass = 0;
					mem_test = 0;
					break;
				}
			}

			if (mem_test == 0)
				ys_dev_warn("PF/PF Buffer %d %08x error 0x%02x%02x%02x%02x\n",
					    i, YS_K2U_MBOX_PF2PF_BUF_OFFSET(i),
					    data[0], data[1], data[2], data[3]);
		}
	} else if (mbox->role == MB_PF) {
		ys_dev_info("== MB_PF\n");
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_BUF_SIZE);
		if (reg != YS_K2U_MBOX_SH_BUF_SIZE) {
			ys_dev_warn("MAILBOX_BUF_SIZE reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE);
		if (reg != 0x00000001) {
			ys_dev_warn("MAILBOX_TIMEOUT_ENABLE reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_CNT);
		if (reg != 0x004c4b40) {
			ys_dev_warn("MAILBOX_TIMEOUT_CNT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_M3_IRQ_OUT_CNT);
		if (reg != 0x00000014) {
			ys_dev_warn("MAILBOX_M3_IRQ_OUT_CNT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("MAILBOX_PF_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MASTER_PREEMPT);
		if (reg != 0) {
			ys_dev_warn("MBOX_MASTER_PREEMPT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MASTER_OPTION);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("MAILBOX_HOST_MASTER_OPTION reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("MAILBOX_LF_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("SOC2HOST_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("M32HOST_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		for (i = 0; i < 511; i++) {
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10));
			if (reg != YS_K2U_MBOX_DEF_VAL) {
				ys_dev_warn("MAILBOX_VF_IRQ_VECTOR reg %d %s %08x\n",
					    i, YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
				test_pass = 0;
			}
		}

		for (i = 0; i < num_vfs; i++) {
			mem_test = 1;
			ys_k2u_mbox_memcpy_fromio(data,
						  mbox->addr + YS_K2U_MBOX_VF_PF_BUF_OFFSET(i),
						  YS_K2U_MBOX_SH_BUF_SIZE);
			ptr = (u32 *)data;
			for (j = 0; j < YS_K2U_MBOX_SH_BUF_SIZE / 4; j++) {
				if (ptr[j] != YS_K2U_MBOX_DEF_VAL) {
					test_pass = 0;
					mem_test = 0;
					break;
				}
			}

			if (mem_test == 0)
				ys_dev_warn("PF/VF Buffer %d %08x error 0x%08x\n",
					    i, YS_K2U_MBOX_VF_PF_BUF_OFFSET(i), ptr[0]);
		}

		for (; i < 511; i++) {
			mem_test = 1;
			ys_k2u_mbox_memcpy_fromio(data,
						  mbox->addr + YS_K2U_MBOX_VF_PF_BUF_OFFSET(i),
						  YS_K2U_MBOX_SH_BUF_SIZE);
			ptr = (u32 *)data;
			for (j = 0; j < YS_K2U_MBOX_SH_BUF_SIZE / 4; j++) {
				if (ptr[j] != YS_K2U_MBOX_ERR_VAL) {
					test_pass = 0;
					mem_test = 0;
					break;
				}
			}

			if (mem_test == 0)
				ys_dev_warn("PF/VF Buffer %d %08x error 0x%08x\n",
					    i, YS_K2U_MBOX_VF_PF_BUF_OFFSET(i), ptr[0]);
		}

		mem_test = 1;
		ys_k2u_mbox_memcpy_fromio(data,
					  mbox->addr + YS_K2U_MBOX_PF2PF_BUF_BASE,
					  YS_K2U_MBOX_SH_BUF_SIZE);
		for (j = 0; j < YS_K2U_MBOX_SH_BUF_SIZE; j++) {
			if (data[j] != YS_K2U_MBOX_DEF_VAL) {
				test_pass = 0;
				mem_test = 0;
				break;
			}
		}

		if (mem_test == 0)
			ys_dev_warn("PF/pF Buffer error 0x%02x%02x%02x%02x\n",
				    data[3], data[2], data[1], data[0]);

	} else if (mbox->role == MB_VF) {
		ys_dev_info("== MB_VF\n");
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_BUF_SIZE);
		if (reg != YS_K2U_MBOX_SH_BUF_SIZE) {
			ys_dev_warn("MAILBOX_BUF_SIZE reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE);
		if (reg != 0x00000001) {
			ys_dev_warn("MAILBOX_TIMEOUT_ENABLE reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_CNT);
		if (reg != 0x004c4b40) {
			ys_dev_warn("MAILBOX_TIMEOUT_CNT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_M3_IRQ_OUT_CNT);
		if (reg != 0x00000014) {
			ys_dev_warn("MAILBOX_M3_IRQ_OUT_CNT reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_DEF_VAL) {
			ys_dev_warn("MAILBOX_VF_IRQ_VECTOR reg %s %08x\n",
				    YS_K2U_MBOX_DEF_VAL_ERR_MSG, reg);
			test_pass = 0;
		}

		mem_test = 1;
		ys_k2u_mbox_memcpy_fromio(data,
					  mbox->addr + YS_K2U_MBOX_VF_PF_BUF_BASE,
					  YS_K2U_MBOX_SH_BUF_SIZE);
		for (i = 0; i < YS_K2U_MBOX_SH_BUF_SIZE; i++) {
			if (data[i] != YS_K2U_MBOX_DEF_VAL) {
				test_pass = 0;
				mem_test = 0;
			}
		}

		if (mem_test == 0)
			ys_dev_warn("PF/VF Buffer error 0x%02x%02x%02x%02x\n",
				    data[0], data[1], data[2], data[3]);
	}

	if (test_pass == 1)
		ys_dev_info("==yusur mailbox reset test succeed==\n");
	else
		ys_dev_err("==yusur mailbox reset test failed==\n");

	return test_pass;
}

static int ys_k2u_mbox_test_vector_reg(struct ys_mbox *mbox, u32 val, u32 test)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	u32 test_pass = 1;
	int num_vfs = YS_K2U_MBOX_VFS_NUM;
	u32 reg;
	u32 i = 0;
	int test_vf = YS_K2U_MBOX_VFS_NUM + 2;

	ys_dev_info("==yusur mailbox test vector reg start==\n");
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role == MB_MASTER) {
		ys_dev_info("== MB_MASTER ==\n");

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_PF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_LF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("SOC2HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("M32HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		for (i = 0; i < num_vfs; i++) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10), val);
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10));
			if (reg != test) {
				ys_dev_warn("MAILBOX_VF%d_IRQ_VECTOR reg rw %d -- %d, old:%d\n",
					    i + 1, val, reg, test);
				test_pass = 0;
			}
		}

		for (; i < test_vf; i++) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10), val);
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10));
			if (reg != YS_K2U_MBOX_ERR_VAL) {
				ys_dev_warn("MAILBOX_VF%d_IRQ_VECTOR reg rw %d -- %d, old:%d\n",
					    i + 1, val, reg, test);
				test_pass = 0;
			}
		}
	} else if (mbox->role == MB_PF) {
		ys_dev_info("== MB_PF ==\n");

		num_vfs = pdev_priv->sriov_info.num_vfs;
		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_PF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_ERR_VAL) {
			ys_dev_warn("MAILBOX_LF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_ERR_VAL) {
			ys_dev_warn("SOC2HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_ERR_VAL) {
			ys_dev_warn("M32HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		for (i = 0; i < num_vfs; i++) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10), val);
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10));
			if (reg != test) {
				ys_dev_warn("MAILBOX_VF%d_IRQ_VECTOR reg rw %d -- %d, old:%d\n",
					    i + 1, val, reg, test);
				test_pass = 0;
			}
		}

		for (; i < test_vf; i++) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10), val);
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR + (i * 0x10));
			if (reg != YS_K2U_MBOX_ERR_VAL) {
				ys_dev_warn("MAILBOX_VF%d_IRQ_VECTOR reg rw %d -- %d, old:%d\n",
					    i + 1, val, reg, test);
				test_pass = 0;
			}
		}
	} else if (mbox->role == MB_VF) {
		ys_dev_info("== MB_VF ==\n");

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_ERR_VAL) {
			ys_dev_warn("MAILBOX_PF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_ERR_VAL) {
			ys_dev_warn("MAILBOX_LF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_ERR_VAL) {
			ys_dev_warn("SOC2HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR);
		if (reg != YS_K2U_MBOX_ERR_VAL) {
			ys_dev_warn("M32HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_VF_IRQ_VF2PF reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		for (i = 1; i < test_vf; i++) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR + (i * 0x10), val);
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR);
			if (reg != YS_K2U_MBOX_ERR_VAL) {
				ys_dev_warn("MAILBOX_VF%d_IRQ_VECTOR reg rw %d -- %d, old:%d\n",
					    i + 1, val, reg, test);
				test_pass = 0;
			}
		}
	}

	if (test_pass == 1)
		ys_dev_info("==yusur mailbox test vector reg succeed==\n");
	else
		ys_dev_err("==yusur mailbox test vector reg failed==\n");

	return test_pass;
}

static int ys_k2u_mbox_set_vector_reg(struct ys_mbox *mbox, u32 val)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	u32 test_pass = 1;
	u32 reg;

	pdev_priv = pci_get_drvdata(mbox->pdev);

	if (mbox->role == MB_MASTER) {
		ys_dev_info("== MB_MASTER yusur mailbox set vector reg val: %d ==\n", val);

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_PF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_LF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("SOC2HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("M32HOST_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}
	} else if (mbox->role == MB_PF) {
		ys_dev_info("== MB_PF yusur mailbox set vector reg val: %d ==\n", val);

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_PF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}

		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_LF_IRQ_VECTOR reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}
	} else if (mbox->role == MB_VF) {
		ys_dev_info("== MB_VF yusur mailbox set vector reg val: %d ==\n", val);

		ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR, val);
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR);
		if (reg != val) {
			ys_dev_warn("MAILBOX_VF_IRQ_VF2PF reg rw %d -- %d\n", val, reg);
			test_pass = 0;
		}
	}

	if (test_pass == 1)
		ys_dev_info("==yusur mailbox set vector reg succeed==\n");
	else
		ys_dev_err("==yusur mailbox set vector reg failed==\n");

	return test_pass;
}

static void ys_k2u_mbox_read_all_regs(struct ys_mbox *mbox)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	u32 reg;

	ys_dev_info("== yusur mailbox read status&debug regs ==\n");

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_BUF_SIZE);
	ys_dev_info("MAILBOX_BUF_SIZE reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE);
	ys_dev_info("MAILBOX_TIMEOUT_ENABLE reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_CNT);
	ys_dev_info("MAILBOX_TIMEOUT_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_M3_IRQ_OUT_CNT);
	ys_dev_info("MAILBOX_M3_IRQ_OUT_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_MAILBOX_VERSION);
	ys_dev_info("MAILBOX_VERSION reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_MAILBOX_INIT_DONE);
	ys_dev_info("MAILBOX_INIT_DONE reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_PF_IRQ_TIME_OUT_ALARM);
	ys_dev_info("PF_IRQ_TIME_OUT_ALARM reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_VF_IRQ_TIME_OUT_ALARM);
	ys_dev_info("VF_IRQ_TIME_OUT_ALARM reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_M3_IRQ_TIME_OUT_ALARM);
	ys_dev_info("M3_IRQ_TIME_OUT_ALARM reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF0_LF1_VF_NUM);
	ys_dev_info("LF0_LF1_VF_NUM reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF2_LF3_VF_NUM);
	ys_dev_info("LF2_LF3_VF_NUM reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF4_LF5_VF_NUM);
	ys_dev_info("LF4_LF5_VF_NUM reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF6_LF7_VF_NUM);
	ys_dev_info("LF6_LF7_VF_NUM reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF0_LF1_REMAP_PF_ID);
	ys_dev_info("LF0_LF1_REMAP_PF_ID reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF2_LF3_REMAP_PF_ID);
	ys_dev_info("LF2_LF3_REMAP_PF_ID reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF4_LF5_REMAP_PF_ID);
	ys_dev_info("LF4_LF5_REMAP_PF_ID reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF6_LF7_REMAP_PF_ID);
	ys_dev_info("LF6_LF7_REMAP_PF_ID reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LF8_REMAP_PF_ID);
	ys_dev_info("LF8_REMAP_PF_ID reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_HOST_IRQ_CNT);
	ys_dev_info("HOST_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M3_MASTER_IRQ_CNT);
	ys_dev_info("M3_MASTER_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_M3_LF_IRQ_CNT);
	ys_dev_info("M3_LF_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_TRIG_VF2PF_IRQ_CNT);
	ys_dev_info("TRIG_VF2PF_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_TRIG_PF2VF_IRQ_CNT);
	ys_dev_info("TRIG_PF2VF_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_TRIG_PF2PF_IRQ_CNT);
	ys_dev_info("TRIG_PF2PF_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_TRIG_M3_MASTER_IRQ_CNT);
	ys_dev_info("TRIG_M3_MASTER_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_TRIG_M3_LF_IRQ_CNT);
	ys_dev_info("TRIG_M3_LF_IRQ_CNT reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_HOST_SOC_SEL);
	ys_dev_info("HOST_SOC_SEL reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_APB_TRIG_ADDR1);
	ys_dev_info("APB_TRIG_ADDR1 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_APB_TRIG_ADDR2);
	ys_dev_info("APB_TRIG_ADDR2 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_APB_WDATA);
	ys_dev_info("APB_WDATA reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MAILBOX_FIFO_EMPTY);
	ys_dev_info("MAILBOX_FIFO_EMPTY reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MAILBOX_FIFO_FULL);
	ys_dev_info("MAILBOX_FIFO_FULL reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_IRQ_OUT_DATA);
	ys_dev_info("IRQ_OUT_DATA reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG0);
	ys_dev_info("PF_VF_IRQ_FLAG0 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG1);
	ys_dev_info("PF_VF_IRQ_FLAG1 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG1);
	ys_dev_info("PF_VF_IRQ_FLAG1 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG3);
	ys_dev_info("PF_VF_IRQ_FLAG3 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG4);
	ys_dev_info("PF_VF_IRQ_FLAG4 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG5);
	ys_dev_info("PF_VF_IRQ_FLAG5 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG6);
	ys_dev_info("PF_VF_IRQ_FLAG6 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG7);
	ys_dev_info("PF_VF_IRQ_FLAG7 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG8);
	ys_dev_info("PF_VF_IRQ_FLAG8 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG9);
	ys_dev_info("PF_VF_IRQ_FLAG9 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG10);
	ys_dev_info("PF_VF_IRQ_FLAG10 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG11);
	ys_dev_info("PF_VF_IRQ_FLAG11 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG12);
	ys_dev_info("PF_VF_IRQ_FLAG12 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG13);
	ys_dev_info("PF_VF_IRQ_FLAG13 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG14);
	ys_dev_info("PF_VF_IRQ_FLAG14 reg: 0x%08x\n", reg);

	reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF_VF_IRQ_FLAG15);
	ys_dev_info("PF_VF_IRQ_FLAG15 reg: 0x%08x\n", reg);
}

static int ys_k2u_mbox_write_mem(struct ys_mbox *mbox, u32 send_id, u32 data)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_k2u_mbox_ctx *ctx;
	u32 buff[YS_K2U_MBOX_MSG_LEN / 4] = {0, };
	u32 offset = 0;
	int i = 0;

	ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	ys_dev_info("==yusur mailbox write memory start==\n");

	switch (ctx->type) {
	case MB_MASTER:
		offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_TH;
		if (pdev_priv->dpu_mode == MODE_DPU_SOC)
			offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_BH;
		break;
	case MB_PF:
		offset = YS_K2U_MBOX_PF2PF_BUF_OFFSET(ctx->func_id) +
				YS_K2U_MBOX_SH_BUF_TH;
		break;
	case MB_VF:
		offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) +
				YS_K2U_MBOX_SH_BUF_TH;
		break;
	case MB_M3:
		offset = YS_K2U_MBOX_M2M3_CHN + YS_K2U_MBOX_SH_BUF_TH;
		break;
	default:
		ys_err(" dst type is unknown!!");
	}

	ys_dev_info("pf:%d, vf:%d, offset:%08x, %d\n",
		    pdev_priv->pf_id, pdev_priv->vf_id, offset, data);

	for (i = 0; i < YS_K2U_MBOX_MSG_LEN / 4; i++)
		buff[i] = data;

	ys_k2u_mbox_memcpy_toio(mbox->addr + offset, (u8 *)&buff, YS_K2U_MBOX_MSG_LEN);

	return 0;
}

static int ys_k2u_mbox_check_mem(struct ys_mbox *mbox, u32 send_id, u32 data)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_k2u_mbox_ctx *ctx;
	u32 buff[YS_K2U_MBOX_MSG_LEN / 4] = {0, };
	u32 offset = 0;
	u32 test_pass = 1;
	int i = 0;
	int num_vfs = YS_K2U_MBOX_VFS_NUM;
	int pf_max = 10;
	u32 permission_flag = 1;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	ctx = (struct ys_k2u_mbox_ctx *)&send_id;
	ys_dev_info("==yusur mailbox check memory start==\n");

	if (mbox->role == MB_MASTER) {
		switch (ctx->type) {
		case MB_MASTER:
			offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_TH;
			if (pdev_priv->dpu_mode == MODE_DPU_SOC)
				offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_BH;
			break;
		case MB_PF:
			offset = YS_K2U_MBOX_PF2PF_BUF_OFFSET(ctx->func_id) +
					YS_K2U_MBOX_SH_BUF_TH;
			if (ctx->func_id > pf_max)
				permission_flag = 0;
			break;
		case MB_VF:
			offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) +
					YS_K2U_MBOX_SH_BUF_TH;
			if (ctx->func_id >= num_vfs)
				permission_flag = 0;
			break;
		case MB_M3:
			offset = YS_K2U_MBOX_M2M3_CHN + YS_K2U_MBOX_SH_BUF_TH;
			break;
		default:
			ys_err(" dst type is unknown!!");
		}

		ys_k2u_mbox_memcpy_fromio((u8 *)buff, mbox->addr + offset, YS_K2U_MBOX_MSG_LEN);
		for (i = 0; i < YS_K2U_MBOX_MSG_LEN / 4; i++) {
			if (permission_flag == 1 && buff[i] != data) {
				ys_dev_warn("type %d,id %d, offset:%08x, check error %08x -- %08x.\n",
					    ctx->type, ctx->func_id, offset, data, buff[i]);
				test_pass = 0;
				break;
			}

			if (permission_flag == 0 && buff[i] != YS_K2U_MBOX_ERR_VAL) {
				ys_dev_warn("type %d,id %d, offset:%08x, check error %08x -- %08x.\n",
					    ctx->type, ctx->func_id, offset, data, buff[i]);
				test_pass = 0;
				break;
			}
		}
	} else if (mbox->role == MB_PF) {
		switch (ctx->type) {
		case MB_MASTER:
			offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_TH;
			if (pdev_priv->dpu_mode == MODE_DPU_SOC)
				offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_BH;
			break;
		case MB_PF:
			offset = YS_K2U_MBOX_PF2PF_BUF_OFFSET(ctx->func_id) +
					YS_K2U_MBOX_SH_BUF_TH;
			if (ctx->func_id > 0)
				permission_flag = 0;
			break;
		case MB_VF:
			offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) +
					YS_K2U_MBOX_SH_BUF_TH;
			if (ctx->func_id >= num_vfs)
				permission_flag = 0;
			break;
		case MB_M3:
			offset = YS_K2U_MBOX_M2M3_CHN + YS_K2U_MBOX_SH_BUF_TH;
			break;
		default:
			ys_err(" dst type is unknown!!");
		}

		ys_k2u_mbox_memcpy_fromio((u8 *)buff, mbox->addr + offset, YS_K2U_MBOX_MSG_LEN);
		for (i = 0; i < YS_K2U_MBOX_MSG_LEN / 4; i++) {
			if (permission_flag == 1 && buff[i] != data) {
				ys_dev_warn("type %d,id %d, offset:%08x, check error %08x -- %08x.\n",
					    ctx->type, ctx->func_id, offset, data, buff[i]);
				test_pass = 0;
				break;
			}

			if (permission_flag == 0 && buff[i] != YS_K2U_MBOX_ERR_VAL) {
				ys_dev_warn("type %d,id %d, offset:%08x, check error %08x -- %08x.\n",
					    ctx->type, ctx->func_id, offset, data, buff[i]);
				test_pass = 0;
				break;
			}
		}
	} else if (mbox->role == MB_VF) {
		switch (ctx->type) {
		case MB_MASTER:
			offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_TH;
			if (pdev_priv->dpu_mode == MODE_DPU_SOC)
				offset = YS_K2U_MBOX_M2M_CHN + YS_K2U_MBOX_SH_BUF_BH;
			permission_flag = 0;
			break;
		case MB_PF:
			offset = YS_K2U_MBOX_PF2PF_BUF_OFFSET(ctx->func_id) +
					YS_K2U_MBOX_SH_BUF_TH;
			permission_flag = 0;
			break;
		case MB_VF:
			offset = YS_K2U_MBOX_VF_PF_BUF_OFFSET(ctx->func_id) +
					YS_K2U_MBOX_SH_BUF_TH;
			if (ctx->func_id > 0)
				permission_flag = 0;
			break;
		case MB_M3:
			offset = YS_K2U_MBOX_M2M3_CHN + YS_K2U_MBOX_SH_BUF_TH;
			break;
		default:
			ys_err(" dst type is unknown!!");
		}

		ys_k2u_mbox_memcpy_fromio((u8 *)buff, mbox->addr + offset, YS_K2U_MBOX_MSG_LEN);
		for (i = 0; i < YS_K2U_MBOX_MSG_LEN / 4; i++) {
			if (permission_flag == 1 && buff[i] != data) {
				ys_dev_warn("type %d,id %d, offset:%08x, check error %08x -- %08x.\n",
					    ctx->type, ctx->func_id, offset, data, buff[i]);
				test_pass = 0;
				break;
			}

			if (permission_flag == 0 && buff[i] != YS_K2U_MBOX_ERR_VAL) {
				ys_dev_warn("type %d,id %d, offset:%08x, check error %08x -- %08x.\n",
					    ctx->type, ctx->func_id, offset, data, buff[i]);
				test_pass = 0;
				break;
			}
		}
	}

	if (test_pass == 1)
		ys_dev_info("==yusur mailbox check mem %08x succeed==\n", offset);
	else
		ys_dev_err("==yusur mailbox check mem %08x failed==\n", offset);

	return test_pass;
}

static int ys_k2u_mbox_test_select_master(struct ys_mbox *mbox, u32 opcode, u32 lf_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	u32 reg;

	ys_dev_info("==yusur mailbox test master start==\n");
	switch (opcode) {
	case 0: // clear
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MASTER_PREEMPT);
		ys_dev_info("pf:%d, vf:%d, read master preempt:%08x\n",
			    pdev_priv->pf_id, pdev_priv->vf_id, reg);

		ys_wr32(mbox->addr, YS_K2U_MBOX_MASTER_PREEMPT, 0);
		ys_dev_info("pf:%d, vf:%d, clear master preempt:%08x\n",
			    pdev_priv->pf_id, pdev_priv->vf_id, 0);
		break;
	case 1: // select
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MASTER_PREEMPT);
		ys_dev_info("pf:%d, vf:%d, select master preempt:%08x\n",
			    pdev_priv->pf_id, pdev_priv->vf_id, reg);
		break;
	case 2: // change
		reg = lf_id << 1 | YS_K2U_MBOX_MASTER_SEL;
		ys_wr32(mbox->addr, YS_K2U_MBOX_MASTER_PREEMPT, reg);
		ys_dev_info("pf:%d, vf:%d, chenge master preempt:%08x\n",
			    pdev_priv->pf_id, pdev_priv->vf_id, lf_id);

		break;
	default:
		ys_dev_info("mbox op code %x err!\n", opcode);
		break;
	}

	return 0;
}

static int ys_k2u_mbox_triger_interrupt(struct ys_mbox *mbox, int type, int id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);

	ys_dev_info("==yusur mailbox triger interrupt test==\n");
	switch (mbox->role) {
	case MB_MASTER:
	case MB_PF:
		if (type == MB_VF) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_TRIGGER, id);
			ys_dev_info("pf:%d, vf:%d, pf trigger vf %d\n",
				    pdev_priv->pf_id, pdev_priv->vf_id, id);
		} else if (type == MB_PF) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_TRIGGER, id);
			ys_dev_info("pf:%d, vf:%d, pf trigger pf %d\n",
				    pdev_priv->pf_id, pdev_priv->vf_id, id);
		}
		break;
	case MB_VF:
		if (type == MB_VF) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_TRIGGER, id);
			ys_dev_info("pf:%d, vf:%d, vf trigger pf %d\n",
				    pdev_priv->pf_id, pdev_priv->vf_id, id);
		} else if (type == MB_PF) {
			ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_TRIGGER, id);
			ys_dev_info("pf:%d, vf:%d, vf trigger master %d\n",
				    pdev_priv->pf_id, pdev_priv->vf_id, id);
		}
		break;
	default:
		ys_err(" dst type is unknown!!");
	}

	return 0;
}

static int ys_k2u_mbox_clear_interrupt(struct ys_mbox *mbox)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	u32 counter = 0;
	u32 vector;
	u32 pending, id;

	ys_dev_info("==yusur mailbox clear interrupt test==\n");
	switch (mbox->role) {
	case MB_MASTER:
	case MB_PF:
		counter = 0;
		pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_PENDING);
		do {
			if (FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_STATUS, pending)) {
				id = FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_VF_ID, pending);
				vector = FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_VECTOR, pending);
				ys_dev_info("pf:%d, vf:%d, vf2pf pending : %08x, vec:%d, vf_id:%d\n"
					    , pdev_priv->pf_id, pdev_priv->vf_id,
					    pending, vector, id);
				pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_PENDING);
			}

			counter++;
			if (counter > 10) {
				ys_dev_info("counter:%d\n", counter);
				break;
			}

		} while (FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_STATUS, pending));

		counter = 0;
		pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_PENDING);
		do {
			if (FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_STATUS, pending)) {
				id = FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_PF_ID, pending);
				vector = FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_VECTOR, pending);
				ys_dev_info("pf:%d, vf:%d, pf2pf pending : %08x, vec:%d, vf_id:%d\n"
					    , pdev_priv->pf_id, pdev_priv->vf_id,
					    pending, vector, id);
				pending = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_PENDING);
			}

			counter++;
			if (counter > 10) {
				ys_dev_info("counter:%d\n", counter);
				break;
			}
		} while (FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_STATUS, pending));
		break;
	case MB_VF:
		counter = 0;
		pending = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_PENDING);
		do {
			if (FIELD_GET(YS_K2U_MBOX_VF2PF_IRQ_P_STATUS, pending)) {
				id = FIELD_GET(YS_K2U_MBOX_VF2PF_IRQ_P_VF_ID, pending);
				vector = FIELD_GET(YS_K2U_MBOX_VF2PF_IRQ_P_VECTOR, pending);
				ys_dev_info("pf:%d, vf:%d, pf2vf pending : %08x, vec:%d, vf_id:%d\n"
					    , pdev_priv->pf_id, pdev_priv->vf_id,
					    pending, vector, id);
				pending = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_PENDING);
			}

			counter++;
			if (counter > 10) {
				ys_dev_info("counter:%d\n", counter);
				break;
			}
		} while (FIELD_GET(YS_K2U_MBOX_VF2PF_IRQ_P_STATUS, pending));
		break;

	default:
		ys_err(" dst type is unknown!!");
	}

	return 0;
}

static int ys_k2u_mbox_interrupt_timeout(struct ys_mbox *mbox, int opcode, int time)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	int ms_cnt = 50000;

	if (opcode)
		ys_dev_info("==yusur mailbox enable interrupt timeout %d ms ==\n", time);
	else
		ys_dev_info("==yusur mailbox disable interrupt timeout ==\n");

	if (opcode == 0) {
		ys_wr32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE, 0);
	} else {
		ys_wr32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE, 1);
		ys_wr32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_CNT, time * ms_cnt);
	}

	return 0;
}

static int ys_k2u_mbox_k2u_sync_test(struct ys_mbox *mbox, struct ys_mbox_msg *msg,
				     u32 opcode, u32 param, u32 param1)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	int ret = 0;

	switch (opcode) {
	case YS_MBOX_TEST_OPCODE_ACK:
		ys_k2u_mbox_send_ack(mbox, msg, param, YS_MBOX_OPCODE_TEST);
		break;
	case YS_MBOX_TEST_OPCODE_RESET:
		ys_k2u_mbox_test_reset(mbox);
		break;

	case YS_MBOX_TEST_OPCODE_VECTOR_REG:
		ys_k2u_mbox_test_vector_reg(mbox, param, param1);
		break;

	case YS_MBOX_TEST_OPCODE_VECTOR_SET:
		ys_k2u_mbox_set_vector_reg(mbox, param);
		break;

	case YS_MBOX_TEST_OPCODE_READ_REGS:
		ys_k2u_mbox_read_all_regs(mbox);
		break;

	case YS_MBOX_TEST_OPCODE_WRITE_MEM:
		ret = ys_k2u_mbox_write_mem(mbox, param, param1);
		break;

	case YS_MBOX_TEST_OPCODE_CHECK_MEM:
		ret = ys_k2u_mbox_check_mem(mbox, param, param1);
		break;

	case YS_MBOX_TEST_OPCODE_TEST_SEL:
		ret = ys_k2u_mbox_test_select_master(mbox, param, param1);
		break;

	case YS_MBOX_TEST_OPCODE_TRIG_INT:
		ret = ys_k2u_mbox_triger_interrupt(mbox, param, param1);
		break;

	case YS_MBOX_TEST_OPCODE_CLR_INT:
		ret = ys_k2u_mbox_clear_interrupt(mbox);
		break;

	case YS_MBOX_TEST_OPCODE_INT_TIMEOUT:
		ret = ys_k2u_mbox_interrupt_timeout(mbox, param, param1);
		break;

	default:
		ys_dev_info("mbox op code %x err!\n", opcode);
		ys_k2u_mbox_send_ack(mbox, msg, param, YS_MBOX_OPCODE_TEST);
		break;
	}

	return ret;
}

int ys_k2u_mbox_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	u32 reg;
	u32 i;
	u32 pf_id;
	u32 id = 0;
	u32 retry_count = 0;
	u32 retry_max = 512;
	struct ys_k2u_mbox *k2u_mbox;
	struct ys_k2u_mbox_ctx *ctx;

	ctx = (struct ys_k2u_mbox_ctx *)&id;
	pdev_priv = pci_get_drvdata(pdev);
	if (IS_ERR_OR_NULL(pdev_priv))
		return -EFAULT;

	mbox = ys_aux_match_mbox_dev(pdev);
	if (IS_ERR_OR_NULL(mbox))
		return -EFAULT;

	/* init mbox base offset */
	ys_k2u_mbox_base = YS_K2U_MBOX_DPU_HOST_BASE;
	if (dpu_soc)
		ys_k2u_mbox_base = YS_K2U_MBOX_DPU_SOC_BASE;

	mbox->addr = (void __iomem *)pdev_priv->bar_addr[YS_K2U_MBOX_BAR];
	/* init mbox base offset */
	ys_k2u_mbox_base = YS_K2U_MBOX_DPU_HOST_BASE;
	if (dpu_soc) {
		ys_k2u_mbox_base = YS_K2U_MBOX_DPU_SOC_BASE;
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_G_MAILBOX_VERSION);
		if (reg == 0xdeadbad5) {
			if (pdev_priv->pf_id == 0) {
				pdev_priv->master = YS_PF_MASTER;
				mbox->role = MB_MASTER;
			} else {
				pdev_priv->master = YS_PF_SLAVE;
				mbox->role = MB_PF;
			}
			return 0;
		}
	}

	k2u_mbox = kzalloc(sizeof(*k2u_mbox), GFP_KERNEL);
	if (!k2u_mbox)
		return -ENOMEM;
	mbox->mb_priv = (void *)k2u_mbox;
	mbox->role = MB_VF;
	for (i = 0; i < MBOX_MAX_CHANNAL; i++) {
		init_llist_head(&mbox->request[i]);
		init_llist_head(&mbox->response[i]);
		spin_lock_init(&ys_k2u_mbox_global_locks[i]);
	}
	/* only pf need to preempt */
	if (!pdev_priv->nic_type->is_vf) {
		mbox->role = MB_PF;
		pdev_priv->master = YS_PF_SLAVE;
		/* master select */
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_MASTER_PREEMPT);
		if (reg & YS_K2U_MBOX_MASTER_SEL) {
			pdev_priv->master = YS_PF_MASTER;
			mbox->role = MB_MASTER;
			ys_dev_info("............ I'm master\n");
			/* get lf to pf map table */
			for (i = YS_K2U_MBOX_LF_START; i <= YS_K2U_MBOX_LF_END; ++i) {
				reg = ys_rd32(mbox->addr, YS_K2U_MBOX_LFX_MEM_OFFSET(i));
				pf_id = (u32)FIELD_GET(YS_K2U_MBOX_LFX_MEM_PF_ID, reg);
				ys_dev_info("addr:%x", YS_K2U_MBOX_LFX_MEM_OFFSET(i));
				ys_dev_info("master lf %d to pf %x, reg:%x", i, pf_id, reg);
				k2u_mbox->pf2lf_table[pf_id] = i;
			}
			/* config pf to pf-master interrupt vector */
			ys_wr32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_VECTOR, YS_K2U_MBOX_IRQ);
			/* config soc master to host pf master interrupt vector */
			ys_wr32(mbox->addr, YS_K2U_MBOX_S2H_IRQ_VECTOR, YS_K2U_MBOX_IRQ);
			/* config m3 master to host pf master interrupt vector*/
			ys_wr32(mbox->addr, YS_K2U_MBOX_M2H_IRQ_VECTOR, YS_K2U_MBOX_IRQ);

			/* the interrupt timeout was enabled */
			ys_wr32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE, 0);
			ys_wr32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_CNT, YS_K2U_MBOX_G_TIMEOUT);
			ys_wr32(mbox->addr, YS_K2U_MBOX_G_TIMEOUT_ENABLE, 1);

			/* clearing pf2pf interrupt */
			reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_PENDING);
			retry_count = 0;
			do {
				if (FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_STATUS, reg)) {
					reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2PF_IRQ_PENDING);
					ys_dev_debug("read YS_K2U_MBOX_PF2PF_IRQ_PENDING:%08x\n",
						     reg);
				}

				retry_count++;
				if (retry_count > retry_max) {
					ys_dev_err("mailbox cannot clear interrupt %08x\n", reg);
					break;
				}
			} while (FIELD_GET(YS_K2U_MBOX_PF2PF_IRQ_P_STATUS, reg));
		}
		/* config pf2vf interrupt vector */
		ys_wr32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_VECTOR, YS_K2U_MBOX_IRQ);

		/* clearing pf2vf interrupt */
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_PENDING);
		retry_count = 0;
		do {
			if (FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_STATUS, reg)) {
				reg = ys_rd32(mbox->addr, YS_K2U_MBOX_PF2VF_IRQ_PENDING);
				ys_dev_debug("read YS_K2U_MBOX_PF2VF_IRQ_PENDING:%08x\n",
					     reg);
			}

			retry_count++;
			if (retry_count > retry_max) {
				ys_dev_err("mailbox cannot clear interrupt %08x\n", reg);
				break;
			}
		} while (FIELD_GET(YS_K2U_MBOX_PF2VF_IRQ_P_STATUS, reg));
	} else {
		/* config vf2pf interrupt vector */
		ys_wr32(mbox->addr, YS_K2U_MBOX_VF_IRQ_VECTOR, YS_K2U_MBOX_IRQ);

		/* clearing vf2pf interrupt */
		reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_PENDING);
		retry_count = 0;
		do {
			if (FIELD_GET(YS_K2U_MBOX_VF2PF_IRQ_P_STATUS, reg)) {
				reg = ys_rd32(mbox->addr, YS_K2U_MBOX_VF_IRQ_PENDING);
				ys_dev_debug("read YS_K2U_MBOX_VF_IRQ_PENDING:%08x\n", reg);
			}

			retry_count++;
			if (retry_count > retry_max) {
				ys_dev_err("mailbox cannot clear interrupt %08x\n", reg);
				break;
			}
		} while (FIELD_GET(YS_K2U_MBOX_VF2PF_IRQ_P_STATUS, reg));
	}

	/* clear mbox shmem */
	if (!pdev_priv->nic_type->is_vf) {
		if (mbox->role == MB_MASTER) {
			/* clear send to PF mbox */
			ctx->type = MB_PF;
			for (i = 0; i < 9; i++) {
				ctx->func_id = i;
				ys_k2u_mbox_clear_send_mailbox(mbox, id);
				ys_k2u_mbox_clear_recv_mailbox(mbox, id);
			}
			/* clear send to vf mbox */
			ctx->type = MB_VF;
			for (i = 0; i < pdev_priv->sriov_info.num_vfs; i++) {
				ctx->func_id = i;
				ys_k2u_mbox_clear_send_mailbox(mbox, id);
				ys_k2u_mbox_clear_recv_mailbox(mbox, id);
			}
		} else {
			/* clear send to master mbox */
			ctx->type = MB_MASTER;
			ys_k2u_mbox_clear_send_mailbox(mbox, id);
			ys_k2u_mbox_clear_recv_mailbox(mbox, id);
			/* clear send to vf mbox */
			ctx->type = MB_VF;
			for (i = 0; i < pdev_priv->sriov_info.num_vfs; i++) {
				ctx->func_id = i;
				ys_k2u_mbox_clear_send_mailbox(mbox, id);
				ys_k2u_mbox_clear_recv_mailbox(mbox, id);
			}
		}
	} else {
		ys_k2u_mbox_clear_send_mailbox(mbox, 0);
		ys_k2u_mbox_clear_recv_mailbox(mbox, 0);
	}
	/* TO DO cfg vf2pf and pf2vf vector */
	mbox->mbox_hw_get_irq_id = ys_k2u_mbox_get_irq_id;
	mbox->mbox_hw_send_msg = ys_k2u_mbox_send_msg;
	mbox->mbox_hw_recv_msg = ys_k2u_mbox_recv_msg;
	mbox->mbox_hw_read_send_mailbox = ys_k2u_mbox_read_send_mailbox;
	mbox->mbox_hw_clear_send_mailbox = ys_k2u_mbox_clear_send_mailbox;
	mbox->mbox_hw_get_irq_status = ys_k2u_mbox_get_irq_status;
	mbox->mbox_test = ys_k2u_mbox_k2u_sync_test;
	return 0;
}
EXPORT_SYMBOL(ys_k2u_mbox_init);
