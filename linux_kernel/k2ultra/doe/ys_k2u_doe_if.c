// SPDX-License-Identifier: GPL-2.0

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/llist.h>

#include "ys_k2u_doe_core.h"

#define PLDA_ISTATUS_HOST		0x18c

int ys_k2u_doe_reg_init(struct ys_k2u_doe_device *ys_k2u_doe)
{
	struct ys_k2u_doe_interface *doe_if[2] = {
		ys_k2u_doe->doe_write_if,
		ys_k2u_doe->doe_read_if,
	};
	u32 offset[2] = {
		YS_K2U_DOE_WR_CHANNEL_BASE,
		YS_K2U_DOE_RD_CHANNEL_BASE,
	};
	struct ys_k2u_doe_event_queue *eq;
	u32 val;
	void __iomem *dma_reg_base;
	int i, ret;

	for (i = 0; i < 2; i++) {
		dma_reg_base = ys_k2u_doe->doe_base + offset[i];
		doe_if[i]->dma_reg_base = dma_reg_base;
		eq = &doe_if[i]->eq;

		ys_k2u_doe_writel(ys_k2u_doe, eq->entry_size,
				  dma_reg_base + YS_K2U_DOE_EVENT_SIZE);
		ys_k2u_doe_writel(ys_k2u_doe, eq->depth * eq->entry_size,
				  dma_reg_base + YS_K2U_DOE_EVENT_TOTAL_SIZE);
		ys_k2u_doe_writel(ys_k2u_doe, (u32)eq->dma_base,
				  dma_reg_base + YS_K2U_DOE_EVENT_BASE_LOW);
		ys_k2u_doe_writel(ys_k2u_doe, (u32)(eq->dma_base >> 32),
				  dma_reg_base + YS_K2U_DOE_EVENT_BASE_HIGH);
		ys_k2u_doe_writel(ys_k2u_doe, (u32)eq->dma_hw_tail,
				  dma_reg_base + YS_K2U_DOE_EVENT_PTR_LOW);
		ys_k2u_doe_writel(ys_k2u_doe, (u32)(eq->dma_hw_tail >> 32),
				  dma_reg_base + YS_K2U_DOE_EVENT_PTR_HIGH);
	}

	/* Set the DOE protection register to low, allowing all instructions to access DOE */
	/* ys_k2u_doe_writel(ys_k2u_doe, 0, dma_reg_base + YS_K2U_DOE_PROTECT_CFG); */

	/* DOE reset must be asserted after event initial */
	val = 1;
	ys_k2u_doe_writel(ys_k2u_doe, val, ys_k2u_doe->doe_base + YS_K2U_DOE_RESET);
	ret = readl_poll_timeout_atomic(ys_k2u_doe->doe_base + YS_K2U_DOE_RESET, val,
					val == 0, 100, 3000);

	if (ret)
		return ret;

	return 0;
}

static int ys_k2u_doe_send_data(struct ys_k2u_doe_interface *doe_if,
				struct ys_k2u_doe_cmd_buffer *cb)
{
	struct ys_k2u_doe_device *ys_k2u_doe = doe_if->ys_k2u_doe;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	u32 len = cb->end_ptr;
	u32 reg_base_shfit = 0;

	/* Let the cmd buffer alignment */
	len = (len + YS_K2U_DOE_CMDDMA_ALIGN) & ~YS_K2U_DOE_CMDDMA_ALIGN;

	/* If there is the reserved 32 Bytes data, set bit16(CMD_VALID) to 0 */
	if (cb->end_ptr & YS_K2U_DOE_CMDDMA_ALIGN)
		memset(cb->base + cb->end_ptr, 0, 32);

	reg_base_shfit = doe_if->mod_reg_base_shfit;

	/* Write dma reg to trigger send */
	spin_lock(&doe_if->transaction_lock);
	ys_k2u_doe_writel(ys_k2u_doe, (u32)cb->dma_base,
			  doe_if->dma_reg_base + reg_base_shfit + YS_K2U_DOE_CMD_ADDR_LOW);
	ys_k2u_doe_writel(ys_k2u_doe, (u32)(cb->dma_base >> 32),
			  doe_if->dma_reg_base + reg_base_shfit + YS_K2U_DOE_CMD_ADDR_HIGH);
	ys_k2u_doe_writel(ys_k2u_doe, len,
			  doe_if->dma_reg_base + reg_base_shfit + YS_K2U_DOE_CMD_LEN);
	ys_k2u_doe_writel(ys_k2u_doe, 1,
			  doe_if->dma_reg_base + reg_base_shfit + YS_K2U_DOE_CMD_CONTROL);
	//atomic_sub(1, &doe_if->hw_buffer_count);
	spin_unlock(&doe_if->transaction_lock);

	ys_dev_debug("Send %s cmd buffer %p.%d\n", doe_if->name,
		     cb->base, cb->end_ptr);
	buffer_dump(ys_k2u_doe, "cmd buffer", cb->base, len);
	CB_CLEAR_TAIL(cb);

	return 0;
}

int ys_k2u_doe_dma_busy(struct ys_k2u_doe_interface *doe_if)
{
	struct ys_k2u_doe_device *ys_k2u_doe = doe_if->ys_k2u_doe;
	u32 hw_buffer_count = 0;
	u32 cpu_relax_count = 1000;

	if (ys_k2u_doe->enble_faster_mode) {
		if (doe_if->is_read)
			hw_buffer_count = ys_rd32(ys_k2u_doe->doe_base,
						  YS_K2U_DOE_RD_CHANNEL_SPACE);
		else
			hw_buffer_count = ys_rd32(ys_k2u_doe->doe_base,
						  YS_K2U_DOE_WR_CHANNEL_SPACE);
	} else {
		do {
			cpu_relax();
			cpu_relax_count--;
			hw_buffer_count = ys_rd32(doe_if->dma_reg_base,
						  YS_K2U_DOE_CMD_CONTROL);
		} while (hw_buffer_count && cpu_relax_count);
		hw_buffer_count = 1;
	}

	atomic_set(&doe_if->hw_buffer_count, hw_buffer_count);
	return hw_buffer_count;
}

/* cmd buffer consumer */
int ys_k2u_doe_send_cmd(struct ys_k2u_doe_interface *doe_if,
			struct ys_k2u_doe_cmd_buffer *cb)
{
	if (!cb || !cb->end_ptr)
		return 0;

	/* Real DMA operations */
	ys_k2u_doe_send_data(doe_if, cb);

	return 0;
}

#ifdef PLDA_VERSION
int ys_k2u_doe_check_irq(struct ys_k2u_doe_interface *doe_if)
{
	u32 val;

	/* Check interrupt status register */
	val = readl(doe_if->ys_k2u_doe->doe_base + PLDA_ISTATUS_HOST);
	if (!(val & BIT(doe_if->msi_index)))
		return -EINVAL;

	return 0;
}

void ys_k2u_doe_clean_irq(struct ys_k2u_doe_interface *doe_if)
{
	struct ys_k2u_doe_device *ys_k2u_doe = doe_if->ys_k2u_doe;
	u32 val;

	/* Write 1 to clean interrupt status, enable interrupt */
	val = readl(doe_if->ys_k2u_doe->dma_base + PLDA_ISTATUS_HOST);
	if (val & BIT(doe_if->msi_index))
		writel(BIT(doe_if->msi_index),
		       ys_k2u_doe->dma_base + PLDA_ISTATUS_HOST);
}
#else
int ys_k2u_doe_check_irq(struct ys_k2u_doe_interface *doe_if)
{
	return 0;
}

void ys_k2u_doe_clean_irq(struct ys_k2u_doe_interface *doe_if) {}
#endif
