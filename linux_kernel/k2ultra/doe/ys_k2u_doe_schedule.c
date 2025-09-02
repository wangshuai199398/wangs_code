// SPDX-License-Identifier: GPL-2.0
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>

#include "ys_k2u_doe_core.h"

/* Invalidate command whose parent command timeout. */
static int ys_k2u_doe_invalidate_cmd(struct ys_k2u_doe_interface *doe_if,
				     struct ys_doe_sw_cmd *cmd)
{
	struct ys_pdev_priv *pdev_priv = NULL;
	struct ys_k2u_doe_desc *desc;
	struct ys_k2u_doe_desc *temp;
	unsigned long flags;

	pdev_priv = pci_get_drvdata(doe_if->ys_k2u_doe->pdev);
	list_for_each_entry_safe(desc, temp, &cmd->cache_list, cache) {
		if (desc->parent ? desc->parent == cmd : desc->cmd == cmd) {
			list_del(&desc->cache);
			atomic_sub(1, &doe_if->cache_list_count);
			if (desc->parent)
				ys_k2u_doe_free_cmd(doe_if, desc->cmd);

			ys_dev_debug("Delete desc form cache-list with tag 0x%04x\n",
				     desc->cmd_tag);
			ys_k2u_doe_free_dsc(doe_if, desc);
		}
	}

	spin_lock_irqsave(&doe_if->work_lock, flags);
	list_for_each_entry(desc, &doe_if->work_list, list) {
		if (desc->parent ? desc->parent == cmd : desc->cmd == cmd)
			desc->invalid = 1;
	}
	spin_unlock_irqrestore(&doe_if->work_lock, flags);

	return 0;
}

static inline u64 ys_k2u_doe_user_cmd_timeout(struct ys_doe_sw_cmd *cmd)
{
	if (cmd->opcode == YS_DOE_SW_CREATE_ARRAY || cmd->opcode == YS_DOE_SW_CREATE_HASH ||
	    cmd->opcode == YS_DOE_SW_DELETE_ARRAY || cmd->opcode == YS_DOE_SW_DELETE_HASH)
		return YS_K2U_DOE_CMD_TIMEOUT;
	else
		return HZ;
}

int ys_k2u_doe_user_cmd_context(struct ys_k2u_doe_device *ys_k2u_doe,
				struct ys_doe_sw_cmd *cmd)
{
	struct ys_k2u_doe_interface *doe_if;
	struct ys_pdev_priv *pdev_priv;
	int ret;
	u64 outtime;

	/* let work to send cmd and polling event */
	if (cmd->is_read)
		doe_if = ys_k2u_doe->doe_read_if;
	else
		doe_if = ys_k2u_doe->doe_write_if;

	pdev_priv = pci_get_drvdata(doe_if->ys_k2u_doe->pdev);

	/* put desc to pending llist */
	ret = ys_k2u_doe_process_cmd(ys_k2u_doe, cmd);
	if (ret)
		return ret;

	/*
	 * The queue-work maybe complete before the desc
	 * has be putted to the pending list
	 */
	ys_k2u_doe_polling_work(doe_if, cmd);

	outtime = get_jiffies_64() + ys_k2u_doe_user_cmd_timeout(cmd);

	while (time_is_after_jiffies64(outtime)) {
		if (!atomic_read((atomic_t *)&cmd->wait_lock))
			break;
		cpu_relax();
	}

	if (cmd->cnt != cmd->succeed + cmd->failed) {
		ys_dev_info("CMD timedout opc:%x tbl:%d!\n",
			    cmd->opcode, cmd->tbl_id);
		ys_dev_info("Total:%d success:%d failed:%d.\n",
			    cmd->cnt, cmd->succeed, cmd->failed);
		ret = -ETIMEDOUT;
		goto err;
	} else if (cmd->failed) {
		ys_dev_info("Total:%d success:%d failed:%d err:%d.\n",
			    cmd->cnt, cmd->succeed, cmd->failed, cmd->err);
	}

	return 0;
err:
	ys_k2u_doe_invalidate_cmd(doe_if, cmd);

	if (cmd->opcode == YS_DOE_SW_CREATE_ARRAY ||
	    cmd->opcode == YS_DOE_SW_CREATE_HASH)
		test_and_clear_bit(cmd->tbl_id, ys_k2u_doe->tbl_bitmap);

	return ret;
}

int ys_k2u_doe_user_cmd_context_poll_wait(struct ys_k2u_doe_device *ys_k2u_doe,
					  struct ys_doe_sw_cmd *cmd)
{
	int ret;
	u64 outtime;
	struct ys_k2u_doe_interface *doe_if;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);

	/* let work to send cmd and polling event */
	if (cmd->is_read)
		doe_if = ys_k2u_doe->doe_read_if;
	else
		doe_if = ys_k2u_doe->doe_write_if;

	/* put desc to pending llist */
	ret = ys_k2u_doe_process_cmd(ys_k2u_doe, cmd);
	if (ret)
		return ret;

	ys_k2u_doe_polling_work(doe_if, cmd);

	outtime = get_jiffies_64() + ys_k2u_doe_user_cmd_timeout(cmd);
	do {
		smp_rmb(); /*Make sure that all cache line entry is flushed*/
		if (cmd->cnt == cmd->succeed + cmd->failed)
			return 0;
	} while (time_is_after_jiffies64(outtime));

	ys_dev_info("CMD timeout opc:%x tbl:%d!\n",
		    cmd->opcode, cmd->tbl_id);
	ys_dev_info("Total:%d succuss=%d failed:%d.\n",
		    cmd->cnt, cmd->succeed, cmd->failed);

	ys_k2u_doe_invalidate_cmd(doe_if, cmd);

	if (cmd->opcode == YS_DOE_SW_CREATE_ARRAY ||
	    cmd->opcode == YS_DOE_SW_CREATE_HASH)
		test_and_clear_bit(cmd->tbl_id, ys_k2u_doe->tbl_bitmap);

	return -ETIMEDOUT;
}

/* If submit error, return err directly */
int ys_k2u_doe_submit_cmd(struct ys_k2u_doe_device *ys_k2u_doe, struct ys_doe_sw_cmd *cmd,
			  struct ys_doe_sw_cmd *parent,
			  int (*complete_desc)(struct ys_k2u_doe_desc *,
					       struct ys_k2u_doe_event *))
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct ys_k2u_doe_interface *doe_if;
	struct ys_k2u_doe_desc *desc;
	struct list_head *cache_list = NULL;

	if (cmd->is_read)
		doe_if = ys_k2u_doe->doe_read_if;
	else
		doe_if = ys_k2u_doe->doe_write_if;

	desc = ys_k2u_doe_alloc_dsc(doe_if);
	if (!desc)
		return -ENOMEM;

	/* cnt of single cmd must initial with 1 for wakeup condition! */
	if (!parent)
		cmd->cnt = 1;

	desc->ys_k2u_doe = ys_k2u_doe;
	desc->cmd = cmd;
	desc->parent = parent;
	desc->complete_desc = complete_desc;
	if (parent) {
		atomic_set((atomic_t *)&parent->wait_lock, 1);
		cache_list = &parent->cache_list;
	} else {
		atomic_set((atomic_t *)&cmd->wait_lock, 1);
		cache_list = &cmd->cache_list;
	}

	ys_dev_debug("Submit %s cmd opc 0x%02x tbl %d\n", doe_if->name,
		     cmd->opcode, cmd->tbl_id);
	list_add_tail(&desc->cache, cache_list);
	atomic_add(1, &doe_if->cache_list_count);

	return 0;
}

static struct ys_k2u_doe_cmd_buffer *ys_k2u_doe_get_cmdbuffer(struct ys_k2u_doe_interface *doe_if)
{
	u8 cb_next = 0;

	cb_next = atomic_add_return(1, &doe_if->cb_next);
	return &doe_if->cb[cb_next % doe_if->cb_depth];
}

/* cmd buffer productor */
int ys_k2u_doe_enqueue_cmdbuffer(struct ys_k2u_doe_interface *doe_if,
				 struct ys_k2u_doe_desc *desc,
				 struct ys_k2u_doe_cmd_buffer *cb)
{
	struct ys_k2u_doe_device *ys_k2u_doe = doe_if->ys_k2u_doe;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	struct ys_doe_sw_cmd *cmd = desc->cmd;
	struct ys_k2u_doe_hw_cmd_head *cmd_head;
	u16 key_len, dov_len, cmd_len;
	void *ptr;
	u16 old_cmd_tag = 0;
	u16 new_cmd_tag = 0;

	if (cmd->opcode == YS_DOE_SW_CMD_PUSH)
		return 0;

	do {
		old_cmd_tag = atomic_read(&doe_if->cmd_tag);
		new_cmd_tag = old_cmd_tag + 1;
	} while (old_cmd_tag != atomic_cmpxchg(&doe_if->cmd_tag, old_cmd_tag, new_cmd_tag));

	desc->cmd_tag = new_cmd_tag;
	desc->is_read = cmd->is_read;
	key_len = ys_k2u_doe->param[cmd->tbl_id].key_len;
	dov_len = ys_k2u_doe->param[cmd->tbl_id].dov_len;

	/* length of opcode and table_id */
	cmd_len = 2;

	/* Init cmd head */
	ptr = cb->base + cb->end_ptr;
	cmd_head = (struct ys_k2u_doe_hw_cmd_head *)ptr;
	cmd_head->valid = 1;
	cmd_head->status = 0;

	ptr += sizeof(*cmd_head);
	cmd_head->table_id = cmd->tbl_id;
	cmd_head->cmd_tag = cpu_to_le16(desc->cmd_tag);

	switch (cmd->opcode) {
	case YS_DOE_SW_RAW_CMD:
		ptr -= 2;
		memcpy(ptr, cmd->cmd, cmd->cmd_size);
		cmd_len = cmd->cmd_size;
		ptr += cmd->cmd_size;

		/* Transter the user-define opcode for desc-complete */
		//cmd->opcode = *(u8 *)cmd->cmd;
		cmd->tbl_id = *(u8 *)(cmd->cmd + 1);
		break;

	case YS_DOE_SW_ARRAY_LOAD:
	case YS_DOE_SW_ARRAY_READ:
		cmd_head->opcode = cmd->opcode;
		*(u32 *)ptr = cpu_to_le32(cmd->index);
		ptr += 4;
		cmd_len += 4;
		break;

	case YS_DOE_SW_ARRAY_STORE:
		cmd_head->status |= GEN_HEAD_PRIORITY(cmd->high_pri);
		cmd_head->opcode = cmd->opcode;
		cmd_head->status |= GEN_HEAD_ENABLE(cmd->enable);
		*(u32 *)ptr = cpu_to_le32(cmd->index);
		ptr += 4;
		cmd_len += 4;
		memcpy(ptr, cmd->data, dov_len);
		ptr += dov_len;
		cmd_len += dov_len;
		break;
	case YS_DOE_SW_ARRAY_WRITE:
		cmd_head->opcode = cmd->opcode;
		cmd_head->status |= GEN_HEAD_ENABLE(cmd->enable);
		*(u32 *)ptr = cpu_to_le32(cmd->index);
		ptr += 4;
		cmd_len += 4;
		memcpy(ptr, cmd->data, dov_len);
		ptr += dov_len;
		cmd_len += dov_len;
		break;

	case YS_DOE_SW_HASH_QUERY:
		cmd_head->opcode = YS_K2U_DOE_HASH_QUERY;
		memcpy(ptr, cmd->key, key_len);
		ptr += key_len;
		cmd_len += key_len;
		break;

	case YS_DOE_SW_HASH_INSERT:
		cmd_head->status |= GEN_HEAD_PRIORITY(cmd->high_pri);
		cmd_head->opcode = cmd->opcode;
		cmd_head->status |= GEN_HEAD_ENABLE(cmd->enable);
		memcpy(ptr, cmd->key, key_len);
		ptr += key_len;
		cmd_len += key_len;
		memcpy(ptr, cmd->value, dov_len);
		ptr += dov_len;
		cmd_len += dov_len;
		break;
	case YS_DOE_SW_HASH_UPDATE:
	case YS_DOE_SW_HASH_SAVE:
		cmd_head->opcode = cmd->opcode;
		cmd_head->status |= GEN_HEAD_ENABLE(cmd->enable);
		memcpy(ptr, cmd->key, key_len);
		ptr += key_len;
		cmd_len += key_len;
		memcpy(ptr, cmd->value, dov_len);
		ptr += dov_len;
		cmd_len += dov_len;
		break;

	case YS_DOE_SW_HASH_DELETE:
		cmd_head->opcode = YS_K2U_DOE_HASH_DELETE;
		memcpy(ptr, cmd->key, key_len);
		ptr += key_len;
		cmd_len += key_len;
		break;

	case YS_DOE_SW_COUNTER_ENABLE:
		cmd_head->status |= GEN_HEAD_PRIORITY(cmd->high_pri);
		cmd_head->opcode = YS_K2U_DOE_ARRAY_STORE;
		cmd_head->status |= GEN_HEAD_ENABLE(cmd->enable);
		*(u32 *)ptr = cpu_to_le32(cmd->index);
		ptr += 4;
		cmd_len += 4;
		memcpy(ptr, cmd->data, dov_len);
		ptr += dov_len;
		cmd_len += dov_len;
		break;

	case YS_DOE_SW_COUNTER_LOAD:
		cmd_head->opcode = YS_DOE_SW_ARRAY_READ;
		cmd_head->table_id = YS_K2U_DOE_BATCH_OP_TABLE;
		*(u32 *)ptr = cpu_to_le32(cmd->tbl_id);
		ptr += 4;
		cmd_len += 4;
		memcpy(ptr, cmd->data, 9);
		ptr += 9;
		cmd_len += 9;
		break;

	default:
		break;
	}
	ys_dev_debug("Enqueue %s cmd%d 0x%04x (%d.%d-%ld) for OPC 0x%x TBL %d\n",
		     doe_if->name, cb->cmd_cnt, desc->cmd_tag, cb->id,
		     cb->end_ptr, ptr - cb->base, cmd->opcode, cmd->tbl_id);

	cmd_head->cmd_len = cmd_len;
	CB_MOVE_TAIL(cb, ptr - cb->base);

	return 0;
}

static int ys_k2u_doe_process_send_date(struct ys_k2u_doe_interface *doe_if,
					struct ys_doe_sw_cmd *cmd)
{
	struct ys_k2u_doe_desc *desc = NULL, *desc_next = NULL;
	unsigned long flags;
	struct ys_k2u_doe_cmd_buffer *cb = NULL;

	cb = ys_k2u_doe_get_cmdbuffer(doe_if);

	/* add desc to work list if there is free space for event */
	list_for_each_entry_safe(desc, desc_next, &cmd->cache_list, cache) {
		ys_k2u_doe_enqueue_cmdbuffer(doe_if, desc, cb);
		list_del(&desc->cache);
		atomic_sub(1, &doe_if->cache_list_count);
		if (ys_k2u_doe_clean_push(doe_if, desc))
			break;

		spin_lock_irqsave(&doe_if->work_lock, flags);
		list_add_tail(&desc->list, &doe_if->work_list);
		atomic_add(1, &doe_if->work_list_count);
		spin_unlock_irqrestore(&doe_if->work_lock, flags);

		if (CB_IS_FULL(cb))
			break;
	}

	/* Send cmd by dma */
	ys_k2u_doe_send_cmd(doe_if, cb);

	return 0;
}

static int ys_k2u_doe_process_working_list(struct ys_k2u_doe_interface *doe_if,
					   struct ys_k2u_doe_event *event)
{
	struct ys_k2u_doe_desc *desc, *temp;
	struct ys_k2u_doe_device *ys_k2u_doe = doe_if->ys_k2u_doe;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);

	spin_lock(&doe_if->work_lock);
	list_for_each_entry_safe(desc, temp, &doe_if->work_list, list) {
		/* If event lost, the head of list must be removed! */
		if (desc->invalid) {
			list_del(&desc->list);
			atomic_sub(1, &doe_if->work_list_count);
			if (desc->parent)
				ys_k2u_doe_free_cmd(doe_if, desc->cmd);

			ys_dev_debug("Delete desc form work-list with tag 0x%04x\n",
				     desc->cmd_tag);

			ys_k2u_doe_free_dsc(doe_if, desc);
		/* Event desc found! */
		} else if (desc->cmd_tag == event->cmd_tag) {
			list_del(&desc->list);
			ys_dev_debug("Ack desc form work-list with tag 0x%04x\n",
				     desc->cmd_tag);
			atomic_sub(1, &doe_if->work_list_count);
			if (desc->complete_desc)
				desc->complete_desc(desc, event);
			spin_unlock(&doe_if->work_lock);
			return 0;
		}
	}
	spin_unlock(&doe_if->work_lock);

	ys_dev_err("%s Unknown event TAG 0x%04x\n", doe_if->name, event->cmd_tag);

	return -EIO;
}

void ys_k2u_desc_completed(struct ys_k2u_doe_interface *doe_if)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(doe_if->ys_k2u_doe->pdev);
	struct ys_k2u_doe_event_queue *eq = &doe_if->eq;
	u32 avail, event_num;
	void *addr;
	int i = 0;
	int j = 0;

	ys_dev_debug("%s eq working! tail %d head %d\n",
		     doe_if->name, eq->sw_tail, eq->sw_head);

	/* Check if there is new events */
	avail = EQ_AVAILABLE(eq);
	if (avail)
		ys_dev_debug("Event Find! %d\n", avail);

	/* Recive event from hardware */
	for (i = 0; i < avail; i++) {
		addr = eq->base + eq->sw_tail * eq->entry_size;

		buffer_dump(doe_if->ys_k2u_doe, doe_if->name, addr, 256);

		/* It's unlikely be locked, unless batch-cmd timeout */
		if (doe_if->is_read) {
			ys_k2u_doe_process_working_list(doe_if, addr);
		} else {
			event_num = le32_to_cpu(*(u32 *)addr);
			addr += (4 + (event_num - 1) *
				 sizeof(struct ys_k2u_doe_event));
			
			if (event_num >= YS_K2U_DOE_EVENT_MAX_LIMIT) {
				ys_dev_err("%s eq recv event:%u over max limit\n",
					   doe_if->name, event_num);
				event_num = YS_K2U_DOE_EVENT_MAX_LIMIT;
			}


			for (j = 0; j < event_num; j++) {
				ys_k2u_doe_process_working_list(doe_if, addr);
				addr -= sizeof(struct ys_k2u_doe_event);
				if (j)
					EQ_WITHDRAW_HEAD(eq);
			}
		}
		EQ_MOVE_TAIL(eq);
	}

	ys_dev_debug("%s eq workdone! tail %d head %d\n",
		     doe_if->name, eq->sw_tail, eq->sw_head);
}

/* This work_queue will be schedules by both ioctl_context and irq_handler */
void ys_k2u_doe_polling_work(struct ys_k2u_doe_interface *doe_if,
			     struct ys_doe_sw_cmd *cmd)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(doe_if->ys_k2u_doe->pdev);
	u64 time_end;
	u32 old_count;

	time_end = get_jiffies_64() + HZ;
	while (true) {
		do {
doe_dma_busy_err:
			old_count = atomic_read(&doe_if->hw_buffer_count);
			if (!old_count) {
				ys_dev_debug("%s hardware cmdbuffer is full!", doe_if->name);
				ys_k2u_doe_dma_busy(doe_if);
				goto doe_dma_busy_err;
			}
		} while (old_count != atomic_cmpxchg(&doe_if->hw_buffer_count,
						     old_count, old_count - 1));

		ys_k2u_doe_process_send_date(doe_if, cmd);

		if (list_empty(&cmd->cache_list))
			break;

		if (time_is_before_jiffies64(time_end))
			break;
	}

	ys_k2u_doe_clean_irq(doe_if);
}
