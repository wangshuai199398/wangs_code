// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/delay.h>

#include "ys_mbox.h"
#include "ys_pdev.h"
#include "../k2ultra/mbox/ys_k2u_mbox.h"
#include "ys_reg_ops.h"

static struct ys_mbox_test_statistics mbox_test_stat;

static u8 ys_mbox_cal_checksum(struct ys_mbox_msg *mbox_msg)
{
	struct ys_mbox_msg tmp;
	u8 new_checksum = 0;
	int i;

	if (IS_ERR_OR_NULL(mbox_msg))
		return 0;

	memcpy(&tmp, mbox_msg, sizeof(tmp));
	for (i = 0; i < YS_MBOX_MSG_LEN; i++)
		new_checksum += tmp.data[i];

	return new_checksum;
}

static int ys_mbox_validate_checksum(struct ys_mbox_msg *mbox_msg)
{
	return ys_mbox_cal_checksum(mbox_msg) == mbox_msg->checksum;
}

static void ys_mbox_print(struct ys_mbox *mbox, struct ys_mbox_msg *mbox_msg, char *msg)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);

	ys_dev_debug("%s", msg);
	ys_dev_debug("mbox_msg->magic_data: 0x%x\n", mbox_msg->magic_data);
	ys_dev_debug("mbox_msg->opcode: 0x%x\n", mbox_msg->opcode);
	ys_dev_debug("mbox_msg->length: 0x%x\n", mbox_msg->length);
	ys_dev_debug("mbox_msg->checksum: 0x%x\n", mbox_msg->checksum);
	ys_dev_debug("mbox_msg->data[0]: %x\n", mbox_msg->data[0]);
	ys_dev_debug("mbox_msg->data[1]: %x\n", mbox_msg->data[1]);
	ys_dev_debug("mbox_msg->data[2]: %x\n", mbox_msg->data[2]);
	ys_dev_debug("mbox_msg->data[3]: %x\n", mbox_msg->data[3]);
}

static void ys_mbox_llist_clear(struct llist_head *head)
{
	struct ys_mbox_llist_node *node, *node_next;
	struct llist_node *entry;

	if (llist_empty(head))
		return;

	entry = llist_del_all(head);
	llist_for_each_entry_safe(node, node_next, entry, llnode) {
		ys_debug("clear llist opcode: %x seq %d\n", node->msg.opcode, node->msg.seqno);
		kfree(node);
	}
}

static void ys_mbox_request_clear(struct ys_mbox *mbox, u32 clear_id)
{
	int i;

	for (i = 0; i < MBOX_MAX_CHANNAL; i++)
		ys_mbox_llist_clear(&mbox->request[i]);
}

static void ys_mbox_response_clear(struct ys_mbox *mbox, u32 clear_id)
{
	int i;

	for (i = 0; i < MBOX_MAX_CHANNAL; i++)
		ys_mbox_llist_clear(&mbox->response[i]);
}

static bool ys_mbox_check_mailbox_unlocked(struct ys_mbox *mbox, u32 send_id)
{
	struct ys_mbox_msg mbox_msg, null_msg = {0};
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);

	if (IS_ERR_OR_NULL(mbox->mbox_hw_read_send_mailbox))
		return true;

	mbox->mbox_hw_read_send_mailbox(mbox, (void *)&mbox_msg, send_id);

	if (memcmp(&mbox_msg, &null_msg, sizeof(mbox_msg)) == 0)
		return true;

	ys_dev_debug("mailbox mbox_msg.opcode %x\n", mbox_msg.opcode);
	return false;
}

static u32 ys_mbox_recv_check(struct ys_mbox_msg *msg)
{
	if (IS_ERR_OR_NULL(msg))
		return -1;

	if (msg->opcode != YS_MBOX_OPCODE_IRQ_UNREGISTER) {
		if (!ys_mbox_validate_checksum(msg)) {
			ys_warn("msg checksum error!\n"
				"msg.checksum:%x, checksum:%x,\n"
				"msg.opcode:%x,\n"
				"msg.data:%s\n",
				msg->checksum, ys_mbox_cal_checksum(msg),
				msg->opcode, msg->data);
			return -1;
		}
	}
	return 0;
}

static void ys_mbox_recv_msg(struct ys_mbox *mbox, struct ys_mbox_msg *mbox_msg, u32 recive_id)
{
	recive_id = recive_id % MBOX_MAX_CHANNAL;
	mbox->mbox_hw_recv_msg(mbox, (void *)mbox_msg, recive_id);
	ys_mbox_print(mbox, mbox_msg, "===mbox msg recv===");
	ys_mbox_recv_check(mbox_msg);
}

static int ys_mbox_llist_dequeue(struct llist_head *head, struct ys_mbox_msg *mbox_msg)
{
	struct ys_mbox_llist_node *node;
	struct llist_node *new_first, *new_last, *removed;

	if (llist_empty(head))
		return 0;

	new_first = llist_del_all(head);
	removed = llist_reverse_order(new_first);
	node = llist_entry(removed, typeof(*node), llnode);
	memcpy(mbox_msg, &node->msg, sizeof(struct ys_mbox_msg));

	if (!removed->next) {
		kfree(node);
		return 1;
	}

	new_last = llist_next(removed);

	llist_reverse_order(new_last);
	llist_add_batch(new_first, new_last, head);

	removed->next = NULL;
	kfree(node);
	return 1;
}

static int ys_mbox_dequeue_request(struct ys_mbox *mbox, struct ys_mbox_msg *mbox_msg, u32 channel)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	int ret = 0;

	ret = ys_mbox_llist_dequeue(&mbox->request[channel], mbox_msg);

	ys_dev_debug("mbox_msg->opcode %x len: %x checksum: %x\n",
		     mbox_msg->opcode, mbox_msg->length, mbox_msg->checksum);
	return ret;
}

static int ys_mbox_dequeue_response(struct ys_mbox *mbox, struct ys_mbox_msg *mbox_msg, u32 channel)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	int ret = 0;

	ret = ys_mbox_llist_dequeue(&mbox->response[channel], mbox_msg);

	ys_dev_debug("response->opcode %x len: %x checksum: %x\n",
		     mbox_msg->opcode, mbox_msg->length, mbox_msg->checksum);
	return ret;
}

static int ys_mbox_send_logic(struct ys_mbox *mbox,
			      struct ys_mbox_msg *send_msg,
			      u32 channel,
			      bool wait_reply,
			      u32 expect_opcode,
			      u32 sync_timeout,
			      struct ys_mbox_msg *recv_msg)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	unsigned long timeout;
	bool unlocked = false;
	struct ys_mbox_llist_node *node;
	static atomic_t seq = ATOMIC_INIT(400000000);

	send_msg->magic_data = MBOX_MAGIC_DATA;

	if (send_msg->opcode >> YS_MBOX_OPCODE_MASK_ACK == 0 && wait_reply)
		send_msg->seqno = atomic_add_return(1, &seq);

	send_msg->checksum = ys_mbox_cal_checksum(send_msg);
	ys_mbox_print(mbox, send_msg, "===mbox msg send===");
	mbox->mbox_hw_send_msg(mbox, (void *)send_msg, channel);
	ys_dev_debug("%s, send mb channel %d opcode %02x expect %x seq %d msg trigger irq finish!\n",
		    __func__, channel, send_msg->opcode, expect_opcode, send_msg->seqno);

	timeout = jiffies + msecs_to_jiffies(1000);
	while (time_before(jiffies, timeout)) {
		if (ys_mbox_check_mailbox_unlocked(mbox, channel)) {
			unlocked = true;
			break;
		}
		ndelay(10000);
	}
	if (!unlocked) {
		ys_dev_warn("msg check unlock failed, The other side did not take the message, channel %d, opcode %x seq %d\n",
			    channel, send_msg->opcode, send_msg->seqno);
		return YS_MBOX_SEND_L2_FAILED;
	}

	if (!wait_reply)
		return YS_MBOX_SEND_OK;

	timeout = jiffies + msecs_to_jiffies(sync_timeout);
	while (time_before(jiffies, timeout)) {
		while (!ys_mbox_dequeue_response(mbox, recv_msg, channel)) {
			ndelay(10000);
			if (time_before(jiffies, timeout)) {
				continue;
			} else {
				ys_dev_warn("mailbox no response failed, channel %d expect %x seq %d\n",
					    channel, expect_opcode, send_msg->seqno);
				return YS_MBOX_SEND_L3_NO_ACK;
			}
		}
		if (recv_msg->opcode == expect_opcode)
			break;
		ys_dev_warn("mailbox out-of-order failed, channel %d opcode %x expect %x seq %d\n",
			    channel, recv_msg->opcode, expect_opcode, send_msg->seqno);
		if (recv_msg->magic_data != MBOX_MAGIC_DATA)
			return YS_MBOX_SEND_L3_NO_ACK;
		node = kzalloc(sizeof(*node), GFP_ATOMIC);
		if (!node)
			return -ENOMEM;
		node->msg = *recv_msg;
		llist_add(&node->llnode, &mbox->response[channel]);
		ndelay(10000);
	}
	if (recv_msg->opcode != expect_opcode) {
		ys_dev_warn("mailbox delay no ack failed, channel %d opcode %x expect %x seq %d\n",
			    channel, recv_msg->opcode, expect_opcode, send_msg->seqno);
		ys_mbox_dequeue_response(mbox, recv_msg, channel);
		return YS_MBOX_SEND_L3_NO_ACK;
	}
	return YS_MBOX_SEND_OK;
}

int ys_mbox_send_msg(struct ys_mbox *mbox,
		     struct ys_mbox_msg *send_msg,
		     u32 channel,
		     enum ys_mbox_mode wait_reply,
		     u32 timeout,
		     struct ys_mbox_msg *recv_msg)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	unsigned long timeout200;
	bool unlocked = false;
	int ret = 0;
	int retry_count = 3;

	channel = channel % MBOX_MAX_CHANNAL;
	while (retry_count--) {
		timeout200 = jiffies + msecs_to_jiffies(200);
		while (time_before(jiffies, timeout200)) {
			if (ys_mbox_check_mailbox_unlocked(mbox, channel)) {
				unlocked = true;
				break;
			}
			ndelay(10000);
		}
		if (!unlocked) {
			ys_dev_warn("mailbox is locked for more than 200ms, clearing lock, channel %d\n",
				    channel);
			if (!IS_ERR_OR_NULL(mbox->mbox_hw_clear_send_mailbox))
				mbox->mbox_hw_clear_send_mailbox(mbox, channel);
			mdelay(500);
			ret = YS_MBOX_SEND_L2_FAILED;
			continue;
		}

		ret = ys_mbox_send_logic(mbox,
					 send_msg,
					 channel,
					 wait_reply,
					 send_msg->opcode | (1 << YS_MBOX_OPCODE_MASK_ACK),
					 timeout,
					 recv_msg);
		if (ret == 0)
			return ret;

		mdelay(500);
		ys_dev_warn("mailbox send failed, retry count %d channel %d\n",
			    retry_count, channel);
		ret = YS_MBOX_SEND_L3_RETRY_FAILED;
	}

	if (ret != 0)
		ys_dev_err("mailbox send failed, channel %d, ret %d opcode %x\n",
			   channel, ret, send_msg->opcode);

	return ret;
}

#ifdef CONFIG_YSARCH_PLAT
EXPORT_SYMBOL(ys_mbox_send_msg);
#endif /* CONFIG_YSARCH_PLAT */

static void ys_mbox_test_success_inc(void)
{
	spin_lock(&mbox_test_stat.lock);
	mbox_test_stat.success_count++;
	spin_unlock(&mbox_test_stat.lock);
}

static void ys_mbox_test_fail_inc(void)
{
	spin_lock(&mbox_test_stat.lock);
	mbox_test_stat.fail_count++;
	spin_unlock(&mbox_test_stat.lock);
}

static void ys_mbox_test_statis_clear(void)
{
	spin_lock(&mbox_test_stat.lock);
	mbox_test_stat.success_count = 0;
	mbox_test_stat.fail_count = 0;
	spin_unlock(&mbox_test_stat.lock);
}

static void ys_mbox_test_statis_display(void)
{
	u32 success_count = 0;
	u32 fail_count = 0;

	spin_lock(&mbox_test_stat.lock);
	success_count = mbox_test_stat.success_count;
	fail_count = mbox_test_stat.fail_count;
	spin_unlock(&mbox_test_stat.lock);

	ys_info("=================================================\n");
	ys_info("success_count:%d\n", success_count);
	ys_info("fail_count:%d\n", fail_count);
	ys_info("=================================================\n");
}

static void ys_mbox_test_init(void)
{
	if (mbox_test_stat.init_flag != 0x1010) {
		mbox_test_stat.init_flag = 0x1010;
		mbox_test_stat.success_count = 0;
		mbox_test_stat.fail_count = 0;
		spin_lock_init(&mbox_test_stat.lock);
	}
}

static void ys_mbox_test_vf_to_pf_stab(struct ys_mbox *mbox, int count)
{
	struct timespec64 start, end;
	u64 t_sec = 0;
	struct ys_mbox_msg mbox_msg = {0};

	ktime_get_real_ts64(&start);
	ys_mbox_request_clear(mbox, 0);
	ys_mbox_response_clear(mbox, 0);
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	memcpy(&mbox_msg.data, "yusur mailbox test", 18);

	while (t_sec < 20000000) {
		if (!ys_mbox_send_msg(mbox, &mbox_msg, 0, MB_NO_REPLY, 0, NULL))
			count--;
		if (count <= 0)
			break;
		ktime_get_real_ts64(&end);
		t_sec = ((end.tv_sec - start.tv_sec) * 1000000 +
			 (end.tv_nsec - start.tv_nsec) / 1000);
	}
	ys_info("vf to pf mailbox test count :%d\n", count);
}

static void ys_mbox_test_vf_to_pf_qps(struct ys_mbox *mbox)
{
	struct timespec64 start, end;
	u64 count = 0;
	u64 t_sec = 0;
	struct ys_mbox_msg mbox_msg = {0};

	ktime_get_real_ts64(&start);
	ys_mbox_request_clear(mbox, 0);
	ys_mbox_response_clear(mbox, 0);
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	memcpy(&mbox_msg.data, "yusur general vf to pf mailbox test!!!\n"
	       "yusur general vf to pf mailbox test!!!\n"
	       "yusur general vf to pf mailbox test!!!!okok", YS_MBOX_MSG_LEN);

	while (t_sec < 1000000) {
		if (!ys_mbox_send_msg(mbox, &mbox_msg, 0, MB_NO_REPLY, 0, NULL))
			count++;
		ktime_get_real_ts64(&end);
		t_sec = ((end.tv_sec - start.tv_sec) * 1000000 +
			 (end.tv_nsec - start.tv_nsec) / 1000);
	}
	ys_info("vf to pf mailbox test count :%lld\n", count);
}

static void ys_mbox_test_vf_to_pf(struct ys_mbox *mbox, int count)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct timespec64 start, end, cur;
	u64 t_sec = 0;
	u32 send_id = 0;
	u32 i = 0;
	u32 *ptr = NULL;
	struct ys_mbox_msg mbox_msg = {0};
	struct ys_mbox_msg mbox_msg1 = {0};

	ys_dev_info("vf2pf mbox test\n");
	ktime_get_real_ts64(&start);
	send_id = 1 << 10 | 0;
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	mbox_msg.length = YS_MBOX_MSG_LEN;

	ptr = (u32 *)mbox_msg.data;
	while (t_sec < MBOX_TEST_TIME) {
		ktime_get_real_ts64(&cur);
		for (i = 0; i < YS_MBOX_MSG_LEN / 4; i++)
			ptr[i] = cur.tv_nsec;

		if (!ys_mbox_send_msg(mbox, &mbox_msg, send_id,
				      MB_WAIT_REPLY, MBOX_TIMEOUT, &mbox_msg1)) {
			for (i = 0; i < YS_MBOX_MSG_LEN; i++) {
				if (mbox_msg.data[i] != mbox_msg1.data[i]) {
					ys_dev_err("data check error [%d] %02x -- %02x\n",
						   i, mbox_msg.data[i], mbox_msg1.data[i]);
					ys_mbox_llist_clear(&mbox->response[send_id]);
					break;
				}
			}

			if (i != YS_MBOX_MSG_LEN)
				break;

			count--;
		}

		if (count <= 0)
			break;

		ktime_get_real_ts64(&end);
		t_sec = ((end.tv_sec - start.tv_sec) * 1000000 +
			 (end.tv_nsec - start.tv_nsec) / 1000);
	}

	if (count == 0) {
		ys_mbox_test_success_inc();
		ys_dev_info("vf to pf mailbox test successful.\n");
	} else {
		ys_mbox_test_fail_inc();
		ys_dev_err("vf to pf mailbox test failed, not sent count :%d\n", count);
	}
}

static void ys_mbox_test_pf_to_vf_stab(struct ys_mbox *mbox, int vf_id, int count)
{
	struct timespec64 start, end;
	u64 t_sec = 0;
	struct ys_mbox_msg mbox_msg;

	ktime_get_real_ts64(&start);
	ys_mbox_request_clear(mbox, 0);
	ys_mbox_response_clear(mbox, 0);
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	memcpy(&mbox_msg.data, "yusur mailbox test", 18);

	while (t_sec < 20000000) {
		if (!ys_mbox_send_msg(mbox, &mbox_msg, vf_id, MB_NO_REPLY, 0, NULL))
			count--;
		if (count <= 0)
			break;
		ktime_get_real_ts64(&end);
		t_sec = ((end.tv_sec - start.tv_sec) * 1000000 +
			 (end.tv_nsec - start.tv_nsec) / 1000);
	}
	ys_info("pf to vf or pf to pf mailbox test count :%d\n", count);
}

static void ys_mbox_test_pf_to_vf_qps(struct ys_mbox *mbox, int vf_id)
{
	struct timespec64 start, end;
	u64 count = 0;
	u64 t_sec = 0;
	struct ys_mbox_msg mbox_msg;

	ktime_get_real_ts64(&start);
	ys_mbox_request_clear(mbox, 0);
	ys_mbox_response_clear(mbox, 0);
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	mbox_msg.send_id = vf_id;
	memcpy(&mbox_msg.data, "yusur general pf to vf or pf to pf\n"
	       "mailbox test!!!yusur general pf to vf or pf to pf\n"
	       "mailbox test!!!yusur general!!!!!!", YS_MBOX_MSG_LEN);

	while (t_sec < 1000000) {
		if (!ys_mbox_send_msg(mbox, &mbox_msg, vf_id, MB_NO_REPLY, 0, NULL))
			count++;
		ktime_get_real_ts64(&end);
		t_sec = ((end.tv_sec - start.tv_sec) * 1000000 +
			 (end.tv_nsec - start.tv_nsec) / 1000);
	}
	ys_info("pf to vf or pf to pf mailbox test count :%lld\n", count);
}

static void ys_mbox_test_pf_to_pf(struct ys_mbox *mbox,
				  int target_type,
				  int pf_id,
				  int count)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct timespec64 start, end, cur;
	u64 t_sec = 0;
	u32 send_id = 0;
	u32 i = 0;
	u32 *ptr = NULL;
	struct ys_mbox_msg mbox_msg = {0};
	struct ys_mbox_msg mbox_msg1 = {0};
	int ret = 0;

	ys_dev_info("pf2pf mbox test, send_id %08x\n", send_id);
	send_id = target_type << 10 | pf_id;
	ktime_get_real_ts64(&start);
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	mbox_msg.length = YS_MBOX_MSG_LEN;
	mbox_msg.send_id = pf_id;

	ptr = (u32 *)mbox_msg.data;
	while (t_sec < MBOX_TEST_TIME) {
		ktime_get_real_ts64(&cur);
		for (i = 0; i < YS_MBOX_MSG_LEN / 4; i++)
			ptr[i] = cur.tv_nsec;

		ret = ys_mbox_send_msg(mbox, &mbox_msg, send_id,
				       MB_WAIT_REPLY, MBOX_TIMEOUT, &mbox_msg1);

		if (!ret) {
			for (i = 0; i < YS_MBOX_MSG_LEN; i++) {
				if (mbox_msg.data[i] != mbox_msg1.data[i]) {
					ys_dev_err("data check error [%d] %02x -- %02x\n",
						   i, mbox_msg.data[i], mbox_msg1.data[i]);
					break;
				}
			}

			if (i != YS_MBOX_MSG_LEN)
				break;

			//ys_info("sync msg opcode %x\n", mbox_msg1.opcode);
			count--;
		}

		if (count <= 0)
			break;

		ktime_get_real_ts64(&end);
		t_sec = ((end.tv_sec - start.tv_sec) * 1000000 +
			 (end.tv_nsec - start.tv_nsec) / 1000);
	}

	if (count == 0) {
		ys_mbox_test_success_inc();
		ys_dev_info("pf to pf mailbox test successful.\n");
	} else {
		ys_mbox_test_fail_inc();
		ys_dev_err("pf to pf mailbox test failed, not sent count :%d\n", count);
	}
}

static void ys_mbox_test_pf_to_vf(struct ys_mbox *mbox, int vf_id, int count)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct timespec64 start, end, cur;
	u64 t_sec = 0;
	u32 send_id = 0;
	u32 i = 0;
	u32 *ptr = NULL;
	struct ys_mbox_msg mbox_msg = {0};
	struct ys_mbox_msg mbox_msg1 = {0};

	ys_dev_info("pf2vf mbox test, send_id %08x\n", vf_id);
	send_id = vf_id;
	ktime_get_real_ts64(&start);
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	mbox_msg.length = YS_MBOX_MSG_LEN;
	mbox_msg.send_id = vf_id;

	ptr = (u32 *)mbox_msg.data;
	while (t_sec < MBOX_TEST_TIME) {
		ktime_get_real_ts64(&cur);
		for (i = 0; i < YS_MBOX_MSG_LEN / 4; i++)
			ptr[i] = cur.tv_nsec;

		if (!ys_mbox_send_msg(mbox, &mbox_msg, send_id,
				      MB_WAIT_REPLY, MBOX_TIMEOUT, &mbox_msg1)) {
			for (i = 0; i < YS_MBOX_MSG_LEN; i++) {
				if (mbox_msg.data[i] != mbox_msg1.data[i]) {
					ys_dev_err("data check error [%d] %02x -- %02x\n",
						   i, mbox_msg.data[i], mbox_msg1.data[i]);
					break;
				}
			}

			if (i != YS_MBOX_MSG_LEN)
				break;

			//ys_info("sync msg opcode %x\n", mbox_msg1.opcode);
			count--;
		}
		if (count <= 0)
			break;

		ktime_get_real_ts64(&end);
		t_sec = ((end.tv_sec - start.tv_sec) * 1000000 +
			 (end.tv_nsec - start.tv_nsec) / 1000);
	}

	if (count == 0) {
		ys_mbox_test_success_inc();
		ys_dev_info("pf to vf mailbox test successful.\n");
	} else {
		ys_mbox_test_fail_inc();
		ys_dev_err("pf to vf mailbox test failed, not sent count :%d\n", count);
	}
}

static void ys_mbox_test_func_to_self_test(struct ys_mbox *mbox, int func_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_mbox_msg mbox_msg;
	struct ys_mbox_msg mbox_msg1;
	struct timespec64 cur;
	u32 i = 0;
	u32 *ptr = NULL;

	ys_dev_info("self mbox send_id %08x\n", func_id);
	ys_mbox_request_clear(mbox, 0);
	ys_mbox_response_clear(mbox, 0);
	mbox_msg.opcode = YS_MBOX_OPCODE_TEST;
	mbox_msg.length = YS_MBOX_MSG_LEN;
	mbox_msg.send_id = func_id;

	ptr = (u32 *)mbox_msg.data;
	ktime_get_real_ts64(&cur);
	for (i = 0; i < YS_MBOX_MSG_LEN / 4; i++)
		ptr[i] = cur.tv_nsec;
	mbox->mbox_hw_send_msg(mbox, (void *)&mbox_msg, func_id);
	mbox->mbox_hw_read_send_mailbox(mbox, (void *)&mbox_msg1, func_id);
	for (i = 0; i < YS_MBOX_MSG_LEN; i++) {
		if (mbox_msg.data[i] != mbox_msg1.data[i]) {
			ys_dev_info("data check error [%d] %02x -- %02x\n",
				    i, mbox_msg.data[i], mbox_msg1.data[i]);
			break;
		}
	}
}

static void ys_mbox_test_reset(struct ys_mbox *mbox)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_RESET, 0, 0);
}

static void ys_mbox_test_vector_reg(struct ys_mbox *mbox, u32 val, u32 test)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_VECTOR_REG, val, test);
}

static void ys_mbox_set_vector_reg(struct ys_mbox *mbox, u32 reg)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_VECTOR_SET, reg, 0);
}

static void ys_mbox_test_read_all_regs(struct ys_mbox *mbox)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_READ_REGS, 0, 0);
}

static void ys_mbox_write_mem(struct ys_mbox *mbox, int type, int id, int data)
{
	u32 send_id;

	send_id = type << 10 | id;

	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_WRITE_MEM, send_id, data);
}

static void ys_mbox_check_mem(struct ys_mbox *mbox, int type, int id, int data)
{
	u32 send_id;

	send_id = type << 10 | id;
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_CHECK_MEM, send_id, data);
}

static void ys_mbox_test_select_master(struct ys_mbox *mbox, int opcode, int lf_id)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_TEST_SEL, opcode, lf_id);
}

static void ys_mbox_triger_interrupt(struct ys_mbox *mbox, int type, int id)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_TRIG_INT, type, id);
}

static void ys_mbox_clear_interrupt(struct ys_mbox *mbox)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_CLR_INT, 0, 0);
}

static void ys_mbox_interrupt_timeout(struct ys_mbox *mbox, int opcode, int time)
{
	if (IS_ERR_OR_NULL(mbox->mbox_test))
		ys_info("mbox_test is NULL\n");
	else
		mbox->mbox_test(mbox, NULL, YS_MBOX_TEST_OPCODE_INT_TIMEOUT, opcode, time);
}

u32 ys_mbox_sysfs_send(struct pci_dev *pdev, const char *buf)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	u32 opcode;
	u32 target_type;
	u32 send_id;
	u8 command[32];

	pdev_priv = pci_get_drvdata(pdev);
	mbox = ys_aux_match_mbox_dev(pdev);

	if (sscanf(buf, "%s%d%d%d", command, &opcode, &target_type, &send_id) != 4)
		return -EFAULT;

	ys_dev_info("store, command= %s,opcode=0x%08x, target_type=0x%08x, value=0x%08x\n",
		    command, opcode, target_type, send_id);

	if (!strcmp(command, "test_statis")) {
		ys_mbox_test_statis_display();
		return 0;
	}

	if (!strcmp(command, "test_clear")) {
		ys_mbox_test_statis_clear();
		return 0;
	}

	if (!strcmp(command, "test_reset")) {
		ys_mbox_test_reset(mbox);
		return 0;
	}

	if (!strcmp(command, "test_vector")) {
		/* opcode is the value that prepares the read and write test */
		/* target_type is the original register value */
		ys_mbox_test_vector_reg(mbox, opcode, target_type);
		return 0;
	}

	if (!strcmp(command, "set_vector")) {
		/* opcode is the value of the set register */
		ys_mbox_set_vector_reg(mbox, opcode);
		return 0;
	}

	if (!strcmp(command, "read_regs")) {
		ys_mbox_test_read_all_regs(mbox);
		return 0;
	}

	if (!strcmp(command, "write_mem")) {
		ys_mbox_write_mem(mbox, target_type, send_id, opcode);
		return 0;
	}

	if (!strcmp(command, "check_mem")) {
		ys_mbox_check_mem(mbox, target_type, send_id, opcode);
		return 0;
	}

	if (!strcmp(command, "sel_master")) {
		ys_mbox_test_select_master(mbox, opcode, target_type);
		return 0;
	}

	if (!strcmp(command, "trig_int")) {
		ys_mbox_triger_interrupt(mbox, target_type, send_id);
		return 0;
	}

	if (!strcmp(command, "clr_int")) {
		ys_mbox_clear_interrupt(mbox);
		return 0;
	}

	/* opcode: 0 disable, 1 enable */
	/* target_type: timeout value */
	if (!strcmp(command, "int_timeout")) {
		ys_mbox_interrupt_timeout(mbox, opcode, target_type);
		return 0;
	}

	if (pdev_priv->nic_type->is_vf) {
		ys_dev_info("vf send to pf\n");
		if (!strcmp(command, "vf2pf")) {
			ys_mbox_test_vf_to_pf(mbox, opcode);
			return 0;
		}
		if (opcode)
			ys_mbox_test_vf_to_pf_stab(mbox, opcode);
		else
			ys_mbox_test_vf_to_pf_qps(mbox);
	} else {
		if (!strcmp(command, "fself")) {
			ys_dev_info("func sends to func itself\n");
			ys_mbox_test_func_to_self_test(mbox, send_id);
			return 0;
		}
		if (!strcmp(command, "pf2pf")) {
			ys_dev_info("pf send to pf\n");
			ys_mbox_test_pf_to_pf(mbox, target_type, send_id, opcode);
			return 0;
		}
		if (!strcmp(command, "pf2vf")) {
			ys_dev_info("pf send to vf\n");
			ys_mbox_test_pf_to_vf(mbox, send_id, opcode);
			return 0;
		}
		ys_dev_info("pf send to vf %d\n", send_id);
		if (send_id > pdev_priv->sriov_info.num_vfs) {
			ys_warn("non valid send_id %d\n", send_id);
			return -EFAULT;
		}
		if (opcode)
			ys_mbox_test_pf_to_vf_stab(mbox, send_id, opcode);
		else
			ys_mbox_test_pf_to_vf_qps(mbox, send_id);
	}

	return 0;
}

static void ys_mbox_func_vf_deal(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 vf_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_mbox_msg response = {0};

	if (msg->opcode >> YS_MBOX_OPCODE_MASK_ACK)
		return;

	switch (msg->opcode) {
	case YS_MBOX_OPCODE_IRQ_UNREGISTER:
		ys_dev_warn("mbox recv unregister opcode!\n");
		goto vf_err_ack;
	case YS_MBOX_OPCODE_TEST:
		if (IS_ERR_OR_NULL(mbox->mbox_test))
			ys_dev_info("mbox_test is NULL\n");
		else
			mbox->mbox_test(mbox, msg, YS_MBOX_TEST_OPCODE_ACK, vf_id, 0);
		break;
	case YS_MBOX_OPCODE_SET_VF_MAC:
		if (IS_ERR_OR_NULL(mbox->mbox_pf_to_vf_set_mac))
			ys_dev_info("mbox_pf_to_vf_set_mac NULL\n");
		else
			mbox->mbox_pf_to_vf_set_mac(mbox, msg, vf_id);
		break;
	case YS_MBOX_OPCODE_SET_PORT_STATUS:
		if (IS_ERR_OR_NULL(mbox->mbox_pf_to_vf_set_port_status))
			ys_dev_info("mbox_pf_to_vf_set_port_status is NULL\n");
		else
			mbox->mbox_pf_to_vf_set_port_status(mbox, msg, vf_id);
		break;
	default:
		ys_dev_info("mbox op code %x err!\n", msg->opcode);
		goto vf_err_ack;
	}

	return;
vf_err_ack:
	memcpy(&response, msg, sizeof(*msg));
	response.opcode |= (1 << YS_MBOX_OPCODE_MASK_ACK);
	response.seqno = msg->seqno;
	ys_mbox_send_msg(mbox, &response, vf_id, MB_NO_REPLY, 0, NULL);
}

static void ys_mbox_func_pf_deal(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 msg_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_mbox_msg response = {0};

	if (msg->opcode >> YS_MBOX_OPCODE_MASK_ACK)
		return;

	switch (msg->opcode) {
	case YS_MBOX_OPCODE_IRQ_UNREGISTER:
		ys_dev_warn("mbox recv unregister opcode!\n");
		goto pf_err_ack;
	case YS_MBOX_OPCODE_TEST:
		if (IS_ERR_OR_NULL(mbox->mbox_test))
			ys_dev_info("mbox_test is NULL\n");
		else
			mbox->mbox_test(mbox, msg, YS_MBOX_TEST_OPCODE_ACK, msg_id, 0);
		break;
	case YS_MBOX_OPCODE_SET_VF_MAC:
		ys_dev_warn("mbox recv wrong opcode! YS_MBOX_OPCODE_SET_VF_MAC(%d)\n",
			    YS_MBOX_OPCODE_SET_VF_MAC);
		goto pf_err_ack;
	case YS_MBOX_OPCODE_SET_TX_INFO:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_txq_info))
			ys_dev_info("mbox_vf_to_pf_set_txq_info is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_txq_info(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_RX_INFO:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_rxq_info))
			ys_dev_info("mbox_vf_to_pf_set_rxq_info is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_rxq_info(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_TX_ASSIGNMENT:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_txq_assignment))
			ys_dev_info("mbox_vf_to_pf_set_txq_assignment is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_txq_assignment(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_RX_ASSIGNMENT:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_rxq_assignment))
			ys_dev_info("mbox_vf_to_pf_set_rxq_assignment is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_rxq_assignment(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_INNER_VLAN:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_inner_vlan))
			ys_dev_info("mbox_vf_to_pf_set_inner_vlan is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_inner_vlan(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_MAC:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_mac))
			ys_dev_info("mbox_vf_to_pf_set_mac is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_mac(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_MC_MAC:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_mc_mac))
			ys_dev_info("mbox_vf_to_pf_set_mc_mac is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_mc_mac(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_MTU:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_mtu))
			ys_dev_info("mbox_vf_to_pf_set_mtu is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_mtu(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_HASH:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_hash))
			ys_dev_info("mbox_vf_to_pf_set_hash is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_hash(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_CLEAR_HASH:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_clear_hash))
			ys_dev_info("mbox_vf_to_pf_clear_hash is NULL\n");
		else
			mbox->mbox_vf_to_pf_clear_hash(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_RXFH:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_rxfh))
			ys_dev_info("mbox_vf_to_pf_set_rxfh is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_rxfh(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_GET_HASH_MODE:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_get_hash_mode))
			ys_dev_info("mbox_vf_to_pf_get_hash_mode is NULL\n");
		else
			mbox->mbox_vf_to_pf_get_hash_mode(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_TX_FEATURES:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_tx_features))
			ys_dev_info("mbox_vf_to_pf_set_tx_features is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_tx_features(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_VLAN_FEATURES:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_vlan_features))
			ys_dev_info("mbox_vf_to_pf_set_vlan_features is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_vlan_features(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_GET_QSET:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_get_qset))
			ys_dev_info("mbox_vf_to_pf_get_qset NULL\n");
		else
			mbox->mbox_vf_to_pf_get_qset(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_FILTER:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_filter))
			ys_dev_info("mbox_vf_to_pf_set_filter is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_filter(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_PROMISC:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_promisc))
			ys_dev_info("mbox_vf_to_pf_set_promisc is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_promisc(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_PORT_ENABLE:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_port_enable))
			ys_dev_info("mbox_vf_to_pf_set_port_enable is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_port_enable(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_SET_PRIV:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_priv))
			ys_dev_info("mbox_vf_to_pf_set_priv is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_priv(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_GET_EEPROM_MAC:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_get_eeprom_mac))
			ys_dev_info("mbox_vf_to_pf_get_eeprom_mac is NULL\n");
		else
			mbox->mbox_vf_to_pf_get_eeprom_mac(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_GET_PIO_RES:
		if (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_get_pio_res))
			ys_dev_info("mbox_vf_to_pf_get_pio_res is NULL\n");
		else
			mbox->mbox_vf_to_pf_get_pio_res(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_NP_OPT:
		if  (IS_ERR_OR_NULL(mbox->mbox_np_opt))
			ys_dev_info("mbox_np_opt is NULL\n");
		else
			mbox->mbox_np_opt(mbox, msg, msg_id);
		break;
	case YS_MBOX_OPCODE_RSS_REDIRECT:
		if  (IS_ERR_OR_NULL(mbox->mbox_vf_to_pf_set_rss_redirect))
			ys_dev_info("mbox_vf_to_pf_set_rss_redirect is NULL\n");
		else
			mbox->mbox_vf_to_pf_set_rss_redirect(mbox, msg, msg_id);
		break;
	default:
		ys_dev_info("mbox op code %x err!\n", msg->opcode);
		goto pf_err_ack;
	}

	return;
pf_err_ack:
	memcpy(&response, msg, sizeof(*msg));
	response.opcode |= (1 << YS_MBOX_OPCODE_MASK_ACK);
	response.seqno = msg->seqno;
	ys_mbox_send_msg(mbox, &response, msg_id, MB_NO_REPLY, 0, NULL);
}

static void ys_mbox_tasklet(unsigned long data)
{
	struct ys_irq *irq;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	struct ys_mbox_msg msg = {0};
	int i;

	irq = (struct ys_irq *)data;
	pdev_priv = pci_get_drvdata(irq->pdev);
	mbox = ys_aux_match_mbox_dev(irq->pdev);

	if (IS_ERR_OR_NULL(mbox))
		return;

	for (i = 0; i < MBOX_MAX_CHANNAL; i++) {
		if (test_and_clear_bit(i, irq->bh_data)) {
			while (ys_mbox_dequeue_request(mbox, &msg, i)) {
				ys_dev_debug("tasklet deal channel %d, opcode %x\n", i, msg.opcode);
				if (pdev_priv->nic_type->is_vf)
					ys_mbox_func_vf_deal(mbox, &msg, i);
				else
					ys_mbox_func_pf_deal(mbox, &msg, i);
			}
		}
	}
}

static irqreturn_t ys_mbox_handle(int irqn, void *data)
{
	unsigned long flags;
	struct ys_irq *irq;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	struct ys_mbox_irq_info irq_info;
	struct ys_mbox_llist_node *node;

	irq = data;
	pdev_priv = pci_get_drvdata(irq->pdev);
	mbox = ys_aux_match_mbox_dev(irq->pdev);

	/* Disable interrupts to avoid random delays when reading mailbox */
	local_irq_save(flags);

	do {
		irq_info = mbox->mbox_hw_get_irq_status(mbox);
		/* only pf need to check irq_status */
		if (!pdev_priv->nic_type->is_vf && irq_info.irq_status == 0)
			break;

		node = kmalloc(sizeof(*node), GFP_ATOMIC);
		if (!node) {
			local_irq_restore(flags);
			return IRQ_HANDLED;
		}

		ys_mbox_recv_msg(mbox, &node->msg, irq_info.msg_id);

		if (node->msg.opcode >> YS_MBOX_OPCODE_MASK_ACK)
			llist_add(&node->llnode, &mbox->response[irq_info.msg_id]);
		else
			llist_add(&node->llnode, &mbox->request[irq_info.msg_id]);

		set_bit(irq_info.msg_id, irq->bh_data);

		/* vf has no pending flag, only deal one msg */
		if (pdev_priv->nic_type->is_vf)
			break;

	} while (1);

	local_irq_restore(flags);

	/* for atomic msg deal */
	tasklet_schedule(&irq->tasklet);

	return IRQ_HANDLED;
}

static int ys_mbox_unregister_irqs(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = NULL;
	struct ys_irq_table *irq_table = NULL;
	struct ys_mbox *mbox;
	int index;

	if (IS_ERR_OR_NULL(pdev))
		return 0;

	pdev_priv = pci_get_drvdata(pdev);
	if (IS_ERR_OR_NULL(pdev_priv))
		return 0;

	irq_table = &pdev_priv->irq_table;
	if (IS_ERR_OR_NULL(irq_table))
		return 0;

	mbox = ys_aux_match_mbox_dev(pdev);
	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("mbox unregister irq,mbox is null\n");
		return 0;
	}

	if (!IS_ERR_OR_NULL(mbox->mbox_hw_get_irq_id)) {
		index = mbox->mbox_hw_get_irq_id(mbox);
		YS_UNREGISTER_IRQ(&irq_table->nh, index, pdev_priv->pdev, NULL);
	}

	return 0;
}

static int ys_mbox_register_irqs(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq_sub sub;
	struct ys_mbox *mbox;
	int ret;
	int index;

	mbox = ys_aux_match_mbox_dev(pdev);
	memset(&sub, 0, sizeof(sub));

	sub.devname = kcalloc(YS_MAX_IRQ_NAME, sizeof(char), GFP_KERNEL);
	if (IS_ERR_OR_NULL(sub.devname))
		return -ENOMEM;
	sub.irq_type = YS_IRQ_TYPE_MBOX;
	sub.handler = ys_mbox_handle;
	sub.bh_type = YS_IRQ_BH_TASKLET;
	sub.bh.tasklet_handler = ys_mbox_tasklet;

	if (!IS_ERR_OR_NULL(mbox->mbox_hw_get_irq_id)) {
		index = mbox->mbox_hw_get_irq_id(mbox);
		snprintf(sub.devname, YS_MAX_IRQ_NAME,
			 "%s[%d](%s)-mbox",
			 pdev_priv->nic_type->func_name, index,
			 pci_name(pdev_priv->pdev));
		ret = YS_REGISTER_IRQ(&irq_table->nh, YS_IRQ_NB_REGISTER_FIXED,
				      index, pdev_priv->pdev, sub);
		if (ret < 0) {
			ys_dev_err("Setup irq %d error: %d", index, ret);
			return ret;
		}
	}

	return 0;
}

int ys_aux_mbox_probe(struct auxiliary_device *auxdev,
		      const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = NULL;
	struct ys_pdev_priv *pdev_priv = NULL;
	struct ys_mbox *mbox = NULL;
	struct hw_adapter_ops ys_k2u_ops = {
		.hw_adp_mbox_init = ys_k2u_mbox_init,
	};
	int ret;

	if (IS_ERR_OR_NULL(auxdev))
		goto err_invalid;

	adev = container_of(auxdev, struct ys_adev, auxdev);
	if (IS_ERR_OR_NULL(adev))
		goto err_invalid;

	mbox = kzalloc(sizeof(*mbox), GFP_KERNEL);
	if (IS_ERR_OR_NULL(mbox))
		return -ENOMEM;

	if (IS_ERR_OR_NULL(adev->pdev))
		goto err_invalid;

	pdev_priv = pci_get_drvdata(adev->pdev);
	if (IS_ERR_OR_NULL(pdev_priv))
		goto err_invalid;

	adev->adev_priv = (void *)mbox;
	mbox->pdev = adev->pdev;
	if (IS_ERR_OR_NULL(pdev_priv->ops))
		pdev_priv->ops = &ys_k2u_ops;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_mbox_init)) {
		ret = pdev_priv->ops->hw_adp_mbox_init(pdev_priv->pdev);
		if (ret) {
			ys_err("hw_adp_mbox_init failed, ret=%d", ret);
			goto mbox_fail;
		}
	} else {
		ys_err("hw_adp_mbox_init is NULL");
		goto mbox_fail;
	}

	ret = ys_mbox_register_irqs(adev->pdev);
	if (ret)
		goto mbox_fail;

	ys_mbox_test_init();
	return 0;

mbox_fail:
	ys_aux_mbox_remove(auxdev);
	return -ENOMEM;
err_invalid:
	ys_err("%s failed, ret=%d", __func__, -EINVAL);
	return -EINVAL;
}

void ys_aux_mbox_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = NULL;
	struct ys_mbox *mbox = NULL;
	struct ys_pdev_priv *pdev_priv = NULL;
	int ret;

	if (IS_ERR_OR_NULL(auxdev))
		goto err_invalid;

	adev = container_of(auxdev, struct ys_adev, auxdev);
	if (IS_ERR_OR_NULL(adev))
		goto err_invalid;

	mbox = (struct ys_mbox *)adev->adev_priv;
	if (IS_ERR_OR_NULL(mbox))
		goto err_invalid;

	if (IS_ERR_OR_NULL(adev->pdev))
		goto err_invalid;

	pdev_priv = pci_get_drvdata(adev->pdev);
	if (IS_ERR_OR_NULL(pdev_priv) || IS_ERR_OR_NULL(pdev_priv->ops))
		goto clean;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_mbox_uninit)) {
		ret = pdev_priv->ops->hw_adp_mbox_uninit(pdev_priv->pdev);
		if (ret)
			ys_err("hw_adp_mbox_uninit failed, ret=%d", ret);
	}

clean:
	ys_mbox_unregister_irqs(adev->pdev);
	kfree(mbox);
	return;
err_invalid:
	ys_err("%s failed, ret=%d", __func__, -EINVAL);
}
