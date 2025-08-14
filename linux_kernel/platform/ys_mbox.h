/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_MBOX_H_
#define __YS_MBOX_H_

#include <linux/pci.h>
#include <linux/llist.h>
#include "ys_auxiliary.h"

#define MBOX_MAX_CHANNAL 4096
#define YS_MBOX_PF_MSG_BASE 128

#define MBOX_MAGIC_DATA     (0x1f47)
#define MBOX_TEST_TIME  (50000000)
#define MBOX_TIMEOUT	(1000)

enum {
	MB_VF,
	MB_PF,
	MB_M3,
	MB_MASTER,
};

static inline const char *mb_role_stringify(u32 role)
{
	switch (role) {
	case MB_VF:
		return "MB_VF";
	case MB_PF:
		return "MB_PF";
	case MB_M3:
		return "MB_M3";
	case MB_MASTER:
		return "MB_MASTER";
	default:
		return "Unsupported MB ROLE";
	}
}

enum ys_mbox_mode {
	MB_NO_REPLY = 0,
	MB_WAIT_REPLY = 1
};

enum {
	YS_MBOX_SEND_OK = 0,
	YS_MBOX_SEND_L2_FAILED,
	YS_MBOX_SEND_L3_NO_ACK,
	YS_MBOX_SEND_L3_RETRY_FAILED,
};

enum {
	YS_MBOX_OPCODE_MASK_COMMAND = 0,
	YS_MBOX_OPCODE_MASK_ACK = 15,
};

enum {
	YS_MBOX_OPCODE_IRQ_UNREGISTER       = 0x00,
	YS_MBOX_OPCODE_TEST                 = 0x01,

	YS_MBOX_OPCODE_SET_TX_INFO          = 0x02,
	YS_MBOX_OPCODE_SET_RX_INFO          = 0x04,
	YS_MBOX_OPCODE_SET_TX_ASSIGNMENT    = 0x06,
	YS_MBOX_OPCODE_SET_RX_ASSIGNMENT    = 0x08,
	YS_MBOX_OPCODE_SET_INNER_VLAN       = 0x0A,
	YS_MBOX_OPCODE_GET_EEPROM_MAC       = 0x0C,
	YS_MBOX_OPCODE_SET_MAC              = 0x0E,
	YS_MBOX_OPCODE_SET_VF_MAC           = 0x10,
	YS_MBOX_OPCODE_SET_MC_MAC           = 0x12,
	YS_MBOX_OPCODE_SET_MTU              = 0x14,
	YS_MBOX_OPCODE_SET_HASH             = 0x16,
	YS_MBOX_OPCODE_CLEAR_HASH           = 0x18,
	YS_MBOX_OPCODE_SET_RXFH             = 0x1A,
	YS_MBOX_OPCODE_GET_HASH_MODE        = 0x1C,
	YS_MBOX_OPCODE_SET_TX_FEATURES      = 0x1E,
	YS_MBOX_OPCODE_SET_VLAN_FEATURES    = 0x20,
	YS_MBOX_OPCODE_GET_QSET             = 0x22,
	YS_MBOX_OPCODE_SET_FILTER           = 0x24,
	YS_MBOX_OPCODE_SET_PROMISC          = 0x26,
	YS_MBOX_OPCODE_SET_PORT_ENABLE      = 0x28,
	YS_MBOX_OPCODE_SET_PRIV             = 0x2A,
	YS_MBOX_OPCODE_SET_PORT_STATUS      = 0x2C,
	YS_MBOX_OPCODE_GET_PIO_RES          = 0x2E,
	YS_MBOX_OPCODE_DEL_VF_CFG           = 0x30,
	YS_MBOX_OPCODE_VF_ETHTOOL_STATS     = 0x31,
	YS_MBOX_OPCODE_PF_TO_PF             = 0x32,
	YS_MBOX_OPCODE_NP_OPT               = 0x34,
	YS_MBOX_OPCODE_RSS_REDIRECT	    = 0x36,
};

enum {
	YS_MBOX_TEST_OPCODE_ACK             = 0x00,
	YS_MBOX_TEST_OPCODE_RESET           = 0x01,
	YS_MBOX_TEST_OPCODE_VECTOR_REG      = 0x02,
	YS_MBOX_TEST_OPCODE_VECTOR_SET      = 0x03,
	YS_MBOX_TEST_OPCODE_READ_REGS       = 0x04,
	YS_MBOX_TEST_OPCODE_WRITE_MEM       = 0x05,
	YS_MBOX_TEST_OPCODE_CHECK_MEM       = 0x06,
	YS_MBOX_TEST_OPCODE_TEST_SEL        = 0x07,
	YS_MBOX_TEST_OPCODE_TRIG_INT        = 0x08,
	YS_MBOX_TEST_OPCODE_CLR_INT         = 0x09,
	YS_MBOX_TEST_OPCODE_INT_TIMEOUT     = 0x0A,
};

#define YS_MBOX_MSG_LEN 116

struct ys_mbox_msg {
	u16 magic_data;
	u16 opcode;
	u8 length;
	u8 checksum;
	u8 send_id;
	u8 flag;
	s32 seqno;
	u8 data[YS_MBOX_MSG_LEN];
};

struct ys_mbox_irq_info {
	u32 vf_num;
	u32 pf_num;
	u16 msg_id;
	u32 vector;
	u32 irq_status;
	u32 pf_triger;
};

struct ys_mbox_test_statistics {
	u32 success_count;
	u32 fail_count;
	u32 init_flag;
	/* mbox lock */
	spinlock_t lock;
};

struct ys_mbox_llist_node {
	struct llist_node llnode;
	struct ys_mbox_msg msg;
};

struct ys_mbox {
	struct pci_dev *pdev;
	int role;
	void *mb_priv;
	void __iomem *addr;
	struct llist_head request[MBOX_MAX_CHANNAL];
	struct llist_head response[MBOX_MAX_CHANNAL];

	u32 (*mbox_hw_get_irq_id)(struct ys_mbox *mbox);
	void (*mbox_hw_send_msg)(struct ys_mbox *mbox, void *data, u32 send_id);
	void (*mbox_hw_recv_msg)(struct ys_mbox *mbox, void *data, u32 send_id);
	void (*mbox_hw_read_send_mailbox)(struct ys_mbox *mbox, void *data, u32 send_id);
	void (*mbox_hw_clear_send_mailbox)(struct ys_mbox *mbox, u32 clear_id);
	struct ys_mbox_irq_info (*mbox_hw_get_irq_status)(struct ys_mbox *mbox);
	void (*mbox_vf_to_pf_set_txq_info)(struct ys_mbox *mbox,
					   struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_rxq_info)(struct ys_mbox *mbox,
					   struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_txq_assignment)(struct ys_mbox *mbox,
						 struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_rxq_assignment)(struct ys_mbox *mbox,
						 struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_inner_vlan)(struct ys_mbox *mbox,
					     struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_mac)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_mc_mac)(struct ys_mbox *mbox,
					 struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_mtu)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_hash)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_clear_hash)(struct ys_mbox *mbox,
					 struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_port_enable)(struct ys_mbox *mbox,
					      struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_rxfh)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_get_hash_mode)(struct ys_mbox *mbox,
					    struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_tx_features)(struct ys_mbox *mbox,
					      struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_vlan_features)(struct ys_mbox *mbox,
						struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_pf_to_vf_set_mac)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_get_qset)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_filter)(struct ys_mbox *mbox,
					 struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_promisc)(struct ys_mbox *mbox,
					  struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_priv)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_get_eeprom_mac)(struct ys_mbox *mbox,
					     struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_pf_to_vf_set_port_status)(struct ys_mbox *mbox,
					      struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_get_pio_res)(struct ys_mbox *mbox,
					  struct ys_mbox_msg *msg, u32 channel);
	int  (*mbox_test)(struct ys_mbox *mbox,
			  struct ys_mbox_msg *msg,
			  u32 opcode,
			  u32 param,
			  u32 param1);
	void (*mbox_np_opt)(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
	void (*mbox_vf_to_pf_set_rss_redirect)(struct ys_mbox *mbox,
					       struct ys_mbox_msg *msg, u32 channel);
};

int ys_mbox_send_msg(struct ys_mbox *mbox,
		     struct ys_mbox_msg *send_msg,
		     u32 channel,
		     enum ys_mbox_mode wait_reply,
		     u32 timeout,
		     struct ys_mbox_msg *recv_msg);
u32 ys_mbox_sysfs_send(struct pci_dev *pdev, const char *buf);
int ys_aux_mbox_probe(struct auxiliary_device *auxdev,
		      const struct auxiliary_device_id *id);
void ys_aux_mbox_remove(struct auxiliary_device *auxdev);

#endif /* __YS_MBOX_H_ */
