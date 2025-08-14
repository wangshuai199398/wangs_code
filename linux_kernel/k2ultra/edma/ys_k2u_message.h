/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_MESSAGE_H__
#define __YS_K2U_MESSAGE_H__

#include "ys_k2u_new_base.h"

enum ys_k2u_msg_id {
	FUNC_GET_QBASE,
	FUNC_GET_IRQNUM,

	QSET_ALLOC,
	QSET_FREE,
	QSET_START,
	QSET_STOP,
};

struct ys_k2u_msg_cmd {
	enum ys_k2u_msg_id id;
	union {
		struct {
			union {
				struct {
					enum ys_k2u_queue_type type;
				} req;
				struct {
					struct ys_k2u_queuebase qbase;
				} rsp;
			};
		} func_qbase;

		struct {
			union {
				struct {
					u32 irqnum;
				} rsp;
			};
		} func_irqnum;

		struct {
			union {
				struct {
					u16 qsetid;
				} rsp;
			};
		} qset_alloc;

		struct {
			union {
				struct {
					u16 qsetid;
				} req;
			};
		} qset_free;

		struct {
			union {
				struct {
					u16 qsetid;
					struct ys_k2u_queuebase rxqbase;
					struct ys_k2u_queuebase txqbase;
				} req;
			};
		} qset_start;

		struct {
			union {
				struct {
					u16 qsetid;
					struct ys_k2u_queuebase txqbase;
				} req;
			};
		} qset_stop;
	};
};

int ys_k2u_msg_send(struct ys_pdev_priv *pdev_priv, struct ys_k2u_msg_cmd *req,
		    struct ys_k2u_msg_cmd *rsp);

int ys_k2u_message_init(struct ys_ndev_priv *ndev_priv);
void ys_k2u_message_uninit(struct ys_ndev_priv *ndev_priv);

#endif /* __YS_K2U_MESSAGE_H__ */
