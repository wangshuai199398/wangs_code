/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_DOE_CORE_H_
#define __YS_K2U_DOE_CORE_H_

#include "ys_adapter.h"
#include "ys_debug.h"
#include "ys_platform.h"
#include "ys_reg_ops.h"
#include "ys_doe.h"
#include "ys_k2u_doe_reg.h"
#include "uapi_ys_doe.h"
#include <linux/rwsem.h>
#include <linux/types.h>

extern bool smart_nic;
extern bool dpu_soc;
extern bool dpu_host;

/* cmd buffer define */
#define YS_K2U_DOE_CB_MAX_CMD			1000

#define YS_K2U_DOE_WRITE_CMD_BUFFER_SIZE	65536
#define YS_K2U_DOE_WRITE_CMD_BUFFER_CNT		64
#define YS_K2U_DOE_WRITE_EVENTQ_DEPTH		16384
#define YS_K2U_DOE_WRITE_EVENTQ_ENTRY_SIZE	256

#define YS_K2U_DOE_READ_CMD_BUFFER_SIZE		65536
#define YS_K2U_DOE_READ_CMD_BUFFER_CNT		64

#define YS_K2U_DOE_READ_EVENTQ_DEPTH		1024
#define YS_K2U_DOE_READ_EVENTQ_ENTRY_SIZE	4096

#define YS_K2U_DOE_CMD_TIMEOUT			(20 * HZ)	/* 20s */
#define POLLING_TIMEDOUT			100000000ULL	/* 100ms */
#define POLLING_WORK_SCHEDULE_TIME		10000000000ULL	/* 10s */

struct ys_k2u_doe_event_queue {
	/* buffer */
	dma_addr_t dma_base;
	void *base;
	u32 depth;
	u32 entry_size;
	u32 entry_bit;
	/* pointer */
	dma_addr_t dma_hw_tail;
	void *hw_tail_ptr;
	u32 sw_head;
	u32 sw_tail;
};

#define EQ_WITHDRAW_HEAD(eq) \
({ \
	typeof(eq) _eq = (eq); \
	_eq->sw_head = (_eq->sw_head - 1) & (_eq->depth - 1); \
})

#define EQ_MOVE_HEAD(eq) \
({ \
	typeof(eq) _eq = (eq); \
	_eq->sw_head = (_eq->sw_head + 1) & (_eq->depth - 1); \
})

#define EQ_MOVE_TAIL(eq) \
({ \
	typeof(eq) _eq = eq; \
	_eq->sw_tail = (_eq->sw_tail + 1) & (_eq->depth - 1); \
})

#define EQ_IS_FULL(eq) \
({ \
	typeof(eq) _eq = eq; \
	((_eq->sw_head + 1) & (_eq->depth - 1)) == _eq->sw_tail; \
})

/*
 * Why is the variable name not `eq`?
 * The macro is used in macro `EQ_AVAILABLE`
 * that also have a variable which name is `eq`.
 * This will make crash.
 */
#define EQ_HW_TAIL(eq) \
({ \
	typeof(eq) _eq1 = eq; \
	(le64_to_cpu(*(u64 *)_eq1->hw_tail_ptr) - \
	(u64)_eq1->dma_base) >> _eq1->entry_bit; \
})

#define EQ_AVAILABLE(eq) \
({ \
	typeof(eq) _eq = eq; \
	(EQ_HW_TAIL(_eq) + _eq->depth - _eq->sw_tail) & (_eq->depth - 1); \
})

#define CB_CLEAR_TAIL(cb) \
({ \
	typeof(cb) _cb = (cb); \
	_cb->end_ptr = 0; \
	_cb->cmd_cnt = 0; \
})

#define CB_MOVE_TAIL(cb, add_size) \
({ \
	typeof(cb) _cb = (cb); \
	_cb->cmd_cnt++; \
	_cb->end_ptr = (add_size); \
	_cb->end_ptr = (_cb->end_ptr + YS_K2U_DOE_CMD_ALIGN) & ~YS_K2U_DOE_CMD_ALIGN; \
})

#define CB_IS_FULL(cb) \
({ \
	typeof(cb) _cb = (cb); \
	_cb->size - _cb->end_ptr < YS_K2U_DOE_CMD_MAXSIZE; \
})

#define CACHE_ITEM_ID(tbl_id, cls_id, cls_cfg) ((((cls_cfg) & 0x1) << 15) | \
					       (((cls_id) & 0xf) << 8) | \
					       ((tbl_id) & 0xff))

struct ys_k2u_doe_cmd_buffer {
	dma_addr_t dma_base;
	void *base;
	u32 size;
	u32 end_ptr;
	u32 cmd_cnt;
	u32 id;
};

struct ys_k2u_doe_interface {
	struct ys_k2u_doe_device		*ys_k2u_doe;
	const char			*name;
	u8				msi_index;
	void __iomem			*dma_reg_base;
	struct ys_k2u_doe_cmd_buffer	*cb;
	atomic_t			cb_next;
	u8				cb_depth;
	u8				is_read;
	union {
		atomic_t		cmd_tag;
		u16			cmd_id;
	};
	u32				mod_reg_base_shfit;
	struct ys_k2u_doe_event_queue	eq;
	struct list_head		work_list;
	struct list_head		cache_list;
	struct llist_head		cmd_mpool;
	struct llist_head		des_mpool;
	atomic_t			work_list_count;
	atomic_t			cache_list_count;
	atomic_t			cmdbuffer_count;
	atomic_t			hw_buffer_count;
	/*
	 * Both user ioctl thread and desc-complete thread will access
	 * the command pointer. We must avoid the access to command
	 * pointer after freed.
	 * Most of the time lock contention does not occur unless timeout.
	 */
	spinlock_t			work_lock;
	/* transaction lock, lock the hardwore DMA interface */
	spinlock_t			transaction_lock;

	struct notifier_block		irq_nb;
	int				irq_vector;
};

struct ys_k2u_doe_desc {
	struct ys_k2u_doe_device		*ys_k2u_doe;
	struct ys_doe_sw_cmd		*parent;
	struct ys_doe_sw_cmd		*cmd;
	/* Do nothing when invalid set */
	u8				invalid;
	u8				is_read;
	union {
		u16		cmd_tag;
		u16		cmd_id;
	};
	struct llist_node		llnode;
	struct list_head		list;
	struct list_head		cache;
	int (*complete_desc)(struct ys_k2u_doe_desc *desc,
			     struct ys_k2u_doe_event *event);
};

struct ys_k2u_doe_table_spec {
	struct ys_k2u_doe_miu_param		miu_param;
	struct ys_k2u_doe_hie_param		hie_param;
	struct ys_k2u_doe_aie_param		aie_param;
	struct ys_k2u_doe_index_param	index_param;
	struct ys_k2u_doe_cache_param	cache_param;
	struct ys_k2u_doe_flush_param	flush_param;
};

struct ys_k2u_doe_device {
	struct pci_dev			*pdev;

	/* char device */
	struct list_head		list;
	struct cdev			cdev;
	dev_t				devt;

	struct ys_doe_ops		*auxdev_ops;

	/* interface */
	wait_queue_head_t		wait;
	void __iomem			*doe_base;	/* doe reg */
	struct ys_k2u_doe_interface		*doe_read_if;
	struct ys_k2u_doe_interface		*doe_write_if;
	/* mutex for accessing hardware */
	struct rw_semaphore		mutex;

	/* hardware resources */
	struct ys_doe_table_param	param[YS_K2U_DOE_TBL_NUM];
	struct ys_k2u_doe_table_spec	spec[YS_K2U_DOE_USER_TBL_NUM + 2];
	struct ys_k2u_doe_mm		*ddr0;
	struct ys_k2u_doe_mm		*ddr1;
	struct ys_k2u_doe_mm		*ram;
	struct ys_k2u_doe_mm		**ddrh;
	struct ys_k2u_doe_mm		**manage_host;
	struct ys_k2u_doe_mm		*index_sram;

	unsigned long			*tbl_bitmap;
	u64				ddrh_array_max;
	u64				manage_host_max;
	u64				host_ddr_size;
	u64				channel_0_size;
	u64				channel_1_size;
	u64				index_sram_size;
	u16				hash_tbl_max;
	u16				hash_tbl_cnt;
	u16				user_tbl_used;
	bool				non_ddr_mode;
	bool				enble_host_ddr;
	bool				enble_dpu_ddr;
	bool				enble_soc_ddr;
	bool				enble_doe_schedule;
	bool				enble_faster_mode;

	/* mutex for init flag */
	struct mutex			mtx_init;
	u8				init;
};

//#define DOE_VERBOSE_DEBUG
#ifdef DOE_VERBOSE_DEBUG
static inline void ys_k2u_doe_writel(struct ys_k2u_doe_device *ys_k2u_doe, u32 val,
				     void __iomem *addr)
{
	u32 old = readl(addr);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);

	writel(val, addr);
	ys_dev_info("write 0x%08x to 0x%p : 0x%08x -> 0x%08x\n",
		    val, addr, old, readl(addr));
}
#else
static inline void ys_k2u_doe_writel(struct ys_k2u_doe_device *ys_k2u_doe, u32 val,
				     void __iomem *addr)
{
	writel(val, addr);
}
#endif

#ifdef DOE_VERBOSE_DEBUG
static inline void buffer_dump(struct ys_k2u_doe_device *ys_k2u_doe, const char *name,
			       void *addr, u32 size)
{
	char buf[128];
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	int i, offset = 0;

	ys_dev_info("DUMP %s form 0x%llx-0x%x\n", name, (u64)addr, size);

	for (i = 0; i < size; i++) {
		if (!(i % 16)) {
			sprintf(buf, "%04x: ", i);
			offset = 6;
		}

		sprintf(buf + offset, "%02x ", *(u8 *)(addr + i));
		offset += 3;

		if (i % 16 == 15 || i + 1 == size)
			ys_dev_info("%s\n", buf);
	}
}
#else
static inline void buffer_dump(struct ys_k2u_doe_device *ys_k2u_doe, const char *name,
			       void *addr, u32 size) {}
#endif /* DOE_VERBOSE_DEBUG */

static inline u8 ys_k2u_doe_get_order(u32 len)
{
	u8 order = 0;

	while ((1 << order) < len)
		order++;

	return order;
}

/* ys_k2u_doe_core.c */
int ys_k2u_doe_submit_ddr_spec(struct ys_k2u_doe_device *ys_k2u_doe, u8 spec_tbl,
			       struct ys_doe_sw_cmd *parent,
			       int (*complete_desc)(struct ys_k2u_doe_desc *desc,
						    struct ys_k2u_doe_event *event));
int ys_k2u_doe_process_cmd(struct ys_k2u_doe_device *ys_k2u_doe, struct ys_doe_sw_cmd *cmd);
struct ys_doe_sw_cmd *ys_k2u_doe_sw_cmd_prepare(struct ys_k2u_doe_device *ys_k2u_doe,
						unsigned long arg);
int ys_k2u_doe_sw_cmd_unprepare(struct ys_k2u_doe_device *ys_k2u_doe,
				struct ys_doe_sw_cmd *sw_cmd,
				int err, int kc);
int ys_k2u_doe_sw_cmd_valid(struct ys_k2u_doe_device *ys_k2u_doe,
			    struct ys_doe_sw_cmd *sw_cmd);
int ys_k2u_doe_table_existed(u32 card_id, u8 table_id);

int ys_k2u_doe_reset(struct ys_k2u_doe_device *ys_k2u_doe, struct ys_doe_sw_cmd *parent);
void *ys_k2u_doe_alloc_cmd(struct ys_k2u_doe_interface *doe_if);
void ys_k2u_doe_free_cmd(struct ys_k2u_doe_interface *doe_if, void *cmd);
void *ys_k2u_doe_alloc_dsc(struct ys_k2u_doe_interface *doe_if);
void ys_k2u_doe_free_dsc(struct ys_k2u_doe_interface *doe_if, void *dsc);
int ys_k2u_doe_clean_push(struct ys_k2u_doe_interface *doe_if,
			  struct ys_k2u_doe_desc *desc);

/* ys_k2u_doe_schedule.c */
int ys_k2u_doe_user_cmd_context(struct ys_k2u_doe_device *ys_k2u_doe,
				struct ys_doe_sw_cmd *cmd);
int ys_k2u_doe_user_cmd_context_poll_wait(struct ys_k2u_doe_device *ys_k2u_doe,
					  struct ys_doe_sw_cmd *cmd);

int ys_k2u_doe_submit_cmd(struct ys_k2u_doe_device *ys_k2u_doe, struct ys_doe_sw_cmd *cmd,
			  struct ys_doe_sw_cmd *parent,
			  int (*complete_desc)(struct ys_k2u_doe_desc *desc,
					       struct ys_k2u_doe_event *event));
int ys_k2u_doe_enqueue_cmdbuffer(struct ys_k2u_doe_interface *doe_if,
				 struct ys_k2u_doe_desc *desc,
				 struct ys_k2u_doe_cmd_buffer *cb);
void ys_k2u_doe_polling_work(struct ys_k2u_doe_interface *doe_if,
			     struct ys_doe_sw_cmd *cmd);
void ys_k2u_desc_completed(struct ys_k2u_doe_interface *doe_if);

/* ys_k2u_doe_if.c */
int ys_k2u_doe_reg_init(struct ys_k2u_doe_device *ys_k2u_doe);
int ys_k2u_doe_dma_busy(struct ys_k2u_doe_interface *doe_if);
int ys_k2u_doe_send_cmd(struct ys_k2u_doe_interface *doe_if,
			struct ys_k2u_doe_cmd_buffer *cb);
int ys_k2u_doe_check_irq(struct ys_k2u_doe_interface *doe_if);
void ys_k2u_doe_clean_irq(struct ys_k2u_doe_interface *doe_if);

/* ys_k2u_doe_init.c */
int ys_k2u_doe_kernel_call(u32 card_id, struct ys_doe_sw_cmd *sw_cmd, u8 poll_wait);
struct ys_k2u_doe_device *ys_k2u_doe_get_device(u32 card_id);

/* ys_doe_kapi.c */
void ys_k2u_doe_init_adev_ops(struct ys_doe_ops *ops);

/* ys_doe_core.c */
int ys_k2u_doe_aux_probe(struct auxiliary_device *auxdev);
void ys_k2u_doe_aux_remove(struct auxiliary_device *auxdev);

int ys_k2u_doe_add_cdev(struct pci_dev *pdev);
int ys_k2u_doe_module_add_cdev(struct pci_dev *pdev);

int ys_k2u_doe_pdev_fix_mode(struct ys_pdev_priv *priv);
void ys_k2u_doe_pdev_unfix_mode(struct ys_pdev_priv *priv);
int ys_k2u_doe_fix_mode(struct ys_k2u_doe_device *ys_k2u_doe);
void ys_k2u_doe_unfix_mode(struct ys_k2u_doe_device *ys_k2u_doe);

s32 ys_k2u_doe_protect_status(u32 card_id);
s32 ys_k2u_doe_set_protect(u32 card_id, u8 status);

u32 ys_k2u_doe_hash_table_max(u32 card_id);
s32 ys_k2u_doe_get_channel_type(u32 card_id, u8 channel_id);

u32 ys_k2u_doe_get_table_cache_entry_limit(u32 card_id, u32 tlb_type);
void ys_k2u_doe_set_table_cache_entry_limit(u32 card_id, u32 tlb_type, u32 data_len);

int ys_k2u_doe_pdev_init(struct ys_pdev_priv *pdev_priv);
void ys_k2u_doe_pdev_uninit(struct ys_pdev_priv *pdev_priv);

/* ys_k2u_doe_addrmap.c */
int ys_k2u_doe_addrmap_init(struct ys_k2u_doe_device *ys_k2u_doe);
void ys_k2u_doe_addrmap_uninit(struct ys_k2u_doe_device *ys_k2u_doe);
#endif /* __YS_K2U_DOE_CORE_H_ */
