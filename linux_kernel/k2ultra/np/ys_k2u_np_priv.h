/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_NP_PRIV_H_
#define __YS_K2U_NP_PRIV_H_

#include <linux/debugfs.h>
#include <linux/pci.h>
#include <linux/refcount.h>
#include <linux/types.h>

#include "../../platform/ys_auxiliary.h"
#include "../../platform/ys_pdev.h"

struct ys_np;
struct ys_np_ops {
	int (*init)(struct ys_np *np);
	void (*fini)(struct ys_np *np);
};

struct ys_np_tbl_ops {
	const char *name;
	const u32 mode_bitmap;
	struct ys_np_table *(*create)(struct ys_np *np);
	void (*destroy)(struct ys_np *np, struct ys_np_table *table);
};

struct ys_np_table {
	const struct ys_np_tbl_ops   *ops;
	struct list_head             node;
	void                         *priv;
};

#define ys_np_err(f, arg...) \
	dev_err(pdev_priv->dev, "%s: [NP]: " f, YS_HW_NAME, ##arg)
#define ys_np_info(f, arg...) \
	dev_info(pdev_priv->dev, "%s: [NP]: " f, YS_HW_NAME, ##arg)

int ys_k2u_np_doe_init(struct ys_np *np);
int ys_k2u_np_doe_tbl_init(struct ys_np *np);
void ys_k2u_np_doe_tbl_fini(struct ys_np *np);
int ys_k2u_np_doe_set_protect(struct ys_np *np, bool protect);

/* NP PPE Cluster */
#define YS_K2U_NP_REGS_BAR              0

#define YS_K2U_NP_BASE                  (0x1000000)
/* Only 4 cluster for NP 2.54 */
#define YS_K2U_NP_PPE_CLUSTE_NUM        (24)
enum { YS_K2U_NP_VALID_CLS_BITMAP_LOW = (BIT(0) | BIT(1) | BIT(2) | BIT(3)) };
enum { YS_K2U_NP_VALID_CLS_BITMAP_HIGH = (BIT(4) | BIT(5) | BIT(6) | BIT(7)) };
enum { YS_K2U_NP_VALID_CLS_BITMAP = (YS_K2U_NP_VALID_CLS_BITMAP_LOW |
				     YS_K2U_NP_VALID_CLS_BITMAP_HIGH) };
#define YS_K2U_NP_CLUSTER_SIZE          (0x20000)

#define YS_NP_HOST_FW_MSG0_L_OFFSET     (0x1000)
#define YS_NP_HOST_FW_MSG1_L_OFFSET     (0x1008)
#define YS_K2U_NP_REG_MAGIC             (0xdeadbadb)

struct ys_np_sw {
	const struct ys_doe_ops      *doe_ops;
	enum ys_dpu_mode             mode;
	const struct ys_np_ops       *ops;
	struct ys_k2u_lag            *lag;
	int                          bus_id;
	int                          id;
	refcount_t                   refcnt;
	struct workqueue_struct      *wq;
	struct dentry                *debugfs_root;
	struct list_head             table_head;
	struct mutex                 cfg_lock; /* for cfg update and show in debugfs. */
	u16                          cfg[YS_K2U_NP_PPE_CLUSTE_NUM][YS_NP_CFG_MAX];
};

struct ys_np {
	struct pci_dev               *pdev;
	struct ys_np_sw              *sw;
};

#endif /* __YS_K2U_NP_PRIV_H_ */
