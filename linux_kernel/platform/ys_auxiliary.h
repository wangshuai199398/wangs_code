/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_AUXILIARY_H_
#define __YS_AUXILIARY_H_

#include <linux/netdevice.h>

#include "ys_utils.h"
#include "ys_queue.h"

#ifdef YS_HAVE_AUXILIARY_BUS
#include <linux/auxiliary_bus.h>
#else
#include "../lib/auxiliary_bus/auxiliary_bus.h"
#endif  /* YS_HAVE_AUXILIARY_BUS */

struct ys_auxiliary_driver {
	u32 aux_drv_support;
	struct auxiliary_driver drv;
	u8 is_registered;
};

#ifdef YS_HAVE_AUXILIARY_REMOVE
#define YS_AUX_DRV(_typename, _probe, _remove, _id_table, _aux_drv_support) { \
	.aux_drv_support = _aux_drv_support, \
	.drv = { \
		.name = _typename, \
		.probe = _probe, \
		.remove = (int (*)(struct auxiliary_device *))_remove, \
		.id_table = _id_table \
	} \
}
#else
#define YS_AUX_DRV(_typename, _probe, _remove, _id_table, _aux_drv_support) { \
	.aux_drv_support = _aux_drv_support, \
	.drv = { \
		.name = _typename, \
		.probe = _probe, \
		.remove = _remove, \
		.id_table = _id_table \
	} \
}
#endif /* YS_HAVE_AUXILIARY_REMOVE */ \


#define YS_AUX_MODULE_NAME YS_DEV_NAME("unic3")

#define AUX_NAME_ETH "eth"
#define AUX_NAME_SF "sf"
#define AUX_NAME_REP "rep"
#define AUX_NAME_I2C "i2c"
#define AUX_NAME_PTP "ptp"
#define AUX_NAME_LAN "lan"
#define AUX_NAME_MAC "mac"
#define AUX_NAME_MBOX "mbox"
#define AUX_NAME_NP "np"
#define AUX_NAME_DOE "doe"
#define AUX_NAME_VDPA "vdpa"

#define AUX_INDEX_OFFSET 10

enum {
	AUX_TYPE_ETH = (1 << 0),
	AUX_TYPE_SF = (1 << 1),
	AUX_TYPE_REP = (1 << 2),

	AUX_TYPE_I2C = (1 << 5),
	AUX_TYPE_PTP = (1 << 6),
	AUX_TYPE_LAN = (1 << 7),
	AUX_TYPE_MAC = (1 << 9),
	AUX_TYPE_MBOX = (1 << 10),
	AUX_TYPE_NP = (1 << 11),
	AUX_TYPE_VDPA = (1 << 12),

	AUX_TYPE_DOE = (1 << 13),
};

enum {
	ET_FLAG_UNREGISTER = 0xFFFF,
	ET_FLAG_REGISTER = 0xF000,
};

struct ys_state_statistics {
	/*
	 * function module registration flag
	 * unused :0xffff
	 * used other :0xf000
	 * used ndev :0x000-0x00f
	 * used sf :0x010-0x0ff
	 * used rep :0x100-0xfff
	 */
	u32 flag;
	void (*et_get_stats)(struct net_device *ndev, u64 *data);
	void (*et_get_stats_strings)(struct net_device *ndev, u8 *data);
	int (*et_get_stats_count)(struct net_device *ndev);
};

struct ys_doe_schedule {
	bool doe_master;
	void *schedule_buf;
	int (*ys_doe_schedule)(struct pci_dev *pdev);
};

struct ys_adev {
	struct auxiliary_device auxdev;
	struct completion comp;
	struct pci_dev *pdev;
	int idx;
	u32 adev_index;
	struct list_head list;
	u32 adev_type;
	void *adev_priv;
	void *adev_extern_ops;
	/*
	 * Must be assigned before adev_add! adev_probe need qbase and qnum to
	 * spawn ndev.
	 */
	struct ys_queue_params qi;
	struct ys_state_statistics state_statistics;

	int ifindex;
};

#define ys_aux_match_eth(pdev, id) \
	({ \
		struct net_device *ndev; \
		ndev = (struct net_device *) \
			ys_aux_match_adev(pdev, AUX_TYPE_ETH, id); \
		ndev; \
	})

#define ys_aux_match_sf(pdev, id) \
	({ \
		struct net_device *ndev; \
		ndev = (struct net_device *) \
			ys_aux_match_adev(pdev, AUX_TYPE_SF, id); \
		ndev; \
	})

#define ys_aux_match_rep(pdev, id) \
	({ \
		struct net_device *ndev; \
		ndev = (struct net_device *) \
			ys_aux_match_adev(pdev, AUX_TYPE_REP, id); \
		ndev; \
	})

#define ys_aux_match_i2c_dev(pdev) \
	({ \
		struct ys_i2c *i2c; \
		i2c = (struct ys_i2c *) \
			ys_aux_match_adev(pdev, AUX_TYPE_I2C, 0); \
		i2c; \
	})

#define ys_aux_match_k2lan_dev(pdev) \
	({ \
		struct ys_lan *lan; \
		lan = (struct ys_lan *) \
			ys_aux_match_adev(pdev, AUX_TYPE_LAN, 0); \
		lan; \
	})

#define ys_aux_match_esw_dev(pdev) \
	({ \
		struct ys_esw *esw; \
		esw = (struct ys_esw *) \
			ys_aux_match_adev(pdev, AUX_TYPE_LAN, 0); \
		esw; \
	})

#define ys_aux_match_k2ulan_dev(pdev) \
	({ \
		struct ys_k2ulan *k2ulan; \
		k2ulan = (struct ys_k2ulan *) \
			ys_aux_match_adev(pdev, AUX_TYPE_LAN, 0); \
		k2ulan; \
	})

#define ys_aux_match_mbox_dev(pdev) \
	({ \
		struct ys_mbox *mbox; \
		mbox = (struct ys_mbox *) \
			ys_aux_match_adev(pdev, AUX_TYPE_MBOX, 0); \
		mbox; \
	})

#define ys_aux_match_mac_dev(pdev) \
	({ \
		struct ys_mac *mac; \
		mac = (struct ys_mac *) \
			ys_aux_match_adev(pdev, AUX_TYPE_MAC, 0); \
		mac; \
	})

#define ys_aux_match_ndev_id(pdev, ndev) \
	({ \
		int ret; \
		ret = ys_aux_match_id(pdev, AUX_TYPE_ETH, (void *)ndev); \
		ret; \
	})

#define ys_aux_match_np_dev(pdev) \
	({ \
		struct ys_np *np; \
		np = (struct ys_np *) \
			ys_aux_match_adev(pdev, AUX_TYPE_NP, 0); \
		np; \
	})

#define ys_aux_match_doe_dev(pdev) \
	({ \
		struct ys_k2u_doe_device *ys_k2u_doe; \
		ys_k2u_doe = (struct ys_k2u_doe_device *) \
			 ys_aux_match_adev(pdev, AUX_TYPE_DOE, 0); \
		ys_k2u_doe; \
	 })

#define ys_aux_match_vdpa_dev(pdev) (ys_aux_match_adev(pdev, AUX_TYPE_VDPA, 0))

void *ys_aux_match_ndev_by_qset(struct pci_dev *pdev, u16 qset);
void *ys_aux_match_adev(struct pci_dev *pdev, int adev_type, int id);
int ys_aux_match_id(struct pci_dev *pdev, int adev_type, void *adev_priv);
struct ys_adev *ys_aux_get_adev(struct pci_dev *pdev, int adev_type,
				void *adev_priv);
void ys_aux_del_all_adev(struct pci_dev *pdev, const char *name);
void ys_aux_del_match_adev(struct pci_dev *pdev, int idx, const char *name);
struct ys_adev *ys_aux_add_adev(struct pci_dev *pdev, int idx,
				const char *name, void *arg);

int ys_aux_ndev_init(struct pci_dev *pdev);
void ys_aux_ndev_uninit(struct pci_dev *pdev);

int ys_aux_dev_init(struct pci_dev *pdev);
void ys_aux_dev_uninit(struct pci_dev *pdev);
int ys_aux_init(u32 pci_support_type);
void ys_aux_uninit(u32 pci_support_type);

int ys_aux_mbox_dev_init(struct pci_dev *pdev);
void ys_aux_mbox_dev_uninit(struct pci_dev *pdev);
#endif /* __YS_AUXILIARY_H_ */
