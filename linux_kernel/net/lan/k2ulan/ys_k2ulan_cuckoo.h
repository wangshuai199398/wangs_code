/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2ULAN_CUCKOO_H_
#define __YS_K2ULAN_CUCKOO_H_

#include "ys_cuckoo_hash.h"
#include "ys_k2ulan_register.h"

#define YS_K2ULAN_CUCKOO_UC_BUCKET_NUM           (3)
#define YS_K2ULAN_CUCKOO_UC_DEPTH                (2048)
#define YS_K2ULAN_CUCKOO_UC_KEY_SIZE             (6)
#define YS_K2ULAN_CUCKOO_UC_VALUE_SIZE           (8)
#define YS_K2ULAN_CUCKOO_UC_SEED_BITS            (32)
#define YS_K2ULAN_CUCKOO_UC_MUX_SEED_BITS        (5)

#define YS_K2ULAN_CUCKOO_UC_WADDR                (YS_K2ULAN_BASE + 0x120000)
#define YS_K2ULAN_CUCKOO_UC_RADDR                YS_K2ULAN_CUCKOO_UC_WADDR
#define YS_K2ULAN_CUCKOO_UC_SEED_ADDR(index)     (YS_K2ULAN_BASE + 0x100110 + 4 * (index))
#define YS_K2ULAN_CUCKOO_UC_MUX_SEED_ADDR(index) (YS_K2ULAN_BASE + 0x100100 + 4 * (index))
#define YS_K2ULAN_CUCKOO_UC_DATA_ROUND           (2)

#define YS_K2ULAN_CUCKOO_LOCK_BASE	(YS_K2ULAN_BASE + 0x8000)
#define YS_K2ULAN_CUCKOO_LOCK_FLAG	(YS_K2ULAN_CUCKOO_LOCK_BASE + (0x20))
#define YS_K2ULAN_CUCKOO_LOCK_STATE	(YS_K2ULAN_CUCKOO_LOCK_BASE + (0x24))
#define YS_K2ULAN_CUCKOO_LOCK_TIMEOUT	(YS_K2ULAN_CUCKOO_LOCK_BASE + (0x28))

#define YS_K2ULAN_CUCKOO_LOCK_TIMEOUT_DEFAULT	(0x10000000)

#define YS_K2ULAN_CUCKOO_TABLE_LOCK	1
#define YS_K2ULAN_CUCKOO_TABLE_UNLOCK	0

struct ys_k2ulan_cuckoo_lock_flag {
	u32 pf_id : 8;
	u32 lock_flag : 1;
	u32 rsvd : 23;
};

#define YS_K2ULAN_CUCKOO_LOCK_REG_PF_ID	GENMASK(7, 0)
#define YS_K2ULAN_CUCKOO_LOCK_REG_FLAG	GENMASK(8, 8)
#define YS_K2ULAN_CUCKOO_LOCK_REG_RSVD	GENMASK(31, 9)

struct ys_k2ulan_cuckoo_lock_timeout {
	u32 lock_timeout;
};

#define YS_K2ULAN_CUCKOO_MC_BUCKET_NUM           (3)
#define YS_K2ULAN_CUCKOO_MC_DEPTH                (2048)
#define YS_K2ULAN_CUCKOO_MC_KEY_SIZE             (3)
#define YS_K2ULAN_CUCKOO_MC_VALUE_SIZE           (8)
#define YS_K2ULAN_CUCKOO_MC_SEED_BITS            (32)
#define YS_K2ULAN_CUCKOO_MC_MUX_SEED_BITS        (5)

#define YS_K2ULAN_CUCKOO_MC_WADDR                (YS_K2ULAN_BASE + 0x150000)
#define YS_K2ULAN_CUCKOO_MC_RADDR                YS_K2ULAN_CUCKOO_MC_WADDR
#define YS_K2ULAN_CUCKOO_MC_SEED_ADDR(index)     (YS_K2ULAN_BASE + 0x100130 + 4 * (index))
#define YS_K2ULAN_CUCKOO_MC_MUX_SEED_ADDR(index) (YS_K2ULAN_BASE + 0x100120 + 4 * (index))
#define YS_K2ULAN_CUCKOO_MC_DATA_ROUND           (2)

extern const struct ys_cuckoo_ops_uncached k2ulan_uc_ops;
extern const struct ys_cuckoo_ops_uncached k2ulan_mc_ops;

/* k2pro+ bnic version */
#define YS_K2ULAN_BNIC_CUCKOO_UC_BUCKET_NUM           (3)
#define YS_K2ULAN_BNIC_CUCKOO_UC_DEPTH                (1024)
#define YS_K2ULAN_BNIC_CUCKOO_UC_KEY_SIZE             (6)
#define YS_K2ULAN_BNIC_CUCKOO_UC_VALUE_SIZE           (8)
#define YS_K2ULAN_BNIC_CUCKOO_UC_SEED_BITS            (32)
#define YS_K2ULAN_BNIC_CUCKOO_UC_MUX_SEED_BITS        (5)

#define YS_K2ULAN_BNIC_CUCKOO_UC_WADDR                (YS_K2ULAN_BASE + 0x120000)
#define YS_K2ULAN_BNIC_CUCKOO_UC_RADDR                YS_K2ULAN_BNIC_CUCKOO_UC_WADDR
#define YS_K2ULAN_BNIC_CUCKOO_UC_SEED_ADDR(index)     (YS_K2ULAN_BASE + 0x100110 + 4 * (index))
#define YS_K2ULAN_BNIC_CUCKOO_UC_MUX_SEED_ADDR(index) (YS_K2ULAN_BASE + 0x100100 + 4 * (index))
#define YS_K2ULAN_BNIC_CUCKOO_UC_DATA_ROUND           (2)

#define YS_K2ULAN_BNIC_CUCKOO_MC_BUCKET_NUM           (3)
#define YS_K2ULAN_BNIC_CUCKOO_MC_DEPTH                (1024)
#define YS_K2ULAN_BNIC_CUCKOO_MC_KEY_SIZE             (3)
#define YS_K2ULAN_BNIC_CUCKOO_MC_VALUE_SIZE           (8)
#define YS_K2ULAN_BNIC_CUCKOO_MC_SEED_BITS            (32)
#define YS_K2ULAN_BNIC_CUCKOO_MC_MUX_SEED_BITS        (5)

#define YS_K2ULAN_BNIC_CUCKOO_MC_WADDR                (YS_K2ULAN_BASE + 0x150000)
#define YS_K2ULAN_BNIC_CUCKOO_MC_RADDR                YS_K2ULAN_BNIC_CUCKOO_MC_WADDR
#define YS_K2ULAN_BNIC_CUCKOO_MC_SEED_ADDR(index)     (YS_K2ULAN_BASE + 0x100130 + 4 * (index))
#define YS_K2ULAN_BNIC_CUCKOO_MC_MUX_SEED_ADDR(index) (YS_K2ULAN_BASE + 0x100120 + 4 * (index))
#define YS_K2ULAN_BNIC_CUCKOO_MC_DATA_ROUND           (2)

extern const struct ys_cuckoo_ops_uncached k2ulan_bnic_uc_ops;
extern const struct ys_cuckoo_ops_uncached k2ulan_bnic_mc_ops;

/* k2pro+ one mac table version */
#define YS_K2ULAN_CUCKOO_MAC_BUCKET_NUM           (3)
#define YS_K2ULAN_CUCKOO_MAC_DEPTH                (4096)
#define YS_K2ULAN_CUCKOO_MAC_KEY_SIZE             (6)
#define YS_K2ULAN_CUCKOO_MAC_VALUE_SIZE           (8)
#define YS_K2ULAN_CUCKOO_MAC_SEED_BITS            (32)
#define YS_K2ULAN_CUCKOO_MAC_MUX_SEED_BITS        (5)

#define YS_K2ULAN_CUCKOO_MAC_WADDR                (YS_K2ULAN_BASE + 0x120000)
#define YS_K2ULAN_CUCKOO_MAC_RADDR                YS_K2ULAN_CUCKOO_MAC_WADDR
#define YS_K2ULAN_CUCKOO_MAC_SEED_ADDR(index)     (YS_K2ULAN_BASE + 0x100110 + 4 * (index))
#define YS_K2ULAN_CUCKOO_MAC_MUX_SEED_ADDR(index) (YS_K2ULAN_BASE + 0x100100 + 4 * (index))
#define YS_K2ULAN_CUCKOO_MAC_DATA_ROUND           (2)

/* k2pro+ bnic one mac table version */
#define YS_K2ULAN_BNIC_CUCKOO_MAC_DEPTH                (2048)

extern const struct ys_cuckoo_ops_uncached k2ulan_mac_ops;
extern const struct ys_cuckoo_ops_uncached k2ulan_bnic_mac_ops;

#endif /*__YS_K2ULAN_CUCKOO_H_*/
