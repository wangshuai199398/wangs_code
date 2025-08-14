/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_DOE_REG_H_
#define __YS_K2U_DOE_REG_H_

#define YS_K2U_DOE_VERSION_NUM		0xd0e2524

#define YS_K2U_FID_PF			GENMASK(31, 16)
#define YS_K2U_FID_VF			GENMASK(15, 0)

#define YS_K2U_DOE_SYS_INFO		0x90
#define YS_K2U_HASH_TLB_NUM		GENMASK(31, 24)
#define YS_K2U_DDR_VALID		GENMASK(23, 16)
#define YS_K2U_WORK_MODE		GENMASK(15, 8)
#define YS_K2U_BOARD_TYPE		GENMASK(7, 0)
#define YS_K2U_HOST_VALID_MASK		0x11
#define YS_K2U_DDR_VALID_MASK		0x22
#define YS_K2U_SOC_VALID_MASK		0x44

/* DOE parameters */
#define YS_K2U_DOE_TBL_NUM		256
#define YS_K2U_DOE_USER_TBL_NUM		238
#define YS_K2U_DOE_TBL_USED_MAX		32
#define YS_K2U_DOE_SPEC_TBL_BASE	240
#define YS_K2U_DOE_CMD_MAXSIZE		0x140	/* index resource 256 Bytes */
#define YS_K2U_DOE_CMD_ALIGN		0x1f	/* 32 byte align */
#define YS_K2U_DOE_CMDDMA_ALIGN		0x1f
#define YS_K2U_DOE_CACHE_NUM		24
#define YS_K2U_DOE_DPU_HASH_TBL_MAX	16
#define YS_K2U_DOE_LEGACY_HASH_TBL_MAX	8

#define YS_K2U_DOE_HCU_PARAM_CNT	0x10

#define YS_K2U_DOE_INDEX_SRAM_SIZE	0x1000
#define YS_K2U_DOE_INDEX_SRAM_ALIGN	0x1

/* Logical address offset for index ddr resources */
#define YS_K2U_DOE_INDEX_ITEM_SIZE	256

#define YS_K2U_DOE_DDR0_SIZE		0x100000000	/* 4G */
#define YS_K2U_DOE_DDR1_SIZE		0x100000000	/* 4G */
#define YS_K2U_DOE_DDR_ALIGN		0xfff		/* 4K */
#define YS_K2U_DOE_DDR_SLICE		0x200000	/* 2M */

#define YS_K2U_DOE_LEGACY_SIZE		0xA0000
#define YS_K2U_DOE_LEGACY_ALIGN		0X7f

#define YS_K2U_DOE_RAM_SIZE		0x8000		/* 32k */
#define YS_K2U_DOE_RAM_ALIGN		0x7

#define YS_K2U_DOE_L1CACHE_SIZE		0x4000		/* 16K */
#define YS_K2U_DOE_L2CACHE_SIZE		0x40000		/* 256K */
#define YS_K2U_DOE_CACHE_ALIGN		0x1

#define YS_K2U_DOE_L1CACHE_NUM		16
#define YS_K2U_DOE_L1CACHE_TAG_NUM	32
#define YS_K2U_DOE_L2CACHE_TAG_NUM	512
#define YS_K2U_DOE_CACHE_TAG_ALIGN	0x0

#define YS_K2U_DOE_ITEMS_PER_TAG	8

#define YS_K2U_DOE_WORKMODE_AIE		0x01
#define YS_K2U_DOE_WORKMODE_LAIE	0x02
#define YS_K2U_DOE_WORKMODE_CIE		0x04
#define YS_K2U_DOE_WORKMODE_MIE		0x08
#define YS_K2U_DOE_WORKMODE_HIE		0x10
#define YS_K2U_DOE_WORKMODE_LHIE	0x20

/* DOE internal register */
#define YS_K2U_DOE_REG_BAR		0
#ifdef CONFIG_YSHW_K2ULTRA_U200
#define YS_K2U_DOE_REG_BASE             0x800000
#else
#define YS_K2U_DOE_REG_BASE		0x1800000
#endif
#define YS_K2U_DOE_VERSION		0x00
#define YS_K2U_DOE_RESET		0x04
#define YS_K2U_DOE_PF_NUM		0x08
#define YS_K2U_DOE_WORK_MODE		0x0c
#define YS_K2U_DOE_RD_CHANNEL_BASE	0x10
#define YS_K2U_DOE_RD_BASE_SHIFT	0x300
#define YS_K2U_DOE_WR_CHANNEL_BASE	0x40
#define YS_K2U_DOE_WR_BASE_SHIFT	0x2e0
#define YS_K2U_DOE_CMD_ADDR_LOW		0x00
#define YS_K2U_DOE_CMD_ADDR_HIGH	0x04
#define YS_K2U_DOE_CMD_LEN		0x08
#define YS_K2U_DOE_CMD_CONTROL		0x0c
#define YS_K2U_DOE_DMA_MODE		0x300
#define YS_K2U_DOE_RD_CHANNEL_SPACE	0x304
#define YS_K2U_DOE_WR_CHANNEL_SPACE	0x308
#define YS_K2U_DOE_EVENT_SIZE		0x10
#define YS_K2U_DOE_EVENT_TOTAL_SIZE	0x14
#define YS_K2U_DOE_EVENT_BASE_LOW	0x18
#define YS_K2U_DOE_EVENT_BASE_HIGH	0x1c
#define YS_K2U_DOE_EVENT_PTR_LOW	0x20
#define YS_K2U_DOE_EVENT_PTR_HIGH	0x24
#define YS_K2U_DOE_IRQ_READ		0x88
#define YS_K2U_DOE_IRQ_WRITE		0x8c
#define YS_K2U_DOE_CHANNEL0_LIMIT	0x94
#define YS_K2U_DOE_CHANNEL1_LIMIT	0x98
#define YS_K2U_DOE_INDEX_SRAM_LIMIT	0x9c
#define YS_K2U_DOE_PROTECT_CFG		0xb0
#define YS_K2U_DOE_PROTECT_ACK		0xb4

#define YS_K2U_DOE_TBL_DEL_ARRAY	0x140014
#define YS_K2U_DOE_TBL_DEL_BIG_HASH	0x180014
#define YS_K2U_DOE_TBL_DEL_COUNTER	0x200014
#define YS_K2U_DOE_TBL_DEL_LOCK		0x140014
#define YS_K2U_DOE_TBL_DEL_METER	0x340014
#define YS_K2U_DOE_TBL_DEL_SMALL_HASH	0x1c0014

#define YS_K2U_DOE_RESET_AIE		0x140010
#define YS_K2U_DOE_RESET_HIE		0x180010
#define YS_K2U_DOE_RESET_CIE		0x200010
#define YS_K2U_DOE_RESET_MIE		0x340010
#define YS_K2U_DOE_RESET_LHIE		0x1c0010

#define YS_K2U_DOE_AIE_HASH_SEED	0x140038
#define YS_K2U_DOE_HIE_HASH_SEED	0x180038
#define YS_K2U_DOE_LHIE_HASH_SEED	0x1c0038
#define YS_K2U_DOE_CIE_HASH_SEED	0x200038
#define YS_K2U_DOE_MIE_HASH_SEED	0x340038

#define YS_K2U_DOE_AIE_DLEN_LIMIT	0x14003c
#define YS_K2U_DOE_HIE_DLEN_LIMIT	0x18003c

#define ADDITION_CMD_NUM		300
#define YS_K2U_DOE_COUNTER_LOAD_STRIDE	0x20

/* Interrupt vector */
enum ys_k2u_doe_irq_type {
#ifdef PLDA_VERSION
	YS_K2U_DOE_IRQ_WRITE_EQ = 24,
	YS_K2U_DOE_IRQ_READ_EQ = 25,
	YS_K2U_DOE_IRQ_MAX = 32,
#else
	YS_K2U_DOE_IRQ_WRITE_EQ = 0,
	YS_K2U_DOE_IRQ_READ_EQ = 1,
	YS_K2U_DOE_IRQ_MAX = 32,
#endif
};

#define GEN_HEAD_ENABLE(report) (((report) & 0x1) << 1)
#define GEN_HEAD_PRIORITY(priority) ((priority) & (0x4 | 0x1))

/*
 * AIE: header + 32'B index + data
 * HIE: header + key + value
 */
struct ys_k2u_doe_hw_cmd_head {
	u16 cmd_tag;
	u16 valid;
	u16 cmd_len;
	u8 status;
	u8 resv[25];
	u8 opcode;
	u8 table_id;
} __packed;

enum ys_k2u_doe_status {
	/* YS_K2U_DOE_STATUS_NONE, */
	YS_K2U_DOE_STATUS_SUCCESS,
	YS_K2U_DOE_STATUS_INVALID_CMD,
};

struct ys_k2u_doe_event {
	u8 status;
	u8 nb; /* number of counter table item while loading */
	u16 cmd_tag;
} __packed;

enum ys_k2u_doe_cmd_opcode {
	YS_K2U_DOE_ARRAY_LOAD = 0x20,
	YS_K2U_DOE_ARRAY_STORE,
	YS_K2U_DOE_ARRAY_READ_CLEAR = 0x26,
	YS_K2U_DOE_ARRAY_WRITE,
	YS_K2U_DOE_ARRAY_READ,
	YS_K2U_DOE_HASH_INSERT = 0x30,
	YS_K2U_DOE_HASH_DELETE,
	YS_K2U_DOE_HASH_QUERY,
};

enum ys_k2u_doe_special_table {
	YS_K2U_DOE_HASH_FLUSH_TABLE = 0xee,	/* 238, Flush table for hash */
	YS_K2U_DOE_INDEX_RES_TABLE = 0xef,	/* 239, Index Resources for hash */
	YS_K2U_DOE_BATCH_OP_TABLE = 0xf0,	/* 240, Batch Operation */
	YS_K2U_DOE_HCU_PARAM_TABLE = 0xf7,	/* 247, Hash Compute Unit */
	YS_K2U_DOE_CACHE_CONFIG_TABLE = 0xf8,	/* 248, Cache Config */
	YS_K2U_DOE_INDEX_MANAGE_TABLE = 0xf9,	/* 249, Index Param Manage for hash */
	YS_K2U_DOE_AIE_PARAM_TABLE = 0xfb,	/* 251, Array Instruction Engine */
	YS_K2U_DOE_HIE_PARAM_TABLE = 0xfc,	/* 252, Hash Instruction Engine */
	YS_K2U_DOE_MIU_PARAM_TABLE = 0xfd,	/* 253, Memory Interface Unit */
};

/* Memory Interface Unit */
struct ys_k2u_doe_miu_param {
	u8 ddr_channel:2;
	u8 endian:1;
	u8 ddr_mode:1;
	u8 rsvd:4;

	u8 item_size;
	u16 item_len;
	u32 ddr_base_low;
	u8 ddr_base_high;
	u32 ddr_base_low1;
	u8 ddr_base_high1;
} __packed;

struct ys_k2u_doe_aie_param {
	u32 depth;
	u16 data_len;
	u8 item_size;

	u8 ddr_channel:2;
	u8 endian:1;
	u8 ddr_mode:1;
	u8 valid:1;
	u8 tbl_type:3;
} __packed;

struct ys_k2u_doe_hie_param {
	u32 mdepth;		/* main table depth */
	u32 sdepth;		/* second table depth */
	u32 index_mask;		/* mask of main table */
	u16 key_len;
	u16 value_len;
	u8 item_size;

	u8 ddr_channel:2;
	u8 endian:1;
	u8 ddr_mode:1;
	u8 valid:1;
	u8 tbl_type:3;
	u32 chain_limit;
} __packed;

struct ys_k2u_doe_cache_param {
	u8 valid:1;
	u8 tbl_type:3;
	u8 ddr_channel:2;
	u8 big_mode:1;
	u8 ddr_mode:1;
	u16 data_len;
	u16 key_len;
	u32 depth;
	u8 item_size;
} __packed;

struct ys_k2u_doe_flush_param {
	u32 start;
	u32 total;
	u8 debug;
} __packed;

struct ys_k2u_doe_index_param {
	u16 ram_physic_base;
	/* ddr_base is the index of resource table, base 256Bytes */
	u32 ddr_physic_base;
	/* point and state: SW init to 0, HW maintain */
	u16 ram_point;
	u32 ddr_point;
	u8 ddr_state;
} __packed;

#endif /* __YS_K2U_DOE_REG_H_ */
