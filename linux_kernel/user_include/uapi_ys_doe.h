/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UAPI_YS_DOE_H_
#define __UAPI_YS_DOE_H_

#include <linux/types.h>
#include <linux/ioctl.h>

enum ys_doe_cmd_opcode {
	YS_DOE_SW_RAW_CMD = 0x01,
	YS_DOE_SW_CREATE_ARRAY = 0x10,
	YS_DOE_SW_DELETE_ARRAY = 0x11,
	YS_DOE_SW_CREATE_HASH = 0x12,
	YS_DOE_SW_DELETE_HASH = 0x13,
	YS_DOE_SW_ARRAY_LOAD = 0x20,
	YS_DOE_SW_ARRAY_STORE = 0x21,
	YS_DOE_SW_ARRAY_LOAD_BATCH = 0x24,
	YS_DOE_SW_ARRAY_STORE_BATCH = 0x25,
	YS_DOE_SW_ARRAY_WRITE = 0x27,
	YS_DOE_SW_ARRAY_READ = 0x28,
	YS_DOE_SW_HASH_INSERT = 0x30,
	YS_DOE_SW_HASH_DELETE = 0x31,
	YS_DOE_SW_HASH_QUERY = 0x32,
	YS_DOE_SW_HASH_UPDATE = 0x33,
	YS_DOE_SW_HASH_INSERT_BATCH = 0x34,
	YS_DOE_SW_HASH_DELETE_BATCH = 0x35,
	YS_DOE_SW_HASH_QUERY_BATCH = 0x36,
	YS_DOE_SW_HASH_SAVE = 0x37,
	YS_DOE_SW_COUNTER_ENABLE = 0x60,
	YS_DOE_SW_COUNTER_ENABLE_BATCH = 0x61,
	YS_DOE_SW_COUNTER_LOAD = 0x62,
	YS_DOE_SW_METER_STORE = 0x63,
	YS_DOE_SW_HW_INIT = 0x80,
	YS_DOE_SW_CMD_PUSH = 0x81,
	YS_DOE_SW_SET_PROTECT,
	YS_DOE_SW_GET_PROTECT,
	YS_DOE_SW_GET_CHANNEL_LOCATION,
	YS_DOE_SW_GET_TABLE_VALID,
};

enum ys_doe_table_location {
	YS_DOE_LOCATION_DDR,
	YS_DOE_LOCATION_RAM,
	YS_DOE_LOCATION_HOST_DDR,
	YS_DOE_LOCATION_SOC_DDR,
};

/* parameters for table creating */
struct ys_doe_table_param {
	unsigned int depth;
	unsigned short dov_len;
	unsigned short key_len;		/* 0 for array table */
	unsigned short index_sram_size;	/* default 256 */

	/* used in k2pro and 2100p */
	unsigned char use_cache;
	unsigned char shared_tbl;
	unsigned char l1_cache_ways[16];
	unsigned char l2_cache_ways;

	/* used in k2pro 2.5 */
	unsigned short tbl_type;
	unsigned short is_small_array;
	unsigned short location;
	unsigned short ddr_channel;
	unsigned short endian;
	unsigned short ddr_mode;	/* 1: double ddr; 0: single ddr */
	unsigned int sdepth;		/* depth of hash second table */
	unsigned int chain_limit;	/* hash表冲突链最大长度 */
	unsigned int hash_seed;		/* hash表冲突链最大长度 */
};

struct ys_doe_sw_cmd {
	unsigned char opcode;
	unsigned char tbl_id;
	unsigned char is_read;

	/* For Counter table enable item */
	unsigned char enable; /* reused by protect status. */

	/* Some cmd need to be send without previous cmd */
	unsigned char independent;

	/*
	 * High priority. Only be used in `store/insert` command.
	 * If the table item is set to high priority, it will be always
	 * in cache.
	 */
	unsigned char high_pri;

	/*
	 * User space should write the number of sub-command when batch
	 * operations.
	 * Besides, The table-create command will also be splited into
	 * lots of sub-cmd, kernel will calculate the count automatically.
	 */
	unsigned int cnt;
	union {
		/* user define for debug */
		struct {
			unsigned int cmd_size;
			char cmd[256];
		};
		/* single array load/store; counter enable */
		struct {
			unsigned int index;
			char data[256];
		};
		/* single hash instruction */
		struct {
			char key[128];
			char value[128];
		};
		/* multi array/hash/counter base operations */
		struct {
			/* counter table batch load */
			unsigned int rsvd;
			unsigned int start;
			unsigned int total;
			char debug;
			unsigned int number;

			void *koi_list;
			void *pair_list;
		};
		/* create table */
		struct ys_doe_table_param tbl_param;

		/* doe channel locations. */
		struct ysk2u_doe_channel channel;

		/* table valid */
		bool tbl_valid;
	};
	/* The number of secceed/failed command */
	unsigned int succeed;
	unsigned int failed;
	/*
	 * Hardware Error code. The err is set to first error code
	 * return by hardware if command is compound.
	 */
	unsigned int err;
	/* Used only for kernel */
	unsigned int koi_nr_pages;
	unsigned int pair_nr_pages;
	unsigned long koi_pages;
	unsigned long pair_pages;
	int wait_lock;
	struct list_head cache_list;
	struct llist_node mp_node;
};

#define YS_DOE_SEND_CMD		_IOWR('D', 2, struct ys_doe_sw_cmd)

#endif /*__UAPI_YS_DOE_H_ */
