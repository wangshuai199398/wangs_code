/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef YS_CUCKOO_HASH_H
#define YS_CUCKOO_HASH_H

#include <linux/io.h>

enum {
	YS_CUCKOO_TYPE_EME,
	YS_CUCKOO_TYPE_CHISHUI,
	YS_CUCKOO_TYPE_LAN_UC,
	YS_CUCKOO_TYPE_LAN_MC,
	YS_CUCKOO_TYPE_K2U_LAN_UC,
	YS_CUCKOO_TYPE_K2U_LAN_MC,
	YS_CUCKOO_TYPE_K2U_BNIC_LAN_UC,
	YS_CUCKOO_TYPE_K2U_BNIC_LAN_MC,
	YS_CUCKOO_TYPE_K2U_LAN_MAC,
	YS_CUCKOO_TYPE_K2U_BNIC_LAN_MAC,
	YS_CUCKOO_TYPE_END,
};

#define YS_CUCKOO_TABLE_CACHED_FLAG	(0x1 << 0)
#define YS_CUCKOO_TABLE_SHARED_FLAG	(0x1 << 1)

#define YS_CUCKOO_TABLE_TEST_CACHED(flag) \
	(((flag) & YS_CUCKOO_TABLE_CACHED_FLAG) != 0)

#define YS_CUCKOO_TABLE_TEST_SHARED(flag) \
	(((flag) & YS_CUCKOO_TABLE_SHARED_FLAG) != 0)

#define YS_CUCKOO_MIN_BUCKETS             (2)
#define YS_CUCKOO_MAX_BUCKETS             (4)
#define YS_CUCKOO_MIN_DEPTH               (2)
#define YS_CUCKOO_MAX_DEPTH               (2048)
#define YS_CUCKOO_MIN_KEY_SIZE            (1)
#define YS_CUCKOO_MAX_KEY_SIZE            (16)
#define YS_CUCKOO_MIN_VALUE_SIZE          (1)
#define YS_CUCKOO_MAX_VALUE_SIZE          (16)
#define YS_CUCKOO_MIN_SEED_BITS           (1)
#define YS_CUCKOO_MAX_SEED_BITS           (32)
#define YS_CUCKOO_MIN_MUX_SEED_BITS       (1)
#define YS_CUCKOO_MAX_MUX_SEED_BITS       (32)
#define YS_CUCKOO_MAX_DATA_ROUND          ((YS_CUCKOO_MAX_KEY_SIZE + \
					   YS_CUCKOO_MAX_VALUE_SIZE) / sizeof(u32))

#define YS_CUCKOO_MAX_INSERT_RETRIES      (10)
#define YS_CUCKOO_MAX_CREATE_SEED_RETRIES (16)
#define YS_CUCKOO_MAX_STR_SIZE            (256)
#define YS_CUCKOO_NEW_RULE                (0xFFFFFFFF)

struct ys_cuckoo_entry {
	u8 is_occupied;
	u8 key[YS_CUCKOO_MAX_KEY_SIZE];
	u8 value[YS_CUCKOO_MAX_VALUE_SIZE];
};

struct ys_cuckoo_hw {
	void *ctx;
	void __iomem *bar_addr;
	u32 init_done_addr;
	u32 seed_addr[YS_CUCKOO_MAX_BUCKETS];
	u32 mux_seed_addr[YS_CUCKOO_MAX_BUCKETS];
	u32 waddr;
	u32 raddr;
	u32 data_addr;
	u32 data_round;
	u32 pf_id;
};

struct ys_cuckoo_kick {
	struct ys_cuckoo_entry entry;
	u32 from_bucket;
	u32 to_bucket;
	u32 from_pos;
	u32 to_pos;
};

struct ys_cuckoo_kick_stream {
	struct ys_cuckoo_kick kicks[YS_CUCKOO_MAX_INSERT_RETRIES];
	u32 count;
};

struct ys_cuckoo_table;
struct ys_cuckoo_ops_cached {
	void (*get_hw_info)(struct ys_cuckoo_table *table);
	u32 (*hash)(const u8 *key, u32 seed, u32 mux_seed);
	u32 (*get_ram_addr)(u32 bucket, u32 pos);
	void (*generate_rule_data)(const u8 *key, const u8 *value,
				   u32 *data);
	void (*parse_rule_data)(const u32 *data, u8 *key, u8 *value);
	int (*store_rule_data)(struct ys_cuckoo_table *table, u8 bucket,
			       u32 pos);
	int (*store_rule_data2file)(struct ys_cuckoo_table *table, u8 bucket,
				    u32 pos);
	int (*backup_entry)(struct ys_cuckoo_table *table,
			    struct ys_cuckoo_entry entry,
			    struct ys_cuckoo_kick_stream *stream,
			    struct ys_cuckoo_kick kick, char *key_str,
			    char *value_str);
};

struct ys_cuckoo_table {
	u32 type;
	u32 flag;
	u32 bucket_count;
	u32 depth;
	u32 key_size;		/* bytes */
	u32 value_size;		/* bytes */
	u32 seed_bits;		/* bits */
	u32 mux_seed_bits;	/* bits */
	u32 init_done;
	u32 seed[YS_CUCKOO_MAX_BUCKETS];
	u32 mux_seed[YS_CUCKOO_MAX_BUCKETS];
	u32 buckets_entry_num[YS_CUCKOO_MAX_BUCKETS];
	struct ys_cuckoo_hw hw;
	u32 (*ys_cuckoo_table_init)(struct ys_cuckoo_table *table);
	u32 (*ys_cuckoo_table_uninit)(struct ys_cuckoo_table *table);
};

void ys_cuckoo_kick_push(struct ys_cuckoo_kick_stream *stream,
			 struct ys_cuckoo_kick kick);

u32 ys_cuckooo_ioread32(struct ys_cuckoo_table *table, u32 reg);
void ys_cuckoo_iowrite32(struct ys_cuckoo_table *table, u32 reg, u32 val);

u32 ys_cuckooo_ioread32_direct(uintptr_t reg_addr);
void ys_cuckoo_iowrite32_direct(uintptr_t reg_addr, u32 val);

// cuckoo cached table
struct ys_cuckoo_table_cached {
	struct ys_cuckoo_table table_base;
	struct ys_cuckoo_entry buckets[YS_CUCKOO_MAX_BUCKETS][YS_CUCKOO_MAX_DEPTH];
	const struct ys_cuckoo_ops_cached *ops;
};

struct ys_cuckoo_table *ys_cuckoo_create(u32 type, u32 flag, u32 pf_id, void __iomem *bar_addr);
void ys_cuckoo_destroy(struct ys_cuckoo_table *table);
int ys_cuckoo_clear_table(struct ys_cuckoo_table *table);
int ys_cuckoo_insert(struct ys_cuckoo_table *table, const u8 *key, const u8 *value);
int ys_cuckoo_delete(struct ys_cuckoo_table *table, const u8 *key);
int ys_cuckoo_change(struct ys_cuckoo_table *table, const u8 *key, const u8 *value);
int ys_cuckoo_search(struct ys_cuckoo_table *table, const u8 *key, u8 *value,
		     u32 *bucket, u32 *pos);
void ys_cuckoo_print_table_occupancy(struct ys_cuckoo_table *table);
void ys_cuckoo_dump_table_key_value(struct ys_cuckoo_table *table);

// cuckoo shared no cache table
struct ys_cuckoo_shared_lock {
	u32 lock_flag_addr;
	u32 lock_state_addr;
	u32 lock_timeout_addr;
	u32 lock_timeout;
};

struct ys_cuckoo_table_uncached {
	struct ys_cuckoo_table table_base;
	const struct ys_cuckoo_ops_uncached *ops;
	struct ys_cuckoo_entry entry_swap;
	struct ys_cuckoo_shared_lock lock_info;
};

struct ys_cuckoo_ops_uncached {
	void (*get_hw_info)(struct ys_cuckoo_table_uncached *table);
	u32 (*hash)(const u8 *key, u32 seed, u32 mux_seed);
	u32 (*get_ram_addr)(u32 bucket, u32 pos);
	void (*generate_rule_data)(const u8 *key, const u8 *value,
				   u32 *data);
	void (*parse_rule_data)(const u32 *data, u8 *key, u8 *value);
	int (*store_rule_data)(struct ys_cuckoo_table_uncached *table, u8 bucket,
			       u32 pos);
	int (*store_rule_data2file)(struct ys_cuckoo_table_uncached *table, u8 bucket,
				    u32 pos);
	int (*backup_entry)(struct ys_cuckoo_table_uncached *table,
			    struct ys_cuckoo_entry entry);
};

#endif // YS_CUCKOO_HASH_H
