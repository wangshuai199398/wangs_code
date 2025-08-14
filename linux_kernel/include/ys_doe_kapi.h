/* SPDX-License-Identifier: GPL-2.0 */

#ifndef YS_DOE_KAPI_H
#define YS_DOE_KAPI_H

#include <linux/types.h>

enum ys_doe_tbl_t {
	DOE_TABLE_NORMAL_ARRAY,
	DOE_TABLE_BIG_HASH,
	DOE_TABLE_COUNTER,
	DOE_TABLE_METER,
	DOE_TABLE_LOCK,
	DOE_TABLE_SMALL_HASH,
	DOE_TABLE_SMALL_ARRAY,
};

enum ys_doe_tbl_location_t {
	DOE_LOCATION_DDR,
	DOE_LOCATION_RAM,
	DOE_LOCATION_HOST_DDR,
	DOE_LOCATION_SOC_DDR,
};

enum ys_doe_ddr_channel_t {
	DOE_CHANNEL_DDR0,
	DOE_CHANNEL_DDR1,
	DOE_CHANNEL_RAM,
};

struct hw_advance_cfg {
	/* k2pro param */
	u8 shared_tbl;
	u8 l1_cache_ways[16];
	u8 l2_cache_ways;

	/* k2pro 2.5 */
	u8 tbl_type;		/* ys_doe_tbl_t */
	u8 location;		/* ys_doe_tbl_location_t */
	u8 ddr_channel;		/* ys_doe_ddr_channel_t */
	u8 endian;		/* 0, Small; 1, Big */
	u8 ddr_mode;		/* 0, signal ddr; 1: double ddr */
	u32 sdepth;		/* hash second-table depth */
	u32 chain_limit;	/* hash表冲突链最大长度 */
	u32 hash_seed;		/* hash表冲突链最大长度 */

};

struct ysk2u_doe_channel {
	int locations[2];
};

struct meter_config {
	__be16 ciir;
	__be32 cbs;
	__be16 pir;
	__be32 pbs;
	u8 att_factor;
} __packed;

s32 hados_doe_tbl_existed(u32 card_id, u8 table_id);

s32 hados_doe_ddr_config(u32 card_id, u64 ddr0_cap, u64 ddr1_cap);

s32 hados_doe_hw_init_v25(u32 card_id, u8 poll_wait);

s32 hados_doe_protect_status_v25(u32 card_id);

s32 hados_doe_set_protect_v25(u32 card_id, u8 status);

s32 hados_doe_create_arraytbl_v25(u32 card_id, u8 table_id, u32 depth,
				  u8 data_len,
				  const struct hw_advance_cfg *cfg,
				  u8 poll_wait);

s32 hados_doe_create_hashtbl_v25(u32 card_id, u8 table_id, u32 depth,
				 u8 key_len, u8 value_len,
				 const struct hw_advance_cfg *cfg,
				 u8 poll_wait);

s32 hados_doe_delete_arraytbl_v25(u32 card_id, u8 table_id, u8 poll_wait);

s32 hados_doe_delete_hashtbl_v25(u32 card_id, u8 table_id, u8 poll_wait);

s32 hados_doe_array_load_v25(u32 card_id, u8 table_id, u32 index,
			     void *data, u8 size, u8 poll_wait);

s32 hados_doe_hash_query_v25(u32 card_id, u8 table_id, const void *key,
			     u8 key_len, void *value, u8 value_len,
			     u8 poll_wait);

s32 hados_doe_hash_delete_v25(u32 card_id, u8 table_id, const void *key,
			      u8 key_len, u8 poll_wait);

u32 hados_doe_array_store_batch_v25(u32 card_id, u8 table_id, u32 cnt,
				    const void *pair_list,
				    u8 poll_wait);

u32 hados_doe_array_load_batch_v25(u32 card_id, u8 table_id, u32 cnt,
				   const void *index_list,
				   void *pair_list, u8 poll_wait);

u32 hados_doe_array_readclear_batch(u32 card_id, u8 table_id, u32 cnt,
				    const void *index_list,
				    void *pair_list, u8 poll_wait);

u32 hados_doe_hash_insert_batch_v25(u32 card_id, u8 table_id, u32 cnt,
				    const void *pair_list, u8 poll_wait);

u32 hados_doe_hash_query_batch_v25(u32 card_id, u8 table_id, u32 cnt,
				   const void *key_list,
				   void *pair_list, u8 poll_wait);

u32 hados_doe_hash_delete_batch_v25(u32 card_id, u8 table_id, u32 cnt,
				    const void *key_list, u8 poll_wait);

/* for k2u doe */
s32 hados_doe_create_countertbl_v25(u32 card_id, u8 tbl_id, u32 depth,
				    const struct hw_advance_cfg *cfg,
				    u8 poll_wait);

s32 hados_doe_create_metertbl_v25(u32 card_id, u8 tbl_id, u32 depth,
				  const struct hw_advance_cfg *cfg,
				  u8 poll_wait);

s32 hados_doe_array_store_v25(u32 card_id, u8 tbl_id, u32 index,
			      const void *data, u8 size, u8 high_pri,
			      u8 poll_wait);

s32 hados_doe_hash_insert_v25(u32 card_id, u8 tbl_id,
			      const void *key, u8 key_len,
			      const void *value, u8 value_len,
			      u8 high_pri, u8 poll_wait);

s32 hados_doe_hash_update_v25(u32 card_id, u8 tbl_id,
			      const void *key, u8 key_len,
			      const void *value, u8 value_len,
			      u8 poll_wait);

s32 hados_doe_hash_save_v25(u32 card_id, u8 tbl_id,
			    const void *key, u8 key_len,
			    const void *value, u8 value_len,
			    u8 poll_wait);

s32 hados_doe_counter_enable_v25(u32 card_id, u8 tbl_id, u32 index, u8 enable,
				 u8 high_pri, u8 clear_data, u8 poll_wait);

u32 hados_doe_counter_enable_batch_v25(u32 card_id, u8 tbl_id, u32 cnt,
				       const void *index_list, u8 enable,
				       u8 poll_wait);

u32 hados_doe_counter_load_v25(u32 card_id, u8 tbl_id, u32 start, u32 cnt,
			       const void *pair_list, u8 poll_wait);

u32 hados_doe_meter_store_v25(u32 card_id, u8 tbl_id, u32 index,
			      struct meter_config *config, u8 high_pri,
			      u8 poll_wait);

u32 hados_doe_hash_table_max(u32 card_id);

s32 hados_doe_get_channel_type(u32 card_id, u8 channel_id);

u32 hados_doe_get_table_cache_entry_limit(u32 card_id, u32 tlb_type);

void hados_doe_set_table_cache_entry_limit(u32 card_id, u32 tlb_type, u32 data_len);

#endif /* YS_DOE_KAPI_H */
