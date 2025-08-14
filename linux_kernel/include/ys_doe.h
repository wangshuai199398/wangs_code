/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_DOE_H_
#define __YS_DOE_H_

#include "ys_doe_kapi.h"

struct ys_doe_ops {
	s32 (*tbl_valid)(u32 card_id, u8 tbl_id);

	s32 (*create_arraytbl)(u32 card_id, u8 tbl_id, u32 depth, u8 data_len,
			       const struct hw_advance_cfg *cfg,
			       u8 poll_wait);
	s32 (*create_countertbl)(u32 card_id, u8 tbl_id, u32 depth,
				 const struct hw_advance_cfg *cfg, u8 poll_wait);
	s32 (*create_metertbl)(u32 card_id, u8 tbl_id, u32 depth,
			       const struct hw_advance_cfg *cfg, u8 poll_wait);

	s32 (*delete_arraytbl)(u32 card_id, u8 tbl_id, u8 poll_wait);

	s32 (*create_hashtbl)(u32 card_id, u8 tbl_id, u32 depth, u8 key_len,
			      u8 value_len, const struct hw_advance_cfg *cfg,
			      u8 poll_wait);
	s32 (*delete_hashtbl)(u32 card_id, u8 tbl_id, u8 poll_wait);

	s32 (*array_store)(u32 card_id, u8 tbl_id, u32 index,
			   const void *data, u8 size,
			   u8 high_pri, u8 poll_wait);
	u32 (*array_store_batch)(u32 card_id, u8 tbl_id, u32 cnt,
				 const void *pair_list,
				 u8 poll_wait);

	s32 (*array_load)(u32 card_id, u8 tbl_id, u32 index, void *data, u8 size,
			  u8 poll_wait);
	u32 (*array_load_batch)(u32 card_id, u8 tbl_id, u32 cnt,
				const void *index_list,
				void *pair_list, u8 poll_wait);

	s32 (*hash_insert)(u32 card_id, u8 tbl_id, const void *key,
			   u8 key_len, const void *value, u8 value_len,
			   u8 high_pri, u8 poll_wait);
	u32 (*hash_insert_batch)(u32 card_id, u8 tbl_id, u32 cnt,
				 const void *pair_list,
				 u8 poll_wait);

	s32 (*hash_query)(u32 card_id, u8 tbl_id, const void *key, u8 key_len,
			  void *value, u8 value_len, u8 poll_wait);
	u32 (*hash_query_batch)(u32 card_id, u8 tbl_id, u32 cnt,
				const void *key_list,
				void *pair_list, u8 poll_wait);

	s32 (*hash_update)(u32 card_id, u8 tbl_id, const void *key,
			   u8 key_len, const void *value, u8 value_len,
			   u8 poll_wait);
	s32 (*hash_save_v25)(u32 card_id, u8 tbl_id, const void *key,
			     u8 key_len, const void *value, u8 value_len,
			     u8 poll_wait);

	s32 (*hash_delete)(u32 card_id, u8 tbl_id, const void *key, u8 key_len,
			   u8 poll_wait);
	u32 (*hash_delete_batch)(u32 card_id, u8 tbl_id, u32 cnt,
				 const void *key_list,
				 u8 poll_wait);

	s32 (*counter_enable)(u32 card_id, u8 tbl_id, u32 index, u8 enable,
			      u8 high_pri, u8 clear_data, u8 poll_wait);
	u32 (*counter_enable_batch)(u32 card_id, u8 tbl_id, u32 cnt,
				    const void *index_list, u8 enable,
				    u8 poll_wait);

	u32 (*counter_load)(u32 card_id, u8 tbl_id, u32 start, u32 cnt,
			    const void *pair_list, u8 poll_wait);
	u32 (*meter_store)(u32 card_id, u8 tbl_id, u32 index,
			   struct meter_config *config, u8 high_pri,
			   u8 poll_wait);

	s32 (*hw_init)(u32 card_id, u8 poll_wait);

	s32 (*ddr_config)(u32 card_id, u64 ddr0_cap, u64 ddr1_cap);

	s32 (*protect_status)(u32 card_id);

	s32 (*set_protect_status)(u32 card_id, u8 status);
};

#endif /* __YS_DOE_H_ */
