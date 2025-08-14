// SPDX-License-Identifier: GPL-2.0

#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/log2.h>
#include <linux/module.h>

#include "ys_k2u_doe_core.h"
#include "../include/ys_doe_kapi.h"

s32 hados_doe_tbl_existed(u32 card_id, u8 tbl_id)
{
	return ys_k2u_doe_table_existed(card_id, tbl_id);
}
EXPORT_SYMBOL(hados_doe_tbl_existed);

s32 hados_doe_hw_init_v25(u32 card_id, u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd = {0};

	cmd.opcode = YS_DOE_SW_HW_INIT;

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hw_init_v25);

s32 hados_doe_protect_status_v25(u32 card_id)
{
	return ys_k2u_doe_protect_status(card_id);
}
EXPORT_SYMBOL(hados_doe_protect_status_v25);

s32 hados_doe_set_protect_v25(u32 card_id, u8 status)
{
	return ys_k2u_doe_set_protect(card_id, status);
}
EXPORT_SYMBOL(hados_doe_set_protect_v25);

s32 hados_doe_create_arraytbl_v25(u32 card_id, u8 tbl_id, u32 depth,
				  u8 data_len,
				  const struct hw_advance_cfg *cfg,
				  u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_CREATE_ARRAY;
	cmd.tbl_id = tbl_id;
	cmd.tbl_param.depth = depth;
	cmd.tbl_param.dov_len = data_len;
	cmd.tbl_param.index_sram_size = 512;
	if (cfg) {
		if (cfg->shared_tbl ||
		    *(u32 *)cfg->l1_cache_ways != 0 ||
		    *(u32 *)(cfg->l1_cache_ways + 4) != 0 ||
		    *(u32 *)(cfg->l1_cache_ways + 8) != 0 ||
		    *(u32 *)(cfg->l1_cache_ways + 12) != 0 ||
		    cfg->l2_cache_ways != 0) {
			cmd.tbl_param.use_cache = 1;
			cmd.tbl_param.shared_tbl = cfg->shared_tbl;
			memcpy(cmd.tbl_param.l1_cache_ways, cfg->l1_cache_ways,
			       sizeof(u8) * 16);
			cmd.tbl_param.l2_cache_ways = cfg->l2_cache_ways;
		} else {
			cmd.tbl_param.use_cache = 0;
		}

		cmd.tbl_param.location = cfg->location;
		cmd.tbl_param.tbl_type = cfg->tbl_type;
		cmd.tbl_param.endian = cfg->endian;
		cmd.tbl_param.ddr_mode = cfg->ddr_mode;
	} else {
		cmd.tbl_param.use_cache = 0;
	}

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_create_arraytbl_v25);

s32 hados_doe_create_countertbl_v25(u32 card_id, u8 tbl_id, u32 depth,
				    const struct hw_advance_cfg *cfg,
				    u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_CREATE_ARRAY;
	cmd.tbl_id = tbl_id;
	cmd.tbl_param.depth = depth;
	cmd.tbl_param.dov_len = 16;
	cmd.tbl_param.index_sram_size = 512;
	cmd.tbl_param.tbl_type = DOE_TABLE_COUNTER;
	if (cfg) {
		cmd.tbl_param.location = cfg->location;
		cmd.tbl_param.endian = cfg->endian;
	} else {
		cmd.tbl_param.location = 0;
		cmd.tbl_param.endian = 0;
	}

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_create_countertbl_v25);

s32 hados_doe_create_metertbl_v25(u32 card_id, u8 tbl_id, u32 depth,
				  const struct hw_advance_cfg *cfg,
				  u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_CREATE_ARRAY;
	cmd.tbl_id = tbl_id;
	cmd.tbl_param.depth = depth;
	cmd.tbl_param.dov_len = 32;
	cmd.tbl_param.index_sram_size = 512;
	cmd.tbl_param.tbl_type = DOE_TABLE_METER;
	if (cfg) {
		cmd.tbl_param.location = cfg->location;
		cmd.tbl_param.endian = cfg->endian;
	} else {
		cmd.tbl_param.location = 0;
		cmd.tbl_param.endian = 0;
	}

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_create_metertbl_v25);

s32 hados_doe_create_hashtbl_v25(u32 card_id, u8 tbl_id, u32 depth,
				 u8 key_len, u8 value_len,
				 const struct hw_advance_cfg *cfg,
				 u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_CREATE_HASH;
	cmd.tbl_id = tbl_id;
	cmd.tbl_param.depth = depth;
	cmd.tbl_param.key_len = key_len;
	cmd.tbl_param.dov_len = value_len;
	if (cfg) {
		if (cfg->shared_tbl ||
		    *(u32 *)cfg->l1_cache_ways != 0 ||
		    *(u32 *)(cfg->l1_cache_ways + 4) != 0 ||
		    *(u32 *)(cfg->l1_cache_ways + 8) != 0 ||
		    *(u32 *)(cfg->l1_cache_ways + 12) != 0 ||
		    cfg->l2_cache_ways != 0) {
			cmd.tbl_param.use_cache = 1;
			cmd.tbl_param.shared_tbl = cfg->shared_tbl;
			memcpy(cmd.tbl_param.l1_cache_ways, cfg->l1_cache_ways,
			       sizeof(u8) * 16);
			cmd.tbl_param.l2_cache_ways = cfg->l2_cache_ways;
		} else {
			cmd.tbl_param.use_cache = 0;
		}

		cmd.tbl_param.location = cfg->location;
		cmd.tbl_param.tbl_type = cfg->tbl_type;
		cmd.tbl_param.endian = cfg->endian;
		cmd.tbl_param.ddr_mode = cfg->ddr_mode;
		cmd.tbl_param.sdepth = (cfg->sdepth / 64 + 1) * 64;
		cmd.tbl_param.chain_limit = cfg->chain_limit;
	} else {
		cmd.tbl_param.use_cache = 0;
		cmd.tbl_param.sdepth = (depth / 64 + 1) * 64; // Depth * 1
	}

	cmd.tbl_param.index_sram_size = cmd.tbl_param.sdepth > 256 ? 256 : cmd.tbl_param.sdepth;

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_create_hashtbl_v25);

s32 hados_doe_delete_arraytbl_v25(u32 card_id, u8 tbl_id, u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_DELETE_ARRAY;
	cmd.tbl_id = tbl_id;

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_delete_arraytbl_v25);

s32 hados_doe_delete_hashtbl_v25(u32 card_id, u8 tbl_id, u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_DELETE_HASH;
	cmd.tbl_id = tbl_id;

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_delete_hashtbl_v25);

s32 hados_doe_array_store_v25(u32 card_id, u8 tbl_id, u32 index,
			      const void *data, u8 size, u8 high_pri,
			      u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_ARRAY_STORE;
	cmd.tbl_id = tbl_id;
	cmd.index = index;
	cmd.high_pri = high_pri;
	memcpy(cmd.data, data, size > 128 ? 128 : size);

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_array_store_v25);

s32 hados_doe_array_load_v25(u32 card_id, u8 tbl_id, u32 index,
			     void *data, u8 size,
			     u8 poll_wait)
{
	s32 ret;
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_ARRAY_LOAD;
	cmd.tbl_id = tbl_id;
	cmd.index = index;
	cmd.is_read = 1;

	ret = ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
	if (!ret)
		memcpy(data, cmd.data, size > 128 ? 128 : size);

	return ret;
}
EXPORT_SYMBOL(hados_doe_array_load_v25);

s32 hados_doe_hash_insert_v25(u32 card_id, u8 tbl_id,
			      const void *key, u8 key_len,
			      const void *value, u8 value_len,
			      u8 high_pri, u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_HASH_INSERT;
	cmd.tbl_id = tbl_id;
	cmd.high_pri = high_pri;
	memcpy(cmd.key, key, key_len > 128 ? 128 : key_len);
	memcpy(cmd.value, value, value_len > 128 ? 128 : value_len);

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hash_insert_v25);

s32 hados_doe_hash_query_v25(u32 card_id, u8 tbl_id, const void *key,
			     u8 key_len, void *value, u8 value_len,
			     u8 poll_wait)
{
	s32 ret;
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_HASH_QUERY;
	cmd.tbl_id = tbl_id;
	cmd.is_read = 1;
	memcpy(cmd.key, key, key_len > 128 ? 128 : key_len);

	ret = ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
	if (!ret)
		memcpy(value, cmd.value, value_len > 128 ? 128 : value_len);

	return ret;
}
EXPORT_SYMBOL(hados_doe_hash_query_v25);

s32 hados_doe_hash_update_v25(u32 card_id, u8 tbl_id,
			      const void *key, u8 key_len,
			      const void *value, u8 value_len,
			      u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd = {0};

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_HASH_UPDATE;
	cmd.tbl_id = tbl_id;
	memcpy(cmd.key, key, key_len > 128 ? 128 : key_len);
	memcpy(cmd.value, value, value_len > 128 ? 128 : value_len);

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hash_update_v25);

s32 hados_doe_hash_delete_v25(u32 card_id, u8 tbl_id, const void *key,
			      u8 key_len, u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_HASH_DELETE;
	cmd.tbl_id = tbl_id;
	memcpy(cmd.key, key, key_len > 128 ? 128 : key_len);

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hash_delete_v25);

s32 hados_doe_hash_save_v25(u32 card_id, u8 tbl_id,
			    const void *key, u8 key_len,
			    const void *value, u8 value_len,
			    u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_HASH_SAVE;
	cmd.tbl_id = tbl_id;
	memcpy(cmd.key, key, key_len > 128 ? 128 : key_len);
	memcpy(cmd.value, value, value_len > 128 ? 128 : value_len);

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hash_save_v25);

static inline u32 send_batch_cmd(u32 card_id, enum ys_doe_cmd_opcode opc,
				 u8 tbl_id, s32 is_read,
				 u32 cnt, u8 enable,
				 void *koi_list, void *pair_list,
				 u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = opc;
	cmd.tbl_id = tbl_id;
	cmd.cnt = cnt;
	cmd.koi_list = koi_list;
	cmd.pair_list = pair_list;
	cmd.is_read = is_read;
	cmd.enable = enable;

	ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);

	return cmd.succeed;
}

u32 hados_doe_array_store_batch_v25(u32 card_id, u8 tbl_id, u32 cnt,
				    const void *pair_list,
				    u8 poll_wait)
{
	return send_batch_cmd(card_id, YS_DOE_SW_ARRAY_STORE_BATCH,
			      tbl_id, 0, cnt, 0,
			      NULL, (void *)pair_list, poll_wait);
}
EXPORT_SYMBOL(hados_doe_array_store_batch_v25);

u32 hados_doe_array_load_batch_v25(u32 card_id, u8 tbl_id, u32 cnt,
				   const void *index_list, void *pair_list,
				   u8 poll_wait)
{
	return send_batch_cmd(card_id, YS_DOE_SW_ARRAY_LOAD_BATCH, tbl_id,
			      1, cnt, 0, (void *)index_list,
			      pair_list, poll_wait);
}
EXPORT_SYMBOL(hados_doe_array_load_batch_v25);

u32 hados_doe_hash_insert_batch_v25(u32 card_id, u8 tbl_id, u32 cnt,
				    const void *pair_list, u8 poll_wait)
{
	return send_batch_cmd(card_id, YS_DOE_SW_HASH_INSERT_BATCH, tbl_id,
			      0, cnt, 0, NULL, (void *)pair_list, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hash_insert_batch_v25);

u32 hados_doe_hash_query_batch_v25(u32 card_id, u8 tbl_id, u32 cnt,
				   const void *key_list,
				   void *pair_list, u8 poll_wait)
{
	return send_batch_cmd(card_id, YS_DOE_SW_HASH_QUERY_BATCH, tbl_id,
			      1, cnt, 0, (void *)key_list,
			      pair_list, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hash_query_batch_v25);

u32 hados_doe_hash_delete_batch_v25(u32 card_id, u8 tbl_id, u32 cnt,
				    const void *key_list, u8 poll_wait)
{
	return send_batch_cmd(card_id, YS_DOE_SW_HASH_DELETE_BATCH, tbl_id,
			      0, cnt, 0, (void *)key_list, NULL, poll_wait);
}
EXPORT_SYMBOL(hados_doe_hash_delete_batch_v25);

s32 hados_doe_counter_enable_v25(u32 card_id, u8 tbl_id, u32 index, u8 enable,
				 u8 high_pri, u8 clear_data, u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_COUNTER_ENABLE;
	cmd.tbl_id = tbl_id;
	cmd.index = index;
	cmd.enable = enable;
	cmd.high_pri = high_pri | (!clear_data ? 0x4 : 0x0);

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_counter_enable_v25);

u32 hados_doe_counter_enable_batch_v25(u32 card_id, u8 tbl_id, u32 cnt,
				       const void *index_list, u8 enable,
				       u8 poll_wait)
{
	return send_batch_cmd(card_id, YS_DOE_SW_COUNTER_ENABLE_BATCH, tbl_id,
			0, cnt, enable, (void *)index_list, NULL, poll_wait);
}
EXPORT_SYMBOL(hados_doe_counter_enable_batch_v25);

u32 hados_doe_counter_load_v25(u32 card_id, u8 tbl_id, u32 start, u32 cnt,
			       const void *pair_list, u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_COUNTER_LOAD;
	cmd.tbl_id = tbl_id;
	cmd.total = cnt;
	cmd.cnt = cnt;
	cmd.start = start;
	cmd.pair_list = (void *)pair_list;
	cmd.is_read = 1;

	ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);

	return cmd.number;
}
EXPORT_SYMBOL(hados_doe_counter_load_v25);

u32 hados_doe_meter_store_v25(u32 card_id, u8 tbl_id, u32 index,
			      struct meter_config *config, u8 high_pri,
			      u8 poll_wait)
{
	struct ys_doe_sw_cmd cmd;
	u8 *p = cmd.data;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = YS_DOE_SW_ARRAY_STORE;
	cmd.tbl_id = tbl_id;
	cmd.index = index;
	cmd.high_pri = high_pri;

	memcpy(p, &config->ciir, sizeof(config->ciir));
	p += sizeof(config->ciir);
	memcpy(p, &config->cbs, sizeof(config->cbs));
	p += sizeof(config->cbs);
	memcpy(p, &config->pir, sizeof(config->pir));
	p += sizeof(config->pir);
	memcpy(p, &config->pbs, sizeof(config->pbs));
	p += sizeof(config->pbs);
	memcpy(p, &config->att_factor, sizeof(config->att_factor));

	return ys_k2u_doe_kernel_call(card_id, &cmd, poll_wait);
}
EXPORT_SYMBOL(hados_doe_meter_store_v25);

u32 hados_doe_hash_table_max(u32 card_id)
{
	return ys_k2u_doe_hash_table_max(card_id);
}
EXPORT_SYMBOL(hados_doe_hash_table_max);

s32 hados_doe_get_channel_type(u32 card_id, u8 channel_id)
{
	return ys_k2u_doe_get_channel_type(card_id, channel_id);
}
EXPORT_SYMBOL(hados_doe_get_channel_type);

u32 hados_doe_get_table_cache_entry_limit(u32 card_id, u32 tlb_type)
{
	return ys_k2u_doe_get_table_cache_entry_limit(card_id, tlb_type);
}
EXPORT_SYMBOL(hados_doe_get_table_cache_entry_limit);

void hados_doe_set_table_cache_entry_limit(u32 card_id, u32 tlb_type, u32 data_len)
{
	return ys_k2u_doe_set_table_cache_entry_limit(card_id, tlb_type, data_len);
}
EXPORT_SYMBOL(hados_doe_set_table_cache_entry_limit);

void ys_k2u_doe_init_adev_ops(struct ys_doe_ops *ops)
{
	ops->create_arraytbl = hados_doe_create_arraytbl_v25;
	ops->create_hashtbl = hados_doe_create_hashtbl_v25;
	ops->delete_arraytbl = hados_doe_delete_arraytbl_v25;
	ops->delete_hashtbl = hados_doe_delete_hashtbl_v25;

	ops->array_store = hados_doe_array_store_v25;
	ops->array_store_batch = hados_doe_array_store_batch_v25;
	ops->array_load = hados_doe_array_load_v25;
	ops->array_load_batch = hados_doe_array_load_batch_v25;

	ops->hash_insert = hados_doe_hash_insert_v25;
	ops->hash_insert_batch = hados_doe_hash_insert_batch_v25;
	ops->hash_query = hados_doe_hash_query_v25;
	ops->hash_query_batch = hados_doe_hash_query_batch_v25;
	ops->hash_delete = hados_doe_hash_delete_v25;
	ops->hash_delete_batch = hados_doe_hash_delete_batch_v25;
	ops->hash_update = hados_doe_hash_update_v25;
	ops->hash_save_v25 = hados_doe_hash_save_v25;

	ops->tbl_valid = hados_doe_tbl_existed;

	ops->hw_init = hados_doe_hw_init_v25;

	ops->create_countertbl = hados_doe_create_countertbl_v25;
	ops->create_metertbl = hados_doe_create_metertbl_v25;
	ops->meter_store = hados_doe_meter_store_v25;
	ops->counter_enable = hados_doe_counter_enable_v25;
	ops->counter_enable_batch = hados_doe_counter_enable_batch_v25;
	ops->counter_load = hados_doe_counter_load_v25;
	ops->protect_status = hados_doe_protect_status_v25;
	ops->set_protect_status = hados_doe_set_protect_v25;
}
