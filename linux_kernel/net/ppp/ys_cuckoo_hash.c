// SPDX-License-Identifier: GPL-2.0-or-later
#include "ys_cuckoo_hash.h"
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/sort.h>
#include <linux/iopoll.h>

#include "ys_platform.h"
#include "../lan/k2ulan/ys_k2ulan_cuckoo.h"
#include "../../platform/ys_pdev.h"

#define YS_CUCKOO_HASH_CACHED 0
#define YS_CUCKOO_HASH_SHARED 0

u32 ys_cuckooo_ioread32(struct ys_cuckoo_table *table, u32 reg)
{
	return
	    ioread32((void __iomem *)((uintptr_t)(table->hw.bar_addr) +
				      (reg)));
}

void ys_cuckoo_iowrite32(struct ys_cuckoo_table *table, u32 reg, u32 val)
{
	return iowrite32(val,
			 (void __iomem *)((uintptr_t)(table->hw.bar_addr) +
					  (reg)));
}

u32 ys_cuckooo_ioread32_direct(uintptr_t reg_addr)
{
	return
	    ioread32((void __iomem *)(reg_addr));
}

void ys_cuckoo_iowrite32_direct(uintptr_t reg_addr, u32 val)
{
	return iowrite32(val,
			 (void __iomem *)(reg_addr));
}

#if YS_CUCKOO_HASH_CACHED
static int ys_cuckoo_read_rule(struct ys_cuckoo_table *table, u8 bucket,
			       u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = { 0 };
	u32 ram_addr;
	u32 cal_pos;
	int i;

	ram_addr = table->ops->get_ram_addr(bucket, pos);
	ys_cuckoo_iowrite32(table, table->hw.raddr, ram_addr);
	for (i = 0; i < table->hw.data_round; i++)
		data[i] = ys_cuckooo_ioread32(table, table->hw.data_addr);

	table->ops->parse_rule_data(data, table->buckets[bucket][pos].key,
				    table->buckets[bucket][pos].value);

	cal_pos = table->ops->hash(table->buckets[bucket][pos].key,
				   table->seed[bucket],
				   table->mux_seed[bucket]);
	if (pos != cal_pos) {
		memset(table->buckets[bucket][pos].key, 0,
		       YS_CUCKOO_MAX_KEY_SIZE);
		memset(table->buckets[bucket][pos].value, 0,
		       YS_CUCKOO_MAX_VALUE_SIZE);
		return -EINVAL;
	}

	return 0;
}
#endif //YS_CUCKOO_HASH_CACHED

static int ys_cuckoo_compare(const void *a, const void *b)
{
	return (*(u32 *)a - *(u32 *)b);
}

static int ys_cuckoo_check_duplicates(u32 *array, u32 size)
{
	u32 *arr;
	int i;

	arr = kcalloc(size, sizeof(u32), GFP_KERNEL);
	if (!arr)
		return -ENOMEM;

	memcpy(arr, array, size * sizeof(u32));

	sort(arr, size, sizeof(u32), ys_cuckoo_compare, NULL);

	for (i = 1; i < size; i++) {
		if (arr[i] == arr[i - 1]) {
			kfree(arr);
			return -EINVAL;
		}
	}

	kfree(arr);

	return 0;
}

static int ys_cuckoo_generate_seed(struct ys_cuckoo_table *table)
{
	u32 mux_seed[YS_CUCKOO_MAX_BUCKETS];
	u32 seed[YS_CUCKOO_MAX_BUCKETS];
	u32 mux_seed_mask;
	u32 seed_mask;
	int no_duplicate = 0;
	int i, j;

	mux_seed_mask = (1ULL << table->mux_seed_bits) - 1;
	seed_mask = (1ULL << table->seed_bits) - 1;
	for (j = 0; j < YS_CUCKOO_MAX_CREATE_SEED_RETRIES; j++) {
		for (i = 0; i < table->bucket_count; i++)
			seed[i] = get_random_u32() & seed_mask;

		for (i = 0; i < table->bucket_count; i++)
			mux_seed[i] = get_random_u32() & mux_seed_mask;
		if (!ys_cuckoo_check_duplicates(seed, table->bucket_count) &&
		    !ys_cuckoo_check_duplicates(mux_seed,
						table->bucket_count)) {
			no_duplicate = 1;
			break;
		}
	}

	if (table->type == YS_CUCKOO_TYPE_K2U_BNIC_LAN_MAC) {
		seed[0] = 0xb85c6f30;
		seed[1] = 0x1bc18361;
		seed[2] = 0x7ea0e640;
		mux_seed[0] = 0x1a;
		mux_seed[1] = 0x12;
		mux_seed[2] = 0x1c;
		no_duplicate = 1;
	}

	if (no_duplicate) {
		for (i = 0; i < table->bucket_count; i++) {
			ys_cuckoo_iowrite32(table, table->hw.seed_addr[i],
					    seed[i]);
			ys_cuckoo_iowrite32(table, table->hw.mux_seed_addr[i],
					    mux_seed[i]);
			ys_debug("bucket %d seed 0x%x mux_seed 0x%x", i,
				seed[i], mux_seed[i]);
		}
		memcpy(table->seed, seed, sizeof(u32) * table->bucket_count);
		memcpy(table->mux_seed, mux_seed,
		       sizeof(u32) * table->bucket_count);

		return 0;
	}

	return -EINVAL;
}

static int ys_cuckoo_set_table_default_params(struct ys_cuckoo_table *table)
{
	//struct ys_cuckoo_table_cached *cached_table = NULL;
	struct ys_cuckoo_table_uncached *uncached_table = NULL;

	switch (table->type) {
	case YS_CUCKOO_TYPE_EME:
//              table->ops = &ppp_ops;
		break;
	case YS_CUCKOO_TYPE_CHISHUI:
//              table->ops = &chishui_ops;
		break;
	case YS_CUCKOO_TYPE_LAN_UC:
		break;
	case YS_CUCKOO_TYPE_LAN_MC:
		break;
	case YS_CUCKOO_TYPE_K2U_LAN_UC:
		uncached_table = (struct ys_cuckoo_table_uncached *)table;
		uncached_table->ops = &k2ulan_uc_ops;
		if (uncached_table->ops->get_hw_info)
			uncached_table->ops->get_hw_info(uncached_table);
		break;
	case YS_CUCKOO_TYPE_K2U_LAN_MC:
		uncached_table = (struct ys_cuckoo_table_uncached *)table;
		uncached_table->ops = &k2ulan_mc_ops;
		if (uncached_table->ops->get_hw_info)
			uncached_table->ops->get_hw_info(uncached_table);
		break;
	case YS_CUCKOO_TYPE_K2U_BNIC_LAN_UC:
		uncached_table = (struct ys_cuckoo_table_uncached *)table;
		uncached_table->ops = &k2ulan_bnic_uc_ops;
		if (uncached_table->ops->get_hw_info)
			uncached_table->ops->get_hw_info(uncached_table);
		break;
	case YS_CUCKOO_TYPE_K2U_BNIC_LAN_MC:
		uncached_table = (struct ys_cuckoo_table_uncached *)table;
		uncached_table->ops = &k2ulan_bnic_mc_ops;
		if (uncached_table->ops->get_hw_info)
			uncached_table->ops->get_hw_info(uncached_table);
		break;
	case YS_CUCKOO_TYPE_K2U_BNIC_LAN_MAC:
		uncached_table = (struct ys_cuckoo_table_uncached *)table;
		uncached_table->ops = &k2ulan_bnic_mac_ops;
		if (uncached_table->ops->get_hw_info)
			uncached_table->ops->get_hw_info(uncached_table);
		break;
	case YS_CUCKOO_TYPE_K2U_LAN_MAC:
		uncached_table = (struct ys_cuckoo_table_uncached *)table;
		uncached_table->ops = &k2ulan_mac_ops;
		if (uncached_table->ops->get_hw_info)
			uncached_table->ops->get_hw_info(uncached_table);
		break;
	default:
		ys_err("Invalid cuckoo hash type");
		return -EINVAL;
	}

	return 0;
}

#if YS_CUCKOO_HASH_CACHED
static int ys_cuckoo_load_from_hw(struct ys_cuckoo_table *table)
{
	int ret;
	int i;
	int j;

	for (i = 0; i < table->bucket_count; i++) {
		table->seed[i] =
		    ys_cuckooo_ioread32(table, table->hw.seed_addr[i]);
		table->mux_seed[i] =
		    ys_cuckooo_ioread32(table, table->hw.mux_seed_addr[i]);
	}

	for (i = 0; i < table->bucket_count; i++) {
		table->buckets_entry_num[i] = 0;
		for (j = 0; j < table->depth; j++) {
			ret = ys_cuckoo_read_rule(table, i, j);
			if (ret == 0)
				table->buckets_entry_num[i]++;
		}
	}

	return 0;
}
#endif

struct ys_cuckoo_table *ys_cuckoo_create(u32 type, u32 flag, u32 pf_id, void __iomem *bar_addr)
{
	struct ys_cuckoo_table *table;
	size_t table_size = 0;
	int ret;

	switch (type) {
	case YS_CUCKOO_TYPE_K2U_LAN_UC:
	case YS_CUCKOO_TYPE_K2U_BNIC_LAN_UC:
	case YS_CUCKOO_TYPE_K2U_LAN_MC:
	case YS_CUCKOO_TYPE_K2U_BNIC_LAN_MC:
	case YS_CUCKOO_TYPE_K2U_LAN_MAC:
	case YS_CUCKOO_TYPE_K2U_BNIC_LAN_MAC:
		if (YS_CUCKOO_TABLE_TEST_CACHED(flag) ||
		    YS_CUCKOO_TABLE_TEST_SHARED(flag)) {
			ys_err("k2u bnic cuckoo hash table invalid flag %d", flag);
			return NULL;
		}
		break;
	default:
		ys_err("Invalid cuckoo hash type %d", type);
		return NULL;
	}

	if (YS_CUCKOO_TABLE_TEST_CACHED(flag))
		table_size = sizeof(struct ys_cuckoo_table_uncached);
	else
		table_size = sizeof(struct ys_cuckoo_table_cached);

	table = kzalloc(table_size, GFP_KERNEL);
	if (!table)
		return NULL;

	table->type = type;
	table->flag = flag;
	table->hw.pf_id = pf_id;
	if (ys_cuckoo_set_table_default_params((struct ys_cuckoo_table *)table) != 0) {
		kfree(table);
		return NULL;
	}
	table->hw.bar_addr = bar_addr;

	if (ys_cuckoo_generate_seed((struct ys_cuckoo_table *)table) != 0) {
		kfree(table);
		return NULL;
	}

	if (table->ys_cuckoo_table_init) {
		ret = table->ys_cuckoo_table_init(table);
		if (ret != 0) {
			kfree(table);
			return NULL;
		}
	}

	return table;
}

void ys_cuckoo_destroy(struct ys_cuckoo_table *table)
{
	int ret;

	if (table->ys_cuckoo_table_uninit) {
		ret = table->ys_cuckoo_table_uninit(table);
		if (ret != 0)
			ys_err("Cuckoo hash type %d uninit failed!", table->type);
	}

	kfree(table);
}

int ys_cuckoo_clear_table(struct ys_cuckoo_table *table)
{
#if YS_CUCKOO_HASH_CACHED
	struct ys_cuckoo_entry entry;
	int i;
	int j;

	if (!table)
		return -EINVAL;

	memset(&entry, 0, sizeof(entry));

	//table->init_done = 0;
	//if (table->hw.init_done_addr)
	//	ys_cuckoo_iowrite32(table, table->hw.init_done_addr, 0);

	for (i = 0; i < table->bucket_count; i++) {
		for (j = 0; j < table->depth; j++)
			table->buckets[i][j] = entry;
		table->buckets_entry_num[i] = 0;
		table->seed[i] = 0;
		ys_cuckoo_iowrite32(table, table->hw.seed_addr[i], 0);
		table->mux_seed[i] = 0;
		ys_cuckoo_iowrite32(table, table->hw.mux_seed_addr[i], 0);
	}
#endif
	return 0;
}

void ys_cuckoo_kick_push(struct ys_cuckoo_kick_stream *stream,
			 struct ys_cuckoo_kick kick)
{
	if (stream->count < YS_CUCKOO_MAX_INSERT_RETRIES) {
		ys_info("push kick entry key: %02x:%02x:%02x:%02x:%02x:%02x",
			kick.entry.key[0], kick.entry.key[1], kick.entry.key[2],
			kick.entry.key[3], kick.entry.key[4], kick.entry.key[5]);
		ys_info("form pos %d, bucket %d, to pos %d, bucket %d",
			kick.from_pos, kick.from_bucket, kick.to_pos, kick.to_bucket);
		stream->kicks[stream->count] = kick;
		stream->count++;
	}
}

static void ys_cuckoo_kick_pop(struct ys_cuckoo_kick_stream *stream,
			       struct ys_cuckoo_kick *kick)
{
	if (stream->count > 0) {
		*kick = stream->kicks[stream->count];
		stream->count--;
		ys_info("kick pop entry key: %02x:%02x:%02x:%02x:%02x:%02x",
			kick->entry.key[0], kick->entry.key[1], kick->entry.key[2],
			kick->entry.key[3], kick->entry.key[4], kick->entry.key[5]);
		ys_info("kick pop entry form pos %d, bucket %d, to pos %d, bucket %d",
			kick->from_pos, kick->from_bucket, kick->to_pos, kick->to_bucket);
		ys_info("kick pop stream info count %d", stream->count);
	}
}

#if YS_CUCKOO_HASH_CACHED
static void ys_cuckoo_array_to_hex(const u8 *arr, u32 len, char *hex_str)
{
	int i;

	for (i = 0; i < len; i++)
		sprintf(hex_str + i * 2, "%02x", arr[i]);

	hex_str[len * 2] = '\0';
}

static int ys_cuckoo_kick(struct ys_cuckoo_table *table,
			  struct ys_cuckoo_entry entry, u32 to_bucket,
			  struct ys_cuckoo_kick_stream *stream)
{
	char key_str[YS_CUCKOO_MAX_STR_SIZE];
	struct ys_cuckoo_entry kicked_entry;
	struct ys_cuckoo_kick kick;
	u32 from_bucket;
	u32 from_pos;
	u32 to_pos;
	int ret = 0;
	int i;

	if (stream->count >= YS_CUCKOO_MAX_INSERT_RETRIES)
		return -EINVAL;

	to_pos =
	    table->ops->hash(entry.key, table->seed[to_bucket],
			     table->mux_seed[to_bucket]);

	/* Avoid reverse movement issues */
	for (i = 0; i < stream->count; i++) {
		if ((to_bucket == stream->kicks[i].from_bucket &&
		     to_pos == stream->kicks[i].from_pos) ||
		    (to_bucket == stream->kicks[i].to_bucket &&
		     to_pos == stream->kicks[i].to_pos))
			return -EINVAL;
	}

	if (stream->count == 0) {
		from_bucket = YS_CUCKOO_NEW_RULE;
		from_pos = 0;
	} else {
		from_bucket = stream->kicks[stream->count - 1].to_bucket;
		from_pos = stream->kicks[stream->count - 1].to_pos;
	}

	ys_cuckoo_array_to_hex(entry.key, table->key_size, key_str);
	ys_debug("kicked key %s bucket %d pos %d", key_str, to_bucket, to_pos);

	kick.entry = entry;
	kick.from_bucket = from_bucket;
	kick.from_pos = from_pos;
	kick.to_bucket = to_bucket;
	kick.to_pos = to_pos;
	ys_cuckoo_kick_push(stream, kick);

	if (table->buckets[to_bucket][to_pos].is_occupied == 1) {
		/* Need kick */
		kicked_entry = table->buckets[to_bucket][to_pos];
		table->buckets[to_bucket][to_pos] = entry;

		for (i = 0; i < table->bucket_count; i++) {
			if (i == to_bucket)
				continue;

			ret = ys_cuckoo_kick(table, kicked_entry, i, stream);
			if (ret == 0)
				break;
		}

		/* If failed exit operation */
		if (ret) {
			ys_cuckoo_kick_pop(stream, &kick);
			table->buckets[to_bucket][to_pos] = kicked_entry;
		}
	} else {
		/* Insert new rule */
		table->buckets[to_bucket][to_pos] = entry;
		table->buckets[to_bucket][to_pos].is_occupied = 1;
		table->buckets_entry_num[to_bucket]++;
	}

	return ret;
}

static int ys_cuckoo_try_insert(struct ys_cuckoo_table *table,
				const u8 *key, const u8 *value,
				struct ys_cuckoo_kick_stream *stream)
{
	u8 value_tmp[YS_CUCKOO_MAX_VALUE_SIZE];
	char value_str[YS_CUCKOO_MAX_STR_SIZE];
	char key_str[YS_CUCKOO_MAX_STR_SIZE];
	struct ys_cuckoo_entry entry;
	struct ys_cuckoo_kick kick;
	u32 from_bucket = 0;
	u32 from_pos = 0;
	u32 to_pos = 0;
	int ret = -1;
	int i;

	ys_cuckoo_array_to_hex(key, table->key_size, key_str);
	ys_cuckoo_array_to_hex(value, table->value_size, value_str);
	ys_debug("Try insert key %s value %s", key_str, value_str);

	/* Key cannot be inserted repeatedly */
	if (ys_cuckoo_search(table, key, value_tmp,
			     &from_bucket, &from_pos) == 0) {
		ys_err("New key %s has already been inserted", key_str);
		return -EINVAL;
	}

	entry.is_occupied = 1;
	memcpy(entry.key, key, table->key_size);
	memcpy(entry.value, value, table->value_size);
	stream->count = 0;
	/* Find buckets that can be directly inserted */
	for (i = 0; i < table->bucket_count; i++) {
		to_pos =
		    table->ops->hash(key, table->seed[i], table->mux_seed[i]);
		if (table->buckets[i][to_pos].is_occupied == 0) {
			table->buckets[i][to_pos] = entry;
			table->buckets[i][to_pos].is_occupied = 1;
			table->buckets_entry_num[i]++;

			kick.entry = entry;
			kick.from_bucket = YS_CUCKOO_NEW_RULE;
			kick.from_pos = 0;
			kick.to_bucket = i;
			kick.to_pos = to_pos;
			ys_cuckoo_kick_push(stream, kick);
			ys_debug("Insert key %s value %s at buckets %d pos %d",
				 key_str, value_str, kick.to_bucket,
				 kick.to_pos);

			return 0;
		}
	}

	/* If not found, enter the cuckoo kick process */
	for (i = 0; i < table->bucket_count; i++) {
		ret = ys_cuckoo_kick(table, entry, i, stream);
		if (ret == 0) {
			// success
			break;
		}
	}

	if (ret) {
		ys_cuckoo_array_to_hex(entry.key, table->key_size, key_str);
		ys_err("Cannot insert key %s", key_str);

		if (table->ops->backup_entry)
			return table->ops->backup_entry(table, entry, stream,
							kick, key_str,
							value_str);
		else
			return -EINVAL;
	}

	return 0;
}

static int ys_cuckoo_reverse_update_table(struct ys_cuckoo_table *table,
					  struct ys_cuckoo_kick_stream *stream)
{
	struct ys_cuckoo_kick kick;
	int ret = 0;
	int i;

	for (i = stream->count - 1; i >= 0; i--) {
		kick = stream->kicks[i];
		table->buckets[kick.to_bucket][kick.to_pos] = kick.entry;
		table->buckets[kick.to_bucket][kick.to_pos].is_occupied = 1;
		table->buckets_entry_num[kick.to_bucket]++;
		if (kick.from_bucket != YS_CUCKOO_NEW_RULE) {
			table->buckets[kick.from_bucket][kick.from_pos].is_occupied = 0;
			table->buckets_entry_num[kick.from_bucket]--;
		}
		ret = table->ops->store_rule_data(table, kick.to_bucket, kick.to_pos);
		if (ret)
			return ret;
	}

	return ret;
}
#endif //YS_CUCKOO_HASH_CACHED

#if YS_CUCKOO_HASH_CACHED
void ys_cuckoo_print_table_occupancy(struct ys_cuckoo_table *table)
{
	float util[YS_CUCKOO_MAX_BUCKETS];
	u32 total_rules = 0;
	u32 check_num;
	int i;
	int j;

	if (!table)
		return;

	for (i = 0; i < table->bucket_count; i++) {
		util[i] = table->buckets_entry_num[i] / (float)table->depth;
		total_rules += table->buckets_entry_num[i];

		check_num = 0;
		for (j = 0; j < table->depth; j++)
			if (table->buckets[i][j].is_occupied == 1)
				check_num++;

		if (check_num != table->buckets_entry_num[i])
			ys_info
			    ("bucket %d buckets_entry_num %d occupied num %d",
			     i, table->buckets_entry_num[i], check_num);
		ys_info("bucket %d entry: %u", i, table->buckets_entry_num[i]);
	}

	ys_info("Total entry: %u", total_rules);
}

void ys_cuckoo_dump_table_key_value(struct ys_cuckoo_table *table)
{
	char value_str[YS_CUCKOO_MAX_STR_SIZE];
	char key_str[YS_CUCKOO_MAX_STR_SIZE];
	int i;
	int j;

	if (!table)
		return;

	for (i = 0; i < table->bucket_count; i++) {
		for (j = 0; j < table->depth; j++) {
			if (table->buckets[i][j].is_occupied == 1) {
				ys_cuckoo_array_to_hex(table->buckets[i][j].key,
						       table->key_size,
						       key_str);
				ys_cuckoo_array_to_hex(table->buckets[i][j].value,
						       table->value_size,
						       value_str);
				ys_info("key %s value %s in bucket %d pos %d",
					key_str, value_str, i, j);
			}
		}
	}
}
#endif //YS_CUCKOO_HASH_CACHED

static int ys_cuckoo_lock_table(struct ys_cuckoo_table *table)
{
	void __iomem *hw_addr;
	u8 retry_cnt = 3;
	u16 pf_id;
	u32 val;
	int ret;

	if (!YS_CUCKOO_TABLE_TEST_SHARED(table->flag))
		return 0;

	hw_addr = table->hw.bar_addr;
	pf_id = table->hw.pf_id;

retry:
	ret = readl_poll_timeout_atomic(hw_addr + YS_K2ULAN_CUCKOO_LOCK_STATE, val,
					(FIELD_GET(YS_K2ULAN_CUCKOO_LOCK_REG_FLAG, val) ==
					 YS_K2ULAN_CUCKOO_TABLE_UNLOCK),
					100, 100000);
	if (ret) {
		ys_err("LAN Get opcode lock failed (0x%08x)\n", val);
		return -ETIMEDOUT;
	}

	/* write to lock */
	val = FIELD_PREP(YS_K2ULAN_CUCKOO_LOCK_REG_PF_ID, pf_id) |
	      FIELD_PREP(YS_K2ULAN_CUCKOO_LOCK_REG_FLAG, YS_K2ULAN_CUCKOO_TABLE_LOCK);
	ys_wr32(hw_addr, YS_K2ULAN_CUCKOO_LOCK_FLAG, val);

	/* verify lock succeed */
	val = ys_rd32(hw_addr, YS_K2ULAN_CUCKOO_LOCK_STATE);
	if (FIELD_GET(YS_K2ULAN_CUCKOO_LOCK_REG_PF_ID, val) != pf_id ||
	    FIELD_GET(YS_K2ULAN_CUCKOO_LOCK_REG_FLAG, val) != YS_K2ULAN_CUCKOO_TABLE_LOCK) {
		if (!retry_cnt) {
			ys_err("K2U lan lock fail!\n");
			return -ETIMEDOUT;
		}
		retry_cnt--;
		goto retry;
	}

	return 0;
}

static void ys_cuckoo_unlock_table(struct ys_cuckoo_table *table)
{
	void __iomem *hw_addr;
	u16 pf_id;
	u32 val;

	if (!YS_CUCKOO_TABLE_TEST_SHARED(table->flag))
		return;

	hw_addr = table->hw.bar_addr;
	pf_id = table->hw.pf_id;

	/* write to unlock */
	val = FIELD_PREP(YS_K2ULAN_CUCKOO_LOCK_REG_PF_ID, pf_id) |
	      FIELD_PREP(YS_K2ULAN_CUCKOO_LOCK_REG_FLAG, YS_K2ULAN_CUCKOO_TABLE_UNLOCK);
	ys_wr32(hw_addr, YS_K2ULAN_CUCKOO_LOCK_FLAG, val);
}

static int ys_cuckoo_check_rule_empty_uncached(struct ys_cuckoo_table_uncached *table,
					       u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = {0};
	u8 key_empty[YS_CUCKOO_MAX_KEY_SIZE] = {0};
	uintptr_t entry_addr;
	struct ys_cuckoo_table *base_info = &table->table_base;
	u32 index;
	int i;

	index = table->ops->get_ram_addr(bucket, pos);
	entry_addr = (uintptr_t)(base_info->hw.bar_addr + base_info->hw.raddr +
				 (index * base_info->value_size));
	for (i = 0; i < base_info->hw.data_round; i++)
		data[i] = ys_cuckooo_ioread32_direct(entry_addr + (i * 4));

	table->ops->parse_rule_data(data, table->entry_swap.key, table->entry_swap.value);

	if (!memcmp(key_empty, table->entry_swap.key, base_info->key_size)) {
		memset(table->entry_swap.value, 0, YS_CUCKOO_MAX_VALUE_SIZE);
		return 0;
	}

	return -EBUSY;
}

static int ys_cuckoo_load_hw_entry_uncached(struct ys_cuckoo_table_uncached *table,
					    u8 bucket, u32 pos, u8 *key, u8 *value)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = {0};
	u32 index;
	uintptr_t entry_addr;
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	if (!table || !key || !value) {
		ys_err("Input parameter error table: %p, key: %p, value: %p, pf %d",
		       table, key, value, table ? table->table_base.hw.pf_id : -1);
		return -EINVAL;
	}

	index = table->ops->get_ram_addr(bucket, pos);
	entry_addr = (uintptr_t)(base_info->hw.bar_addr +
				 base_info->hw.raddr + (index * base_info->value_size));
	for (i = 0; i < base_info->hw.data_round; i++) {
		data[i] = ys_cuckooo_ioread32_direct(entry_addr + (i * sizeof(u32)));
		ys_debug("read rule into var: addr %08lx, data round %d, data 0x%08x",
			entry_addr, i, data[i]);
	}

	table->ops->parse_rule_data(data, key, value);

	return 0;
}

static int ys_cuckoo_load_hw_raw_entry_uncached(struct ys_cuckoo_table_uncached *table,
						u8 bucket, u32 pos, u8 *key, u32 *data)
{
	u8 value[YS_CUCKOO_MAX_VALUE_SIZE] = {0};
	u32 index;
	uintptr_t entry_addr;
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	if (!table || !key) {
		ys_err("Input parameter table: %p, key %p, pf %d", table, key,
		       table ? table->table_base.hw.pf_id : -1);
		return -EINVAL;
	}

	index = table->ops->get_ram_addr(bucket, pos);
	entry_addr = (uintptr_t)(base_info->hw.bar_addr +
			base_info->hw.raddr + (index * base_info->value_size));
	for (i = 0; i < base_info->hw.data_round; i++) {
		data[i] = ys_cuckooo_ioread32_direct(entry_addr + (i * sizeof(u32)));
		ys_debug("read rule into var: addr %08lx, data round %d, data 0x%08x",
			entry_addr, i, data[i]);
	}
	table->ops->parse_rule_data(data, key, value);

	return 0;
}

static int ys_cuckoo_load_hw_entry_into_table_uncached(struct ys_cuckoo_table_uncached *table,
						       u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = {0};
	u32 index;
	uintptr_t entry_addr;
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	index = table->ops->get_ram_addr(bucket, pos);
	entry_addr = (uintptr_t)(base_info->hw.bar_addr +
				 base_info->hw.raddr + (index * base_info->value_size));
	for (i = 0; i < base_info->hw.data_round; i++) {
		data[i] = ys_cuckooo_ioread32_direct(entry_addr + (i * sizeof(u32)));
		ys_debug("read rule shared: addr %08lx, data round %d, data 0x%08x",
			entry_addr, i, data[i]);
	}

	table->ops->parse_rule_data(data, table->entry_swap.key, table->entry_swap.value);

	return 0;
}

#if YS_CUCKOO_HASH_SHARED
static int ys_cuckoo_load_hw_entry_into_table_shared(struct ys_cuckoo_table *table,
						     u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = {0};
	u32 index;
	u32 entry_addr;
	int i;

	index = table->ops->get_ram_addr(bucket, pos);
	entry_addr = table->hw.raddr + (index * table->value_size);
	for (i = 0; i < table->hw.data_round; i++) {
		data[i] = ys_cuckooo_ioread32(table,
					      entry_addr + (i * sizeof(u32)));
		ys_debug("read rule shared: addr %08x, data round %d, data 0x%08x",
			entry_addr, i, data[i]);
	}

	table->ops->parse_rule_data(data, table->buckets[bucket][pos].key,
				    table->buckets[bucket][pos].value);

	return 0;
}

static int ys_cuckoo_load_seed(struct ys_cuckoo_table *table)
{
	u32 mux_seed[YS_CUCKOO_MAX_BUCKETS];
	u32 seed[YS_CUCKOO_MAX_BUCKETS];
	u32 mux_seed_mask;
	u32 seed_mask;
	int i;

	mux_seed_mask = (1ULL << table->mux_seed_bits) - 1;
	seed_mask = (1ULL << table->seed_bits) - 1;
	for (i = 0; i < table->bucket_count; i++) {
		seed[i] = ys_cuckooo_ioread32(table, table->hw.seed_addr[i]);
		mux_seed[i] = ys_cuckooo_ioread32(table, table->hw.mux_seed_addr[i]);
		ys_debug("load bucket %d: seed 0x%08x, mux_seed 0x%08x", i, seed[i], mux_seed[i]);
	}

	/* sanity check seed value in hardware */
	if (ys_cuckoo_check_duplicates(seed, table->bucket_count) ||
	    ys_cuckoo_check_duplicates(mux_seed, table->bucket_count)) {
		ys_err("Seed value has duplicate form register!");
		return -1;
	}

	/* store seed value into table */
	memcpy(table->seed, seed, sizeof(u32) * table->bucket_count);
	memcpy(table->mux_seed, mux_seed, sizeof(u32) * table->bucket_count);

	return 0;
}

void *ys_cuckoo_create_shared(u32 type, void *bar_addr, u16 pf_id, bool create)
{
	struct ys_cuckoo_table *table;

	if (type < YS_CUCKOO_TYPE_K2U_LAN_UC || type > YS_CUCKOO_TYPE_K2U_LAN_MC) {
		ys_info("Input invalid table type %d for create cuckoo shared table!", type);
		return NULL;
	}

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;

	table->type = type;
	if (ys_cuckoo_set_table_default_params(table) != 0) {
		kfree(table);
		return NULL;
	}
	table->hw.bar_addr = bar_addr;
	table->hw.pf_id = pf_id;

	if (create) {
		if (table->init_done == 0) {
			ys_info("Create a new cuckoo shared table");
			ys_cuckoo_clear_table(table);
			if (ys_cuckoo_generate_seed(table) != 0) {
				ys_err("Failed to generate cuckoo hash seeds");
				kfree(table);
				return NULL;
			}
			if (table->hw.init_done_addr)
				ys_cuckoo_iowrite32(table, table->hw.init_done_addr, 1);
			table->init_done = 1;
		} else {
			ys_err("Cuckoo shared table owner create more than once");
			kfree(table);
			return NULL;
		}
	} else {
		if (ys_cuckoo_load_seed(table) != 0) {
			ys_err("Failed get seed form register!");
			kfree(table);
			return NULL;
		}
	}

	return table;
}
#endif //YS_CUCKOO_HASH_SHARED

static int ys_cuckoo_update_kicks(struct ys_cuckoo_table_uncached *table,
				  struct ys_cuckoo_kick_stream *stream)
{
	struct ys_cuckoo_kick kick;
	struct ys_cuckoo_table *base_info;
	u32 index;
	u32 entry_addr;
	int i, j;

	ys_info("%s start kick entry %d", __func__, stream->count);

	base_info = &table->table_base;
	for (i = stream->count - 1; i >= 0; i--) {
		kick = stream->kicks[i];
		index = table->ops->get_ram_addr(kick.to_bucket, kick.to_pos);
		entry_addr = base_info->hw.waddr + base_info->value_size * index;
		for (j = 0; j < base_info->hw.data_round; j++)
			ys_cuckoo_iowrite32(base_info, entry_addr + 4 * j,
					    *(((u32 *)kick.entry.value) + j));
	}

	return 0;
}

static int ys_cuckoo_kick_uncached(struct ys_cuckoo_table_uncached *table,
				   struct ys_cuckoo_entry *entry, u32 to_bucket,
				   struct ys_cuckoo_kick_stream *stream)
{
	struct ys_cuckoo_table *base_info;
	struct ys_cuckoo_entry kicked_entry;
	u8 key_empty[YS_CUCKOO_MAX_KEY_SIZE] = {0};
	struct ys_cuckoo_kick kick;
	u32 from_bucket;
	u32 from_pos;
	u32 to_pos;
	int pos_occupied = 0;
	int ret = 0;
	int i;

	if (stream->count >= YS_CUCKOO_MAX_INSERT_RETRIES) {
		ys_info("stream %p over max retries!!!", stream);
		return -EINVAL;
	}
	ys_info("stream %p count %d", stream, stream->count);

	base_info = &table->table_base;
	to_pos = table->ops->hash(entry->key, base_info->seed[to_bucket],
				  base_info->mux_seed[to_bucket]);
	/* Avoid reverse movement issues */
	for (i = 0; i < stream->count; i++) {
		if ((to_bucket == stream->kicks[i].from_bucket &&
		     to_pos == stream->kicks[i].from_pos) ||
		    (to_bucket == stream->kicks[i].to_bucket &&
		     to_pos == stream->kicks[i].to_pos))
			return -EINVAL;
	}

	if (stream->count == 0) {
		from_bucket = YS_CUCKOO_NEW_RULE;
		from_pos = 0;
	} else {
		from_bucket = stream->kicks[stream->count - 1].to_bucket;
		from_pos = stream->kicks[stream->count - 1].to_pos;
	}

	kick.entry = *entry;
	kick.from_bucket = from_bucket;
	kick.from_pos = from_pos;
	kick.to_bucket = to_bucket;
	kick.to_pos = to_pos;
	ys_cuckoo_kick_push(stream, kick);

	ys_cuckoo_load_hw_raw_entry_uncached(table, to_bucket, to_pos,
					     kicked_entry.key, (u32 *)kicked_entry.value);
	pos_occupied = memcmp(key_empty, kicked_entry.key, base_info->key_size);
	if (pos_occupied != 0) {
		/* Need more kick */
		for (i = 0; i < base_info->bucket_count; i++) {
			if (i == to_bucket)
				continue;

			ret = ys_cuckoo_kick_uncached(table, &kicked_entry, i, stream);
			if (ret == 0)
				break;
		}
		/* If failed exit operation */
		if (ret)
			ys_cuckoo_kick_pop(stream, &kick);
	}

	return 0;
}

static int ys_cuckoo_insert_uncached(struct ys_cuckoo_table_uncached *table,
				     const u8 *key, const u32 *value)
{
	u32 to_pos = 0;
	u32 index;
	u32 entry_addr;
	struct ys_cuckoo_entry *entry;
	struct ys_cuckoo_table *base_info;
	struct ys_cuckoo_kick_stream *stream;
	int ret;
	int i;

	if (!table || !key || !value) {
		ys_err("Input parameter error table: %p, key: %p, value: %p, pf %d",
		       table, key, value, table ? table->table_base.hw.pf_id : -1);
		return -EINVAL;
	}
	base_info = &table->table_base;

	ret = ys_cuckoo_lock_table(base_info);
	if (ret) {
		ys_err("ys cuckoo uncached table lock fail for insert!");
		return -EBUSY;
	}

	for (i = 0; i < base_info->bucket_count; i++) {
		to_pos = table->ops->hash(key, base_info->seed[i], base_info->mux_seed[i]);
		ret = ys_cuckoo_check_rule_empty_uncached(table, i, to_pos);
		if (ret == 0)
			break;
	}

	if (i == base_info->bucket_count) {
		stream = kzalloc(sizeof(*stream), GFP_KERNEL);
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (stream && entry) {
			memcpy(entry->key, key, base_info->key_size);
			memcpy(entry->value, (u8 *)value, base_info->value_size);
			for (i = 0; base_info->bucket_count; i++) {
				ret = ys_cuckoo_kick_uncached(table, entry, i, stream);
				if (ret == 0) {
					ret = ys_cuckoo_update_kicks(table, stream);
					break;
				}
				memset(stream, 0, sizeof(*stream));
			}
			kfree(entry);
			kfree(stream);
			if (ret == 0) {
				ys_info("ys cuckoo uncached table kick insert ok!");
				ys_cuckoo_unlock_table(base_info);
				return ret;
			}
		} else {
			kfree(stream);
			kfree(entry);
			ys_err("ys cuckoo uncached table insert alloc memory failed!");
		}
		ys_err("ys cuckoo uncached table insert entry failed!");
		ys_cuckoo_unlock_table(base_info);
		return -EAGAIN;
	}

	index = table->ops->get_ram_addr(i, to_pos);
	entry_addr = base_info->hw.waddr + base_info->value_size * index;
	for (i = 0; i < base_info->hw.data_round; i++)
		ys_cuckoo_iowrite32(base_info, entry_addr + 4 * i, value[i]);
	ys_cuckoo_unlock_table(base_info);

	return 0;
}

static int ys_cuckoo_update_uncached(struct ys_cuckoo_table_uncached *table,
				     const u8 *key, const u32 *value)
{
	u32 to_pos = 0;
	u32 index;
	u32 entry_addr;
	u8 hw_key[YS_CUCKOO_MAX_KEY_SIZE] = {0};
	u8 hw_value[YS_CUCKOO_MAX_VALUE_SIZE] = {0};
	struct ys_cuckoo_table *base_info;
	int ret;
	int i;

	if (!table || !key || !value) {
		ys_err("Input parameter error table: %p, key: %p, value: %p, pf %d",
		       table, key, value, table ? table->table_base.hw.pf_id : -1);
		return -EINVAL;
	}
	base_info = &table->table_base;

	ret = ys_cuckoo_lock_table(base_info);
	if (ret) {
		ys_err("ys cuckoo shared table lock fail for insert!");
		return -EBUSY;
	}

	for (i = 0; i < base_info->bucket_count; i++) {
		to_pos = table->ops->hash(key, base_info->seed[i], base_info->mux_seed[i]);
		ret = ys_cuckoo_load_hw_entry_uncached(table, i, to_pos, hw_key, hw_value);
		if (ret != 0) {
			ys_err("%s get bucket %d pos %d entry failed for update!",
			       __func__, i, to_pos);
			ys_cuckoo_unlock_table(base_info);
			return -EFAULT;
		}
		if (memcmp(key, hw_key, base_info->key_size) == 0) {
			ys_info("%s match bucket %d pos %d entry !", __func__, i, to_pos);
			break;
		}
	}

	if (i == base_info->bucket_count) {
		ys_err("ys cuckoo shared table update entry failed!");
		ys_cuckoo_unlock_table(base_info);
		return -EAGAIN;
	}

	index = table->ops->get_ram_addr(i, to_pos);
	entry_addr = base_info->hw.waddr + base_info->value_size * index;
	for (i = 0; i < base_info->hw.data_round; i++)
		ys_cuckoo_iowrite32(base_info, entry_addr + 4 * i, value[i]);
	ys_cuckoo_unlock_table(base_info);

	return 0;
}

static int ys_cuckoo_search_uncached(struct ys_cuckoo_table_uncached *table,
				     const u8 *key, u32 *value)
{
	u32 to_pos = 0;
	u8 hw_key[YS_CUCKOO_MAX_KEY_SIZE] = {0};
	u8 hw_value[YS_CUCKOO_MAX_VALUE_SIZE] = {0};
	struct ys_cuckoo_table *base_info;
	int ret;
	int i;

	if (!table || !key || !value) {
		ys_err("Input parameter error table: %p, key: %p, value: %p, pf %d",
		       table, key, value, table ? table->table_base.hw.pf_id : -1);
		return -EINVAL;
	}
	base_info = &table->table_base;

	ret = ys_cuckoo_lock_table(base_info);
	if (ret) {
		ys_err("ys cuckoo shared table lock fail for insert!");
		return -EBUSY;
	}

	for (i = 0; i < base_info->bucket_count; i++) {
		to_pos = table->ops->hash(key, base_info->seed[i], base_info->mux_seed[i]);
		ret = ys_cuckoo_load_hw_entry_uncached(table, i, to_pos, hw_key, hw_value);
		if (ret != 0) {
			ys_err("%s get bucket %d pos %d entry failed for update!",
			       __func__, i, to_pos);
			ys_cuckoo_unlock_table(base_info);
			return -EFAULT;
		}
		if (memcmp(key, hw_key, base_info->key_size) == 0) {
			ys_info("%s match bucket %d pos %d entry !", __func__, i, to_pos);
			break;
		}
	}
	ys_cuckoo_unlock_table(base_info);

	if (i == base_info->bucket_count) {
		ys_err("ys cuckoo shared table update entry failed!");
		return -EAGAIN;
	}
	memcpy(value, hw_value, base_info->value_size);

	return 0;
}

static int ys_cuckoo_delete_uncached(struct ys_cuckoo_table_uncached *table,
				     const u8 *key)
{
	char value_empty[YS_CUCKOO_MAX_VALUE_SIZE] = {0};
	u32 to_pos;
	u32 index;
	u32 entry_addr;
	struct ys_cuckoo_table *base_info;
	int i;
	int ret;

	if (!table || !key) {
		ys_err("Input parameter error");
		return -EINVAL;
	}
	base_info = &table->table_base;

	ret = ys_cuckoo_lock_table(base_info);
	if (ret) {
		ys_err("ys cuckoo shared table lock fail for delete!");
		return -EBUSY;
	}

	for (i = 0; i < base_info->bucket_count; i++) {
		to_pos = table->ops->hash(key, base_info->seed[i], base_info->mux_seed[i]);
		ret = ys_cuckoo_load_hw_entry_into_table_uncached(table, i, to_pos);
		if (ret) {
			ys_err("ys cuckoo read shared table lock failed!");
			ys_cuckoo_unlock_table(base_info);
			return ret;
		}
		ys_debug("bucket %d, pos %d, hw mac: %02x:%02x:%02x:%02x:%02x:%02x", i, to_pos,
			table->entry_swap.key[0], table->entry_swap.key[1],
			table->entry_swap.key[2], table->entry_swap.key[3],
			table->entry_swap.key[4], table->entry_swap.key[5]);
		if (!memcmp(table->entry_swap.key, key, base_info->key_size)) {
			index = table->ops->get_ram_addr(i, to_pos);
			entry_addr = base_info->hw.waddr + base_info->value_size * index;
			for (i = 0; i < base_info->hw.data_round; i++)
				ys_cuckoo_iowrite32(base_info, entry_addr + 4 * i, value_empty[i]);
			break;
		}
	}
	if (i == base_info->bucket_count)
		ys_err("ys cuckoo shared table delete entry no exist!");

	ys_cuckoo_unlock_table(base_info);

	return 0;
}

int ys_cuckoo_insert(struct ys_cuckoo_table *table, const u8 *key, const u8 *value)
{
	struct ys_cuckoo_table_cached *table_tmp = NULL;
	//struct ys_cuckoo_kick_stream stream;
	int ret = -1;

	if (!table || !key || !value) {
		ys_err("Input parameter error");
		return -EINVAL;
	}
	if (YS_CUCKOO_TABLE_TEST_CACHED(table->flag)) {
#if YS_CUCKOO_HASH_CACHED
		table_tmp = kzalloc(sizeof(*table_tmp), GFP_KERNEL);
		if (!table_tmp) {
			ret = -ENOMEM;
			goto inset_out;
		}

		*table_tmp = *table;
		ret = ys_cuckoo_try_insert(table_tmp, key, value, &stream);
		if (ret) {
			ys_err("Failed to insert rule");
			goto inset_out;
		}

		ret = ys_cuckoo_reverse_update_table(table, &stream);
		if (ret) {
			ys_err("Failed to reverse update table");
			goto inset_out;
		}
#endif
	} else {
		ret = ys_cuckoo_insert_uncached((struct ys_cuckoo_table_uncached *)table,
						key, (u32 *)value);
		if (ret) {
			ys_err("Failed to insert uncached table");
			return ret;
		}
	}
//inset_out:
	kfree(table_tmp);

	return ret;
}

int ys_cuckoo_delete(struct ys_cuckoo_table *table, const u8 *key)
{
	//u8 value_tmp[YS_CUCKOO_MAX_VALUE_SIZE];
	//char key_str[YS_CUCKOO_MAX_STR_SIZE];
	//u32 bucket;
	//u32 pos;

	if (!table || !key) {
		ys_err("Input parameter error");
		return -EINVAL;
	}

	if (YS_CUCKOO_TABLE_TEST_CACHED(table->flag)) {
#if YS_CUCKOO_HASH_CACHED
		if (ys_cuckoo_search(handle, key, value_tmp, &bucket, &pos)) {
			ys_cuckoo_array_to_hex(key, table->key_size, key_str);
			ys_err("Failed to find key %s", key_str);
			return -EINVAL;
		}

		table->buckets[bucket][pos].is_occupied = 0;
		table->buckets_entry_num[bucket]--;
		memset(table->buckets[bucket][pos].key, 0, YS_CUCKOO_MAX_KEY_SIZE);
		memset(table->buckets[bucket][pos].value, 0, YS_CUCKOO_MAX_VALUE_SIZE);
#endif
	} else {
		return ys_cuckoo_delete_uncached((struct ys_cuckoo_table_uncached *)table, key);
	}

	return 0;
}

int ys_cuckoo_change(struct ys_cuckoo_table *table, const u8 *key, const u8 *value)
{
	//u8 value_tmp[YS_CUCKOO_MAX_VALUE_SIZE];
	//char old_value_str[YS_CUCKOO_MAX_STR_SIZE];
	//char value_str[YS_CUCKOO_MAX_STR_SIZE];
	//char key_str[YS_CUCKOO_MAX_STR_SIZE];
	//u32 bucket;
	//u32 pos;

	if (!table || !key || !value) {
		ys_err("Input parameter error");
		return -EINVAL;
	}

	if (YS_CUCKOO_TABLE_TEST_CACHED(table->flag)) {
#if YS_CUCKOO_HASH_CACHED
		if (ys_cuckoo_search(handle, key, value_tmp, &bucket, &pos)) {
			ys_cuckoo_array_to_hex(key, table->key_size, key_str);
			ys_err("Failed to find key %s", key_str);
			return -EINVAL;
		}

		ys_cuckoo_array_to_hex(key, table->key_size, key_str);
		ys_cuckoo_array_to_hex(value, table->value_size, value_str);
		ys_cuckoo_array_to_hex(table->buckets[bucket][pos].value,
				       table->value_size, old_value_str);
		ys_debug("Change key %s in bucket %d pos %d value from %s to %s",
			 key_str, bucket, pos, old_value_str, value_str);
		memcpy(table->buckets[bucket][pos].key, key, table->key_size);
		memcpy(table->buckets[bucket][pos].value, value, table->value_size);
#endif
	} else {
		return ys_cuckoo_update_uncached((struct ys_cuckoo_table_uncached *)table,
						 key, (u32 *)value);
	}

	return 0;
}

int ys_cuckoo_search(struct ys_cuckoo_table *table, const u8 *key, u8 *value,
		     u32 *bucket, u32 *pos)
{
	//char key_str[YS_CUCKOO_MAX_STR_SIZE];
	int ret = -1;
	//int i;
	//int j;

	if (!table || !key || !value || !bucket || !pos) {
		ys_err
		    ("Input parameter error, table:%p, key:%p, value:%p, bucket:%p, pos:%p",
		     table, key, value, bucket, pos);
		return -EINVAL;
	}

	if (YS_CUCKOO_TABLE_TEST_CACHED(table->flag)) {
#if YS_CUCKOO_HASH_CACHED
		ys_cuckoo_array_to_hex(key, table->key_size, key_str);
		ys_debug("Try to find key %s in buckets", key_str);

		for (i = 0; i < table->bucket_count; i++) {
			j = table->ops->hash(key, table->seed[i], table->mux_seed[i]);
			ys_debug("Position in bucket %d is %d", i, j);
			if (table->buckets[i][j].is_occupied == 1 &&
			    !memcmp(key, table->buckets[i][j].key, table->key_size)) {
				if (ret == 0) {
					ys_err("Found duplicate key %s in buckets",
					       key_str);
					ys_err("Last %s in bucket %d pos %d", key_str,
					       *bucket, *pos);
					ys_err("Duplicate %s in bucket %d pos %d",
					       key_str, i, j);
				}
				memcpy(value, table->buckets[i][j].value,
				       table->value_size);
				*bucket = i;
				*pos = j;
				ret = 0;
			}
		}
#endif
	} else {
		return ys_cuckoo_search_uncached((struct ys_cuckoo_table_uncached *)table,
						 key, (u32 *)value);
	}

	return ret;
}
