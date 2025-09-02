// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_tc_priv.h"
#include "../np/ys_k2u_np.h"

static void ys_tc_table_dump(struct ys_tc_priv *tc_priv, const char *note,
			     struct ys_tc_table *table)
{
	if (table->type & YS_TC_TABLE_ARRAY) {
		ys_tc_debug("%s: array table %s, id %d, size %d, value_len %d.\n",
			    note, table->name, table->id, table->size, table->value_len);
	} else {
		ys_tc_debug("%s: hash table %s, id %d, size %d, key_len %d, value_len %d.\n",
			    note, table->name, table->id, table->size,
			    table->key_len, table->value_len);
	}
}

static void ys_tc_table_error_stats(struct ys_tc_switchdev *switchdev, int err_code)
{
	if (!err_code)
		return;

	if (err_code > 0 && err_code < ARRAY_SIZE(switchdev->doe_errors))
		atomic64_inc(&switchdev->doe_errors[err_code]);
	else
		atomic64_inc(&switchdev->doe_errors[0]);
}

static int ys_tc_arraytable_create_cb(struct ys_tc_priv *tc_priv,
				      struct ys_tc_table *table)
{
	struct ys_tc_switchdev *switchdev = table->switchdev;

	ys_tc_table_dump(tc_priv, "create : ", table);

	if (switchdev->doe_ops->tbl_valid(switchdev->id, table->id))
		switchdev->doe_ops->delete_arraytbl(switchdev->id, table->id, 0);

	return switchdev->doe_ops->create_arraytbl(switchdev->id, table->id,
						   table->size, table->value_len,
						   table->extra, 0);
}

static void ys_tc_arraytable_destroy_cb(struct ys_tc_priv *tc_priv,
					struct ys_tc_table *table)
{
	int ret = 0;
	struct ys_tc_switchdev *switchdev = table->switchdev;

	ys_tc_table_dump(tc_priv, "destroy : ", table);

	ret = switchdev->doe_ops->delete_arraytbl(switchdev->id, table->id, 0);
	if (ret)
		ys_tc_err("Failed to delete array table %d, ret %d.\n", table->id, ret);
}

static struct ys_tc_table_entry *ys_tc_table_entry_alloc(struct ys_tc_priv *tc_priv,
							 struct ys_tc_table *table,
							 size_t data_size, const int *idx)
{
	int ret = 0;
	int start = 0;
	int end = 0;
	struct ys_tc_table_entry *entry = NULL;

	entry = kzalloc(struct_size(entry, data, data_size), GFP_KERNEL);
	if (!entry)
		return NULL;

	if (idx) {
		start = *idx;
		end = start + 1;
	} else {
		start = table->start_idx;
		end = table->size;
	}

	spin_lock(&table->idr_slock);
	ret = idr_alloc_cyclic(&table->idr, entry, start, end, GFP_ATOMIC);
	spin_unlock(&table->idr_slock);
	if (ret < 0 || ret >= table->size) {
		kfree(entry);
		ys_tc_debug("Table %s idr alloc failed, ret = %d\n", table->name, ret);
		return NULL;
	}

	entry->idx = ret;
	return entry;
}

static  struct ys_tc_table_entry *ys_tc_arraytable_alloc_cb(struct ys_tc_priv *tc_priv,
							    struct ys_tc_table *table,
							    const int *idx, const void *data)
{
	struct ys_tc_table_entry *entry = NULL;
	size_t entry_data_size = 0;

	entry_data_size = table->value_len;
	entry_data_size = ALIGN(entry_data_size, 8);

	entry = ys_tc_table_entry_alloc(tc_priv, table, entry_data_size, idx);
	if (entry)
		refcount_set(&entry->refcnt, 1);
	return entry;
}

static int ys_tc_arraytable_add_cb(struct ys_tc_priv *tc_priv,
				   struct ys_tc_table_entry *entry)
{
	int ret = 0;
	int idx = entry->idx;

	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	int len = table->value_len;
	u8 pri = test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags) ? 1 : 0;

	ys_tc_hexdump(entry->data, len, "add array table %d, idx %d, data : ", table->id, idx);
	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_ARRAY_STORE_TOTAL]);

	ret = switchdev->doe_ops->array_store(switchdev->id, table->id,
						  idx, entry->data, len, pri, 0);
	if (ret) {
		atomic64_inc(&switchdev->stats[YS_TC_STATES_ARRAY_STORE_FAIL]);
		ys_tc_err("Failed to add array table %d, idx %d, ret %d.\n", table->id, idx, ret);
	}

	return ret;
}

static void ys_tc_arraytable_del_cb(struct ys_tc_priv *tc_priv,
				    struct ys_tc_table_entry *entry)
{
	ys_tc_debug("del array table %d, idx %d\n", entry->table->id, entry->idx);
}

static inline void ys_tc_table_entry_cache_update(struct ys_tc_table_entry *entry,
						  const __be64 *be_pkts, const __be64 *be_bytes)
{
	struct ys_tc_table_commcnt_data *data = NULL;
	u64 new_cpu_pkts = be64_to_cpu(*be_pkts);
	u64 new_cpu_bytes = be64_to_cpu(*be_bytes);
	u64 cur_cpu_pkts = 0;
	u64 cur_cpu_bytes = 0;

	data = (struct ys_tc_table_commcnt_data *)entry->data;

	spin_lock(&data->cache_slock);
	cur_cpu_pkts = be64_to_cpu(data->be_pkts);
	cur_cpu_bytes = be64_to_cpu(data->be_bytes);

	if (new_cpu_pkts > cur_cpu_pkts) {
		data->be_pkts = *be_pkts;
		data->used = jiffies;
	}
	if (new_cpu_bytes > cur_cpu_bytes)
		data->be_bytes = *be_bytes;
	spin_unlock(&data->cache_slock);
}

static int ys_tc_cnt_table_create_cb(struct ys_tc_priv *tc_priv,
				     struct ys_tc_table *table)
{
	int ret = 0;

	if (table->value_len != YS_TC_CNT_TBL_VAL_LEN)
		return -EOPNOTSUPP;

	table->buf = kzalloc((sizeof(u32) + sizeof(u64) * 2) * YS_TC_CNT_LOAD_BATCH, GFP_KERNEL);
	if (!table->buf)
		return -ENOMEM;

	table->bitmask = kvcalloc(BITS_TO_LONGS(table->size), sizeof(unsigned long), GFP_KERNEL);
	if (!table->bitmask) {
		ret = -ENOMEM;
		goto failed;
	}

	ret = ys_tc_arraytable_create_cb(tc_priv, table);
	if (ret)
		goto failed;

	return 0;

failed:
	kvfree(table->bitmask);
	table->bitmask = NULL;
	kfree(table->buf);
	table->buf = NULL;
	return ret;
}

static void ys_tc_cnt_table_destroy_cb(struct ys_tc_priv *tc_priv,
				       struct ys_tc_table *table)
{
	ys_tc_arraytable_destroy_cb(tc_priv, table);
	kvfree(table->bitmask);
	table->bitmask = NULL;
	kfree(table->buf);
	table->buf = NULL;
}

static struct ys_tc_table_entry *ys_tc_cnt_table_alloc_cb(struct ys_tc_priv *tc_priv,
							  struct ys_tc_table *table,
							  const int *idx, const void *data)
{
	struct ys_tc_table_entry *entry = NULL;
	size_t entry_data_size = 0;
	struct ys_tc_table_commcnt_data *cnt_data = NULL;

	entry_data_size = sizeof(struct ys_tc_table_commcnt_data);
	entry_data_size = ALIGN(entry_data_size, 8);

	entry = ys_tc_table_entry_alloc(tc_priv, table, entry_data_size, idx);
	if (entry) {
		cnt_data = (struct ys_tc_table_commcnt_data *)entry->data;
		spin_lock_init(&cnt_data->cache_slock);
		refcount_set(&entry->refcnt, 1);
	}

	return entry;
}

static int ys_tc_cnt_table_add_cb(struct ys_tc_priv *tc_priv,
				  struct ys_tc_table_entry *entry)
{
	int ret = 0;
	int idx = entry->idx;
	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	const u8 pri = test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags) ? 1 : 0;
	const u8 op_enable = 1;
	const u8 clear_data = 1;

	ys_tc_hexdump(entry->data, YS_TC_CNT_TBL_VAL_LEN,
		      "add counter table %d, idx %d, pri %d, data : ", table->id, idx, pri);

	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_COUNTER_ENABLE_TOTAL]);
	ret = switchdev->doe_ops->counter_enable(switchdev->id, table->id, idx, op_enable, pri,
						 clear_data, 0);
	if (ret) {
		ys_tc_err("Failed to enable counter: table %d, idx %d, ret %d.\n",
			  table->id, idx, ret);
		atomic64_inc(&switchdev->stats[YS_TC_STATES_COUNTER_ENABLE_FAIL]);
		ys_tc_table_error_stats(entry->table->switchdev, ret);
	}

	return ret;
}

static void ys_tc_cnt_table_del_cb(struct ys_tc_priv *tc_priv,
				   struct ys_tc_table_entry *entry)
{
	int ret = 0;
	int idx = entry->idx;
	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	const u8 op_enable = 1;
	const u8 op_disable = 0;
	const u8 op_clear_data = 1;
	const u8 op_keep_data = 0;
	const u8 no_pri = 0;

	/* Agreement with doe for (priority) counter usage.
	 * 1. To enable counter:
	 *    1.1 enable = 1, pri = 1, clear_data = 1 -> Enable high priority counter.
	 *    1.2 enable = 1, pri = 0, clear_data = 1 -> Enable normal counter.
	 * 2. To undergrade counter (with high priority):
	 *    2.1 enable = 1, pri = 0, clear_data = 0 -> Keep data, set no prority.
	 * 3. To disable counter(with no priority):
	 *    3.1 enable = 0, pri = 0, clear_data = 1 -> clear data.
	 */

	ys_tc_debug("Disable counter: table %d, idx %d\n", table->id, idx);
	if (test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags)) {
		/* If the entry is high priority, lower its priority first. */
		atomic64_inc(&switchdev->metrics[YS_TC_METRICS_COUNTER_DOWNGRADE_TOTAL]);
		ret = switchdev->doe_ops->counter_enable(switchdev->id, table->id, idx, op_enable,
							 no_pri, op_keep_data, 0);
		if (ret) {
			ys_tc_err("Failed to unset counter priority: table %d, idx %d, ret %d.\n",
				  table->id, idx, ret);
			atomic64_inc(&switchdev->stats[YS_TC_STATES_COUNTER_DOWNGRADE_FAIL]);
			ys_tc_table_error_stats(entry->table->switchdev, ret);
		}
	}

	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_COUNTER_DISABLE_TOTAL]);
	ret = switchdev->doe_ops->counter_enable(switchdev->id, table->id, idx, op_disable,
						 no_pri, op_clear_data, 0);
	if (ret) {
		ys_tc_err("Failed to disable counter: table %d, idx %d, ret %d.\n",
			  table->id, idx, ret);
		atomic64_inc(&switchdev->stats[YS_TC_STATES_COUNTER_DISABLE_FAIL]);
		ys_tc_table_error_stats(entry->table->switchdev, ret);
	}
}

static int ys_tc_hashtable_create_cb(struct ys_tc_priv *tc_priv,
				     struct ys_tc_table *table)
{
	struct ys_tc_switchdev *switchdev = table->switchdev;
	int id = switchdev->id;

	ys_tc_table_dump(tc_priv, "create : ", table);

	if (switchdev->doe_ops->tbl_valid(switchdev->id, table->id))
		switchdev->doe_ops->delete_hashtbl(id, table->id, 0);
	return switchdev->doe_ops->create_hashtbl(id, table->id, table->size,
						  table->key_len, table->value_len,
						  table->extra, 0);
}

static void ys_tc_hashtable_destroy_cb(struct ys_tc_priv *tc_priv,
				       struct ys_tc_table *table)
{
	struct ys_tc_switchdev *switchdev = table->switchdev;

	ys_tc_table_dump(tc_priv, "destroy : ", table);

	(void)switchdev->doe_ops->delete_hashtbl(switchdev->id, table->id, 0);
}

static struct ys_tc_table_entry *ys_tc_hashtable_alloc_cb(struct ys_tc_priv *tc_priv,
							  struct ys_tc_table *table,
							  const int *idx, const void *data)
{
	struct ys_tc_table_entry *entry = NULL;
	size_t entry_data_size = 0;

	entry_data_size = table->key_len + table->value_len;
	entry_data_size = ALIGN(entry_data_size, 8);

	entry = ys_tc_table_entry_alloc(tc_priv, table, entry_data_size, idx);
	if (entry)
		refcount_set(&entry->refcnt, 1);
	return entry;
}

static int ys_tc_hashtable_add_cb(struct ys_tc_priv *tc_priv,
				  struct ys_tc_table_entry *entry)
{
	int ret = 0;
	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	u8 pri = test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags) ? 1 : 0;

	ys_tc_hexdump(entry->data, table->key_len,
		      "add table %d key : ", table->id);
	ys_tc_hexdump(entry->data + table->key_len, table->value_len,
		      "add table %d val : ", table->id);

	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_HASH_INSERT_TOTAL]);
	ret = switchdev->doe_ops->hash_insert(switchdev->id, table->id, entry->data,
						  table->key_len,
						  entry->data + table->key_len,
						  table->value_len, pri, 0);
	if (ret) {
		ys_tc_err("Failed to insert hash: table %d, ret %d.\n", table->id, ret);
		atomic64_inc(&switchdev->stats[YS_TC_STATES_HASH_INSERT_FAIL]);
		ys_tc_table_error_stats(entry->table->switchdev, ret);
	}

	return ret;
}

static void ys_tc_hashtable_del_cb(struct ys_tc_priv *tc_priv,
				   struct ys_tc_table_entry *entry)
{
	int ret = 0;
	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;

	ys_tc_hexdump(entry->data, table->key_len,
		      "del table %d key : ", table->id);
	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_HASH_DEL_TOTAL]);
	ret = switchdev->doe_ops->hash_delete(switchdev->id, table->id, entry->data,
					      table->key_len, 0);
	if (ret) {
		ys_tc_err("Failed to del hash: table %d, ret %d.\n", table->id, ret);
		atomic64_inc(&switchdev->stats[YS_TC_STATES_HASH_DEL_FAIL]);
		ys_tc_table_error_stats(switchdev, ret);
	}
}

static inline struct workqueue_struct *ys_tc_table_wq(struct ys_tc_table *table)
{
	return table->wq ? table->wq : table->switchdev->wq;
}

static void ys_tc_table_work_proc(struct ys_tc_table *table, void (*extra)(struct ys_tc_table *))
{
	struct llist_node *dellist = NULL;
	struct llist_node *addlist = NULL;
	struct ys_tc_table_entry *entry = NULL;
	struct ys_tc_table_entry *tmp = NULL;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	struct workqueue_struct *wq = ys_tc_table_wq(table);

	set_bit(YS_TC_TABLE_FLAG_WORK_PROCESS, &table->flags);
	if (test_bit(YS_TC_TABLE_FLAG_DUMP, &table->flags)) {
		/* Dump in progress, trigger a next round. */
		mod_delayed_work(wq, &table->tc_work, 0);
		atomic64_inc(&switchdev->metrics[YS_TC_METRICS_WORK_RETRY_TOTAL]);
		return;
	}
	/* put dellist first to avoid race */
	dellist = llist_del_all(&table->dellist);
	addlist = llist_del_all(&table->addlist);
	llist_for_each_entry(entry, addlist, addlist) {
		table->entry_list[entry->idx] = entry;
		if (table->bitmask)
			__set_bit(entry->idx, table->bitmask);
	}

	llist_for_each_entry_safe(entry, tmp, dellist, dellist) {
		/*
		 * Here entry del/add is non-ordered.
		 *   For same index: entry_A(del) + entry_B(add)
		 *   For same entry(same index): entry_C(add) + entry_C(del)
		 */
		if (table->entry_list[entry->idx] == entry) {
			table->entry_list[entry->idx] = NULL;
			if (table->bitmask)
				__clear_bit(entry->idx, table->bitmask);
		}
		kfree(entry);
	}

	if (extra)
		extra(table);

	clear_bit(YS_TC_TABLE_FLAG_WORK_PROCESS, &table->flags);
}

static void ys_tc_table_work(struct work_struct *work)
{
	struct ys_tc_table *table = container_of(work, struct ys_tc_table, tc_work.work);

	ys_tc_table_work_proc(table, NULL);
}

static void ys_tc_cnt_table_walk_update_array_load(struct ys_tc_table *table)
{
	int ret = 0;
	u32 idx_pos = 0;
	u8 *cur_buf = NULL;
	const __be64 *pkts = NULL;
	const __be64 *bytes = NULL;

	struct ys_tc_table_entry *entry = NULL;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	int id = switchdev->id;

	if (!atomic_read(&table->used))
		return;

	for (idx_pos = 0; idx_pos < table->size; idx_pos++) {
		entry = table->entry_list[idx_pos];
		if (!entry || !test_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags))
			continue;

		atomic64_inc(&switchdev->metrics[YS_TC_METRICS_ARRAY_LOAD_TOTAL]);
		ret = switchdev->doe_ops->array_load(id, table->id, idx_pos, table->buf, 16, 0);
		if (ret) {
			atomic64_inc(&switchdev->stats[YS_TC_STATES_ARRAY_LOAD_FAIL]);
			ys_tc_table_error_stats(switchdev, ret);
			continue;
		}

		cur_buf = table->buf;
		pkts = (__be64 *)(cur_buf);
		bytes = (__be64 *)(cur_buf + sizeof(__be64));
		ys_tc_table_entry_cache_update(entry, pkts, bytes);
	}
}

static void ys_tc_cnt_table_walk_update_counter_load(struct ys_tc_table *table)
{
	u32 idx_pos = 0;
	u32 cur_idx = 0;
	u8 *cur_buf = NULL;
	u32 ret_cnt = 0;
	u32 i = 0;
	u32 load_batch = YS_TC_CNT_LOAD_BATCH;
	const size_t cnt_len = sizeof(u32) + sizeof(u64) * 2;
	const __be64 *pkts = NULL;
	const __be64 *bytes = NULL;

	struct ys_tc_table_entry *entry = NULL;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	int id = switchdev->id;

	if (!atomic_read(&table->used))
		return;

	for (idx_pos = 0; idx_pos < table->size; idx_pos += load_batch) {
		/*
		 * find_next_bit is a non-atomic operation.
		 * It would got error number according to https://lwn.net/Articles/954719/.
		 */
		idx_pos = find_next_bit(table->bitmask, table->size, idx_pos);
		/* while (idx_pos < table->size && !table->entry_list[idx_pos]) idx_pos++; */
		if (idx_pos >= table->size)
			break;

		/* Recalculate the start index to avoid cross-over page size 4k. */
		idx_pos = idx_pos / 64 * 64;
		/* Change batch number if overflow */
		load_batch = YS_TC_CNT_LOAD_BATCH;
		if (idx_pos + YS_TC_CNT_LOAD_BATCH > table->size)
			load_batch = table->size - idx_pos;

		atomic64_inc(&switchdev->metrics[YS_TC_METRICS_COUNTER_LOAD_TOTAL]);
		ret_cnt = switchdev->doe_ops->counter_load(id, table->id, idx_pos,
							   load_batch, table->buf, 0);
		if (ret_cnt > load_batch) {
			atomic64_inc(&switchdev->stats[YS_TC_STATES_COUNTER_LOAD_FAIL]);
			continue;
		}
		for (i = 0; i < ret_cnt; i++) {
			cur_buf = table->buf + i * cnt_len;
			cur_idx = be32_to_cpu(*((__be32 *)cur_buf));
			if (cur_idx >= table->size) {
				atomic64_inc(&switchdev->stats[YS_TC_STATES_COUNTER_LOAD_FAIL]);
				continue;
			}

			entry = table->entry_list[cur_idx];
			if (!entry || !test_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags))
				continue;

			pkts = (__be64 *)(cur_buf + sizeof(u32));
			bytes = (__be64 *)(cur_buf + sizeof(u32) + sizeof(__be64));
			ys_tc_table_entry_cache_update(entry, pkts, bytes);
		}
	}
}

static int ys_tc_meter_table_add_cb(struct ys_tc_priv *tc_priv,
				    struct ys_tc_table_entry *entry)
{
	int ret = 0;
	int idx = entry->idx;

	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	int len = table->value_len;

	ys_tc_hexdump(entry->data, len, "add meter table %d, idx %d, data : ", table->id, idx);
	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_METER_STORE_TOTAL]);

	ret = switchdev->doe_ops->meter_store(switchdev->id, table->id, idx,
					      (struct meter_config *)entry->data, 0, 0);
	if (ret) {
		atomic64_inc(&switchdev->stats[YS_TC_STATES_METER_STORE_FAIL]);
		ys_tc_table_error_stats(switchdev, ret);
		ys_tc_err("Failed to add meter table %d, idx %d, ret %d.\n",
			  table->id, idx, ret);
	}

	return ret;
}

static void ys_tc_counter_work_on_ram(struct work_struct *work)
{
	struct ys_tc_table *table = container_of(work, struct ys_tc_table, tc_work.work);
	struct workqueue_struct *wq = ys_tc_table_wq(table);

	queue_delayed_work(wq, &table->tc_work, table->work_interval);
	ys_tc_table_work_proc(table, ys_tc_cnt_table_walk_update_array_load);
}

static void ys_tc_counter_work_on_ddr(struct work_struct *work)
{
	struct ys_tc_table *table = container_of(work, struct ys_tc_table, tc_work.work);
	struct workqueue_struct *wq = ys_tc_table_wq(table);

	queue_delayed_work(wq, &table->tc_work, table->work_interval);
	ys_tc_table_work_proc(table, ys_tc_cnt_table_walk_update_counter_load);
}

static int ys_tc_ref_table_create_cb(struct ys_tc_priv *tc_priv,
				     struct ys_tc_table *table)
{
	int ret = 0;

	table->ref_ht_params = (struct rhashtable_params) {
					.head_offset = offsetof(struct ys_tc_table_entry, node),
					.key_offset = offsetof(struct ys_tc_table_entry, data),
					.key_len = table->value_len,
					.automatic_shrinking = true,
				};

	ret = rhashtable_init(&table->ref_ht, &table->ref_ht_params);
	if (ret) {
		ys_tc_err("Failed to create ref hashtable failed, table id %d.\n", table->id);
		return ret;
	}

	ret = ys_tc_arraytable_create_cb(tc_priv, table);
	if (ret)
		goto failed;

	return 0;

failed:
	rhashtable_destroy(&table->ref_ht);
	return ret;
}

static void ys_tc_ref_table_destroy_cb(struct ys_tc_priv *tc_priv,
				       struct ys_tc_table *table)
{
	ys_tc_arraytable_destroy_cb(tc_priv, table);
	rhashtable_destroy(&table->ref_ht);
}

static struct ys_tc_table_entry *ys_tc_ref_table_alloc_cb(struct ys_tc_priv *tc_priv,
							  struct ys_tc_table *table,
							  const int *idx, const void *data)
{
	struct ys_tc_table_entry *entry = NULL;
	size_t entry_data_size = 0;
	int ret = 0;

	entry = rhashtable_lookup_fast(&table->ref_ht, data, table->ref_ht_params);
	if (entry && refcount_inc_not_zero(&entry->refcnt))
		return entry;

	entry_data_size = table->value_len;
	entry_data_size = ALIGN(entry_data_size, 8);

	entry = ys_tc_table_entry_alloc(tc_priv, table, entry_data_size, idx);
	if (!entry)
		return NULL;

	refcount_set(&entry->refcnt, 1);
	memcpy(entry->data, data, table->value_len);
	ret = rhashtable_insert_fast(&table->ref_ht, &entry->node, table->ref_ht_params);
	if (ret) {
		ys_tc_err("Failed to add into ref hash table %d, ret %d.\n", table->id, ret);
		ys_tc_table_free(tc_priv, entry);
		return NULL;
	}
	return entry;
}

static void ys_tc_ref_table_del_cb(struct ys_tc_priv *tc_priv,
				   struct ys_tc_table_entry *entry)
{
	struct ys_tc_table *table = entry->table;

	ys_tc_debug("del array table %d, idx %d\n", entry->table->id, entry->idx);
	rhashtable_remove_fast(&table->ref_ht, &entry->node, table->ref_ht_params);
}

static const struct ys_tc_table_ops array_ops = {
	.create = ys_tc_arraytable_create_cb,
	.destroy = ys_tc_arraytable_destroy_cb,
	.alloc = ys_tc_arraytable_alloc_cb,
	.add = ys_tc_arraytable_add_cb,
	.del = ys_tc_arraytable_del_cb,
	.work = ys_tc_table_work,
};

static const struct ys_tc_table_ops ram_cnt_ops = {
	.create = ys_tc_cnt_table_create_cb,
	.destroy = ys_tc_cnt_table_destroy_cb,
	.alloc = ys_tc_cnt_table_alloc_cb,
	.add = ys_tc_cnt_table_add_cb,
	.del = ys_tc_cnt_table_del_cb,
	.work = ys_tc_counter_work_on_ram,
};

static const struct ys_tc_table_ops ddr_cnt_ops = {
	.create = ys_tc_cnt_table_create_cb,
	.destroy = ys_tc_cnt_table_destroy_cb,
	.alloc = ys_tc_cnt_table_alloc_cb,
	.add = ys_tc_cnt_table_add_cb,
	.del = ys_tc_cnt_table_del_cb,
	.work = ys_tc_counter_work_on_ddr,
};

static const struct ys_tc_table_ops hash_ops = {
	.create = ys_tc_hashtable_create_cb,
	.destroy = ys_tc_hashtable_destroy_cb,
	.alloc = ys_tc_hashtable_alloc_cb,
	.add = ys_tc_hashtable_add_cb,
	.del = ys_tc_hashtable_del_cb,
	.work = ys_tc_table_work,
};

static const struct ys_tc_table_ops meter_ops = {
	.create = ys_tc_arraytable_create_cb,
	.destroy = ys_tc_arraytable_destroy_cb,
	.alloc = ys_tc_arraytable_alloc_cb,
	.add = ys_tc_meter_table_add_cb,
	.del = ys_tc_arraytable_del_cb,
	.work = ys_tc_table_work,
};

static const struct ys_tc_table_ops ref_ops = {
	.create = ys_tc_ref_table_create_cb,
	.destroy = ys_tc_ref_table_destroy_cb,
	.alloc = ys_tc_ref_table_alloc_cb,
	.add = ys_tc_arraytable_add_cb,
	.del = ys_tc_ref_table_del_cb,
	.work = ys_tc_table_work,
};

static void ys_tc_table_array_debugfs_show(struct seq_file *seq, struct ys_tc_table *table)
{
	struct ys_tc_table_entry *entry = NULL;
	size_t i = 0;
	int ref = 0;

	seq_printf(seq, "name %s : size %d, used %d, type %d, location %d\n", table->name,
		   table->size, atomic_read(&table->used), table->extra->tbl_type,
		   table->extra->location);
	seq_printf(seq, "%-8s + %-8s\n", "idx", "value");

	for (i = 0; i < table->size; i++) {
		entry = table->entry_list[i];
		if (!entry || !test_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags))
			continue;

		seq_printf(seq, "idx : %-8d", entry->idx);
		if (test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags))
			seq_puts(seq, ", high priority");
		ref = refcount_read(&entry->refcnt);
		if (ref > 1)
			seq_printf(seq, ", refcnt %d", ref);
		seq_puts(seq, "\n");

		seq_hex_dump(seq, "val : ", DUMP_PREFIX_NONE, 32, 1,
			     entry->data, table->value_len, false);
		seq_puts(seq, "\n");
	}
}

static void ys_tc_table_hash_debugfs_show(struct seq_file *seq, struct ys_tc_table *table)
{
	struct ys_tc_table_entry *entry = NULL;
	size_t i = 0;

	seq_printf(seq, "name %s : size %d, used %d\n", table->name,
		   table->size, atomic_read(&table->used));
	seq_printf(seq, "%-8s + %-8s\n", "key", "value");

	for (i = 0; i < table->size; i++) {
		entry = table->entry_list[i];
		if (!entry || !test_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags))
			continue;

		seq_printf(seq, "idx : %-8d", entry->idx);
		if (test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags))
			seq_puts(seq, ", high priority");
		seq_puts(seq, "\n");

		seq_hex_dump(seq, "key : ", DUMP_PREFIX_NONE, 32, 1,
			     entry->data, table->key_len, false);

		seq_hex_dump(seq, "val : ", DUMP_PREFIX_NONE, 32, 1,
			     entry->data + table->key_len,
			     table->value_len, false);
		seq_puts(seq, "\n");
	}
}

static int ys_tc_table_debugfs_show(struct seq_file *seq, void *data)
{
	struct ys_tc_table *table = seq->private;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	bool skip = false;

	set_bit(YS_TC_TABLE_FLAG_DUMP, &table->flags);
	if (test_bit(YS_TC_TABLE_FLAG_WORK_PROCESS, &table->flags)) {
		skip = true;
		goto out;
	}

	if (table->type & YS_TC_TABLE_ARRAY)
		ys_tc_table_array_debugfs_show(seq, table);
	else
		ys_tc_table_hash_debugfs_show(seq, table);

out:
	clear_bit(YS_TC_TABLE_FLAG_DUMP, &table->flags);
	if (skip) {
		atomic64_inc(&switchdev->metrics[YS_TC_METRICS_DUMP_SKIP_TOTAL]);
		seq_puts(seq, "Device busy, please try again.\n");
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ys_tc_table_debugfs);

static int ys_tc_table_create(struct ys_tc_priv *tc_priv,
			      const struct ys_tc_table_create_param *param)
{
	int ret = 0;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	char name[32] = {0};
	struct ys_tc_table *table = NULL;
	char work_q_name[32] = {0};

	table = kvzalloc(struct_size(table, entry_list, param->size), GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	switch (param->id) {
	case YS_TC_TABLE_ID_IPV4_FLOW:
	case YS_TC_TABLE_ID_IPV6_FLOW:
		table->type = YS_TC_TABLE_HASH;
		table->ops = &hash_ops;
		table->key_len = param->key_len;
		break;

	case YS_TC_TABLE_ID_COMMCNT:
		table->type = YS_TC_TABLE_ARRAY | YS_TC_TABLE_CNT;
		if (param->extra.location == DOE_LOCATION_RAM)
			table->ops = &ram_cnt_ops;
		else
			table->ops = &ddr_cnt_ops;

		table->work_interval = msecs_to_jiffies(param->work_interval);
		break;

	case YS_TC_TABLE_ID_METER:
		table->type = YS_TC_TABLE_ARRAY | YS_TC_TABLE_METER;
		table->ops = &meter_ops;
		break;

	case YS_TC_TABLE_ID_VXLANENCAP:
	case YS_TC_TABLE_ID_GNVENCAP:
		table->type = YS_TC_TABLE_ARRAY | YS_TC_TABLE_REF;
		table->ops = &ref_ops;
		break;

	default:
		table->type = YS_TC_TABLE_ARRAY;
		table->ops = &array_ops;
		break;
	}
	(void)strscpy(table->name, param->name, sizeof(table->name));
	atomic_set(&table->used, 0);
	init_llist_head(&table->addlist);
	init_llist_head(&table->dellist);
	table->switchdev = switchdev;

	table->id = param->id;
	table->size = param->size;
	table->value_len = param->value_len;
	table->extra = &param->extra;

	idr_init(&table->idr);
	spin_lock_init(&table->idr_slock);

	if (table->type & YS_TC_TABLE_ARRAY)
		table->start_idx = param->start_idx;

	if (table->type & YS_TC_TABLE_CNT) {
		snprintf(work_q_name, sizeof(work_q_name), "ys_tc_sw_%d_work_%d",
			 switchdev->id, table->id);
		table->wq = create_singlethread_workqueue(work_q_name);
		if (!table->wq) {
			ret = -ENOMEM;
			goto wq_fail;
		}
	}

	ys_tc_info("Create: table %s, id %d, size %u, type %d, location %d, key_len %d, value %d.\n",
		   table->name, table->id,
		   table->size, param->extra.tbl_type, param->extra.location,
		   table->key_len, table->value_len);

	INIT_DELAYED_WORK(&table->tc_work, table->ops->work);
	ret = table->ops->create(tc_priv, table);
	if (ret) {
		ys_tc_err("Failed to create table %s, ret %d.\n", table->name, ret);
		goto table_create_fail;
	}

	switchdev->ys_tc_tables[table->id] = table;

	if (switchdev->debugfs_root) {
		snprintf(name, sizeof(name), "table_%d", table->id);
		table->debugfs_file = debugfs_create_file(name, 0400, switchdev->debugfs_root,
							  table, &ys_tc_table_debugfs_fops);
		if (IS_ERR(table->debugfs_file)) {
			ys_tc_err("Failed to create debugfs file %s\n", name);
			table->debugfs_file = NULL;
		}
	}

	return 0;

table_create_fail:
	if (table->wq)
		destroy_workqueue(table->wq);
wq_fail:
	kvfree(table);
	return ret;
}

static void ys_tc_table_destroy(struct ys_tc_priv *tc_priv,
				struct ys_tc_table *table)
{
	struct ys_tc_table_entry *entry = NULL;
	size_t i = 0;
	u32 nb = 0;

	if (!table)
		return;

	ys_tc_table_work_proc(table, NULL);
	for (i = 0; i < table->size; i++) {
		entry = table->entry_list[i];
		if (entry) {
			nb++;
			kfree(entry);
		}
	}
	ys_tc_info("Destroy table %d, %u entries.", table->id, nb);

	if (table->wq)
		destroy_workqueue(table->wq);

	table->ops->destroy(tc_priv, table);
	idr_destroy(&table->idr);
	kvfree(table);
}

static void ys_tc_table_flush(struct ys_tc_priv *tc_priv)
{
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	struct ys_tc_table *table = NULL;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(switchdev->ys_tc_tables); i++) {
		table = switchdev->ys_tc_tables[i];
		if (!table)
			continue;

		set_bit(YS_TC_TABLE_FLAG_WORK_CANCEL, &table->flags);
		cancel_delayed_work_sync(&table->tc_work);
		debugfs_remove(table->debugfs_file);
	}

	for (i = 0; i < ARRAY_SIZE(switchdev->ys_tc_tables); i++) {
		table = switchdev->ys_tc_tables[i];
		if (!table)
			continue;

		ys_tc_table_destroy(tc_priv, table);
		switchdev->ys_tc_tables[i] = NULL;
	}
}

struct ys_tc_table *ys_tc_table_find(struct ys_tc_priv *tc_priv,
				     enum ys_tc_table_id id)
{
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	return switchdev->ys_tc_tables[id];
}

struct ys_tc_table_entry *ys_tc_table_alloc(struct ys_tc_priv *tc_priv,
					    enum ys_tc_table_id id,
					    const int *idx, const void *data)
{
	struct ys_tc_table_entry *entry = NULL;
	struct ys_tc_table *table = ys_tc_table_find(tc_priv, id);

	if (!table)
		return NULL;

	if (atomic_read(&table->used) >= table->size) {
		ys_tc_debug("Table %s is full\n", table->name);
		return NULL;
	}

	entry = table->ops->alloc(tc_priv, table, idx, data);
	if (!entry)
		return NULL;

	/* For reference entry, job done after entry ref cnt added. */
	if (test_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags))
		return entry;

	entry->table = table;
	clear_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags);

	return entry;
}

static void ys_tc_table_free_pre(struct ys_tc_priv *tc_priv,
				 struct ys_tc_table_entry *entry)
{
	struct ys_tc_table *table = entry->table;

	spin_lock(&table->idr_slock);
	idr_remove(&table->idr, entry->idx);
	spin_unlock(&table->idr_slock);
}

static void ys_tc_table_do_del_and_free(struct ys_tc_priv *tc_priv,
					struct ys_tc_table_entry *entry)
{
	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	struct workqueue_struct *wq = ys_tc_table_wq(table);

	table->ops->del(tc_priv, entry);

	if (test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags))
		atomic64_inc(&switchdev->metrics[YS_TC_METRICS_HIGH_PRI_UNSET_TOTAL]);

	clear_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags);
	atomic_dec(&table->used);

	ys_tc_table_free_pre(tc_priv, entry);

	llist_add(&entry->dellist, &table->dellist);
	if (!test_bit(YS_TC_TABLE_FLAG_WORK_CANCEL, &table->flags))
		queue_delayed_work(wq, &table->tc_work, 0);
}

void ys_tc_table_free(struct ys_tc_priv *tc_priv,
		      struct ys_tc_table_entry *entry)
{
	if (!entry)
		return;

	if (!refcount_dec_and_test(&entry->refcnt))
		return;

	/* For ref table, alloc (add failed?)-> free on valid entry. */
	if (test_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags)) {
		ys_tc_table_do_del_and_free(tc_priv, entry);
		return;
	}

	ys_tc_table_free_pre(tc_priv, entry);
	kfree(entry);
}

int ys_tc_table_add(struct ys_tc_priv *tc_priv, struct ys_tc_table_entry *entry)
{
	struct ys_tc_table *table = entry->table;
	struct ys_tc_switchdev *switchdev = table->switchdev;
	int ret = 0;
	struct workqueue_struct *wq = ys_tc_table_wq(table);

	/* For reference entry, job done. */
	if (test_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags))
		return 0;

	if (test_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &entry->flags))
		atomic64_inc(&switchdev->metrics[YS_TC_METRICS_HIGH_PRI_SET_TOTAL]);

	ret = table->ops->add(tc_priv, entry);
	if (ret) {
		ys_tc_err("Failed to table add, table %s %d, ret %d.\n",
			  table->name, table->id, ret);
		return ret;
	}

	atomic_inc(&table->used);
	set_bit(YS_TC_TABLE_ENTRY_VALID, &entry->flags);

	llist_add(&entry->addlist, &table->addlist);
	/*
	 * If work is Pending(waiting for enqueue to execute),
	 * queue_delayed_work will not change the delay time,
	 * but mod_delayed_work will.
	 */
	if (!test_bit(YS_TC_TABLE_FLAG_WORK_CANCEL, &table->flags))
		queue_delayed_work(wq, &table->tc_work, 0);

	return 0;
}

void ys_tc_table_del_and_free(struct ys_tc_priv *tc_priv,
			      struct ys_tc_table_entry *entry)
{
	if (!entry)
		return;

	if (!refcount_dec_and_test(&entry->refcnt))
		return;

	ys_tc_table_do_del_and_free(tc_priv, entry);
}

int ys_tc_table_update(struct ys_tc_priv *tc_priv, struct ys_tc_table_entry *entry)
{
	struct ys_tc_table *table = entry->table;

	if (table->type & YS_TC_TABLE_ARRAY)
		return table->ops->add(tc_priv, entry);

	return -EOPNOTSUPP;
}

#define YS_TC_TABLE_IPV4_KEY_LEN	(sizeof(u16) +            /* src_vf */ \
					 sizeof(u8) +             /* src_pf */ \
					 sizeof(u8) +             /* protocol */ \
					 sizeof(u32) * 2 +        /* src_ip + dst_ip */ \
					 sizeof(u16) * 2 +        /* src_port + dst_port */ \
					 sizeof(u32) +            /* tenant_id */ \
					 sizeof(u8) * 12 +        /* dst_mac + src_mac */ \
					 sizeof(u16) +            /* vlan_id */ \
					 sizeof(u8) +             /* fragment */ \
					 sizeof(u8))              /* reserved */

#define YS_TC_TABLE_IPV6_KEY_LEN	(sizeof(u16) +            /* src_vf */ \
					 sizeof(u8) +             /* src_pf */ \
					 sizeof(u8) +             /* protocol */ \
					 sizeof(u8) * 16 * 2 +    /* src_ip +dst_ip */ \
					 sizeof(u16) * 2 +        /* src_port + dst_port */ \
					 sizeof(u32) +            /* tenant_id */ \
					 sizeof(u8) * 12 +        /* dst_mac + src_mac */ \
					 sizeof(u16) +            /* vlan_id */ \
					 sizeof(u8) +             /* fragment */ \
					 sizeof(u8))              /* reserved */

/* Key of vxlan_encap_tbl have 4 formats:
 * 1. type(1) + len(1) + eth(14) + ipv4(20) + udp(8) + vxlan(8)
 * 2. type(1) + len(1) + eth(14) + vlan(4) + ipv4(20) + udp(8) + vxlan(8)
 * 3. type(1) + len(1) + eth(14) + ipv6(40) + udp(8) + vxlan(8)
 * 4. type(1) + len(1) + eth(14) + vlan(4) + ipv6(40) + udp(8) + vxlan(8)
 * So maximium_value is 76
 */
#define YS_TC_TABLE_VXLANECAP_KEY_LEN	76

/* Key of geneve_encap_tbl have 4 formats:
 * 1. type(1) + len(1) + eth(14) + ipv4(20) + udp(8) + geneve(8) + geneve_opt(8)
 * 2. type(1) + len(1) + eth(14) + vlan(4) + ipv4(20) + udp(8) + geneve(8) + geneve_opt(8)
 * 3. type(1) + len(1) + eth(14) + ipv6(40) + udp(8) + geneve(8) + geneve_opt(8)
 * 4. type(1) + len(1) + eth(14) + vlan(4) + ipv6(40) + udp(8) + geneve(8) + geneve_opt(8)
 * Now we only support GENEVE option with class OVN (0x0102) and 8 bytes in total.
 * So maximium_value is 84.
 */
#define YS_TC_TABLE_GNVECAP_KEY_LEN	84

#define YS_TC_TABLE_HASH_VALUELEN_MAX	128
#define YS_TC_TABLE_FLOW_NUM_MAX	100000
#define YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM	64

/* default(1) + ipv4(1) + ipv6(1) + vxlan(4) + geneve(4) + qinq(2) */
#define YS_TC_L3_PROTRO_CLS_TBL_SIZE    (1 + 2 + 4 + 4 + 2)

#define YS_TC_TABLE_COMMCNT_NUM \
	(YS_TC_TABLE_FLOW_NUM_MAX + YS_TC_L3_PROTRO_CLS_TBL_SIZE + YS_TC_TABLES_NUM)

#define YS_TC_TABLE_COMMCNT_NUM_ON_RAM \
	(YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM + YS_TC_L3_PROTRO_CLS_TBL_SIZE + YS_TC_TABLES_NUM)

static struct ys_tc_table_create_param create_params[] = {
	{
		.name = "l3proto_cls_table",
		.id = YS_TC_TABLE_ID_L3PROTO,
		.size = YS_TC_L3_PROTRO_CLS_TBL_SIZE,
		.value_len = 32,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 1,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 10,

			/* There's a reserved ram/cache resource for small array */
			.tbl_type      = DOE_TABLE_SMALL_ARRAY,
			.location      = DOE_LOCATION_RAM,
			.endian	       = 1,
			.ddr_mode      = 0,
		},
	}, {
		.name = "ipv4_flow_cls_table",
		.id = YS_TC_TABLE_ID_IPV4_FLOW,
		.size = YS_TC_TABLE_FLOW_NUM_MAX,
		.size_on_ram = YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM,
		.value_len = YS_TC_TABLE_HASH_VALUELEN_MAX,
		.key_len = YS_TC_TABLE_IPV4_KEY_LEN,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 1,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 10,

			.tbl_type      = DOE_TABLE_BIG_HASH,
			.location      = DOE_LOCATION_DDR,
			.endian        = 1,
			.ddr_mode      = 0,
			.chain_limit   = 0,
			.hash_seed     = 0,
		},
	}, {
		.name = "ipv6_flow_cls_table",
		.id = YS_TC_TABLE_ID_IPV6_FLOW,
		.size = YS_TC_TABLE_FLOW_NUM_MAX,
		.size_on_ram = YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM,
		.value_len = YS_TC_TABLE_HASH_VALUELEN_MAX,
		.key_len = YS_TC_TABLE_IPV6_KEY_LEN,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 1,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 10,

			.tbl_type      = DOE_TABLE_BIG_HASH,
			.location      = DOE_LOCATION_DDR,
			.endian        = 1,
			.ddr_mode      = 0,
			.chain_limit   = 0,
			.hash_seed     = 0,
		},
	}, {
		.name = "miss_table",
		.id = YS_TC_TABLE_ID_MISS,
		.size = YS_TC_TABLES_NUM,
		.value_len = 32,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 1,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 10,

			/* There's a reserved ram/cache resource for small array */
			.tbl_type      = DOE_TABLE_SMALL_ARRAY,
			.location      = DOE_LOCATION_RAM,
			.endian        = 1,
			.ddr_mode      = 0,
		},
	}, {
		.name = "common_pktcnt_table",
		.id = YS_TC_TABLE_ID_COMMCNT,
		.size = YS_TC_TABLE_COMMCNT_NUM,
		.size_on_ram = YS_TC_TABLE_COMMCNT_NUM_ON_RAM,
		.value_len = 16,
		.work_interval = 1000,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 0,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 0,

			.tbl_type      = DOE_TABLE_COUNTER,
			.location      = DOE_LOCATION_DDR,
			.endian        = 1,
			.ddr_mode      = 0,
		},
	}, {
		.name = "vxlan_encap_table",
		.id = YS_TC_TABLE_ID_VXLANENCAP,
		.size = YS_TC_TABLE_FLOW_NUM_MAX,
		.size_on_ram = YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM,
		.value_len = YS_TC_TABLE_VXLANECAP_KEY_LEN,
		/* min length: type(1) + len(1) + eth(14) + ipv4(20) + udp(8) + vxlan(8) */
		.value_min_len = 52,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 1,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 10,

			.tbl_type      = DOE_TABLE_NORMAL_ARRAY,
			.location      = DOE_LOCATION_DDR,
			.endian        = 1,
			.ddr_mode      = 0,
		},
	}, {
		.name = "flow_mirror_table",
		.id = YS_TC_TABLE_ID_MIRROR,
		.size = YS_TC_TABLE_FLOW_NUM_MAX,
		.size_on_ram = YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM,
		.value_len = 32,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 1,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 10,

			.tbl_type      = DOE_TABLE_NORMAL_ARRAY,
			.location      = DOE_LOCATION_DDR,
			.endian        = 1,
			.ddr_mode      = 0,
		},
	}, {
		.name = "meter_table",
		.id = YS_TC_TABLE_ID_METER,
		.size = YS_TC_TABLE_FLOW_NUM_MAX,
		.size_on_ram = YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM,
		.value_len = sizeof(struct meter_config),
		.start_idx = 1,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 0,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 0,

			.tbl_type      = DOE_TABLE_METER,
			.location      = DOE_LOCATION_DDR,
			.endian        = 1,
			.ddr_mode      = 0,
		},
	}, {
		.name = "geneve_encap",
		.id = YS_TC_TABLE_ID_GNVENCAP,
		.size = YS_TC_TABLE_FLOW_NUM_MAX,
		.size_on_ram = YS_TC_TABLE_FLOW_NUM_MAX_ON_RAM,
		.value_len = YS_TC_TABLE_GNVECAP_KEY_LEN,
		/* type(1) + len(1) + eth(14) + ipv4(20) + udp(8) + geneve(8) */
		.value_min_len = 52,
		.extra = (struct hw_advance_cfg) {
			.shared_tbl    = 1,
			.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			.l2_cache_ways = 10,

			.tbl_type      = DOE_TABLE_NORMAL_ARRAY,
			.location      = DOE_LOCATION_DDR,
			.endian        = 1,
			.ddr_mode      = 0,
		},
	},
};

static int ys_tc_debug_doe_show(struct seq_file *seq, void *data)
{
	struct ys_tc_switchdev *switchdev = seq->private;
	size_t i = 0;
	u64 val_show = 0;
	const char *metric_name[ARRAY_SIZE(switchdev->metrics)] = {
		[YS_TC_METRICS_ARRAY_STORE_TOTAL]       = "Array store total",
		[YS_TC_METRICS_ARRAY_LOAD_TOTAL]        = "Array load total",
		[YS_TC_METRICS_METER_STORE_TOTAL]       = "Meter store total",
		[YS_TC_METRICS_COUNTER_ENABLE_TOTAL]    = "Counter enable total",
		[YS_TC_METRICS_COUNTER_DISABLE_TOTAL]   = "Counter disable total",
		[YS_TC_METRICS_COUNTER_LOAD_TOTAL]      = "Counter load total",
		[YS_TC_METRICS_COUNTER_DOWNGRADE_TOTAL] = "Counter unset priority total",
		[YS_TC_METRICS_HASH_INSERT_TOTAL]       = "Hash insert total",
		[YS_TC_METRICS_HASH_DEL_TOTAL]          = "Hash delete total",
		[YS_TC_METRICS_HIGH_PRI_SET_TOTAL]      = "High priority set total",
		[YS_TC_METRICS_HIGH_PRI_UNSET_TOTAL]    = "High priority unset total",
		[YS_TC_METRICS_FLOW_ADD_TOTAL]          = "Flow add total",
		[YS_TC_METRICS_FLOW_DEL_TOTAL]          = "Flow delete total",
		[YS_TC_METRICS_WORK_RETRY_TOTAL]        = "Work retry total",
		[YS_TC_METRICS_DUMP_SKIP_TOTAL]         = "Dump skip total",
	};

	const char *stat_name[ARRAY_SIZE(switchdev->stats)] = {
		[YS_TC_STATES_ARRAY_STORE_FAIL]         = "Array store fail total",
		[YS_TC_STATES_ARRAY_LOAD_FAIL]          = "Array load fail total",
		[YS_TC_STATES_METER_STORE_FAIL]         = "Meter store fail total",
		[YS_TC_STATES_COUNTER_ENABLE_FAIL]      = "Counter enable fail total",
		[YS_TC_STATES_COUNTER_DISABLE_FAIL]     = "Counter disable fail total",
		[YS_TC_STATES_COUNTER_LOAD_FAIL]        = "Counter load fail total",
		[YS_TC_STATES_COUNTER_DOWNGRADE_FAIL]   = "Counter unset priority fail total",
		[YS_TC_STATES_HASH_INSERT_FAIL]         = "Hash insert fail total",
		[YS_TC_STATES_HASH_DEL_FAIL]            = "Hash delete fail total",
	};

	/* DOE errors */
	val_show = atomic64_read(&switchdev->doe_errors[0]);
	seq_printf(seq, "%-30s: %llu\n", "Unknown error total", val_show);
	for (i = 1; i < ARRAY_SIZE(switchdev->doe_errors); i++) {
		val_show = atomic64_read(&switchdev->doe_errors[i]);
		if (!val_show)
			continue;
		seq_printf(seq, "Error code %lu total: %llu\n", i, val_show);
	}

	/* Stats errors */
	for (i = 0; i < ARRAY_SIZE(switchdev->stats); i++) {
		val_show = atomic64_read(&switchdev->stats[i]);
		if (val_show)
			seq_printf(seq, "%-30s: %llu\n", stat_name[i], val_show);
	}

	/* Metrics */
	for (i = 0; i < ARRAY_SIZE(switchdev->metrics); i++) {
		val_show = atomic64_read(&switchdev->metrics[i]);
		seq_printf(seq, "%-30s: %llu\n", metric_name[i], val_show);
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ys_tc_debug_doe);

static void ys_tc_doe_debugfs_init(struct ys_tc_switchdev *switchdev)
{
	if (switchdev->debugfs_root) {
		debugfs_create_file("doe_stats", 0400, switchdev->debugfs_root, switchdev,
				    &ys_tc_debug_doe_fops);
	}
}

static int ys_tc_doe_settle(struct ys_tc_switchdev *switchdev, const int *prefer,
			    size_t perfer_len, int *location)
{
	size_t i = 0;
	size_t k = 0;

	for (k = 0; k < perfer_len; k++) {
		for (i = 0; i < YS_TC_DOE_CHANNEL_NUM; i++) {
			if (prefer[k] == switchdev->doe_chl_info.location[i]) {
				*location = prefer[k];
				return 0;
			}
		}
	}
	return -EINVAL;
}

static int ys_tc_table_settle_location(struct ys_tc_priv *tc_priv, int *location)
{
	const int smartnic_lc_prefer[] = { DOE_LOCATION_DDR, DOE_LOCATION_HOST_DDR };
	const int dpu_lc_prefer[] = { DOE_LOCATION_DDR, DOE_LOCATION_SOC_DDR };

	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	struct net_device *ndev = tc_priv->ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (pdev_priv->dpu_mode == MODE_SMART_NIC)
		return ys_tc_doe_settle(switchdev, smartnic_lc_prefer,
					ARRAY_SIZE(smartnic_lc_prefer), location);
	else
		return ys_tc_doe_settle(switchdev, dpu_lc_prefer,
					ARRAY_SIZE(dpu_lc_prefer), location);
}

int ys_tc_table_init(struct ys_tc_priv *tc_priv)
{
	int ret, i;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	struct net_device *ndev = tc_priv->ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_tc_table_create_param *tbl_param = NULL;
	int final_location = 0;

	ret = ys_tc_table_settle_location(tc_priv, &final_location);
	if (ret) {
		ys_tc_err("Failed to settle doe location, ret %d\n", ret);
		return ret;
	}

	ys_tc_doe_debugfs_init(switchdev);

	/* Stop NP access DOE */
	ret = ys_np_set_tbl_ready(pdev_priv, false);
	if (ret) {
		ys_tc_err("Failed to unset table ready, ret %d\n", ret);
		return ret;
	}
	/* Enable DOE protect */
	ret = ys_np_set_doe_protect(pdev_priv, true);
	if (ret) {
		ys_tc_err("Failed to enable doe protect, ret %d\n", ret);
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(create_params); i++) {
		tbl_param = &create_params[i];
		tbl_param->extra.sdepth = tbl_param->size;

		if (tbl_param->extra.location != DOE_LOCATION_RAM) {
			tbl_param->extra.location = final_location;
			if (final_location == DOE_LOCATION_RAM && tbl_param->size_on_ram)
				tbl_param->size = tbl_param->size_on_ram;
		}

		if (tbl_param->extra.tbl_type == DOE_TABLE_NORMAL_ARRAY ||
		    tbl_param->extra.tbl_type == DOE_TABLE_LOCK) {
			if (tbl_param->value_min_len > switchdev->array_tbl_value_len_max)
				continue;
			if (tbl_param->value_len > switchdev->array_tbl_value_len_max) {
				if (!tbl_param->value_min_len)
					continue;
				else
					tbl_param->value_len = switchdev->array_tbl_value_len_max;
			}
		} else if (tbl_param->extra.tbl_type == DOE_TABLE_BIG_HASH) {
			if (tbl_param->key_len > switchdev->hash_tbl_key_len_max)
				continue;
			if (tbl_param->value_len > switchdev->hash_tbl_value_len_max)
				tbl_param->value_len = switchdev->hash_tbl_value_len_max;
		}

		ret = ys_tc_table_create(tc_priv, tbl_param);
		if (ret) {
			ys_tc_err("Failed to create table %s\n", tbl_param->name);
			goto failed;
		}
	}

	/* When DOE protect is enabled, the ops allowed:
	 * 1. table create
	 * 2. table delete
	 * 3. counter load
	 */
	/* Disable DOE protect */
	ret = ys_np_set_doe_protect(pdev_priv, false);
	if (ret) {
		ys_tc_err("Failed to disable doe protect, ret %d\n", ret);
		goto failed;
	}

	ret = ys_tc_flow_once_init(tc_priv);
	if (ret) {
		ys_tc_err("Failed to run init flow once\n");
		goto failed;
	}

	/* Allow NP access DOE */
	ret = ys_np_set_tbl_ready(pdev_priv, true);
	if (ret) {
		ys_tc_err("Failed to set table ready, ret %d.\n", ret);
		goto failed;
	}

	return 0;

failed:
	ys_tc_table_flush(tc_priv);
	return ret;
}

void ys_tc_table_exit(struct ys_tc_priv *tc_priv)
{
	int ret = 0;
	struct net_device *ndev = tc_priv->ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	/* Stop NP access DOE */
	ret = ys_np_set_tbl_ready(pdev_priv, false);
	if (ret)
		ys_tc_err("Failed to unset table ready, ret %d\n", ret);
	/* Enable DOE protect */
	ret = ys_np_set_doe_protect(pdev_priv, true);
	if (ret)
		ys_tc_err("Failed to enable doe protect, ret %d\n", ret);

	ys_tc_table_flush(tc_priv);
}
