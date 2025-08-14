// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_np_priv.h"
#include "../include/ys_doe.h"

enum {
	YS_NP_DOE_PROTECT_OFF = 0,
	YS_NP_DOE_PROTECT_ON = 1,
};

struct ys_np_cnt_tbl_entry {
	__be64 pkts;
	__be64 bytes;
};

enum { YS_NP_CNT_TBL_ID = 103 };
enum { YS_NP_CNT_LOAD_BATCH = 128 };
enum { YS_NP_CNT_LOAD_ITEM_LEN = sizeof(__be32) + 2 * sizeof(__be64) };

struct ys_np_cnt_tbl_priv {
	struct delayed_work np_work;
	unsigned long work_interval;
	struct ys_np_sw *np_sw;
	u32 nb_entries;
	u16 entry_len;
	int id;
	char name[32];
	struct dentry *debugfs_file;
	struct mutex mlock; /* for table entry update and debugfs */
	int doe_location;
	struct {
		atomic64_t counter_load_total;
		atomic64_t counter_load_fail;
		atomic64_t array_load_total;
		atomic64_t array_load_fail;
	} doe_stats;
	void (*walk_update)(struct ys_np_cnt_tbl_priv *priv);

	u8 buf[YS_NP_CNT_LOAD_BATCH * YS_NP_CNT_LOAD_ITEM_LEN];
	struct ys_np_cnt_tbl_entry entry_list[];
};

int ys_k2u_np_doe_set_protect(struct ys_np *np, bool protect)
{
	const unsigned long wait_slice = 1000;
	const size_t max_wait_loop = 10;
	size_t i = 0;
	int ret = 0;
	const u8 val = protect ? YS_NP_DOE_PROTECT_ON : YS_NP_DOE_PROTECT_OFF;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	struct ys_np_sw *np_sw = np->sw;

	ys_np_info("Call doe set_protect_status, val = %u\n", val);
	ret = np_sw->doe_ops->set_protect_status(np_sw->bus_id, val);
	if (ret) {
		ys_np_err("Failed to call set_protect_status ret %d\n", ret);
		return ret;
	}

	for (i = 0; i < max_wait_loop; i++) {
		usleep_range(wait_slice / 2, wait_slice);

		ret = np_sw->doe_ops->protect_status(np_sw->bus_id);
		if (ret == val)
			return 0;
	}

	ys_np_err("Failed to wait for doe protect status.\n");
	return -EINVAL;
}

int ys_k2u_np_doe_init(struct ys_np *np)
{
	int ret = 0;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	struct ys_np_sw *np_sw = np->sw;

	//usleep_range(1000, 2000);
	ret = np_sw->doe_ops->hw_init(np_sw->bus_id, 0);
	if (ret) {
		ys_np_err("Failed to doe hw_init on bus %d, ret %d\n", np_sw->bus_id, ret);
		return ret;
	}

	return 0;
}

static void ys_np_cnt_tbl_walk_update_array_load(struct ys_np_cnt_tbl_priv *priv)
{
	u32 idx_pos = 0;
	u8 *cur_buf = NULL;
	const __be64 *pkts = NULL;
	const __be64 *bytes = NULL;

	struct ys_np_sw *np_sw = priv->np_sw;
	struct ys_np_cnt_tbl_entry *entry = NULL;

	mutex_lock(&priv->mlock);
	for (idx_pos = 0; idx_pos < priv->nb_entries; idx_pos++) {
		atomic64_inc(&priv->doe_stats.array_load_total);
		if (np_sw->doe_ops->array_load(np_sw->bus_id, priv->id,
					       idx_pos, priv->buf, 16, 0)) {
			atomic64_inc(&priv->doe_stats.array_load_fail);
			continue;
		}

		entry = &priv->entry_list[idx_pos];
		cur_buf = priv->buf;

		pkts = (__be64 *)(cur_buf);
		bytes = (__be64 *)(cur_buf + sizeof(__be64));
		entry->pkts = *pkts;
		entry->bytes = *bytes;
	}
	mutex_unlock(&priv->mlock);
}

static void ys_np_cnt_tbl_walk_update_counter_load(struct ys_np_cnt_tbl_priv *priv)
{
	u32 idx_pos = 0;
	u32 cur_idx = 0;
	u8 *cur_buf = NULL;
	u32 ret_cnt = 0;
	u32 i = 0;
	u32 load_batch = YS_NP_CNT_LOAD_BATCH;
	const __be64 *pkts = NULL;
	const __be64 *bytes = NULL;

	struct ys_np_sw *np_sw = priv->np_sw;
	struct ys_np_cnt_tbl_entry *entry = NULL;

	mutex_lock(&priv->mlock);
	for (idx_pos = 0; idx_pos < priv->nb_entries; idx_pos += load_batch) {
		/* Change batch number if overflow */
		load_batch = YS_NP_CNT_LOAD_BATCH;
		if (idx_pos + YS_NP_CNT_LOAD_BATCH > priv->nb_entries)
			load_batch = priv->nb_entries - idx_pos;

		atomic64_inc(&priv->doe_stats.counter_load_total);
		ret_cnt = np_sw->doe_ops->counter_load(np_sw->bus_id, priv->id, idx_pos,
						       load_batch, priv->buf, 0);
		if (ret_cnt > load_batch) {
			atomic64_inc(&priv->doe_stats.counter_load_fail);
			continue;
		}
		for (i = 0; i < ret_cnt; i++) {
			cur_buf = priv->buf + i * YS_NP_CNT_LOAD_ITEM_LEN;
			cur_idx = be32_to_cpu(*((__be32 *)cur_buf));
			if (cur_idx >= priv->nb_entries) {
				atomic64_inc(&priv->doe_stats.counter_load_fail);
				continue;
			}

			entry = &priv->entry_list[cur_idx];

			pkts = (__be64 *)(cur_buf + sizeof(u32));
			bytes = (__be64 *)(cur_buf + sizeof(u32) + sizeof(__be64));
			entry->pkts = *pkts;
			entry->bytes = *bytes;
		}
	}
	mutex_unlock(&priv->mlock);
}

static void ys_k2u_np_cnt_work(struct work_struct *work)
{
	struct ys_np_cnt_tbl_priv *priv = container_of(work,
						       struct ys_np_cnt_tbl_priv, np_work.work);
	struct ys_np_sw *np_sw = priv->np_sw;

	priv->walk_update(priv);
	queue_delayed_work(np_sw->wq, &priv->np_work, priv->work_interval);
}

static int ys_np_cnt_tbl_debugfs_show(struct seq_file *seq, void *data)
{
	struct ys_np_cnt_tbl_priv *priv = seq->private;
	const struct ys_np_cnt_tbl_entry *entry = NULL;
	size_t i = 0;
	u64 val_show = 0;

	seq_printf(seq, "name %s : size %u, location %d.\n",
		   priv->name, priv->nb_entries, priv->doe_location);
	seq_printf(seq, "%-8s + %-8s\n", "idx", "value");

	mutex_lock(&priv->mlock);
	for (i = 0; i < priv->nb_entries; i++) {
		entry = &priv->entry_list[i];
		seq_printf(seq, "idx : %-8lu\n", i);

		seq_hex_dump(seq, "val : ", DUMP_PREFIX_NONE, 32, 1,
			     entry, priv->entry_len, false);
		seq_puts(seq, "\n");
	}
	mutex_unlock(&priv->mlock);

	val_show = atomic64_read(&priv->doe_stats.counter_load_total);
	seq_printf(seq, "%-30s: %llu\n", "Counter load total", val_show);

	val_show = atomic64_read(&priv->doe_stats.counter_load_fail);
	if (val_show)
		seq_printf(seq, "%-30s: %llu\n", "Counter load fail total", val_show);

	val_show = atomic64_read(&priv->doe_stats.array_load_total);
	seq_printf(seq, "%-30s: %llu\n", "Array load total", val_show);

	val_show = atomic64_read(&priv->doe_stats.array_load_fail);
	if (val_show)
		seq_printf(seq, "%-30s: %llu\n", "Array load fail total", val_show);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ys_np_cnt_tbl_debugfs);

enum { YS_NP_DOE_CHANNEL_NUM = 2 };

static int ys_k2u_np_settle_doe(struct ys_np_sw *np_sw, const int *prefer,
				size_t perfer_len, int *location)
{
	int doe_location[YS_NP_DOE_CHANNEL_NUM] = {0};
	int i = 0;
	size_t k = 0;

	for (i = 0; i < YS_NP_DOE_CHANNEL_NUM; i++)
		doe_location[i] = hados_doe_get_channel_type(np_sw->bus_id, i);

	for (k = 0; k < perfer_len; k++) {
		for (i = 0; i < YS_NP_DOE_CHANNEL_NUM; i++) {
			if (prefer[k] == doe_location[i]) {
				*location = prefer[k];
				return 0;
			}
		}
	}
	return -EINVAL;
}

static int ys_k2u_np_get_doe_location(struct ys_np_sw *np_sw, int *location)
{
	const int smartnic_lc_prefer[] = { DOE_LOCATION_DDR, DOE_LOCATION_HOST_DDR };
	const int dpu_lc_prefer[] = { DOE_LOCATION_DDR, DOE_LOCATION_SOC_DDR };

	switch (np_sw->mode) {
	case MODE_LEGACY:
		*location = DOE_LOCATION_RAM;
		return 0;

	case MODE_SMART_NIC:
		return ys_k2u_np_settle_doe(np_sw, smartnic_lc_prefer,
					    ARRAY_SIZE(smartnic_lc_prefer), location);

	case MODE_DPU_SOC:
		return ys_k2u_np_settle_doe(np_sw, dpu_lc_prefer,
					    ARRAY_SIZE(dpu_lc_prefer), location);

	default:
		return -EOPNOTSUPP;
	}
}

static struct ys_np_table *ys_k2u_np_cnt_tbl_create(struct ys_np *np)
{
	const char *tbl_name = "np_interrnal_cnt_table";
	const int tbl_id = YS_NP_CNT_TBL_ID;
	u32 tbl_size = 1024;
	const u16 val_len = 16;
	struct hw_advance_cfg extra = {
		.shared_tbl    = 0,
		.l1_cache_ways = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		.l2_cache_ways = 0,

		.tbl_type      = DOE_TABLE_COUNTER,
		.location      = DOE_LOCATION_DDR,
		.endian        = 1,
		.ddr_mode      = 0,
	};
	const unsigned long work_interval = 10000;
	const u8 op_enable = 1;
	const u8 clear_data = 1;
	const u8 pri = 0;

	int ret = 0;
	u32 i = 0;
	struct ys_np_table *table = NULL;
	struct ys_np_cnt_tbl_priv *priv = NULL;
	char name[32] = {0};
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	struct ys_np_sw *np_sw = np->sw;
	size_t alloc_size = 0;
	int location = 0;

	if (!np_sw)
		return NULL;

	ret = ys_k2u_np_get_doe_location(np_sw, &location);
	if (ret) {
		ys_np_err("Failed to get doe location, ret %d\n", ret);
		return NULL;
	}
	extra.location = location;
	ys_np_info("Doe location %d, for mode %d.\n", extra.location, np_sw->mode);
	/* Overwrite the size as it's on ram. */
	if (extra.location == DOE_LOCATION_RAM)
		tbl_size = 64;

	if (np_sw->doe_ops->tbl_valid(np_sw->bus_id, tbl_id))
		np_sw->doe_ops->delete_arraytbl(np_sw->bus_id, tbl_id, 0);
	ret = np_sw->doe_ops->create_arraytbl(np_sw->bus_id, tbl_id, tbl_size, val_len, &extra, 0);
	if (ret) {
		ys_np_err("Failed to create table %d, ret %d\n", tbl_id, ret);
		goto fail;
	}

	for (i = 0; i < tbl_size; i++) {
		ret = np_sw->doe_ops->counter_enable(np_sw->bus_id, tbl_id, i, op_enable,
						     pri, clear_data, 0);
		if (ret) {
			ys_np_err("Failed to enable index %u, table %d, ret %d\n", i, tbl_id, ret);
			goto fail;
		}
	}

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto fail;

	alloc_size = sizeof(*priv) + sizeof(struct ys_np_cnt_tbl_entry) * tbl_size;
	// struct_size is in <linux/overflow.h> not valid for all kernel version.
	//priv = kzalloc(struct_size(priv, entry_list, tbl_size), GFP_KERNEL);
	priv = kzalloc(alloc_size, GFP_KERNEL);
	if (!priv)
		goto fail;

	snprintf(name, sizeof(name), "table_%d", tbl_id);
	priv->debugfs_file = debugfs_create_file(name, 0400, np_sw->debugfs_root,
						 priv, &ys_np_cnt_tbl_debugfs_fops);
	if (IS_ERR(priv->debugfs_file)) {
		ys_np_err("Failed to create debugfs file %s\n", name);
		priv->debugfs_file = NULL;
	}

	mutex_init(&priv->mlock);
	priv->np_sw = np->sw;
	priv->work_interval = msecs_to_jiffies(work_interval);
	priv->nb_entries = tbl_size;
	priv->id = tbl_id;
	priv->entry_len = val_len;
	priv->doe_location = extra.location;
	atomic64_set(&priv->doe_stats.counter_load_total, 0);
	atomic64_set(&priv->doe_stats.counter_load_fail, 0);
	atomic64_set(&priv->doe_stats.array_load_total, 0);
	atomic64_set(&priv->doe_stats.array_load_fail, 0);
	snprintf(priv->name, sizeof(priv->name), "%s", tbl_name);
	table->priv = priv;

	if (extra.location == DOE_LOCATION_RAM)
		priv->walk_update = ys_np_cnt_tbl_walk_update_array_load;
	else
		priv->walk_update = ys_np_cnt_tbl_walk_update_counter_load;
	INIT_DELAYED_WORK(&priv->np_work, ys_k2u_np_cnt_work);
	queue_delayed_work(np_sw->wq, &priv->np_work, priv->work_interval);
	return table;
fail:
	if (table)
		kfree(table->priv);
	kfree(table);
	return NULL;
}

static void ys_k2u_np_cnt_tbl_destroy(struct ys_np *np, struct ys_np_table *table)
{
	struct ys_np_cnt_tbl_priv *priv = table->priv;

	cancel_delayed_work_sync(&priv->np_work);
	debugfs_remove(priv->debugfs_file);

	kfree(priv);
	kfree(table);
}

static const struct ys_np_tbl_ops ys_np_cnt_tbl_ops = {
	.name = "NP counter table",
	.mode_bitmap = BIT(MODE_LEGACY) | BIT(MODE_SMART_NIC) | BIT(MODE_DPU_SOC),
	.create = ys_k2u_np_cnt_tbl_create,
	.destroy = ys_k2u_np_cnt_tbl_destroy,
};

static const struct ys_np_tbl_ops *ys_np_tbl_ops_list[] = {
	&ys_np_cnt_tbl_ops,
};

int ys_k2u_np_doe_tbl_init(struct ys_np *np)
{
	int i = 0;
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	const struct ys_np_tbl_ops *tbl_ops = NULL;
	struct ys_np_table *table = NULL;
	struct ys_np_sw *np_sw = np->sw;

	for (i = 0; i < ARRAY_SIZE(ys_np_tbl_ops_list); i++) {
		tbl_ops = ys_np_tbl_ops_list[i];
		if (!(tbl_ops->mode_bitmap & BIT(np_sw->mode)))
			continue;

		ys_np_info("np doe table create: %s.", tbl_ops->name);
		table = tbl_ops->create(np);
		if (!table) {
			ys_np_info("Failed to run %s create.", tbl_ops->name);
			goto fail;
		}

		table->ops = tbl_ops;
		list_add(&table->node, &np_sw->table_head);
	}

	ys_np_info("np doe table init success.");
	return 0;

fail:
	ys_k2u_np_doe_tbl_fini(np);
	return -EINVAL;
}

void ys_k2u_np_doe_tbl_fini(struct ys_np *np)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(np->pdev);
	struct ys_np_table *table = NULL;
	struct ys_np_table *tmp = NULL;
	struct ys_np_sw *np_sw = np->sw;

	list_for_each_entry_safe(table, tmp, &np_sw->table_head, node) {
		ys_np_info("np doe table destroy: %s.", table->ops->name);
		list_del(&table->node);
		table->ops->destroy(np, table);
	}
	ys_np_info("np doe table fini done.");
}
