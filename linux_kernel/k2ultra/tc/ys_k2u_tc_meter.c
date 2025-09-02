// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_tc_priv.h"

static void
find_att_factor_and_cir(u64 rate, int *best_att_factor, int *best_cir)
{
	// Constants
	int MAX_ATT_FACTOR = 15;
	int MAX_CIR = 2047;
	u64 BASE = 10000000; // 10^7 for integer calculations, 0.1us
	int att_factor;
	int cir;

	// Variables to track the best match
	u64 min_diff = ~0UL;  // Initialize to maximum u64
	*best_att_factor = -1;
	*best_cir = -1;

	// Loop through possible values of att_factor and CIR
	for (att_factor = 0; att_factor <= MAX_ATT_FACTOR; att_factor++) {
		// Calculate the divisor as 2^att_factor (using bit shifting for integer power)
		u64 divisor = 1UL << att_factor;

		for (cir = 1; cir <= MAX_CIR; cir++) {
			// Calculate the rate for the current att_factor and CIR
			u64 cal_rate = (cir * BASE) / divisor;

			// Calculate the difference between calculated rate and the target rate
			u64 diff = (cal_rate > rate) ? (cal_rate - rate) : (rate - cal_rate);

			// Update the best matching values if this is a closer match
			if (diff < min_diff) {
				min_diff = diff;
				*best_att_factor = att_factor;
				*best_cir = cir;
			}
		}
	}
}

static struct ys_tc_meter *
ys_tc_meter_alloc(struct ys_tc_priv *tc_priv,
		  __u32 index, __u64 rate, __u32 burst)
{
	struct ys_tc_meter *meter;
	struct ys_tc_table_entry *entry;
	struct meter_config *data;
	int best_att_factor, best_cir;

	meter = kzalloc(sizeof(*meter), GFP_KERNEL);
	if (!meter)
		return NULL;

	meter->tc_priv = tc_priv;
	meter->index = index;
	meter->rate_bytes_ps = rate;
	meter->burst = burst;

	entry = ys_tc_table_alloc(tc_priv, YS_TC_TABLE_ID_METER, NULL, NULL);
	if (!entry) {
		ys_tc_debug("meter table alloc failed\n");
		goto failed;
	}
	meter->meter_tbl_entry = entry;

	entry = ys_tc_table_alloc(tc_priv, YS_TC_TABLE_ID_COMMCNT, NULL, NULL);
	if (!entry) {
		ys_tc_debug("meter green cnt table alloc failed\n");
		goto failed;
	}
	meter->green_cnt_entry = entry;

	entry = ys_tc_table_alloc(tc_priv, YS_TC_TABLE_ID_COMMCNT, NULL, NULL);
	if (!entry) {
		ys_tc_debug("meter red cnt table alloc failed\n");
		goto failed;
	}
	meter->red_cnt_entry = entry;

	data = (struct meter_config *)meter->meter_tbl_entry->data;

	find_att_factor_and_cir(rate, &best_att_factor, &best_cir);
	if (best_att_factor != -1 && best_cir != -1) {
		data->ciir = cpu_to_be16(best_cir);
		data->cbs = cpu_to_be32(burst);
		data->pir = cpu_to_be16(best_cir);
		data->pbs = cpu_to_be32(burst);
		data->att_factor = best_att_factor;
	} else {
		goto failed;
	}

	refcount_set(&meter->refcnt, 1);

	ys_tc_debug("index %d, rate %llu, burst %u, pir = %d, pbs = %d\n",
		    index, rate, burst, data->pir, data->pbs);

	return meter;
failed:
	if (meter->meter_tbl_entry)
		ys_tc_table_free(tc_priv, meter->meter_tbl_entry);
	if (meter->green_cnt_entry)
		ys_tc_table_free(tc_priv, meter->green_cnt_entry);
	if (meter->red_cnt_entry)
		ys_tc_table_free(tc_priv, meter->red_cnt_entry);
	kfree(meter);
	return NULL;
}

static void
ys_tc_meter_update(struct ys_tc_priv *tc_priv,
		   struct ys_tc_meter *meter,
		   __u32 index, __u64 rate, __u32 burst)
{
	struct meter_config *data;
	int ret;
	int best_att_factor, best_cir;

	meter->rate_bytes_ps = rate;
	meter->burst = burst;

	data = (struct meter_config *)meter->meter_tbl_entry->data;
	find_att_factor_and_cir(rate, &best_att_factor, &best_cir);
	if (best_att_factor != -1 && best_cir != -1) {
		data->ciir = cpu_to_be16(best_cir);
		data->cbs = cpu_to_be32(burst);
		data->pir = cpu_to_be16(best_cir);
		data->pbs = cpu_to_be32(burst);
		data->att_factor = best_att_factor;
	}

	ys_tc_debug("index %d, rate %llu, burst %u, pir = %d, pbs = %d\n",
		    index, rate, burst, data->pir, data->pbs);

	ret = ys_tc_table_update(tc_priv, meter->meter_tbl_entry);
	if (ret)
		ys_tc_debug("meter table update failed\n");
}

static int
ys_tc_meter_add(struct ys_tc_priv *tc_priv,
		struct ys_tc_meter *meter)
{
	int ret;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	ret = ys_tc_table_add(tc_priv, meter->meter_tbl_entry);
	if (ret) {
		ys_tc_debug("meter table add failed\n");
		return ret;
	}

	ret = ys_tc_table_add(tc_priv, meter->green_cnt_entry);
	if (ret) {
		ys_tc_debug("meter green cnt table add failed\n");
		goto green_failed;
	}

	ret = ys_tc_table_add(tc_priv, meter->red_cnt_entry);
	if (ret) {
		ys_tc_debug("meter red cnt table add failed\n");
		goto red_failed;
	}

	ret = rhashtable_insert_fast(&switchdev->meter_ht, &meter->node,
				     *switchdev->meter_ht_params);
	if (ret) {
		ys_tc_err("failed to add meter to hash table\n");
		goto hash_failed;
	}

	return ret;

hash_failed:
	ys_tc_table_del_and_free(tc_priv, meter->red_cnt_entry);
	meter->red_cnt_entry = NULL;
red_failed:
	ys_tc_table_del_and_free(tc_priv, meter->green_cnt_entry);
	meter->green_cnt_entry = NULL;
green_failed:
	ys_tc_table_del_and_free(tc_priv, meter->meter_tbl_entry);
	meter->meter_tbl_entry = NULL;
	return ret;
}

struct ys_tc_meter *
ys_tc_meter_lookup(struct ys_tc_priv *tc_priv, __u32 index)
{
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	struct ys_tc_meter *meter;

	meter = rhashtable_lookup(&switchdev->meter_ht, &index,
				  *switchdev->meter_ht_params);
	return meter;
}

static void
ys_tc_meter_del_and_free(struct ys_tc_priv *tc_priv, struct ys_tc_meter *meter)
{
	if (!meter)
		return;

	ys_tc_table_del_and_free(tc_priv, meter->meter_tbl_entry);
	meter->meter_tbl_entry = NULL;

	ys_tc_table_del_and_free(tc_priv, meter->green_cnt_entry);
	meter->green_cnt_entry = NULL;

	ys_tc_table_del_and_free(tc_priv, meter->red_cnt_entry);
	meter->red_cnt_entry = NULL;

	kfree_rcu(meter, rcu_head);
}

static void
ys_tc_meter_free(struct ys_tc_priv *tc_priv,
		 struct ys_tc_meter *meter)
{
	if (!meter)
		return;

	if (meter->meter_tbl_entry)
		ys_tc_table_free(tc_priv, meter->meter_tbl_entry);
	if (meter->green_cnt_entry)
		ys_tc_table_free(tc_priv, meter->green_cnt_entry);
	if (meter->red_cnt_entry)
		ys_tc_table_free(tc_priv, meter->red_cnt_entry);

	kfree(meter);
}

static int ys_tc_valid_act(struct ys_tc_priv *tc_priv,
			   struct flow_offload_action *fl_act)
{
	int i;
	struct flow_action_entry *action;

	if (fl_act->action.num_entries != 1)
		return -EOPNOTSUPP;

	flow_action_for_each(i, action, &fl_act->action) {
		if (action->id != FLOW_ACTION_POLICE)
			return -EOPNOTSUPP;
		if (action->police.exceed.act_id != FLOW_ACTION_DROP)
			return -EOPNOTSUPP;
		if (action->police.notexceed.act_id != FLOW_ACTION_PIPE &&
		    action->police.notexceed.act_id != FLOW_ACTION_ACCEPT)
			return -EOPNOTSUPP;
		if (action->police.rate_bytes_ps == 0 ||
		    action->police.burst == 0)
			return -EINVAL;
	}

	return 0;
}

void ys_tc_meter_put(struct ys_tc_priv *tc_priv, struct ys_tc_meter *meter)
{
	if (refcount_dec_and_test(&meter->refcnt))
		ys_tc_meter_del_and_free(tc_priv, meter);
}

int ys_tc_add_act(struct ys_tc_priv *tc_priv,
		  struct flow_offload_action *fl_act)
{
	int ret;
	__u32 index;
	__u64 rate;
	__u32 burst;
	struct ys_tc_meter *meter;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	ret = ys_tc_valid_act(tc_priv, fl_act);
	if (ret) {
		ys_tc_debug("act valid failed\n");
		return ret;
	}

	index = fl_act->action.entries[0].hw_index;
	rate = fl_act->action.entries[0].police.rate_bytes_ps;
	burst = fl_act->action.entries[0].police.burst;

	meter = rhashtable_lookup_fast(&switchdev->meter_ht, &fl_act->index,
				       *switchdev->meter_ht_params);
	if (meter) {
		if (!refcount_inc_not_zero(&meter->refcnt))
			return -ENOENT;

		if (meter->rate_bytes_ps == rate && meter->burst == burst) {
			ys_tc_debug("meter 0x%x already exist\n", index);
			ys_tc_meter_put(tc_priv, meter);
			return -EEXIST;
		}
		ys_tc_meter_update(tc_priv, meter, index, rate, burst);
		ys_tc_meter_put(tc_priv, meter);
		return 0;
	}

	meter = ys_tc_meter_alloc(tc_priv, index, rate, burst);
	if (!meter) {
		ys_tc_debug("meter alloc failed\n");
		return -ENOMEM;
	}

	ret = ys_tc_meter_add(tc_priv, meter);
	if (ret) {
		ys_tc_debug("meter add failed\n");
		ys_tc_meter_free(tc_priv, meter);
		return ret;
	}

	return 0;
}

int ys_tc_del_act(struct ys_tc_priv *tc_priv,
		  struct flow_offload_action *fl_act)
{
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	struct ys_tc_meter *meter;
	int ret = 0;

	meter = rhashtable_lookup_fast(&switchdev->meter_ht, &fl_act->index,
				       *switchdev->meter_ht_params);
	if (!meter) {
		ys_tc_debug("meter 0x%x lookup failed\n", fl_act->index);
		ret = -ENOENT;
		goto fail;
	}
	WARN_ON(rhashtable_remove_fast(&switchdev->meter_ht, &meter->node,
				       *switchdev->meter_ht_params));

	ys_tc_meter_put(tc_priv, meter);

	return 0;

fail:
	return ret;
}

int ys_tc_stat_act(struct ys_tc_priv *tc_priv,
		   struct flow_offload_action *fl_act)
{
	struct ys_tc_meter *meter;
	struct ys_tc_table_entry *entry;
	struct ys_tc_table_commcnt_data *data;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	__u64 used = 0;
	u64 new_pkts = 0;
	u64 new_bytes = 0;
	u64 delta_pkts = 0;
	u64 delta_bytes = 0;
	u64 new_drops = 0;
	u64 delta_drops = 0;

	rcu_read_lock();
	meter = rhashtable_lookup(&switchdev->meter_ht, &fl_act->index,
				  *switchdev->meter_ht_params);
	if (!meter || !refcount_inc_not_zero(&meter->refcnt)) {
		ys_tc_debug("meter 0x%x lookup failed\n", fl_act->index);
		rcu_read_unlock();
		return -ENOENT;
	}
	rcu_read_unlock();

	entry = meter->green_cnt_entry;
	data = (struct ys_tc_table_commcnt_data *)(entry->data);
	spin_lock(&data->cache_slock);
	new_pkts = be64_to_cpu(data->be_pkts);
	new_bytes = be64_to_cpu(data->be_bytes);

	if (new_pkts > data->last_pkts && new_bytes > data->last_bytes) {
		delta_pkts = new_pkts - data->last_pkts;
		delta_bytes = new_bytes - data->last_bytes;

		data->last_pkts = new_pkts;
		data->last_bytes = new_bytes;
		used = data->used;
	}
	spin_unlock(&data->cache_slock);

	entry = meter->red_cnt_entry;
	data = (struct ys_tc_table_commcnt_data *)(entry->data);
	spin_lock(&data->cache_slock);
	new_drops = be64_to_cpu(data->be_pkts);
	if (new_drops > data->last_pkts) {
		delta_drops = new_drops - data->last_pkts;
		data->last_pkts = new_drops;
	}
	spin_unlock(&data->cache_slock);
	if (!delta_pkts)
		goto out;

	flow_stats_update(&fl_act->stats, delta_bytes, delta_pkts, delta_drops, used,
			  FLOW_ACTION_HW_STATS_DELAYED);

out:
	ys_tc_meter_put(tc_priv, meter);
	return 0;
}

static struct rhashtable_params meter_ht_params = {
	.head_offset = offsetof(struct ys_tc_meter, node),
	.key_offset = offsetof(struct ys_tc_meter, index),
	.key_len = sizeof_field(struct ys_tc_meter, index),
	.automatic_shrinking = true,
};

int ys_tc_meter_init(struct ys_tc_priv *tc_priv)
{
	int ret;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	ret = rhashtable_init(&switchdev->meter_ht, &meter_ht_params);
	if (ret != 0) {
		ys_tc_err("create tc meter hashtable failed\n");
		return ret;
	}
	switchdev->meter_ht_params = &meter_ht_params;

	return 0;
}

static void meter_ht_release(void *ptr, void *arg)
{
	struct ys_tc_meter *meter = ptr;
	struct ys_tc_priv *tc_priv = NULL;

	if (!meter)
		return;
	tc_priv = meter->tc_priv;
	ys_tc_meter_del_and_free(tc_priv, meter);
}

void ys_tc_meter_exit(struct ys_tc_priv *tc_priv)
{
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	rhashtable_free_and_destroy(&switchdev->meter_ht, meter_ht_release, NULL);
}
