// SPDX-License-Identifier: GPL-2.0
#include "ys_debug.h"
#include "ys_k2ulan_cuckoo.h"

#define K2ULAN_CUCKOO_BACKUP	0
#define K2ULAN_CUCKOO_CACHED	0

static u32 ys_k2ulan_cuckoo_uc_crc32_48bit(const u8 *key, u32 seed)
{
	u32 crc = 0;
	u8 c[32] = { 0 };
	u8 q[32] = { 0 };
	u8 in[48] = { 0 };
	int i, j;

	for (i = 0; i < 32; i++)
		q[i] = (seed >> i) & 0x1;

	for (i = 0; i < 6; i++)
		for (j = 0; j < 8; j++)
			in[i * 8 + j] = (key[i] >> j) & 0x1;

	c[0] =
	    q[0] ^ q[8] ^ q[9] ^ q[10] ^ q[12] ^ q[13] ^ q[14] ^ q[15] ^ q[16] ^
	    q[18] ^ q[21] ^ q[28] ^ q[29] ^ q[31] ^ in[0] ^ in[6] ^ in[9] ^
	    in[10] ^ in[12] ^ in[16] ^ in[24] ^ in[25] ^ in[26] ^ in[28] ^
	    in[29] ^ in[30] ^ in[31] ^ in[32] ^ in[34] ^ in[37] ^ in[44] ^
	    in[45] ^ in[47];
	c[1] =
	    q[0] ^ q[1] ^ q[8] ^ q[11] ^ q[12] ^ q[17] ^ q[18] ^ q[19] ^ q[21] ^
	    q[22] ^ q[28] ^ q[30] ^ q[31] ^ in[0] ^ in[1] ^ in[6] ^ in[7] ^
	    in[9] ^ in[11] ^ in[12] ^ in[13] ^ in[16] ^ in[17] ^ in[24] ^ in[27]
	    ^ in[28] ^ in[33] ^ in[34] ^ in[35] ^ in[37] ^ in[38] ^ in[44] ^
	    in[46] ^ in[47];
	c[2] =
	    q[0] ^ q[1] ^ q[2] ^ q[8] ^ q[10] ^ q[14] ^ q[15] ^ q[16] ^ q[19] ^
	    q[20] ^ q[21] ^ q[22] ^ q[23] ^ q[28] ^ in[0] ^ in[1] ^ in[2] ^
	    in[6] ^ in[7] ^ in[8] ^ in[9] ^ in[13] ^ in[14] ^ in[16] ^ in[17] ^
	    in[18] ^ in[24] ^ in[26] ^ in[30] ^ in[31] ^ in[32] ^ in[35] ^
	    in[36] ^ in[37] ^ in[38] ^ in[39] ^ in[44];
	c[3] =
	    q[1] ^ q[2] ^ q[3] ^ q[9] ^ q[11] ^ q[15] ^ q[16] ^ q[17] ^ q[20] ^
	    q[21] ^ q[22] ^ q[23] ^ q[24] ^ q[29] ^ in[1] ^ in[2] ^ in[3] ^
	    in[7] ^ in[8] ^ in[9] ^ in[10] ^ in[14] ^ in[15] ^ in[17] ^ in[18] ^
	    in[19] ^ in[25] ^ in[27] ^ in[31] ^ in[32] ^ in[33] ^ in[36] ^
	    in[37] ^ in[38] ^ in[39] ^ in[40] ^ in[45];
	c[4] =
	    q[2] ^ q[3] ^ q[4] ^ q[8] ^ q[9] ^ q[13] ^ q[14] ^ q[15] ^ q[17] ^
	    q[22] ^ q[23] ^ q[24] ^ q[25] ^ q[28] ^ q[29] ^ q[30] ^ q[31] ^
	    in[0] ^ in[2] ^ in[3] ^ in[4] ^ in[6] ^ in[8] ^ in[11] ^ in[12] ^
	    in[15] ^ in[18] ^ in[19] ^ in[20] ^ in[24] ^ in[25] ^ in[29] ^
	    in[30] ^ in[31] ^ in[33] ^ in[38] ^ in[39] ^ in[40] ^ in[41] ^
	    in[44] ^ in[45] ^ in[46] ^ in[47];
	c[5] =
	    q[3] ^ q[4] ^ q[5] ^ q[8] ^ q[12] ^ q[13] ^ q[21] ^ q[23] ^ q[24] ^
	    q[25] ^ q[26] ^ q[28] ^ q[30] ^ in[0] ^ in[1] ^ in[3] ^ in[4] ^
	    in[5] ^ in[6] ^ in[7] ^ in[10] ^ in[13] ^ in[19] ^ in[20] ^ in[21] ^
	    in[24] ^ in[28] ^ in[29] ^ in[37] ^ in[39] ^ in[40] ^ in[41] ^
	    in[42] ^ in[44] ^ in[46];
	c[6] =
	    q[4] ^ q[5] ^ q[6] ^ q[9] ^ q[13] ^ q[14] ^ q[22] ^ q[24] ^ q[25] ^
	    q[26] ^ q[27] ^ q[29] ^ q[31] ^ in[1] ^ in[2] ^ in[4] ^ in[5] ^
	    in[6] ^ in[7] ^ in[8] ^ in[11] ^ in[14] ^ in[20] ^ in[21] ^ in[22] ^
	    in[25] ^ in[29] ^ in[30] ^ in[38] ^ in[40] ^ in[41] ^ in[42] ^
	    in[43] ^ in[45] ^ in[47];
	c[7] =
	    q[0] ^ q[5] ^ q[6] ^ q[7] ^ q[8] ^ q[9] ^ q[12] ^ q[13] ^ q[16] ^
	    q[18] ^ q[21] ^ q[23] ^ q[25] ^ q[26] ^ q[27] ^ q[29] ^ q[30] ^
	    q[31] ^ in[0] ^ in[2] ^ in[3] ^ in[5] ^ in[7] ^ in[8] ^ in[10] ^
	    in[15] ^ in[16] ^ in[21] ^ in[22] ^ in[23] ^ in[24] ^ in[25] ^
	    in[28] ^ in[29] ^ in[32] ^ in[34] ^ in[37] ^ in[39] ^ in[41] ^
	    in[42] ^ in[43] ^ in[45] ^ in[46] ^ in[47];
	c[8] =
	    q[1] ^ q[6] ^ q[7] ^ q[12] ^ q[15] ^ q[16] ^ q[17] ^ q[18] ^ q[19] ^
	    q[21] ^ q[22] ^ q[24] ^ q[26] ^ q[27] ^ q[29] ^ q[30] ^ in[0] ^
	    in[1] ^ in[3] ^ in[4] ^ in[8] ^ in[10] ^ in[11] ^ in[12] ^ in[17] ^
	    in[22] ^ in[23] ^ in[28] ^ in[31] ^ in[32] ^ in[33] ^ in[34] ^
	    in[35] ^ in[37] ^ in[38] ^ in[40] ^ in[42] ^ in[43] ^ in[45] ^
	    in[46];
	c[9] =
	    q[2] ^ q[7] ^ q[8] ^ q[13] ^ q[16] ^ q[17] ^ q[18] ^ q[19] ^ q[20] ^
	    q[22] ^ q[23] ^ q[25] ^ q[27] ^ q[28] ^ q[30] ^ q[31] ^ in[1] ^
	    in[2] ^ in[4] ^ in[5] ^ in[9] ^ in[11] ^ in[12] ^ in[13] ^ in[18] ^
	    in[23] ^ in[24] ^ in[29] ^ in[32] ^ in[33] ^ in[34] ^ in[35] ^
	    in[36] ^ in[38] ^ in[39] ^ in[41] ^ in[43] ^ in[44] ^ in[46] ^
	    in[47];
	c[10] =
	    q[0] ^ q[3] ^ q[10] ^ q[12] ^ q[13] ^ q[15] ^ q[16] ^ q[17] ^ q[19]
	    ^ q[20] ^ q[23] ^ q[24] ^ q[26] ^ in[0] ^ in[2] ^ in[3] ^ in[5] ^
	    in[9] ^ in[13] ^ in[14] ^ in[16] ^ in[19] ^ in[26] ^ in[28] ^ in[29]
	    ^ in[31] ^ in[32] ^ in[33] ^ in[35] ^ in[36] ^ in[39] ^ in[40] ^
	    in[42];
	c[11] =
	    q[0] ^ q[1] ^ q[4] ^ q[8] ^ q[9] ^ q[10] ^ q[11] ^ q[12] ^ q[15] ^
	    q[17] ^ q[20] ^ q[24] ^ q[25] ^ q[27] ^ q[28] ^ q[29] ^ q[31] ^
	    in[0] ^ in[1] ^ in[3] ^ in[4] ^ in[9] ^ in[12] ^ in[14] ^ in[15] ^
	    in[16] ^ in[17] ^ in[20] ^ in[24] ^ in[25] ^ in[26] ^ in[27] ^
	    in[28] ^ in[31] ^ in[33] ^ in[36] ^ in[40] ^ in[41] ^ in[43] ^
	    in[44] ^ in[45] ^ in[47];
	c[12] =
	    q[1] ^ q[2] ^ q[5] ^ q[8] ^ q[11] ^ q[14] ^ q[15] ^ q[25] ^ q[26] ^
	    q[30] ^ q[31] ^ in[0] ^ in[1] ^ in[2] ^ in[4] ^ in[5] ^ in[6] ^
	    in[9] ^ in[12] ^ in[13] ^ in[15] ^ in[17] ^ in[18] ^ in[21] ^ in[24]
	    ^ in[27] ^ in[30] ^ in[31] ^ in[41] ^ in[42] ^ in[46] ^ in[47];
	c[13] =
	    q[0] ^ q[2] ^ q[3] ^ q[6] ^ q[9] ^ q[12] ^ q[15] ^ q[16] ^ q[26] ^
	    q[27] ^ q[31] ^ in[1] ^ in[2] ^ in[3] ^ in[5] ^ in[6] ^ in[7] ^
	    in[10] ^ in[13] ^ in[14] ^ in[16] ^ in[18] ^ in[19] ^ in[22] ^
	    in[25] ^ in[28] ^ in[31] ^ in[32] ^ in[42] ^ in[43] ^ in[47];
	c[14] =
	    q[1] ^ q[3] ^ q[4] ^ q[7] ^ q[10] ^ q[13] ^ q[16] ^ q[17] ^ q[27] ^
	    q[28] ^ in[2] ^ in[3] ^ in[4] ^ in[6] ^ in[7] ^ in[8] ^ in[11] ^
	    in[14] ^ in[15] ^ in[17] ^ in[19] ^ in[20] ^ in[23] ^ in[26] ^
	    in[29] ^ in[32] ^ in[33] ^ in[43] ^ in[44];
	c[15] =
	    q[0] ^ q[2] ^ q[4] ^ q[5] ^ q[8] ^ q[11] ^ q[14] ^ q[17] ^ q[18] ^
	    q[28] ^ q[29] ^ in[3] ^ in[4] ^ in[5] ^ in[7] ^ in[8] ^ in[9] ^
	    in[12] ^ in[15] ^ in[16] ^ in[18] ^ in[20] ^ in[21] ^ in[24] ^
	    in[27] ^ in[30] ^ in[33] ^ in[34] ^ in[44] ^ in[45];
	c[16] =
	    q[1] ^ q[3] ^ q[5] ^ q[6] ^ q[8] ^ q[10] ^ q[13] ^ q[14] ^ q[16] ^
	    q[19] ^ q[21] ^ q[28] ^ q[30] ^ q[31] ^ in[0] ^ in[4] ^ in[5] ^
	    in[8] ^ in[12] ^ in[13] ^ in[17] ^ in[19] ^ in[21] ^ in[22] ^ in[24]
	    ^ in[26] ^ in[29] ^ in[30] ^ in[32] ^ in[35] ^ in[37] ^ in[44] ^
	    in[46] ^ in[47];
	c[17] =
	    q[2] ^ q[4] ^ q[6] ^ q[7] ^ q[9] ^ q[11] ^ q[14] ^ q[15] ^ q[17] ^
	    q[20] ^ q[22] ^ q[29] ^ q[31] ^ in[1] ^ in[5] ^ in[6] ^ in[9] ^
	    in[13] ^ in[14] ^ in[18] ^ in[20] ^ in[22] ^ in[23] ^ in[25] ^
	    in[27] ^ in[30] ^ in[31] ^ in[33] ^ in[36] ^ in[38] ^ in[45] ^
	    in[47];
	c[18] =
	    q[3] ^ q[5] ^ q[7] ^ q[8] ^ q[10] ^ q[12] ^ q[15] ^ q[16] ^ q[18] ^
	    q[21] ^ q[23] ^ q[30] ^ in[2] ^ in[6] ^ in[7] ^ in[10] ^ in[14] ^
	    in[15] ^ in[19] ^ in[21] ^ in[23] ^ in[24] ^ in[26] ^ in[28] ^
	    in[31] ^ in[32] ^ in[34] ^ in[37] ^ in[39] ^ in[46];
	c[19] =
	    q[0] ^ q[4] ^ q[6] ^ q[8] ^ q[9] ^ q[11] ^ q[13] ^ q[16] ^ q[17] ^
	    q[19] ^ q[22] ^ q[24] ^ q[31] ^ in[3] ^ in[7] ^ in[8] ^ in[11] ^
	    in[15] ^ in[16] ^ in[20] ^ in[22] ^ in[24] ^ in[25] ^ in[27] ^
	    in[29] ^ in[32] ^ in[33] ^ in[35] ^ in[38] ^ in[40] ^ in[47];
	c[20] =
	    q[0] ^ q[1] ^ q[5] ^ q[7] ^ q[9] ^ q[10] ^ q[12] ^ q[14] ^ q[17] ^
	    q[18] ^ q[20] ^ q[23] ^ q[25] ^ in[4] ^ in[8] ^ in[9] ^ in[12] ^
	    in[16] ^ in[17] ^ in[21] ^ in[23] ^ in[25] ^ in[26] ^ in[28] ^
	    in[30] ^ in[33] ^ in[34] ^ in[36] ^ in[39] ^ in[41];
	c[21] =
	    q[1] ^ q[2] ^ q[6] ^ q[8] ^ q[10] ^ q[11] ^ q[13] ^ q[15] ^ q[18] ^
	    q[19] ^ q[21] ^ q[24] ^ q[26] ^ in[5] ^ in[9] ^ in[10] ^ in[13] ^
	    in[17] ^ in[18] ^ in[22] ^ in[24] ^ in[26] ^ in[27] ^ in[29] ^
	    in[31] ^ in[34] ^ in[35] ^ in[37] ^ in[40] ^ in[42];
	c[22] =
	    q[0] ^ q[2] ^ q[3] ^ q[7] ^ q[8] ^ q[10] ^ q[11] ^ q[13] ^ q[15] ^
	    q[18] ^ q[19] ^ q[20] ^ q[21] ^ q[22] ^ q[25] ^ q[27] ^ q[28] ^
	    q[29] ^ q[31] ^ in[0] ^ in[9] ^ in[11] ^ in[12] ^ in[14] ^ in[16] ^
	    in[18] ^ in[19] ^ in[23] ^ in[24] ^ in[26] ^ in[27] ^ in[29] ^
	    in[31] ^ in[34] ^ in[35] ^ in[36] ^ in[37] ^ in[38] ^ in[41] ^
	    in[43] ^ in[44] ^ in[45] ^ in[47];
	c[23] =
	    q[0] ^ q[1] ^ q[3] ^ q[4] ^ q[10] ^ q[11] ^ q[13] ^ q[15] ^ q[18] ^
	    q[19] ^ q[20] ^ q[22] ^ q[23] ^ q[26] ^ q[30] ^ q[31] ^ in[0] ^
	    in[1] ^ in[6] ^ in[9] ^ in[13] ^ in[15] ^ in[16] ^ in[17] ^ in[19] ^
	    in[20] ^ in[26] ^ in[27] ^ in[29] ^ in[31] ^ in[34] ^ in[35] ^
	    in[36] ^ in[38] ^ in[39] ^ in[42] ^ in[46] ^ in[47];
	c[24] =
	    q[0] ^ q[1] ^ q[2] ^ q[4] ^ q[5] ^ q[11] ^ q[12] ^ q[14] ^ q[16] ^
	    q[19] ^ q[20] ^ q[21] ^ q[23] ^ q[24] ^ q[27] ^ q[31] ^ in[1] ^
	    in[2] ^ in[7] ^ in[10] ^ in[14] ^ in[16] ^ in[17] ^ in[18] ^ in[20]
	    ^ in[21] ^ in[27] ^ in[28] ^ in[30] ^ in[32] ^ in[35] ^ in[36] ^
	    in[37] ^ in[39] ^ in[40] ^ in[43] ^ in[47];
	c[25] =
	    q[1] ^ q[2] ^ q[3] ^ q[5] ^ q[6] ^ q[12] ^ q[13] ^ q[15] ^ q[17] ^
	    q[20] ^ q[21] ^ q[22] ^ q[24] ^ q[25] ^ q[28] ^ in[2] ^ in[3] ^
	    in[8] ^ in[11] ^ in[15] ^ in[17] ^ in[18] ^ in[19] ^ in[21] ^ in[22]
	    ^ in[28] ^ in[29] ^ in[31] ^ in[33] ^ in[36] ^ in[37] ^ in[38] ^
	    in[40] ^ in[41] ^ in[44];
	c[26] =
	    q[2] ^ q[3] ^ q[4] ^ q[6] ^ q[7] ^ q[8] ^ q[9] ^ q[10] ^ q[12] ^
	    q[15] ^ q[22] ^ q[23] ^ q[25] ^ q[26] ^ q[28] ^ q[31] ^ in[0] ^
	    in[3] ^ in[4] ^ in[6] ^ in[10] ^ in[18] ^ in[19] ^ in[20] ^ in[22] ^
	    in[23] ^ in[24] ^ in[25] ^ in[26] ^ in[28] ^ in[31] ^ in[38] ^
	    in[39] ^ in[41] ^ in[42] ^ in[44] ^ in[47];
	c[27] =
	    q[3] ^ q[4] ^ q[5] ^ q[7] ^ q[8] ^ q[9] ^ q[10] ^ q[11] ^ q[13] ^
	    q[16] ^ q[23] ^ q[24] ^ q[26] ^ q[27] ^ q[29] ^ in[1] ^ in[4] ^
	    in[5] ^ in[7] ^ in[11] ^ in[19] ^ in[20] ^ in[21] ^ in[23] ^ in[24]
	    ^ in[25] ^ in[26] ^ in[27] ^ in[29] ^ in[32] ^ in[39] ^ in[40] ^
	    in[42] ^ in[43] ^ in[45];
	c[28] =
	    q[4] ^ q[5] ^ q[6] ^ q[8] ^ q[9] ^ q[10] ^ q[11] ^ q[12] ^ q[14] ^
	    q[17] ^ q[24] ^ q[25] ^ q[27] ^ q[28] ^ q[30] ^ in[2] ^ in[5] ^
	    in[6] ^ in[8] ^ in[12] ^ in[20] ^ in[21] ^ in[22] ^ in[24] ^ in[25]
	    ^ in[26] ^ in[27] ^ in[28] ^ in[30] ^ in[33] ^ in[40] ^ in[41] ^
	    in[43] ^ in[44] ^ in[46];
	c[29] =
	    q[5] ^ q[6] ^ q[7] ^ q[9] ^ q[10] ^ q[11] ^ q[12] ^ q[13] ^ q[15] ^
	    q[18] ^ q[25] ^ q[26] ^ q[28] ^ q[29] ^ q[31] ^ in[3] ^ in[6] ^
	    in[7] ^ in[9] ^ in[13] ^ in[21] ^ in[22] ^ in[23] ^ in[25] ^ in[26]
	    ^ in[27] ^ in[28] ^ in[29] ^ in[31] ^ in[34] ^ in[41] ^ in[42] ^
	    in[44] ^ in[45] ^ in[47];
	c[30] =
	    q[6] ^ q[7] ^ q[8] ^ q[10] ^ q[11] ^ q[12] ^ q[13] ^ q[14] ^ q[16] ^
	    q[19] ^ q[26] ^ q[27] ^ q[29] ^ q[30] ^ in[4] ^ in[7] ^ in[8] ^
	    in[10] ^ in[14] ^ in[22] ^ in[23] ^ in[24] ^ in[26] ^ in[27] ^
	    in[28] ^ in[29] ^ in[30] ^ in[32] ^ in[35] ^ in[42] ^ in[43] ^
	    in[45] ^ in[46];
	c[31] =
	    q[7] ^ q[8] ^ q[9] ^ q[11] ^ q[12] ^ q[13] ^ q[14] ^ q[15] ^ q[17] ^
	    q[20] ^ q[27] ^ q[28] ^ q[30] ^ q[31] ^ in[5] ^ in[8] ^ in[9] ^
	    in[11] ^ in[15] ^ in[23] ^ in[24] ^ in[25] ^ in[27] ^ in[28] ^
	    in[29] ^ in[30] ^ in[31] ^ in[33] ^ in[36] ^ in[43] ^ in[44] ^
	    in[46] ^ in[47];

	for (i = 0; i < 32; i++)
		crc |= c[i] << i;

	return crc;
}

#if K2ULAN_CUCKOO_CACHED
static u32 ys_k2ulan_cuckoo_uc_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 11;	/* 11bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_uc_crc32_48bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

static u32 ys_k2ulan_cuckoo_uc_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 11) | (pos & 0x7FF));
}

static void ys_k2ulan_cuckoo_uc_generate_rule_data(const u8 *key, const u8 *value,
						   u32 *data)
{
	memcpy(data, value, YS_K2ULAN_CUCKOO_UC_VALUE_SIZE);
}

static void ys_k2ulan_cuckoo_uc_parse_rule_data(const u32 *data, u8 *key,
						u8 *value)
{
	u8 *p = (u8 *)data;

	/* [9:0] MAC VALUE */
	value[0] = p[0];
	value[1] = p[1] & 0x3;

	/* [63:16] Unicast MAC ADDR */
	memcpy(key, &p[2], YS_K2ULAN_CUCKOO_UC_KEY_SIZE);

	/* [10] enable flag */
	value[1] |= ((p[1] & 0x4) << 4);
}

static int ys_k2ulan_cuckoo_uc_store_rule_data(struct ys_cuckoo_table *table,
					       u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = { 0 };
	u32 index;
	u32 entry_addr;
	int i;

	table->ops->generate_rule_data(table->buckets[bucket][pos].key,
				       table->buckets[bucket][pos].value, data);

	if (bucket == YS_K2ULAN_CUCKOO_UC_BUCKET_NUM) {
		entry_addr = table->hw.waddr + 0xc000 + 0x100 * pos;
	} else {
		index = table->ops->get_ram_addr(bucket, pos);
		entry_addr = table->hw.waddr + table->value_size * index;
	}
	for (i = 0; i < table->hw.data_round; i++)
		ys_cuckoo_iowrite32(table, entry_addr + 4 * i, data[i]);

	return 0;
}

static int ys_k2ulan_cuckoo_uc_store_rule_data2file(struct ys_cuckoo_table *table,
						    u8 bucket, u32 pos)
{

	return 0;
}

#if K2ULAN_CUCKOO_BACKUP
static int ys_k2ulan_cuckoo_uc_backup_entry(struct ys_cuckoo_table *table,
					    struct ys_cuckoo_entry entry,
					    struct ys_cuckoo_kick_stream *stream,
					    struct ys_cuckoo_kick kick,
					    char *key_str, char *value_str)
{
	int i;

	if (table->buckets[YS_K2ULAN_CUCKOO_UC_BUCKET_NUM][2].is_occupied == 1) {
		ys_err("Backup entry space is already full.");
		return -1;
	}
	for (i = 0; i < 3; i++) {
		if (table->buckets[YS_K2ULAN_CUCKOO_UC_BUCKET_NUM][i].is_occupied == 0) {
			table->buckets[YS_K2ULAN_CUCKOO_UC_BUCKET_NUM][i] = entry;
			table->buckets[YS_K2ULAN_CUCKOO_UC_BUCKET_NUM][i].is_occupied = 1;
			table->buckets_entry_num[YS_K2ULAN_CUCKOO_UC_BUCKET_NUM]++;
			kick.entry = entry;
			kick.from_bucket = YS_CUCKOO_NEW_RULE;
			kick.from_pos = 0;
			kick.to_bucket = YS_K2ULAN_CUCKOO_UC_BUCKET_NUM;
			kick.to_pos = i;
			ys_cuckoo_kick_push(stream, kick);
			ys_debug("Insert key %s value %s at buckets %d pos %d",
				 key_str, value_str, YS_K2ULAN_CUCKOO_UC_BUCKET_NUM, i);

			return 0;
		}
	}

	return -1;
}
#endif

static void ys_k2ulan_cuckoo_uc_get_hw_info(struct ys_cuckoo_table *table)
{
	int i;

	table->bucket_count = YS_K2ULAN_CUCKOO_UC_BUCKET_NUM;
	table->depth = YS_K2ULAN_CUCKOO_UC_DEPTH;
	table->key_size = YS_K2ULAN_CUCKOO_UC_KEY_SIZE;
	table->value_size = YS_K2ULAN_CUCKOO_UC_VALUE_SIZE;
	table->seed_bits = YS_K2ULAN_CUCKOO_UC_SEED_BITS;
	table->mux_seed_bits = YS_K2ULAN_CUCKOO_UC_MUX_SEED_BITS;
	for (i = 0; i < table->bucket_count; i++) {
		table->hw.seed_addr[i] = YS_K2ULAN_CUCKOO_UC_SEED_ADDR(i);
		table->hw.mux_seed_addr[i] = YS_K2ULAN_CUCKOO_UC_MUX_SEED_ADDR(i);
	}
	table->hw.init_done_addr = 0;
	table->hw.waddr = YS_K2ULAN_CUCKOO_UC_WADDR;
	table->hw.raddr = YS_K2ULAN_CUCKOO_UC_RADDR;
	table->hw.data_addr = 0;
	table->hw.data_round = YS_K2ULAN_CUCKOO_UC_DATA_ROUND;
	table->hw.lock_flag_addr = YS_K2ULAN_CUCKOO_LOCK_BASE + YS_K2ULAN_CUCKOO_LOCK_FLAG;
	table->hw.lock_state_addr = YS_K2ULAN_CUCKOO_LOCK_BASE + YS_K2ULAN_CUCKOO_LOCK_STATE;
	table->hw.lock_timeout_addr = YS_K2ULAN_CUCKOO_LOCK_BASE + YS_K2ULAN_CUCKOO_LOCK_TIMEOUT;
	table->hw.lock_timeout = YS_K2ULAN_CUCKOO_LOCK_TIMEOUT_DEFAULT;
}

const struct ys_cuckoo_ops_cached k2ulan_uc_ops = {
	.get_hw_info = ys_k2ulan_cuckoo_uc_get_hw_info,
	.hash = ys_k2ulan_cuckoo_uc_hash,
	.get_ram_addr = ys_k2ulan_cuckoo_uc_get_ram_addr,
	.generate_rule_data = ys_k2ulan_cuckoo_uc_generate_rule_data,
	.parse_rule_data = ys_k2ulan_cuckoo_uc_parse_rule_data,
	.store_rule_data = ys_k2ulan_cuckoo_uc_store_rule_data,
	.store_rule_data2file = ys_k2ulan_cuckoo_uc_store_rule_data2file,
	//.backup_entry = ys_k2ulan_cuckoo_uc_backup_entry,
};
#endif //K2ULAN_CUCKOO_CACHED

static u32 ys_k2ulan_cuckoo_mc_crc32_24bit(const u8 *key, u32 seed)
{
	u32 crc = 0;
	u8 c[32] = {0};
	u8 q[32] = {0};
	u8 in[24] = {0};
	int i, j;

	for (i = 0; i < 32; i++)
		q[i] = (seed >> i) & 0x1;

	for (i = 0; i < YS_K2ULAN_CUCKOO_MC_KEY_SIZE; i++)
		for (j = 0; j < 8; j++)
			in[i * 8 + j] = (key[i] >> j) & 0x1;

	c[0] =
	    q[8] ^ q[14] ^ q[17] ^ q[18] ^ q[20] ^ q[24] ^ in[0] ^ in[6] ^ in[9]
	    ^ in[10] ^ in[12] ^ in[16];
	c[1] =
	    q[8] ^ q[9] ^ q[14] ^ q[15] ^ q[17] ^ q[19] ^ q[20] ^ q[21] ^ q[24]
	    ^ q[25] ^ in[0] ^ in[1] ^ in[6] ^ in[7] ^ in[9] ^ in[11] ^ in[12] ^
	    in[13] ^ in[16] ^ in[17];
	c[2] =
	    q[8] ^ q[9] ^ q[10] ^ q[14] ^ q[15] ^ q[16] ^ q[17] ^ q[21] ^ q[22]
	    ^ q[24] ^ q[25] ^ q[26] ^ in[0] ^ in[1] ^ in[2] ^ in[6] ^ in[7] ^
	    in[8] ^ in[9] ^ in[13] ^ in[14] ^ in[16] ^ in[17] ^ in[18];
	c[3] =
	    q[9] ^ q[10] ^ q[11] ^ q[15] ^ q[16] ^ q[17] ^ q[18] ^ q[22] ^ q[23]
	    ^ q[25] ^ q[26] ^ q[27] ^ in[1] ^ in[2] ^ in[3] ^ in[7] ^ in[8] ^
	    in[9] ^ in[10] ^ in[14] ^ in[15] ^ in[17] ^ in[18] ^ in[19];
	c[4] =
	    q[8] ^ q[10] ^ q[11] ^ q[12] ^ q[14] ^ q[16] ^ q[19] ^ q[20] ^ q[23]
	    ^ q[26] ^ q[27] ^ q[28] ^ in[0] ^ in[2] ^ in[3] ^ in[4] ^ in[6] ^
	    in[8] ^ in[11] ^ in[12] ^ in[15] ^ in[18] ^ in[19] ^ in[20];
	c[5] =
	    q[8] ^ q[9] ^ q[11] ^ q[12] ^ q[13] ^ q[14] ^ q[15] ^ q[18] ^ q[21]
	    ^ q[27] ^ q[28] ^ q[29] ^ in[0] ^ in[1] ^ in[3] ^ in[4] ^ in[5] ^
	    in[6] ^ in[7] ^ in[10] ^ in[13] ^ in[19] ^ in[20] ^ in[21];
	c[6] =
	    q[9] ^ q[10] ^ q[12] ^ q[13] ^ q[14] ^ q[15] ^ q[16] ^ q[19] ^ q[22]
	    ^ q[28] ^ q[29] ^ q[30] ^ in[1] ^ in[2] ^ in[4] ^ in[5] ^ in[6] ^
	    in[7] ^ in[8] ^ in[11] ^ in[14] ^ in[20] ^ in[21] ^ in[22];
	c[7] =
	    q[8] ^ q[10] ^ q[11] ^ q[13] ^ q[15] ^ q[16] ^ q[18] ^ q[23] ^ q[24]
	    ^ q[29] ^ q[30] ^ q[31] ^ in[0] ^ in[2] ^ in[3] ^ in[5] ^ in[7] ^
	    in[8] ^ in[10] ^ in[15] ^ in[16] ^ in[21] ^ in[22] ^ in[23];
	c[8] =
	    q[8] ^ q[9] ^ q[11] ^ q[12] ^ q[16] ^ q[18] ^ q[19] ^ q[20] ^ q[25]
	    ^ q[30] ^ q[31] ^ in[0] ^ in[1] ^ in[3] ^ in[4] ^ in[8] ^ in[10] ^
	    in[11] ^ in[12] ^ in[17] ^ in[22] ^ in[23];
	c[9] =
	    q[9] ^ q[10] ^ q[12] ^ q[13] ^ q[17] ^ q[19] ^ q[20] ^ q[21] ^ q[26]
	    ^ q[31] ^ in[1] ^ in[2] ^ in[4] ^ in[5] ^ in[9] ^ in[11] ^ in[12] ^
	    in[13] ^ in[18] ^ in[23];
	c[10] =
	    q[8] ^ q[10] ^ q[11] ^ q[13] ^ q[17] ^ q[21] ^ q[22] ^ q[24] ^ q[27]
	    ^ in[0] ^ in[2] ^ in[3] ^ in[5] ^ in[9] ^ in[13] ^ in[14] ^ in[16] ^
	    in[19];
	c[11] =
	    q[8] ^ q[9] ^ q[11] ^ q[12] ^ q[17] ^ q[20] ^ q[22] ^ q[23] ^ q[24]
	    ^ q[25] ^ q[28] ^ in[0] ^ in[1] ^ in[3] ^ in[4] ^ in[9] ^ in[12] ^
	    in[14] ^ in[15] ^ in[16] ^ in[17] ^ in[20];
	c[12] =
	    q[8] ^ q[9] ^ q[10] ^ q[12] ^ q[13] ^ q[14] ^ q[17] ^ q[20] ^ q[21]
	    ^ q[23] ^ q[25] ^ q[26] ^ q[29] ^ in[0] ^ in[1] ^ in[2] ^ in[4] ^
	    in[5] ^ in[6] ^ in[9] ^ in[12] ^ in[13] ^ in[15] ^ in[17] ^ in[18] ^
	    in[21];
	c[13] =
	    q[9] ^ q[10] ^ q[11] ^ q[13] ^ q[14] ^ q[15] ^ q[18] ^ q[21] ^ q[22]
	    ^ q[24] ^ q[26] ^ q[27] ^ q[30] ^ in[1] ^ in[2] ^ in[3] ^ in[5] ^
	    in[6] ^ in[7] ^ in[10] ^ in[13] ^ in[14] ^ in[16] ^ in[18] ^ in[19]
	    ^ in[22];
	c[14] =
	    q[10] ^ q[11] ^ q[12] ^ q[14] ^ q[15] ^ q[16] ^ q[19] ^ q[22] ^
	    q[23] ^ q[25] ^ q[27] ^ q[28] ^ q[31] ^ in[2] ^ in[3] ^ in[4] ^
	    in[6] ^ in[7] ^ in[8] ^ in[11] ^ in[14] ^ in[15] ^ in[17] ^ in[19] ^
	    in[20] ^ in[23];
	c[15] =
	    q[11] ^ q[12] ^ q[13] ^ q[15] ^ q[16] ^ q[17] ^ q[20] ^ q[23] ^
	    q[24] ^ q[26] ^ q[28] ^ q[29] ^ in[3] ^ in[4] ^ in[5] ^ in[7] ^
	    in[8] ^ in[9] ^ in[12] ^ in[15] ^ in[16] ^ in[18] ^ in[20] ^ in[21];
	c[16] =
	    q[8] ^ q[12] ^ q[13] ^ q[16] ^ q[20] ^ q[21] ^ q[25] ^ q[27] ^ q[29]
	    ^ q[30] ^ in[0] ^ in[4] ^ in[5] ^ in[8] ^ in[12] ^ in[13] ^ in[17] ^
	    in[19] ^ in[21] ^ in[22];
	c[17] =
	    q[9] ^ q[13] ^ q[14] ^ q[17] ^ q[21] ^ q[22] ^ q[26] ^ q[28] ^ q[30]
	    ^ q[31] ^ in[1] ^ in[5] ^ in[6] ^ in[9] ^ in[13] ^ in[14] ^ in[18] ^
	    in[20] ^ in[22] ^ in[23];
	c[18] =
	    q[10] ^ q[14] ^ q[15] ^ q[18] ^ q[22] ^ q[23] ^ q[27] ^ q[29] ^
	    q[31] ^ in[2] ^ in[6] ^ in[7] ^ in[10] ^ in[14] ^ in[15] ^ in[19] ^
	    in[21] ^ in[23];
	c[19] =
	    q[11] ^ q[15] ^ q[16] ^ q[19] ^ q[23] ^ q[24] ^ q[28] ^ q[30] ^
	    in[3] ^ in[7] ^ in[8] ^ in[11] ^ in[15] ^ in[16] ^ in[20] ^ in[22];
	c[20] =
	    q[12] ^ q[16] ^ q[17] ^ q[20] ^ q[24] ^ q[25] ^ q[29] ^ q[31] ^
	    in[4] ^ in[8] ^ in[9] ^ in[12] ^ in[16] ^ in[17] ^ in[21] ^ in[23];
	c[21] =
	    q[13] ^ q[17] ^ q[18] ^ q[21] ^ q[25] ^ q[26] ^ q[30] ^ in[5] ^
	    in[9] ^ in[10] ^ in[13] ^ in[17] ^ in[18] ^ in[22];
	c[22] =
	    q[8] ^ q[17] ^ q[19] ^ q[20] ^ q[22] ^ q[24] ^ q[26] ^ q[27] ^ q[31]
	    ^ in[0] ^ in[9] ^ in[11] ^ in[12] ^ in[14] ^ in[16] ^ in[18] ^
	    in[19] ^ in[23];
	c[23] =
	    q[8] ^ q[9] ^ q[14] ^ q[17] ^ q[21] ^ q[23] ^ q[24] ^ q[25] ^ q[27]
	    ^ q[28] ^ in[0] ^ in[1] ^ in[6] ^ in[9] ^ in[13] ^ in[15] ^ in[16] ^
	    in[17] ^ in[19] ^ in[20];
	c[24] =
	    q[0] ^ q[9] ^ q[10] ^ q[15] ^ q[18] ^ q[22] ^ q[24] ^ q[25] ^ q[26]
	    ^ q[28] ^ q[29] ^ in[1] ^ in[2] ^ in[7] ^ in[10] ^ in[14] ^ in[16] ^
	    in[17] ^ in[18] ^ in[20] ^ in[21];
	c[25] =
	    q[1] ^ q[10] ^ q[11] ^ q[16] ^ q[19] ^ q[23] ^ q[25] ^ q[26] ^ q[27]
	    ^ q[29] ^ q[30] ^ in[2] ^ in[3] ^ in[8] ^ in[11] ^ in[15] ^ in[17] ^
	    in[18] ^ in[19] ^ in[21] ^ in[22];
	c[26] =
	    q[2] ^ q[8] ^ q[11] ^ q[12] ^ q[14] ^ q[18] ^ q[26] ^ q[27] ^ q[28]
	    ^ q[30] ^ q[31] ^ in[0] ^ in[3] ^ in[4] ^ in[6] ^ in[10] ^ in[18] ^
	    in[19] ^ in[20] ^ in[22] ^ in[23];
	c[27] =
	    q[3] ^ q[9] ^ q[12] ^ q[13] ^ q[15] ^ q[19] ^ q[27] ^ q[28] ^ q[29]
	    ^ q[31] ^ in[1] ^ in[4] ^ in[5] ^ in[7] ^ in[11] ^ in[19] ^ in[20] ^
	    in[21] ^ in[23];
	c[28] =
	    q[4] ^ q[10] ^ q[13] ^ q[14] ^ q[16] ^ q[20] ^ q[28] ^ q[29] ^ q[30]
	    ^ in[2] ^ in[5] ^ in[6] ^ in[8] ^ in[12] ^ in[20] ^ in[21] ^ in[22];
	c[29] =
	    q[5] ^ q[11] ^ q[14] ^ q[15] ^ q[17] ^ q[21] ^ q[29] ^ q[30] ^ q[31]
	    ^ in[3] ^ in[6] ^ in[7] ^ in[9] ^ in[13] ^ in[21] ^ in[22] ^ in[23];
	c[30] =
	    q[6] ^ q[12] ^ q[15] ^ q[16] ^ q[18] ^ q[22] ^ q[30] ^ q[31] ^ in[4]
	    ^ in[7] ^ in[8] ^ in[10] ^ in[14] ^ in[22] ^ in[23];
	c[31] =
	    q[7] ^ q[13] ^ q[16] ^ q[17] ^ q[19] ^ q[23] ^ q[31] ^ in[5] ^ in[8]
	    ^ in[9] ^ in[11] ^ in[15] ^ in[23];

	for (i = 0; i < 32; i++)
		crc |= c[i] << i;

	return crc;
}

#if K2ULAN_CUCKOO_CACHED
static u32 ys_k2ulan_cuckoo_mc_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 11;	/* 11bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_mc_crc32_24bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

static u32 ys_k2ulan_cuckoo_mc_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 11) | (pos & 0x7FF));
}

static void ys_k2ulan_cuckoo_mc_generate_rule_data(const u8 *key, const u8 *value,
						   u32 *data)
{
	memcpy(data, value, YS_K2ULAN_CUCKOO_MC_VALUE_SIZE);
}

static void ys_k2ulan_cuckoo_mc_parse_rule_data(const u32 *data, u8 *key,
						u8 *value)
{
	u8 *p = (u8 *)data;

	/* [9:0] MAC VALUE */
	value[0] = p[0];
	value[1] = p[1] & 0x3;

	/* [10] enable flag */
	value[1] |= (!!(p[1] & 0x4) << 4);

	/* [55:32] MUX MAC ADDR */
	memcpy(key, &p[4], YS_K2ULAN_CUCKOO_MC_KEY_SIZE);
}
#endif

#if K2ULAN_CUCKOO_CACHED
static int ys_k2ulan_cuckoo_mc_store_rule_data(struct ys_cuckoo_table *table,
					       u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = { 0 };
	u32 index;
	u32 entry_addr;
	int i;

	table->ops->generate_rule_data(table->buckets[bucket][pos].key,
				       table->buckets[bucket][pos].value, data);

	if (bucket == YS_K2ULAN_CUCKOO_MC_BUCKET_NUM) {
		entry_addr = table->hw.waddr + 0xc000 + 0x100 * pos;
	} else {
		index = table->ops->get_ram_addr(bucket, pos);
		entry_addr = table->hw.waddr + table->value_size * index;
	}
	for (i = 0; i < table->hw.data_round; i++)
		ys_cuckoo_iowrite32(table, entry_addr + 4 * i, data[i]);

	return 0;
}

static void ys_k2ulan_cuckoo_mc_get_hw_info(struct ys_cuckoo_table *table)
{
	int i;

	table->bucket_count = YS_K2ULAN_CUCKOO_MC_BUCKET_NUM;
	table->depth = YS_K2ULAN_CUCKOO_MC_DEPTH;
	table->key_size = YS_K2ULAN_CUCKOO_MC_KEY_SIZE;
	table->value_size = YS_K2ULAN_CUCKOO_MC_VALUE_SIZE;
	table->seed_bits = YS_K2ULAN_CUCKOO_MC_SEED_BITS;
	table->mux_seed_bits = YS_K2ULAN_CUCKOO_MC_MUX_SEED_BITS;
	for (i = 0; i < table->bucket_count; i++) {
		table->hw.seed_addr[i] = YS_K2ULAN_CUCKOO_MC_SEED_ADDR(i);
		table->hw.mux_seed_addr[i] = YS_K2ULAN_CUCKOO_MC_MUX_SEED_ADDR(i);
	}
	table->hw.init_done_addr = 0;
	table->hw.waddr = YS_K2ULAN_CUCKOO_MC_WADDR;
	table->hw.raddr = YS_K2ULAN_CUCKOO_MC_RADDR;
	table->hw.data_addr = 0;
	table->hw.data_round = YS_K2ULAN_CUCKOO_MC_DATA_ROUND;
	table->hw.lock_flag_addr = YS_K2ULAN_CUCKOO_LOCK_BASE + YS_K2ULAN_CUCKOO_LOCK_FLAG;
	table->hw.lock_state_addr = YS_K2ULAN_CUCKOO_LOCK_BASE + YS_K2ULAN_CUCKOO_LOCK_STATE;
	table->hw.lock_timeout_addr = YS_K2ULAN_CUCKOO_LOCK_BASE + YS_K2ULAN_CUCKOO_LOCK_TIMEOUT;
	table->hw.lock_timeout = YS_K2ULAN_CUCKOO_LOCK_TIMEOUT_DEFAULT;
}

const struct ys_cuckoo_ops_cached k2ulan_mc_ops = {
	.get_hw_info = ys_k2ulan_cuckoo_mc_get_hw_info,
	.hash = ys_k2ulan_cuckoo_mc_hash,
	.get_ram_addr = ys_k2ulan_cuckoo_mc_get_ram_addr,
	.generate_rule_data = ys_k2ulan_cuckoo_mc_generate_rule_data,
	.parse_rule_data = ys_k2ulan_cuckoo_mc_parse_rule_data,
	.store_rule_data = ys_k2ulan_cuckoo_mc_store_rule_data,
	//.store_rule_data2file = ys_k2ulan_cuckoo_mc_store_rule_data2file,
	//.backup_entry = ys_k2ulan_cuckoo_uc_backup_entry,
};
#endif

static void ys_k2ulan_bnic_cuckoo_uc_get_hw_info(struct ys_cuckoo_table_uncached *table)
{
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	base_info->bucket_count = YS_K2ULAN_BNIC_CUCKOO_UC_BUCKET_NUM;
	base_info->depth = YS_K2ULAN_BNIC_CUCKOO_UC_DEPTH;
	base_info->key_size = YS_K2ULAN_BNIC_CUCKOO_UC_KEY_SIZE;
	base_info->value_size = YS_K2ULAN_BNIC_CUCKOO_UC_VALUE_SIZE;
	base_info->seed_bits = YS_K2ULAN_BNIC_CUCKOO_UC_SEED_BITS;
	base_info->mux_seed_bits = YS_K2ULAN_BNIC_CUCKOO_UC_MUX_SEED_BITS;
	for (i = 0; i < base_info->bucket_count; i++) {
		base_info->hw.seed_addr[i] = YS_K2ULAN_BNIC_CUCKOO_UC_SEED_ADDR(i);
		base_info->hw.mux_seed_addr[i] = YS_K2ULAN_BNIC_CUCKOO_UC_MUX_SEED_ADDR(i);
	}
	base_info->hw.init_done_addr = 0;
	base_info->hw.waddr = YS_K2ULAN_BNIC_CUCKOO_UC_WADDR;
	base_info->hw.raddr = YS_K2ULAN_BNIC_CUCKOO_UC_RADDR;
	base_info->hw.data_addr = 0;
	base_info->hw.data_round = YS_K2ULAN_BNIC_CUCKOO_UC_DATA_ROUND;
}

static u32 ys_k2ulan_bnic_cuckoo_uc_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 10;	/* 10bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_uc_crc32_48bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

static u32 ys_k2ulan_bnic_cuckoo_uc_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 11) | (pos & 0x3FF));
}

static void ys_k2ulan_bnic_cuckoo_uc_generate_rule_data(const u8 *key,
							const u8 *value,
							u32 *data)
{
	memcpy(data, value, YS_K2ULAN_BNIC_CUCKOO_UC_VALUE_SIZE);
}

static void ys_k2ulan_bnic_cuckoo_uc_parse_rule_data(const u32 *data,
						     u8 *key, u8 *value)
{
	u8 *p = (u8 *)data;

	/* [9:0] MAC VALUE */
	value[0] = p[0];
	value[1] = p[1] & 0x3;

	/* [63:16] Unicast MAC ADDR */
	memcpy(key, &p[2], YS_K2ULAN_BNIC_CUCKOO_UC_KEY_SIZE);

	/* [10] enable flag */
	value[1] |= ((p[1] & 0x4) << 4);
}

static int ys_k2ulan_bnic_cuckoo_uc_store_rule_data(struct ys_cuckoo_table_uncached *table,
						    u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = {0};
	u32 index;
	uintptr_t entry_addr;
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	table->ops->generate_rule_data(table->entry_swap.key,
				       table->entry_swap.value, data);

	if (bucket == YS_K2ULAN_BNIC_CUCKOO_UC_BUCKET_NUM) {
		entry_addr = (uintptr_t)(base_info->hw.bar_addr +
					 base_info->hw.waddr + 0xc000 + 0x100 * pos);
	} else {
		index = table->ops->get_ram_addr(bucket, pos);
		entry_addr = (uintptr_t)(base_info->hw.bar_addr +
					 base_info->hw.waddr + base_info->value_size * index);
	}
	for (i = 0; i < base_info->hw.data_round; i++)
		ys_cuckoo_iowrite32_direct(entry_addr + 4 * i, data[i]);

	return 0;
}

const struct ys_cuckoo_ops_uncached k2ulan_bnic_uc_ops = {
	.get_hw_info = ys_k2ulan_bnic_cuckoo_uc_get_hw_info,
	.hash = ys_k2ulan_bnic_cuckoo_uc_hash,
	.get_ram_addr = ys_k2ulan_bnic_cuckoo_uc_get_ram_addr,
	.generate_rule_data = ys_k2ulan_bnic_cuckoo_uc_generate_rule_data,
	.parse_rule_data = ys_k2ulan_bnic_cuckoo_uc_parse_rule_data,
	.store_rule_data = ys_k2ulan_bnic_cuckoo_uc_store_rule_data,
};

static u32 ys_k2ulan_bnic_cuckoo_mc_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 10;	/* 10bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_mc_crc32_24bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

static u32 ys_k2ulan_bnic_cuckoo_mc_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 11) | (pos & 0x3FF));
}

static void ys_k2ulan_bnic_cuckoo_mc_generate_rule_data(const u8 *key, const u8 *value,
							u32 *data)
{
	memcpy(data, value, YS_K2ULAN_BNIC_CUCKOO_MC_VALUE_SIZE);
}

static void ys_k2ulan_bnic_cuckoo_mc_parse_rule_data(const u32 *data, u8 *key,
						     u8 *value)
{
	u8 *p = (u8 *)data;

	/* [9:0] MAC VALUE */
	value[0] = p[0];
	value[1] = p[1] & 0x3;

	/* [10] enable flag */
	value[1] |= (!!(p[1] & 0x4) << 4);

	/* [55:32] MUX MAC ADDR */
	memcpy(key, &p[4], YS_K2ULAN_BNIC_CUCKOO_MC_KEY_SIZE);
}

static int ys_k2ulan_bnic_cuckoo_mc_store_rule_data(struct ys_cuckoo_table_uncached *table,
						    u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = { 0 };
	u32 index;
	uintptr_t entry_addr;
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	table->ops->generate_rule_data(table->entry_swap.key,
				       table->entry_swap.value, data);

	if (bucket == YS_K2ULAN_BNIC_CUCKOO_MC_BUCKET_NUM) {
		entry_addr = (uintptr_t)(base_info->hw.bar_addr +
					 base_info->hw.waddr + 0xc000 + 0x100 * pos);
	} else {
		index = table->ops->get_ram_addr(bucket, pos);
		entry_addr = (uintptr_t)(base_info->hw.bar_addr +
					 base_info->hw.waddr + base_info->value_size * index);
	}
	for (i = 0; i < base_info->hw.data_round; i++)
		ys_cuckoo_iowrite32_direct(entry_addr + 4 * i, data[i]);

	return 0;
}

static void ys_k2ulan_bnic_cuckoo_mc_get_hw_info(struct ys_cuckoo_table_uncached *table)
{
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	base_info->bucket_count = YS_K2ULAN_BNIC_CUCKOO_MC_BUCKET_NUM;
	base_info->depth = YS_K2ULAN_BNIC_CUCKOO_MC_DEPTH;
	base_info->key_size = YS_K2ULAN_BNIC_CUCKOO_MC_KEY_SIZE;
	base_info->value_size = YS_K2ULAN_BNIC_CUCKOO_MC_VALUE_SIZE;
	base_info->seed_bits = YS_K2ULAN_BNIC_CUCKOO_MC_SEED_BITS;
	base_info->mux_seed_bits = YS_K2ULAN_BNIC_CUCKOO_MC_MUX_SEED_BITS;
	for (i = 0; i < base_info->bucket_count; i++) {
		base_info->hw.seed_addr[i] = YS_K2ULAN_BNIC_CUCKOO_MC_SEED_ADDR(i);
		base_info->hw.mux_seed_addr[i] = YS_K2ULAN_BNIC_CUCKOO_MC_MUX_SEED_ADDR(i);
	}
	base_info->hw.waddr = YS_K2ULAN_BNIC_CUCKOO_MC_WADDR;
	base_info->hw.raddr = YS_K2ULAN_BNIC_CUCKOO_MC_RADDR;
	base_info->hw.data_addr = 0;
	base_info->hw.data_round = YS_K2ULAN_BNIC_CUCKOO_MC_DATA_ROUND;
}

const struct ys_cuckoo_ops_uncached k2ulan_bnic_mc_ops = {
	.get_hw_info = ys_k2ulan_bnic_cuckoo_mc_get_hw_info,
	.hash = ys_k2ulan_bnic_cuckoo_mc_hash,
	.get_ram_addr = ys_k2ulan_bnic_cuckoo_mc_get_ram_addr,
	.generate_rule_data = ys_k2ulan_bnic_cuckoo_mc_generate_rule_data,
	.parse_rule_data = ys_k2ulan_bnic_cuckoo_mc_parse_rule_data,
	.store_rule_data = ys_k2ulan_bnic_cuckoo_mc_store_rule_data,
};

static void ys_k2ulan_cuckoo_uc_get_hw_info(struct ys_cuckoo_table_uncached *table)
{
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	base_info->bucket_count = YS_K2ULAN_CUCKOO_UC_BUCKET_NUM;
	base_info->depth = YS_K2ULAN_CUCKOO_UC_DEPTH;
	base_info->key_size = YS_K2ULAN_CUCKOO_UC_KEY_SIZE;
	base_info->value_size = YS_K2ULAN_CUCKOO_UC_VALUE_SIZE;
	base_info->seed_bits = YS_K2ULAN_CUCKOO_UC_SEED_BITS;
	base_info->mux_seed_bits = YS_K2ULAN_CUCKOO_UC_MUX_SEED_BITS;
	for (i = 0; i < base_info->bucket_count; i++) {
		base_info->hw.seed_addr[i] = YS_K2ULAN_CUCKOO_UC_SEED_ADDR(i);
		base_info->hw.mux_seed_addr[i] = YS_K2ULAN_CUCKOO_UC_MUX_SEED_ADDR(i);
	}
	base_info->hw.init_done_addr = 0;
	base_info->hw.waddr = YS_K2ULAN_CUCKOO_UC_WADDR;
	base_info->hw.raddr = YS_K2ULAN_CUCKOO_UC_RADDR;
	base_info->hw.data_addr = 0;
	base_info->hw.data_round = YS_K2ULAN_CUCKOO_UC_DATA_ROUND;
}

static u32 ys_k2ulan_cuckoo_uc_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 11;	/* 11bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_uc_crc32_48bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

static u32 ys_k2ulan_cuckoo_uc_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 11) | (pos & 0x7FF));
}

const struct ys_cuckoo_ops_uncached k2ulan_uc_ops = {
	.get_hw_info = ys_k2ulan_cuckoo_uc_get_hw_info,
	.hash = ys_k2ulan_cuckoo_uc_hash,
	.get_ram_addr = ys_k2ulan_cuckoo_uc_get_ram_addr,
	.generate_rule_data = ys_k2ulan_bnic_cuckoo_uc_generate_rule_data,
	.parse_rule_data = ys_k2ulan_bnic_cuckoo_uc_parse_rule_data,
	.store_rule_data = ys_k2ulan_bnic_cuckoo_uc_store_rule_data,
};

static void ys_k2ulan_cuckoo_mc_get_hw_info(struct ys_cuckoo_table_uncached *table)
{
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	base_info->bucket_count = YS_K2ULAN_BNIC_CUCKOO_MC_BUCKET_NUM;
	base_info->depth = YS_K2ULAN_CUCKOO_MC_DEPTH;
	base_info->key_size = YS_K2ULAN_BNIC_CUCKOO_MC_KEY_SIZE;
	base_info->value_size = YS_K2ULAN_BNIC_CUCKOO_MC_VALUE_SIZE;
	base_info->seed_bits = YS_K2ULAN_BNIC_CUCKOO_MC_SEED_BITS;
	base_info->mux_seed_bits = YS_K2ULAN_BNIC_CUCKOO_MC_MUX_SEED_BITS;
	for (i = 0; i < base_info->bucket_count; i++) {
		base_info->hw.seed_addr[i] = YS_K2ULAN_BNIC_CUCKOO_MC_SEED_ADDR(i);
		base_info->hw.mux_seed_addr[i] = YS_K2ULAN_BNIC_CUCKOO_MC_MUX_SEED_ADDR(i);
	}
	base_info->hw.waddr = YS_K2ULAN_BNIC_CUCKOO_MC_WADDR;
	base_info->hw.raddr = YS_K2ULAN_BNIC_CUCKOO_MC_RADDR;
	base_info->hw.data_addr = 0;
	base_info->hw.data_round = YS_K2ULAN_BNIC_CUCKOO_MC_DATA_ROUND;
}

static u32 ys_k2ulan_cuckoo_mc_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 11) | (pos & 0x7FF));
}

static u32 ys_k2ulan_cuckoo_mc_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 11;	/* 11bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_mc_crc32_24bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

const struct ys_cuckoo_ops_uncached k2ulan_mc_ops = {
	.get_hw_info = ys_k2ulan_cuckoo_mc_get_hw_info,
	.hash = ys_k2ulan_cuckoo_mc_hash,
	.get_ram_addr = ys_k2ulan_cuckoo_mc_get_ram_addr,
	.generate_rule_data = ys_k2ulan_bnic_cuckoo_mc_generate_rule_data,
	.parse_rule_data = ys_k2ulan_bnic_cuckoo_mc_parse_rule_data,
	.store_rule_data = ys_k2ulan_bnic_cuckoo_mc_store_rule_data,
};

static u32 ys_k2ulan_cuckoo_mac_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 12;	/* 12bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_uc_crc32_48bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

static void ys_k2ulan_cuckoo_mac_parse_rule_data(const u32 *data,
						 u8 *key, u8 *value)
{
	u8 *p = (u8 *)data;

	/* [47:0] MAC ADDR */
	memcpy(key, &p[0], YS_K2ULAN_CUCKOO_MAC_KEY_SIZE);

	/* [58:48] MAC VALUE */
	value[0] = p[6];
	value[1] = p[7] & 0x7;

	/* [59] enable flag */
	value[1] |= p[7] & 0x8;
}

static int ys_k2ulan_cuckoo_mac_store_rule_data(struct ys_cuckoo_table_uncached *table,
						u8 bucket, u32 pos)
{
	u32 data[YS_CUCKOO_MAX_DATA_ROUND] = { 0 };
	u32 index;
	uintptr_t entry_addr;
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	table->ops->generate_rule_data(table->entry_swap.key,
				       table->entry_swap.value, data);

	if (bucket == YS_K2ULAN_CUCKOO_MAC_BUCKET_NUM) {
		entry_addr = (uintptr_t)(base_info->hw.bar_addr +
					 base_info->hw.waddr + 0x18000 + 0x8 * pos);
	} else {
		index = table->ops->get_ram_addr(bucket, pos);
		entry_addr = (uintptr_t)(base_info->hw.bar_addr +
					 base_info->hw.waddr + base_info->value_size * index);
	}
	for (i = 0; i < base_info->hw.data_round; i++)
		ys_cuckoo_iowrite32_direct(entry_addr + 4 * i, data[i]);

	return 0;
}

static void ys_k2ulan_cuckoo_mac_generate_rule_data(const u8 *key, const u8 *value,
						    u32 *data)
{
	memcpy(data, value, YS_K2ULAN_CUCKOO_MAC_VALUE_SIZE);
}

static u32 ys_k2ulan_cuckoo_mac_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 12) | (pos & 0xFFF));
}

static void ys_k2ulan_cuckoo_mac_get_hw_info(struct ys_cuckoo_table_uncached *table)
{
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	base_info->bucket_count = YS_K2ULAN_CUCKOO_MAC_BUCKET_NUM;
	base_info->depth = YS_K2ULAN_CUCKOO_MAC_DEPTH;
	base_info->key_size = YS_K2ULAN_CUCKOO_MAC_KEY_SIZE;
	base_info->value_size = YS_K2ULAN_CUCKOO_MAC_VALUE_SIZE;
	base_info->seed_bits = YS_K2ULAN_CUCKOO_MAC_SEED_BITS;
	base_info->mux_seed_bits = YS_K2ULAN_CUCKOO_MAC_MUX_SEED_BITS;
	for (i = 0; i < base_info->bucket_count; i++) {
		base_info->hw.seed_addr[i] = YS_K2ULAN_CUCKOO_MAC_SEED_ADDR(i);
		base_info->hw.mux_seed_addr[i] = YS_K2ULAN_CUCKOO_MAC_MUX_SEED_ADDR(i);
	}
	base_info->hw.waddr = YS_K2ULAN_CUCKOO_MAC_WADDR;
	base_info->hw.raddr = YS_K2ULAN_CUCKOO_MAC_RADDR;
	base_info->hw.data_addr = 0;
	base_info->hw.data_round = YS_K2ULAN_CUCKOO_MAC_DATA_ROUND;
}

const struct ys_cuckoo_ops_uncached k2ulan_mac_ops = {
	.get_hw_info = ys_k2ulan_cuckoo_mac_get_hw_info,
	.hash = ys_k2ulan_cuckoo_mac_hash,
	.get_ram_addr = ys_k2ulan_cuckoo_mac_get_ram_addr,
	.generate_rule_data = ys_k2ulan_cuckoo_mac_generate_rule_data,
	.parse_rule_data = ys_k2ulan_cuckoo_mac_parse_rule_data,
	.store_rule_data = ys_k2ulan_bnic_cuckoo_mc_store_rule_data,
};

static u32 ys_k2ulan_bnic_cuckoo_mac_hash(const u8 *key, u32 seed, u32 mux_seed)
{
	const u32 out_width = 11;	/* 11bits */
	u64 crc_total;
	u64 crc_high;
	u64 crc_low;
	u64 crc_out;
	u64 crc32;
	u32 pos;

	crc32 = ys_k2ulan_cuckoo_uc_crc32_48bit(key, seed);

	crc_total = (crc32 << 32) >> mux_seed;
	crc_high = (crc_total & 0xFFFFFFFF00000000) >> 32;
	crc_low = crc_total & 0xFFFFFFFF;

	crc_out = crc_high | crc_low;
	pos = (int)(crc_out % (1 << out_width));

	return pos;
}

static u32 ys_k2ulan_bnic_cuckoo_mac_get_ram_addr(u32 bucket, u32 pos)
{
	return (((bucket & 0x3) << 12) | (pos & 0x7FF));
}

static void ys_k2ulan_bnic_cuckoo_mac_get_hw_info(struct ys_cuckoo_table_uncached *table)
{
	struct ys_cuckoo_table *base_info = &table->table_base;
	int i;

	base_info->bucket_count = YS_K2ULAN_CUCKOO_MAC_BUCKET_NUM;
	base_info->depth = YS_K2ULAN_BNIC_CUCKOO_MAC_DEPTH;
	base_info->key_size = YS_K2ULAN_CUCKOO_MAC_KEY_SIZE;
	base_info->value_size = YS_K2ULAN_CUCKOO_MAC_VALUE_SIZE;
	base_info->seed_bits = YS_K2ULAN_CUCKOO_MAC_SEED_BITS;
	base_info->mux_seed_bits = YS_K2ULAN_CUCKOO_MAC_MUX_SEED_BITS;
	for (i = 0; i < base_info->bucket_count; i++) {
		base_info->hw.seed_addr[i] = YS_K2ULAN_CUCKOO_MAC_SEED_ADDR(i);
		base_info->hw.mux_seed_addr[i] = YS_K2ULAN_CUCKOO_MAC_MUX_SEED_ADDR(i);
	}
	base_info->hw.waddr = YS_K2ULAN_CUCKOO_MAC_WADDR;
	base_info->hw.raddr = YS_K2ULAN_CUCKOO_MAC_RADDR;
	base_info->hw.data_addr = 0;
	base_info->hw.data_round = YS_K2ULAN_CUCKOO_MAC_DATA_ROUND;
}

const struct ys_cuckoo_ops_uncached k2ulan_bnic_mac_ops = {
	.get_hw_info = ys_k2ulan_bnic_cuckoo_mac_get_hw_info,
	.hash = ys_k2ulan_bnic_cuckoo_mac_hash,
	.get_ram_addr = ys_k2ulan_bnic_cuckoo_mac_get_ram_addr,
	.generate_rule_data = ys_k2ulan_cuckoo_mac_generate_rule_data,
	.parse_rule_data = ys_k2ulan_cuckoo_mac_parse_rule_data,
	.store_rule_data = ys_k2ulan_cuckoo_mac_store_rule_data,
};
