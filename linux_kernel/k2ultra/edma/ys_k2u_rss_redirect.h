/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_RSS_REDIRECT_H__
#define __YS_K2U_RSS_REDIRECT_H__

enum {
	YS_K2U_CMD_RSS_REDIRECT_GET = 1,
	YS_K2U_CMD_RSS_REDIRECT_TABLE_INIT,
	YS_K2U_CMD_RSS_REDIRECT_TABLE_SET,
	YS_K2U_CMD_RSS_REDIRECT_KEY_SET,
	YS_K2U_CMD_RSS_REDIRECT_KEY_GET,
};

struct ys_k2u_mbox_rss_redirect_cmd {
	u8 cmd_type;
	s8 cmd_status;
	u16 qstart;
	u16 qnb;
	u8 data_len;
	u8 cmd_data[];
};

void ys_k2u_pf_rss_redirect_table_default(void __iomem *hw_addr, u16 qstart, u16 qnb);
void ys_k2u_pf_rss_redirect_table_set(void __iomem *hw_addr, u16 qstart, u16 qnb, u8 *data);
void ys_k2u_pf_rss_redirect_table_get(void __iomem *hw_addr, u16 qstart, u16 qnb, u8 *out);
void ys_k2u_pf_hash_key_set(void __iomem *hw_addr, const u8 *key);
void ys_k2u_pf_hash_key_get(void __iomem *hw_addr, u8 *out);
void ys_k2u_rss_redirect_table_init(struct net_device *ndev, u16 rxqnum);
void ys_k2u_mbox_rss_redirect_proc(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 channel);
void ys_k2u_rss_init(struct net_device *ndev);

#endif /*__YS_K2U_RSS_REDIRECT_H__*/
