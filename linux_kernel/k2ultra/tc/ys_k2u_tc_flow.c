// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_tc_priv.h"
#include "../platform/ysif_linux.h"

/* ystc basic start */

static inline bool eth_addr_is_zero(unsigned char *addr)
{
	return (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 &&
		addr[3] == 0 && addr[4] == 0 && addr[5] == 0);
}

static inline bool in6_addr_is_zero(struct in6_addr *addr)
{
	return (addr->s6_addr32[0] == 0 &&
		addr->s6_addr32[1] == 0 &&
		addr->s6_addr32[2] == 0 &&
		addr->s6_addr32[3] == 0);
}

/* ystc basic end */
/* ystc action start */

static const struct ys_tc_ops_action *ys_tc_get_action_ops(enum ys_tc_action_type action_type);

static struct ys_tc_action_entry*
ys_tc_action_entry_next(const struct ys_tc_action_buf *action_buf, u8 datalen)
{
	struct ys_tc_action_entry *action_entry = NULL;

	// entry: type(1) + len(1) + data
	if (action_buf->offset + 2 + datalen > action_buf->size)
		return NULL;

	action_entry = (struct ys_tc_action_entry *)(action_buf->data + action_buf->offset);
	return action_entry;
}

static inline void ys_tc_action_entry_mv_offset(struct ys_tc_action_buf *action_buf,
						const struct ys_tc_ops_action *ops)
{
	// entry: type(1) + len(1) + data
	action_buf->offset += 2 + ops->datalen;
}

static int
ys_tc_action_parse_comm(struct ys_tc_priv *tc_priv,
			const struct ys_tc_ops_action *ops,
			struct ys_tc_action_ctx *ctx)
{
	struct ys_tc_action_buf *action_buf = &ctx->action_buf;
	const struct ys_tc_action_meta *action_meta = &ctx->action_meta;

	struct ys_tc_action_entry *act_entry = NULL;

	act_entry = ys_tc_action_entry_next(action_buf, ops->datalen);
	if (!act_entry)
		return -ENOBUFS;

	if (ops->datalen)
		return -EINVAL;

	if ((ops->type == YS_TC_ACTION_VXLAN_DECAP ||
	     ops->type == YS_TC_ACTION_GENEVE_DECAP) &&
	    !(action_meta->flags & YS_TC_FLAG_REALDECAP))
		return 0;

	act_entry->type = ops->type;
	act_entry->len = ops->datalen;
	ys_tc_action_entry_mv_offset(action_buf, ops);

	return 0;
}

static int ys_tc_flow_add_entry(struct ys_tc_flow *flow, struct ys_tc_table_entry *tbl_entry)
{
	struct ys_tc_table_entry_node *entry_node = NULL;

	if (!flow || !tbl_entry)
		return 0;

	entry_node = kzalloc(sizeof(*entry_node), GFP_KERNEL);
	if (!entry_node)
		return -ENOMEM;

	INIT_LIST_HEAD(&entry_node->flow_node);
	entry_node->tbl_entry = tbl_entry;
	list_add_tail(&entry_node->flow_node, &flow->tbl_entry_head);
	return 0;
}

static int
ys_tc_action_parse_count(struct ys_tc_priv *tc_priv,
			 const struct ys_tc_ops_action *ops,
			 struct ys_tc_action_ctx *ctx)
{
	struct ys_tc_action_buf *action_buf = &ctx->action_buf;
	const struct ys_tc_action_meta *action_meta = &ctx->action_meta;
	struct ys_tc_flow *flow = ctx->flow;

	int ret = 0;
	struct ys_tc_action_entry *act_entry = NULL;
	struct ys_tc_table_entry *tbl_entry = NULL;

	act_entry = ys_tc_action_entry_next(action_buf, ops->datalen);
	if (!act_entry)
		return -ENOBUFS;

	tbl_entry = ys_tc_table_alloc(tc_priv, YS_TC_TABLE_ID_COMMCNT, NULL, NULL);
	if (!tbl_entry)
		return -ENOENT;

	if (action_meta->flags & YS_TC_FLAG_HIGHPRI)
		set_bit(YS_TC_TABLE_ENTRY_HIGHPRI, &tbl_entry->flags);

	ret = ys_tc_table_add(tc_priv, tbl_entry);
	if (ret) {
		ys_tc_debug("failed to add table %s\n", tbl_entry->table->name);
		ys_tc_table_free(tc_priv, tbl_entry);
		return ret;
	}

	act_entry->type = ops->type;
	act_entry->len = ops->datalen;
	act_entry->data.count_id = cpu_to_be32(tbl_entry->idx);
	ys_tc_action_entry_mv_offset(action_buf, ops);

	ret = ys_tc_flow_add_entry(flow, tbl_entry);
	if (ret) {
		ys_tc_table_del_and_free(tc_priv, tbl_entry);
		return ret;
	}

	if (flow)
		flow->cnt_entry = tbl_entry;
	return 0;
}

static int
ys_tc_action_parse_jump_mac_vlan_ip_ipv6(struct ys_tc_priv *tc_priv,
					 const struct ys_tc_ops_action *ops,
					 struct ys_tc_action_ctx *ctx)
{
	struct ys_tc_action_buf *action_buf = &ctx->action_buf;
	const struct ys_tc_action_meta *action_meta = &ctx->action_meta;

	struct ys_tc_action_entry *act_entry = NULL;

	act_entry = ys_tc_action_entry_next(action_buf, ops->datalen);
	if (!act_entry)
		return -ENOBUFS;

	switch (ops->type) {
	case YS_TC_ACTION_SET_MAC_SRC:
		ether_addr_copy(act_entry->data.src_eth, action_meta->eth.h_source);
		break;
	case YS_TC_ACTION_SET_MAC_DST:
		ether_addr_copy(act_entry->data.dst_eth, action_meta->eth.h_dest);
		break;
	case YS_TC_ACTION_PUSH_VLAN:
		act_entry->data.vlan_tag = action_meta->vlan_tag;
		break;
	case YS_TC_ACTION_SET_VLANID:
		act_entry->data.vlan_id = action_meta->vlan_id;
		break;
	case YS_TC_ACTION_SET_VLAN_PCP:
		act_entry->data.vlan_pcp = action_meta->vlan_pcp;
		break;
	case YS_TC_ACTION_SET_IP_SRC:
		act_entry->data.src_ipv4 = action_meta->ipv4.saddr;
		break;
	case YS_TC_ACTION_SET_IP_DST:
		act_entry->data.dst_ipv4 = action_meta->ipv4.daddr;
		break;
	case YS_TC_ACTION_SET_TTL:
		act_entry->data.ttl = cpu_to_be16(action_meta->ipv4.ttl) ?:
			cpu_to_be16(action_meta->ipv6.hop_limit);
		break;
	case YS_TC_ACTION_SET_DSCP:
		act_entry->data.ipv4_dscp =
			cpu_to_be16((action_meta->ipv4.tos & 0xfc) >> 2);
		break;
	case YS_TC_ACTION_SET_IPV6_SRC:
		memcpy(act_entry->data.src_ipv6, &action_meta->ipv6.saddr, ops->datalen);
		break;
	case YS_TC_ACTION_SET_IPV6_DST:
		memcpy(act_entry->data.dst_ipv6, &action_meta->ipv6.daddr, ops->datalen);
		break;
	case YS_TC_ACTION_SET_IPV6_DSCP:
		act_entry->data.ipv6_dscp =
			cpu_to_be16(((action_meta->ipv6.priority << 4) +
				     (action_meta->ipv6.flow_lbl[0] >> 4)) >> 2);
		break;
	case YS_TC_ACTION_SET_TP_SRC:
		act_entry->data.src_port = action_meta->tcp.source;
		break;
	case YS_TC_ACTION_SET_TP_DST:
		act_entry->data.dst_port = action_meta->tcp.dest;
		break;
	case YS_TC_ACTION_JUMP:
		act_entry->data.jump_id = cpu_to_be16(action_meta->jump_id);
		break;
	case YS_TC_ACTION_METER:
		act_entry->data.meter_action.meter_id = cpu_to_be32(action_meta->meter_id);
		act_entry->data.meter_action.green_cnt_idx =
			cpu_to_be32(action_meta->meter_green_cnt_idx);
		act_entry->data.meter_action.red_cnt_idx =
			cpu_to_be32(action_meta->meter_red_cnt_idx);
		break;
	default:
		return -EOPNOTSUPP;
	}
	act_entry->type = ops->type;
	act_entry->len = ops->datalen;
	ys_tc_action_entry_mv_offset(action_buf, ops);

	return 0;
}

static __be16
ys_tc_action_tun_srcport(const struct ys_tc_flow_metadata *md)
{
	__u32 hash = 0;

	if (md->src_addr.is_ipv6)
		hash = jhash(&md->src_addr.ipv6, sizeof(md->src_addr.ipv6), hash);
	else
		hash = jhash(&md->src_addr.ipv4, sizeof(md->src_addr.ipv4), hash);

	if (md->dst_addr.is_ipv6)
		hash = jhash(&md->dst_addr.ipv6, sizeof(md->dst_addr.ipv6), hash);
	else
		hash = jhash(&md->dst_addr.ipv4, sizeof(md->dst_addr.ipv4), hash);

	hash = jhash(&md->src_port, sizeof(md->src_port), hash);
	hash = jhash(&md->dst_port, sizeof(md->dst_port), hash);
	hash = jhash(&md->proto, sizeof(md->proto), hash);
	hash ^= hash << 16;

	return htons((((u64)hash * (61000 - 32768)) >> 32) + 32768);
}

static bool
ys_tc_lag_can_offload(struct ys_tc_priv *tc_priv, struct net_device *lag_master)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	int bus_id = switchdev->id;
	struct net_device *netdev_tmp;
	bool ret;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(lag_master, netdev_tmp) {
		/* ys nic and uplink only */
		if (netdev_tmp->netdev_ops != &ys_ndev_ops) {
			ret = false;
			goto out;
		}
		ndev_priv = netdev_priv(netdev_tmp);
		pdev_priv = pci_get_drvdata(ndev_priv->pdev);
		/* uplink and same switch dev only*/
		if (!ys_k2u_ndev_is_uplink(ndev_priv) || bus_id != pdev_priv->pdev->bus->number) {
			ret = false;
			goto out;
		}
	}
	ret = true;

out:
	rcu_read_unlock();
	return ret;
}

static int
ys_tc_action_fill_tunnelinfo(struct ys_tc_priv *tc_priv, struct ys_tc_action_meta *action_meta)
{
	int ret;

	struct flowi4 fl4 = { 0 };
	struct rtable *rt;
	struct neighbour *n = NULL;
	struct ip_tunnel_info *info;

	struct flowi6 fl6 = { 0};
	struct dst_entry *dst;

	bool is_ipv6;

	is_ipv6 = ip_tunnel_info_af(&action_meta->tunnel_info) == AF_INET6;
	info = &action_meta->tunnel_info;

	if (!is_ipv6) {
		fl4.flowi4_tos = RT_TOS(info->key.tos);
		fl4.daddr = info->key.u.ipv4.dst;
		fl4.saddr = info->key.u.ipv4.src;
		fl4.flowi4_proto = IPPROTO_UDP;
		fl4.fl4_dport = info->key.tp_dst;

		rt = ip_route_output_key(dev_net(action_meta->out_ndev), &fl4);
		ret = PTR_ERR_OR_ZERO(rt);
		if (ret)
			return ret;

		if (!rt->dst.dev || !netif_running(rt->dst.dev)) {
			ys_tc_warn("invalid dst->dev after ip_route_output_key: dev=%p name=%s\n",
				   rt->dst.dev, rt->dst.dev ? rt->dst.dev->name : "NULL");
			ip_rt_put(rt);
			return -ENETUNREACH;
		}

		n = dst_neigh_lookup(&rt->dst, &fl4.daddr);
		if (!n) {
			ip_rt_put(rt);
			return -ENETUNREACH;
		}

		action_meta->out_ndev = rt->dst.dev;
		if (!info->key.u.ipv4.src)
			info->key.u.ipv4.src = fl4.saddr;
		if (!info->key.ttl)
			info->key.ttl = ip4_dst_hoplimit(&rt->dst);
	} else {
		fl6.flowlabel = ip6_make_flowinfo(info->key.tos, info->key.label);
		fl6.daddr = info->key.u.ipv6.dst;
		fl6.saddr = info->key.u.ipv6.src;
		fl6.flowi6_proto = IPPROTO_UDP;
		fl6.fl6_dport = info->key.tp_dst;

		dst = ipv6_stub->ipv6_dst_lookup_flow(dev_net(action_meta->out_ndev),
						      NULL, &fl6, NULL);
		if (IS_ERR(dst))
			return PTR_ERR(dst);

		n = dst_neigh_lookup(dst, &fl6.daddr);
		if (!n) {
			dst_release(dst);
			return -ENETUNREACH;
		}

		action_meta->pre_out_ndev = action_meta->out_ndev;
		action_meta->out_ndev = dst->dev;
		if (in6_addr_is_zero(&info->key.u.ipv6.src))
			info->key.u.ipv6.src = fl6.saddr;
		if (!info->key.ttl)
			info->key.ttl = ip6_dst_hoplimit(dst);
	}

	if (!ys_tc_dev_valid(action_meta->out_ndev) &&
	    !netif_is_lag_master(action_meta->out_ndev)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = 0;
	if (!(n->nud_state & NUD_VALID) || n->dead) {
		neigh_event_send(n, NULL);
		ret = -EAGAIN;
		goto out;
	}

	ether_addr_copy(action_meta->tunnel_eth.h_source, action_meta->out_ndev->dev_addr);
	neigh_ha_snapshot(action_meta->tunnel_eth.h_dest, n, action_meta->out_ndev);
	action_meta->tunnel_eth.h_proto = is_ipv6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);

out:
	if (is_ipv6)
		dst_release(dst);
	else
		ip_rt_put(rt);
	neigh_release(n);

	return ret;
}

/* Convert 64 bit tunnel ID to 24 bit VNI. */
static void tunnel_id_to_vni(__be64 tun_id, __u8 *vni)
{
	vni[0] = (__force __u8)((__force u64)tun_id >> 40);
	vni[1] = (__force __u8)((__force u64)tun_id >> 48);
	vni[2] = (__force __u8)((__force u64)tun_id >> 56);
}

static int
ys_tc_action_build_encaphdr(struct ys_tc_priv *tc_priv,
			    const struct ys_tc_flow_metadata *flow_meta,
			    const struct ys_tc_action_meta *action_meta,
			    struct ys_tc_action_tunencap_data *tunencap_data,
			    size_t encap_data_len)
{
	bool is_ipv6;
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	struct udphdr *udp;
	struct vxlanhdr *vxlan;
	struct genevehdr *geneve;
	struct geneve_opt *geneve_opt;
	size_t len_left = encap_data_len;

	enum ys_tc_action_vxlanencap_data_type vxlan_type;
	enum ys_tc_action_gnvencap_data_type gnv_type;

	const struct ip_tunnel_info *info = &action_meta->tunnel_info;

	is_ipv6 = ip_tunnel_info_af(info) == AF_INET6;

	/* Ether */
	if (len_left < sizeof(struct ethhdr))
		return -EINVAL;

	eth = (struct ethhdr *)(tunencap_data->data);
	*eth = action_meta->tunnel_eth;

	tunencap_data->len = sizeof(struct ethhdr);
	len_left -= sizeof(struct ethhdr);

	/* IP */
	if (is_ipv6) {
		if (len_left < sizeof(struct ipv6hdr))
			return -EINVAL;

		ipv6 = (struct ipv6hdr *)(eth + 1);
		ipv6->version = 6;
		ip6_flow_hdr(ipv6, info->key.tos, info->key.label);
		ipv6->hop_limit = info->key.ttl;
		ipv6->nexthdr = IPPROTO_UDP;
		ipv6->saddr = info->key.u.ipv6.src;
		ipv6->daddr = info->key.u.ipv6.dst;

		tunencap_data->len += sizeof(struct ipv6hdr);
		len_left -= sizeof(struct ipv6hdr);

		udp = (struct udphdr *)(ipv6 + 1);
	} else {
		if (len_left < sizeof(struct iphdr))
			return -EINVAL;

		ipv4 = (struct iphdr *)(eth + 1);
		ipv4->version = 4;
		ipv4->ihl = 5;
		ipv4->tos = info->key.tos;
		ipv4->ttl = info->key.ttl;
		ipv4->protocol = IPPROTO_UDP;
		ipv4->saddr = info->key.u.ipv4.src;
		ipv4->daddr = info->key.u.ipv4.dst;

		tunencap_data->len += sizeof(struct iphdr);
		len_left -= sizeof(struct iphdr);

		udp = (struct udphdr *)(ipv4 + 1);
	}

	/* VLAN TODO */

	/* UDP */
	if (len_left < sizeof(struct udphdr))
		return -EINVAL;

	udp->dest = info->key.tp_dst;
	udp->source = 0;

	tunencap_data->len += sizeof(struct udphdr);
	len_left -= sizeof(struct udphdr);

	/* Tunnel - vxlan/geneve */
	if (info->key.tp_dst == htons(IANA_VXLAN_UDP_PORT)) {
		vxlan_type = is_ipv6 ? YS_TC_ACTION_VXLANENCAP_IPV6 :
			YS_TC_ACTION_VXLANENCAP_IPV4;
		tunencap_data->type = vxlan_type;
		tunencap_data->len += sizeof(struct vxlanhdr);

		if (len_left < sizeof(struct vxlanhdr))
			return -EINVAL;
		vxlan = (struct vxlanhdr *)(udp + 1);
		vxlan->vx_flags = VXLAN_HF_VNI;
		vxlan->vx_vni = vxlan_vni_field(tunnel_id_to_key32(info->key.tun_id));
		len_left -= sizeof(struct vxlanhdr);
	} else {
		if (is_ipv6)
			gnv_type = info->options_len ? YS_TC_ACTION_GNVENCAP_IPV6OPT :
				YS_TC_ACTION_GNVENCAP_IPV6;
		else
			gnv_type = info->options_len ? YS_TC_ACTION_GNVENCAP_IPV4OPT :
				YS_TC_ACTION_GNVENCAP_IPV4;
		tunencap_data->type = gnv_type;
		tunencap_data->len += sizeof(struct genevehdr) + info->options_len;

		if (len_left < (sizeof(struct genevehdr) + info->options_len))
			return -EINVAL;
		geneve = (struct genevehdr *)(udp + 1);
		geneve->ver = 0;
		geneve->opt_len = info->options_len / 4;
		geneve->oam = !!(info->key.tun_flags & TUNNEL_OAM);
		geneve->critical = !!(info->key.tun_flags & TUNNEL_CRIT_OPT);
		geneve->rsvd1 = 0;
		tunnel_id_to_vni(info->key.tun_id, geneve->vni);
		geneve->proto_type = htons(ETH_P_TEB);
		memcpy(geneve + 1, action_meta->tunnel_opt, info->options_len);
		geneve_opt = (struct geneve_opt *)(geneve + 1);
		if (info->options_len && geneve_opt->type & GENEVE_CRIT_OPT_TYPE)
			geneve->critical = 1;
		len_left -= sizeof(struct genevehdr) + info->options_len;
	}
	return 0;
}

static int
ys_tc_action_flat_tunnel_encap(struct ys_tc_priv *tc_priv,
			       struct ys_tc_action_buf *action_buf,
			       const struct ys_tc_action_tunencap_data *encap_data,
			       __be16 udp_source)
{
	struct ethhdr *eth = NULL;
	struct iphdr *ipv4 = NULL;
	struct udphdr *udp = NULL;
	struct ys_tc_action_entry *act_entry = NULL;
	const u8 vxlan_v4_encap_len = sizeof(struct ethhdr) +
				      sizeof(struct iphdr) +
				      sizeof(struct udphdr) +
				      sizeof(struct vxlanhdr);
	const struct ys_tc_ops_action vxlan_v4_encap_ops = {
		.type = YS_TC_ACTION_ENCAP_VXLAN_IPV4,
		.datalen = vxlan_v4_encap_len,
		.parse = NULL
	};
	struct ys_tc_switchdev *switchdev = tc_priv->switchdev;

	if (switchdev->hash_tbl_cache_high)
		return -EOPNOTSUPP;

	if (encap_data->type != YS_TC_ACTION_VXLANENCAP_IPV4)
		return -EOPNOTSUPP;
	if (encap_data->len != vxlan_v4_encap_len)
		return -EOPNOTSUPP;

	act_entry = ys_tc_action_entry_next(action_buf, vxlan_v4_encap_len);
	if (!act_entry)
		return -ENOBUFS;

	act_entry->type = YS_TC_ACTION_ENCAP_VXLAN_IPV4;
	act_entry->len = vxlan_v4_encap_len;
	memcpy(act_entry->data.vxlan_ipv4, encap_data->data, vxlan_v4_encap_len);

	eth = (struct ethhdr *)(act_entry->data.vxlan_ipv4);
	ipv4 = (struct iphdr *)(eth + 1);
	udp = (struct udphdr *)(ipv4 + 1);
	udp->source = udp_source;

	ys_tc_action_entry_mv_offset(action_buf, &vxlan_v4_encap_ops);
	return 0;
}

static int
ys_tc_action_parse_tunnel_encap(struct ys_tc_priv *tc_priv,
				const struct ys_tc_ops_action *ops,
				struct ys_tc_action_ctx *ctx)
{
	const struct ys_tc_flow_metadata *flow_meta = ctx->flow_meta;
	struct ys_tc_action_meta *action_meta = &ctx->action_meta;
	struct ys_tc_flow *flow = ctx->flow;
	struct ys_tc_action_buf *action_buf = ctx->encap_buf;

	int ret;
	size_t encap_data_len = 0;
	struct ys_tc_action_entry *act_entry = NULL;
	struct ys_tc_table_entry *tbl_entry = NULL;
	enum ys_tc_table_id table_id;
	struct ys_tc_action_tunencap_data *encap_data = NULL;
	struct ys_tc_table *table = NULL;
	const struct ys_tc_ops_action *tp_src_ops = NULL;
	struct ys_tc_action_entry *tp_src_entry = NULL;

	__be16 udp_source = 0;

	if (!flow_meta)
		return -EINVAL;

	act_entry = ys_tc_action_entry_next(action_buf, ops->datalen);
	if (!act_entry)
		return -ENOBUFS;

	ret = ys_tc_action_fill_tunnelinfo(tc_priv, action_meta);
	if (ret)
		return ret;

	table_id = (ops->type == YS_TC_ACTION_VXLAN_ENCAP) ?
		YS_TC_TABLE_ID_VXLANENCAP : YS_TC_TABLE_ID_GNVENCAP;

	table = ys_tc_table_find(tc_priv, table_id);
	if (!table)
		return -EINVAL;

	encap_data_len = ys_tc_table_get_valuelen(table);
	encap_data = kzalloc(sizeof(*encap_data) + encap_data_len, GFP_KERNEL);
	if (!encap_data)
		return -ENOMEM;

	ret = ys_tc_action_build_encaphdr(tc_priv, flow_meta, action_meta,
					  encap_data, encap_data_len);
	if (ret) {
		kfree(encap_data);
		return ret;
	}

	udp_source = ys_tc_action_tun_srcport(flow_meta);
	ret = ys_tc_action_flat_tunnel_encap(tc_priv, action_buf, encap_data, udp_source);
	if (!ret) {
		kfree(encap_data);
		return 0;
	}

	tbl_entry = ys_tc_table_alloc(tc_priv, table_id, NULL, encap_data);
	kfree(encap_data);
	encap_data = NULL;
	if (!tbl_entry)
		return -ENOMEM;

	ret = ys_tc_table_add(tc_priv, tbl_entry);
	if (ret) {
		ys_tc_debug("failed to add table %s\n", tbl_entry->table->name);
		ys_tc_table_free(tc_priv, tbl_entry);
		return ret;
	}

	act_entry->data.tun_tbl_id = cpu_to_be32(tbl_entry->idx);
	act_entry->type = ops->type;
	act_entry->len = ops->datalen;

	ys_tc_action_entry_mv_offset(action_buf, ops);
	ret = ys_tc_flow_add_entry(flow, tbl_entry);
	if (ret) {
		ys_tc_table_del_and_free(tc_priv, tbl_entry);
		return ret;
	}

	tp_src_ops = ys_tc_get_action_ops(YS_TC_ACTION_SET_TP_SRC);
	tp_src_entry = ys_tc_action_entry_next(action_buf, tp_src_ops->datalen);
	if (!tp_src_entry)
		return -ENOBUFS;

	tp_src_entry->data.src_port = udp_source;
	tp_src_entry->type = tp_src_ops->type;
	tp_src_entry->len = tp_src_ops->datalen;

	ys_tc_action_entry_mv_offset(action_buf, tp_src_ops);
	return 0;
}

static int
ys_tc_action_parse_output(struct ys_tc_priv *tc_priv,
			  const struct ys_tc_ops_action *ops,
			  struct ys_tc_action_ctx *ctx)
{
	const struct ys_tc_flow_metadata *flow_meta = ctx->flow_meta;
	struct ys_tc_action_meta *action_meta = &ctx->action_meta;
	struct ys_tc_action_buf *action_buf = &ctx->action_buf;

	struct ys_tc_action_entry *act_entry = NULL;
	struct net_device *in_ndev, *out_ndev;
	struct ys_tc_priv *out_tc_priv;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	int idx;

	if (!flow_meta)
		return -EINVAL;

	act_entry = ys_tc_action_entry_next(action_buf, ops->datalen);
	if (!act_entry)
		return -ENOBUFS;

	if (netif_is_lag_master(flow_meta->in_ndev))
		in_ndev = tc_priv->ndev;
	else
		in_ndev = flow_meta->in_ndev;

	if (action_meta->encap_in_mirror)
		out_ndev = action_meta->pre_out_ndev;
	else
		out_ndev = action_meta->out_ndev;

	if (netif_is_lag_master(out_ndev)) {
		if (!ys_tc_lag_can_offload(tc_priv, out_ndev))
			return -EINVAL;

		idx = ys_k2u_get_lag_group_id_by_master(switchdev->id, out_ndev);
		if (idx < 0) {
			ys_tc_debug("Failed to get lag group id by master %s\n", out_ndev->name);
			return -EINVAL;
		}
		act_entry->data.port.pf_id = 0;
		act_entry->data.port.vf_id = cpu_to_be16(YS_K2U_NP_LAG_QSET(idx));
		act_entry->data.port.resv = 0;

		act_entry->type = ops->type;
		act_entry->len = ops->datalen;
		ys_tc_action_entry_mv_offset(action_buf, ops);

		return 0;
	}

	if (!ys_tc_same_switchdev(in_ndev, out_ndev)) {
		ys_tc_debug("in_dev %s and out_dev %s is not in same switchdev\n",
			    in_ndev->name, out_ndev->name);
		return -EINVAL;
	}

	out_tc_priv = ys_tc_get_priv(out_ndev);

	act_entry->data.port.pf_id = 0;
	act_entry->data.port.vf_id = cpu_to_be16(out_tc_priv->qset);
	act_entry->data.port.resv = 0;

	act_entry->type = ops->type;
	act_entry->len = ops->datalen;
	ys_tc_action_entry_mv_offset(action_buf, ops);
	return 0;
}

static struct ys_tc_table_entry *ys_tc_alloc_mirror_tbl_entry(struct ys_tc_priv *tc_priv,
							      struct ys_tc_action_buf *mirror_buf)
{
	struct ys_tc_table_entry *mirror_tbl_entry = NULL;

	mirror_tbl_entry = ys_tc_table_alloc(tc_priv, YS_TC_TABLE_ID_MIRROR, NULL, NULL);
	if (!mirror_tbl_entry)
		return NULL;

	mirror_buf->data = mirror_tbl_entry->data;
	mirror_buf->size = ys_tc_table_get_valuelen(mirror_tbl_entry->table);
	mirror_buf->offset = 0;

	return mirror_tbl_entry;
}

static int
ys_tc_action_parse_mirror(struct ys_tc_priv *tc_priv,
			  const struct ys_tc_ops_action *ops,
			  struct ys_tc_action_ctx *ctx)
{
	int ret = 0;
	struct ys_tc_action_meta *action_meta = &ctx->action_meta;
	struct ys_tc_action_buf *action_buf = &ctx->action_buf;
	struct ys_tc_action_buf mirror_buf = {0};
	struct ys_tc_action_buf *p_mirror_buf = NULL;

	struct ys_tc_table_entry *mirror_tbl_entry = NULL;
	struct ys_tc_priv *out_tc_priv = NULL;
	struct ys_tc_action_entry *mirror_act_entry = NULL;
	struct ys_tc_action_entry *ouput_act_entry = NULL;
	struct ys_tc_action_entry *end_act_entry = NULL;
	const struct ys_tc_ops_action *output_ops = NULL;
	const struct ys_tc_ops_action *end_ops = NULL;
	struct net_device *mirror_ndev = action_meta->mirror_ndev;

	if (action_meta->encap_in_mirror)
		mirror_ndev = action_meta->out_ndev;
	out_tc_priv = ys_tc_get_priv(mirror_ndev);
	if (!out_tc_priv) {
		ys_tc_debug("Failed to get tc priv dev%s\n", mirror_ndev->name);
		return -EOPNOTSUPP;
	}

	mirror_act_entry = ys_tc_action_entry_next(action_buf, ops->datalen);
	if (!mirror_act_entry)
		return -ENOBUFS;

	if (action_meta->encap_in_mirror) {
		mirror_tbl_entry = ctx->mirror_tbl_entry;
		p_mirror_buf = &ctx->mirror_buf;
		ctx->mirror_tbl_entry = NULL;
	} else {
		mirror_tbl_entry = ys_tc_alloc_mirror_tbl_entry(tc_priv, &mirror_buf);
		if (!mirror_tbl_entry)
			return -ENOENT;
		p_mirror_buf = &mirror_buf;
	}

	mirror_act_entry->type = YS_TC_ACTION_FLOW_MIRROR;
	mirror_act_entry->len = ops->datalen;
	mirror_act_entry->data.mirror_id = cpu_to_be32(mirror_tbl_entry->idx);

	// Mirror table entry: output action.
	output_ops = ys_tc_get_action_ops(YS_TC_ACTION_OUTPUT_PORT);
	ouput_act_entry = ys_tc_action_entry_next(p_mirror_buf, output_ops->datalen);
	if (!ouput_act_entry) {
		ret = -ENOBUFS;
		goto failed;
	}
	ouput_act_entry->type = YS_TC_ACTION_OUTPUT_PORT;
	ouput_act_entry->len = output_ops->datalen;
	ouput_act_entry->data.port.pf_id = 0;
	ouput_act_entry->data.port.vf_id = cpu_to_be16(out_tc_priv->qset);
	ouput_act_entry->data.port.resv = 0;
	ys_tc_action_entry_mv_offset(p_mirror_buf, output_ops);

	// Mirror table entry: end action.
	end_ops = ys_tc_get_action_ops(YS_TC_ACTION_END);
	end_act_entry = ys_tc_action_entry_next(p_mirror_buf, end_ops->datalen);
	if (!end_act_entry) {
		ret = -ENOBUFS;
		goto failed;
	}
	end_act_entry->type = YS_TC_ACTION_END;
	end_act_entry->len = end_ops->datalen;
	ys_tc_action_entry_mv_offset(p_mirror_buf, end_ops);

	ret = ys_tc_table_add(tc_priv, mirror_tbl_entry);
	if (ret) {
		ys_tc_debug("failed to add mirror table.");
		goto failed;
	}

	ys_tc_action_entry_mv_offset(action_buf, ops);
	ret = ys_tc_flow_add_entry(ctx->flow, mirror_tbl_entry);
	if (ret)
		ys_tc_table_del_and_free(tc_priv, mirror_tbl_entry);
	return ret;

failed:
	ys_tc_table_free(tc_priv, mirror_tbl_entry);
	return ret;
}

static int
ys_tc_group_get_id(struct ys_tc_priv *tc_priv)
{
	int group_id = 0;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	if (atomic_read(&switchdev->group_id_used) >= YS_K2ULAN_TC_MC_GROUP_NUM) {
		ys_tc_info("lan multicast group is full\n");
		return YS_K2ULAN_TC_MC_GROUP_NUM;
	}

	group_id = find_first_zero_bit(switchdev->group_id_bitmap,
				       YS_K2ULAN_TC_MC_GROUP_NUM);
	if (group_id != YS_K2ULAN_TC_MC_GROUP_NUM) {
		ys_tc_info("alloc group id: %d\n", group_id);
		bitmap_set(switchdev->group_id_bitmap, group_id, 1);
		atomic_inc(&switchdev->group_id_used);
		return group_id;
	}

	return YS_K2ULAN_TC_MC_GROUP_NUM;
}

static struct ys_tc_group_entry *ys_tc_group_alloc(struct ys_tc_priv *tc_priv)
{
	struct ys_tc_group_entry *group_entry;

	group_entry = kzalloc(sizeof(*group_entry), GFP_KERNEL);
	if (!group_entry)
		return NULL;

	return group_entry;
}

static int
ys_tc_action_parse_group(struct ys_tc_priv *tc_priv,
			 const struct ys_tc_ops_action *ops,
			 struct ys_tc_action_ctx *ctx)
{
	__u16 group_id = YS_K2ULAN_TC_MC_GROUP_NUM;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	const struct ys_tc_flow_metadata *flow_meta = ctx->flow_meta;
	struct ys_tc_action_meta *action_meta = &ctx->action_meta;
	struct ys_tc_action_buf *action_buf = &ctx->action_buf;
	struct ys_tc_flow *flow = ctx->flow;
	struct ys_tc_action_entry *act_entry = NULL;
	struct ys_tc_group_entry *group_entry = NULL;
	struct ys_ndev_priv *ndev_priv = NULL;
	int ret;

	if (!flow_meta)
		return -EINVAL;
	ndev_priv = netdev_priv(flow_meta->in_ndev);

	act_entry = ys_tc_action_entry_next(action_buf, ops->datalen);
	if (!act_entry)
		return -ENOBUFS;

	group_entry = rhashtable_lookup_fast(&switchdev->multicast_ht,
					     &action_meta->bitmap,
					     *switchdev->multicast_ht_params);
	if (group_entry && refcount_inc_not_zero(&group_entry->refcnt)) {
		group_id = group_entry->group_id;
		ys_tc_debug("founded, add refcnt group_id %d, refcnt %d\n", group_id,
			    group_entry->refcnt.refs.counter);
	} else {
		group_id = ys_tc_group_get_id(tc_priv);
		if (group_id == YS_K2ULAN_TC_MC_GROUP_NUM)
			return -ENOMEM;
		group_entry = ys_tc_group_alloc(tc_priv);
		if (!group_entry) {
			ys_tc_err("multicast group alloc failed\n");
			return -ENOMEM;
		}
		group_entry->group_id = group_id;
		memcpy(group_entry->bitmap, action_meta->bitmap,
		       YS_K2ULAN_TC_MC_GROUP_QBMP_LEN * sizeof(u32));

		ret = rhashtable_insert_fast(&switchdev->multicast_ht, &group_entry->node,
					     *switchdev->multicast_ht_params);
		if (ret) {
			ys_tc_err("failed to add group_entry to tc hash table\n");
			kfree(group_entry);
			return -ENOMEM;
		}

		refcount_set(&group_entry->refcnt, 1);
		ys_tc_debug("not founded!, switchdev add new group entry group_id %d\n", group_id);
		if (ndev_priv->ys_ndev_hw && ndev_priv->ys_ndev_hw->ys_set_tc_mc_group) {
			ndev_priv->ys_ndev_hw->ys_set_tc_mc_group(flow_meta->in_ndev,
				  group_id, (u32 *)action_meta->bitmap);
		} else {
			ys_tc_err("ys_set_tc_mc_group is NULL, please check ndev_priv->ys_ndev_hw\n");
			rhashtable_remove_fast(&switchdev->multicast_ht, &group_entry->node,
					       *switchdev->multicast_ht_params);
			kfree(group_entry);
			return -EOPNOTSUPP;
		}
	}
	flow->group_entry = group_entry;

	act_entry->type = ops->type;
	act_entry->len = ops->datalen;
	act_entry->data.group_id = cpu_to_be16(group_id);
	ys_tc_action_entry_mv_offset(action_buf, ops);

	return 0;
}

static const struct ys_tc_ops_action ys_tc_ops_actions[YS_TC_ACTION_MAX] = {
#define OPS_ITEM(_type, _datalen, _parse) \
	{ \
		.type = _type, \
		.datalen = _datalen, \
		.parse = _parse, \
	}
	OPS_ITEM(YS_TC_ACTION_COUNT, 4, ys_tc_action_parse_count),
	OPS_ITEM(YS_TC_ACTION_VXLAN_DECAP, 0, ys_tc_action_parse_comm),
	OPS_ITEM(YS_TC_ACTION_GENEVE_DECAP, 0, ys_tc_action_parse_comm),
	OPS_ITEM(YS_TC_ACTION_SET_MAC_SRC, 6, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_MAC_DST, 6, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_POP_VLAN, 0, ys_tc_action_parse_comm),
	OPS_ITEM(YS_TC_ACTION_PUSH_VLAN, 4, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_VLANID, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_VLAN_PCP, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_IP_SRC, 4, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_IP_DST, 4, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_DSCP, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_TTL, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_IPV6_SRC, 16, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_IPV6_DST, 16, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_IPV6_DSCP, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_DEC_TTL, 0, ys_tc_action_parse_comm),
	OPS_ITEM(YS_TC_ACTION_SET_TP_SRC, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_SET_TP_DST, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_VXLAN_ENCAP, 4, ys_tc_action_parse_tunnel_encap),
	OPS_ITEM(YS_TC_ACTION_GENEVE_ENCAP, 4, ys_tc_action_parse_tunnel_encap),
	OPS_ITEM(YS_TC_ACTION_FLOW_MIRROR, 4, ys_tc_action_parse_mirror),
	OPS_ITEM(YS_TC_ACTION_METER, 12, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_QUEUE, 2, ys_tc_action_parse_comm),
	OPS_ITEM(YS_TC_ACTION_OUTPUT_PORT, 4, ys_tc_action_parse_output),
	OPS_ITEM(YS_TC_ACTION_DROP, 0, ys_tc_action_parse_comm),
	OPS_ITEM(YS_TC_ACTION_JUMP, 2, ys_tc_action_parse_jump_mac_vlan_ip_ipv6),
	OPS_ITEM(YS_TC_ACTION_GROUP, 2, ys_tc_action_parse_group),
	OPS_ITEM(YS_TC_ACTION_END, 0, ys_tc_action_parse_comm),
#undef OPS_ITEM
};

static inline void ys_tc_action_add(enum ys_tc_action_type type,
				    struct ys_tc_action_meta *action_meta)
{
	unsigned long nr = type;

	__set_bit(nr, action_meta->action_bits);
	action_meta->pos++;
	action_meta->action_pos_list[type] = action_meta->pos;
}

static inline bool ys_tc_action_exists(long nr, struct ys_tc_action_meta *action_meta)
{
	return test_bit(nr, action_meta->action_bits);
}

static inline void ys_tc_action_del(long nr, struct ys_tc_action_meta *action_meta)
{
	__clear_bit(nr, action_meta->action_bits);
}

static inline bool ys_tc_action_empty(struct ys_tc_action_meta *action_meta)
{
	return bitmap_empty(action_meta->action_bits, YS_TC_ACTION_MAX);
}

static int ys_tc_get_action_type_by_pos(const struct ys_tc_action_meta *action_meta, int pos)
{
	int type = 0;

	for (type = 0; type < YS_TC_ACTION_MAX; type++) {
		if (action_meta->action_pos_list[type] == pos)
			return type;
	}

	return YS_TC_ACTION_MAX;
}

static void ys_tc_action_order_tune(struct ys_tc_action_meta *action_meta)
{
	const int vxlan_encap_pos = action_meta->action_pos_list[YS_TC_ACTION_VXLAN_ENCAP];
	const int geneve_encap_pos = action_meta->action_pos_list[YS_TC_ACTION_GENEVE_ENCAP];
	int target_pos = 0;
	enum ys_tc_action_type type_to_swap = YS_TC_ACTION_MAX;

	if (!vxlan_encap_pos && !geneve_encap_pos)
		return;

	if (action_meta->encap_in_mirror)
		target_pos = action_meta->action_pos_list[YS_TC_ACTION_FLOW_MIRROR] - 1;
	else
		target_pos = action_meta->action_pos_list[YS_TC_ACTION_OUTPUT_PORT] - 1;

	type_to_swap = ys_tc_get_action_type_by_pos(action_meta, target_pos);
	if (type_to_swap < 0 || type_to_swap >= YS_TC_ACTION_MAX)
		return;
	action_meta->action_pos_list[type_to_swap] = vxlan_encap_pos + geneve_encap_pos;

	if (vxlan_encap_pos)
		action_meta->action_pos_list[YS_TC_ACTION_VXLAN_ENCAP] = target_pos;
	else
		action_meta->action_pos_list[YS_TC_ACTION_GENEVE_ENCAP] = target_pos;
}

static const struct ys_tc_ops_action *ys_tc_get_action_ops(enum ys_tc_action_type action_type)
{
	size_t i = 0;
	static const struct ys_tc_ops_action *act_pos_array[YS_TC_ACTION_MAX] = {0};
	const struct ys_tc_ops_action *ops_act = NULL;

	if (action_type < 0 || action_type >= YS_TC_ACTION_MAX)
		return NULL;

	if (act_pos_array[action_type])
		return act_pos_array[action_type];

	for (i = 0; i < ARRAY_SIZE(ys_tc_ops_actions); i++) {
		ops_act = &ys_tc_ops_actions[i];
		if (ops_act->type == action_type) {
			act_pos_array[action_type] = ops_act;
			return ops_act;
		}
	}

	return NULL;
}

static int ys_tc_action_do_parse(struct ys_tc_priv *tc_priv,
				 const struct ys_tc_ops_action *ops_act,
				 struct ys_tc_action_ctx *ctx)
{
	int ret = 0;
	struct ys_tc_action_meta *action_meta = &ctx->action_meta;

	if (!ys_tc_action_exists(ops_act->type, action_meta))
		return 0;

	ys_tc_action_del(ops_act->type, action_meta);

	ret = ops_act->parse(tc_priv, ops_act, ctx);
	if (ret) {
		ys_tc_debug("Failed to parse action %d, ret %d", ops_act->type, ret);
		return ret;
	}

	return 0;
}

static int ys_tc_action_compile(struct ys_tc_priv *tc_priv,
				struct ys_tc_action_ctx *ctx)
{
	int ret = 0;
	int pos = 0;
	size_t i = 0;
	struct ys_tc_action_meta *action_meta = &ctx->action_meta;
	const struct ys_tc_ops_action *ops_act = NULL;
	enum ys_tc_action_type action_type = 0;
	struct ys_tc_table_entry *mirror_tbl_entry = NULL;

	if (ys_tc_action_empty(action_meta))
		return 0;

	if (action_meta->encap_in_mirror) {
		mirror_tbl_entry = ys_tc_alloc_mirror_tbl_entry(tc_priv, &ctx->mirror_buf);
		if (!mirror_tbl_entry)
			return -ENOENT;
		ctx->mirror_tbl_entry = mirror_tbl_entry;
		ctx->encap_buf = &ctx->mirror_buf;
	} else {
		ctx->encap_buf = &ctx->action_buf;
	}

	/* The position value is started from 1, 0 is treated as invalid. */
	for (pos = 1; pos <= action_meta->pos; pos++) {
		action_type = ys_tc_get_action_type_by_pos(action_meta, pos);
		ops_act = ys_tc_get_action_ops(action_type);
		if (ops_act) {
			ret = ys_tc_action_do_parse(tc_priv, ops_act, ctx);
			if (ret)
				goto failed;
		}
	}

	if (!ys_tc_action_empty(action_meta)) {
		for (i = 0; i < ARRAY_SIZE(action_meta->action_bits); i++)
			ys_tc_err("unknown action [%lu]: 0x%lx", i, action_meta->action_bits[i]);
		ret = -EINVAL;
		goto failed;
	}

	return 0;

failed:
	ys_tc_table_free(tc_priv, ctx->mirror_tbl_entry);
	return ret;
}

/* ystc action end */
/* ystc flow_act start */

struct ys_tc_ops_flow_act {
	int (*parse)(struct ys_tc_priv *tc_priv,
		     const struct flow_action_entry *act,
		     const struct ys_tc_flow_metadata *flow_meta,
		     struct ys_tc_action_meta *action_meta);
};

static int ys_tc_flow_act_common(struct ys_tc_priv *tc_priv,
				 const struct flow_action_entry *act,
				 const struct ys_tc_flow_metadata *flow_meta,
				 struct ys_tc_action_meta *action_meta)
{
	struct ys_tc_meter *meter;
	bool vlan_push_exist = false;
	__u16 vlan_vid;

	switch (act->id) {
	case FLOW_ACTION_DROP:
		 ys_tc_action_add(YS_TC_ACTION_DROP, action_meta);
		break;
	case FLOW_ACTION_VLAN_POP:
		ys_tc_action_add(YS_TC_ACTION_POP_VLAN, action_meta);
		break;
	case FLOW_ACTION_CSUM:
		break;
	case FLOW_ACTION_VLAN_PUSH:
		if (act->vlan.proto != cpu_to_be16(ETH_P_8021Q) &&
		    act->vlan.proto != cpu_to_be16(ETH_P_8021AD))
			return -EINVAL;

		if (ys_tc_action_exists(YS_TC_ACTION_PUSH_VLAN, action_meta))
			return -EOPNOTSUPP;

		ys_tc_action_add(YS_TC_ACTION_PUSH_VLAN, action_meta);
		action_meta->vlan_tpid = act->vlan.proto;
		action_meta->vlan_vid |= cpu_to_be16(act->vlan.vid & VLAN_VID_MASK);
		vlan_vid = act->vlan.prio;
		vlan_vid = (act->vlan.prio << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK;
		action_meta->vlan_vid |= cpu_to_be16(vlan_vid);
		break;

	case FLOW_ACTION_VLAN_MANGLE:
		vlan_push_exist = ys_tc_action_exists(YS_TC_ACTION_PUSH_VLAN, action_meta);
		if (act->vlan.proto)
			return -EOPNOTSUPP;
		if (act->vlan.vid && !vlan_push_exist) {
			ys_tc_action_add(YS_TC_ACTION_SET_VLANID, action_meta);
			action_meta->vlan_id = cpu_to_be16(act->vlan.vid);
		}
		if (act->vlan.vid && vlan_push_exist)
			action_meta->vlan_vid |= cpu_to_be16(act->vlan.vid & VLAN_VID_MASK);
		if (act->vlan.prio && !vlan_push_exist) {
			ys_tc_action_add(YS_TC_ACTION_SET_VLAN_PCP, action_meta);
			action_meta->vlan_pcp = cpu_to_be16(act->vlan.prio);
		}
		if (act->vlan.prio && vlan_push_exist) {
			vlan_vid = act->vlan.prio;
			vlan_vid = (act->vlan.prio << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK;
			action_meta->vlan_vid |= cpu_to_be16(vlan_vid);
		}
		break;
	case FLOW_ACTION_TUNNEL_ENCAP:
		if (act->tunnel->options_len &&
		    act->tunnel->key.tp_dst != htons(GENEVE_UDP_PORT))
			return -EOPNOTSUPP;
		if (act->tunnel->options_len && act->tunnel->options_len != 8)
			return -EOPNOTSUPP;
		if (act->tunnel->options_len) {
			struct geneve_opt *opt =
				(struct geneve_opt *)ip_tunnel_info_opts(act->tunnel);

			if (opt->opt_class != cpu_to_be16(0x0102) ||
			    opt->type != 0x80)
				return -EOPNOTSUPP;
			memcpy(action_meta->tunnel_opt, opt, 8);
		}
		action_meta->tunnel_info = *act->tunnel;
		/* Now we only offload GENEVE tunnel with no option or OVN specific option
		 * (transmits the logical ingress and logical egress ports
		 * in a TLV with class 0x0102, type 0x80, and a 32-bit value).
		 */
		switch (act->tunnel->key.tp_dst) {
		case htons(IANA_VXLAN_UDP_PORT):
			ys_tc_action_add(YS_TC_ACTION_VXLAN_ENCAP, action_meta);
			break;
		case htons(GENEVE_UDP_PORT):
			ys_tc_action_add(YS_TC_ACTION_GENEVE_ENCAP, action_meta);
			break;
		default:
			return -EOPNOTSUPP;
		}
		action_meta->has_tnl_encap = true;
		break;
	case FLOW_ACTION_TUNNEL_DECAP:
		switch (flow_meta->tun_dst_port) {
		case htons(IANA_VXLAN_UDP_PORT):
			ys_tc_action_add(YS_TC_ACTION_VXLAN_DECAP, action_meta);
			break;
		case htons(GENEVE_UDP_PORT):
			ys_tc_action_add(YS_TC_ACTION_GENEVE_DECAP, action_meta);
			break;
		default:
			return -EOPNOTSUPP;
		}
		break;
	case FLOW_ACTION_POLICE:
		rcu_read_lock();
		meter = ys_tc_meter_lookup(tc_priv, act->hw_index);
		if (!meter || !refcount_inc_not_zero(&meter->refcnt)) {
			rcu_read_unlock();
			return -EINVAL;
		}

		ys_tc_action_add(YS_TC_ACTION_METER, action_meta);
		action_meta->meter_id = meter->meter_tbl_entry->idx;
		action_meta->meter_green_cnt_idx = meter->green_cnt_entry->idx;
		action_meta->meter_red_cnt_idx = meter->red_cnt_entry->idx;
		rcu_read_unlock();

		ys_tc_meter_put(tc_priv, meter);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static inline void set_pedit_value(void *data, u32 val, u32 mask, u32 off)
{
	u32 old_value = get_unaligned((u32 *)(((char *)data) + off));

	val &= ~mask;
	val |= (old_value & mask);
	put_unaligned(val, (u32 *)(((char *)data) + off));
}

static int ys_tc_flow_act_mangle(struct ys_tc_priv *tc_priv,
				 const struct flow_action_entry *act,
				 const struct ys_tc_flow_metadata *flow_meta,
				 struct ys_tc_action_meta *action_meta)
{
	struct {
		char is_eth;
		char is_ip4;
		char is_ip6;
		char is_tcp;
		char is_udp;
	} flag = { 0 };
	enum flow_action_mangle_base htype;
	u32 val;
	u32 mask;
	u32 off;

	htype = act->mangle.htype;
	off = act->mangle.offset;
	mask = act->mangle.mask;
	val = act->mangle.val;

	switch (htype) {
	case TCA_PEDIT_KEY_EX_HDR_TYPE_ETH:
		flag.is_eth = 1;
		set_pedit_value(&action_meta->eth, val, mask, off);
		break;
	case TCA_PEDIT_KEY_EX_HDR_TYPE_IP4:
		flag.is_ip4 = 1;
		set_pedit_value(&action_meta->ipv4, val, mask, off);
		break;
	case TCA_PEDIT_KEY_EX_HDR_TYPE_IP6:
		flag.is_ip6 = 1;
		set_pedit_value(&action_meta->ipv6, val, mask, off);
		break;
	case TCA_PEDIT_KEY_EX_HDR_TYPE_TCP:
		flag.is_tcp = 1;
		set_pedit_value(&action_meta->tcp, val, mask, off);
		break;
	case TCA_PEDIT_KEY_EX_HDR_TYPE_UDP:
		flag.is_udp = 1;
		set_pedit_value(&action_meta->tcp, val, mask, off);
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (flag.is_eth && !eth_addr_is_zero(action_meta->eth.h_source))
		ys_tc_action_add(YS_TC_ACTION_SET_MAC_SRC, action_meta);

	if (flag.is_eth && !eth_addr_is_zero(action_meta->eth.h_dest))
		ys_tc_action_add(YS_TC_ACTION_SET_MAC_DST, action_meta);

	if (flag.is_ip4 && action_meta->ipv4.saddr)
		ys_tc_action_add(YS_TC_ACTION_SET_IP_SRC, action_meta);

	if (flag.is_ip4 && action_meta->ipv4.daddr)
		ys_tc_action_add(YS_TC_ACTION_SET_IP_DST, action_meta);

	if (flag.is_ip4 && action_meta->ipv4.tos)
		ys_tc_action_add(YS_TC_ACTION_SET_DSCP, action_meta);

	if (flag.is_ip4 && action_meta->ipv4.ttl)
		ys_tc_action_add(YS_TC_ACTION_SET_TTL, action_meta);

	if ((flag.is_tcp || flag.is_udp) && action_meta->tcp.source)
		ys_tc_action_add(YS_TC_ACTION_SET_TP_SRC, action_meta);

	if ((flag.is_tcp || flag.is_udp) && action_meta->tcp.dest)
		ys_tc_action_add(YS_TC_ACTION_SET_TP_DST, action_meta);

	if (flag.is_ip6 && !in6_addr_is_zero(&action_meta->ipv6.saddr))
		ys_tc_action_add(YS_TC_ACTION_SET_IPV6_SRC, action_meta);

	if (flag.is_ip6 && !in6_addr_is_zero(&action_meta->ipv6.daddr))
		ys_tc_action_add(YS_TC_ACTION_SET_IPV6_DST, action_meta);

	if (flag.is_ip6 && (action_meta->ipv6.priority || (action_meta->ipv6.flow_lbl[0] & 0xf0)))
		ys_tc_action_add(YS_TC_ACTION_SET_IPV6_DSCP, action_meta);

	if (flag.is_ip6 && action_meta->ipv6.hop_limit)
		ys_tc_action_add(YS_TC_ACTION_SET_TTL, action_meta);

	return 0;
}

static int ys_tc_flow_act_output(struct ys_tc_priv *tc_priv,
				 const struct flow_action_entry *act,
				 const struct ys_tc_flow_metadata *flow_meta,
				 struct ys_tc_action_meta *action_meta)
{
	int dst_qset;

	if (ys_tc_action_exists(YS_TC_ACTION_OUTPUT_PORT, action_meta))
		return -EOPNOTSUPP;

	if (ys_tc_action_exists(YS_TC_ACTION_GROUP, action_meta)) {
		if (!ys_tc_dev_valid(act->dev))
			return -EINVAL;

		dst_qset = ys_k2u_ndev_get_dstqsetid(netdev_priv(act->dev));
		if (dst_qset < 0 || dst_qset >= YSC_K2ULAN_MC_GROUP_QBMP_NUM)
			return -EINVAL;

		bitmap_set(action_meta->bitmap, dst_qset, 1);
		return 0;
	}

	ys_tc_action_add(YS_TC_ACTION_OUTPUT_PORT, action_meta);
	action_meta->out_ndev = act->dev;
	ys_tc_debug("Tc output dev: %s\n", act->dev->name);

	// The action_meta->out_ndev could be changed by encap tunnel routing.
	// For openflow: add-flow br1 'in_port=p1pf1hpf,actions=clone(vxlan1),output=p1pf0hpf'
	// Generates tc actions: Encap / Mirror vxlan_sys_4789 / output <mirror port>
	// That would be two flows:
	//     a) 'in_port=p1pf1hpf,output=p1pf0hpf'
	//     b) 'in_port=p1pf1hpf,set_tunnel:<>,set_field:<>->tun_dst,output=vxlan1'
	// The encap is for mirror port, which is known by action_meta->encap_in_mirror.
	// The pre output dev should save for output action.
	action_meta->pre_out_ndev = action_meta->out_ndev;
	return 0;
}

static int ys_tc_flow_act_mirror(struct ys_tc_priv *tc_priv,
				 const struct flow_action_entry *act,
				 const struct ys_tc_flow_metadata *flow_meta,
				 struct ys_tc_action_meta *action_meta)
{
	int dst_qset;

	if (ys_tc_action_exists(YS_TC_ACTION_FLOW_MIRROR, action_meta)) {
		if (!ys_tc_action_exists(YS_TC_ACTION_GROUP, action_meta))
			ys_tc_action_add(YS_TC_ACTION_GROUP, action_meta);

		if (!ys_tc_dev_valid(act->dev))
			return -EINVAL;

		dst_qset = ys_k2u_ndev_get_dstqsetid(netdev_priv(act->dev));
		if (dst_qset < 0 || dst_qset >= YSC_K2ULAN_MC_GROUP_QBMP_NUM)
			return -EINVAL;

		bitmap_set(action_meta->bitmap, dst_qset, 1);

		if (!ys_tc_dev_valid(action_meta->mirror_ndev))
			return -EINVAL;

		dst_qset = ys_k2u_ndev_get_dstqsetid(netdev_priv(action_meta->mirror_ndev));
		if (dst_qset < 0 || dst_qset >= YSC_K2ULAN_MC_GROUP_QBMP_NUM)
			return -EINVAL;

		bitmap_set(action_meta->bitmap, dst_qset, 1);
		ys_tc_action_del(YS_TC_ACTION_FLOW_MIRROR, action_meta);
	} else if (ys_tc_action_exists(YS_TC_ACTION_GROUP, action_meta)) {
		if (!ys_tc_dev_valid(act->dev))
			return -EINVAL;

		dst_qset = ys_k2u_ndev_get_dstqsetid(netdev_priv(act->dev));
		if (dst_qset < 0 || dst_qset >= YSC_K2ULAN_MC_GROUP_QBMP_NUM)
			return -EINVAL;

		bitmap_set(action_meta->bitmap, dst_qset, 1);
	} else {
		ys_tc_action_add(YS_TC_ACTION_FLOW_MIRROR, action_meta);
		action_meta->mirror_ndev = act->dev;
		ys_tc_debug("Tc mirror dev: %s\n", act->dev->name);

		if (action_meta->has_tnl_encap && ys_tc_is_netdev_to_offload(act->dev))
			action_meta->encap_in_mirror = true;
	}

	return 0;
}

static struct ys_tc_ops_flow_act ys_tc_ops_flow_acts[NUM_FLOW_ACTIONS] = {
#define OPS_ITEM(_id, _parse) \
	[_id] = { .parse = _parse }
	OPS_ITEM(FLOW_ACTION_DROP, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_REDIRECT, ys_tc_flow_act_output),
	OPS_ITEM(FLOW_ACTION_MIRRED, ys_tc_flow_act_mirror),
	OPS_ITEM(FLOW_ACTION_REDIRECT_INGRESS, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_MIRRED_INGRESS, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_VLAN_PUSH, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_VLAN_POP, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_VLAN_MANGLE, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_TUNNEL_ENCAP, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_TUNNEL_DECAP, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_MANGLE, ys_tc_flow_act_mangle),
	OPS_ITEM(FLOW_ACTION_CSUM, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_QUEUE, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_SAMPLE, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_POLICE, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_CT, ys_tc_flow_act_common),
	OPS_ITEM(FLOW_ACTION_CT_METADATA, ys_tc_flow_act_common),
#undef OPS_ITEM
};

/* ystc flow_act end */
/* ystc flow start */

static struct net_device *
ys_tc_flow_ndev_get(struct ys_tc_priv *tc_priv,
		    struct ys_tc_addr *src_addr,
		    struct ys_tc_addr *dst_addr)
{
	int ret;
	struct flowi4 fl4 = { 0 };
	struct flowi6 fl6 = { 0};
	struct rtable *rt;
	struct dst_entry *dst;
	struct net_device *ret_dev = NULL;

	if (!src_addr->is_ipv6 && !dst_addr->is_ipv6) {
		fl4.saddr = src_addr->ipv4;
		fl4.daddr = dst_addr->ipv4;
		rt = ip_route_output_key(dev_net(tc_priv->ndev), &fl4);
		ret = PTR_ERR_OR_ZERO(rt);
		if (ret)
			return NULL;
		ret_dev = rt->dst.dev;

		if (!ret_dev || !netif_running(ret_dev)) {
			ys_tc_warn("invalid or down dev from dst, possible fnhe race\n");
			ip_rt_put(rt);
			return NULL;
		}

		ip_rt_put(rt);
		return ret_dev;
#if IS_ENABLED(CONFIG_INET) && IS_ENABLED(CONFIG_IPV6)
	} else if (src_addr->is_ipv6 && dst_addr->is_ipv6) {
		fl6.saddr = src_addr->ipv6;
		fl6.daddr = dst_addr->ipv6;

		dst = ipv6_stub->ipv6_dst_lookup_flow(dev_net(tc_priv->ndev),
						      NULL, &fl6, NULL);
		if (IS_ERR(dst))
			return NULL;
		ret_dev = dst->dev;
		dst_release(dst);
	}
#endif

	return ret_dev;
}

static inline bool flow_mask_valid(void *mask, size_t len)
{
	return !memchr_inv(mask, 0xff, len);
}

#define FLOW_MASK_VALID(msk) ({ \
	typeof(msk) _msk = (msk); \
	flow_mask_valid(_msk, sizeof(*(_msk)));	\
})

static int
ys_tc_flow_valid_tunnel_opt(struct ys_tc_priv *tc_priv, struct flow_rule *rule,
			    struct ys_tc_flow_metadata *md)
{
	struct flow_match_enc_opts enc_opts;

	struct geneve_opt *option_key;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_OPTS))
		return 0;

	flow_rule_match_enc_opts(rule, &enc_opts);

	if (enc_opts.key->dst_opt_type != TUNNEL_GENEVE_OPT ||
	    enc_opts.key->len != 8)
		return -EOPNOTSUPP;

	option_key = (struct geneve_opt *)&enc_opts.key->data[0];

	if (option_key->opt_class != cpu_to_be16(0x0102) ||
	    option_key->type != 0x80)
		return -EOPNOTSUPP;

	memcpy(md->tun_opt, option_key, sizeof(md->tun_opt));

	return 0;
}

static int ys_tc_flow_valid(struct ys_tc_priv *tc_priv,
			    struct flow_cls_offload *cls_flower,
			    struct ys_tc_flow_metadata *flow_md)
{
	int ret;
	struct flow_match_basic basic_match;
	struct flow_match_eth_addrs eth_match;

	struct flow_match_control ctrl_match;
	struct flow_match_control enc_ctrl_match;
	struct flow_match_enc_keyid enc_keyid_match;
	struct flow_match_ports enc_ports_match;

	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct net_device *netdev_tmp;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ICMP) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TIPC) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ARP) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_FLOW_LABEL) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_GRE_KEYID) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_MPLS_ENTROPY) ||
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_MPLS)) {
		ys_tc_debug("flow not support icmp/tipc/arp/mpls/gre\n");
		return -EOPNOTSUPP;
	}

	flow_md->in_ndev = tc_priv->ndev;

	/* basic */
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		ys_tc_debug("flow need support basic\n");
		return -EINVAL;
	}
	flow_rule_match_basic(rule, &basic_match);
	if (!FLOW_MASK_VALID(&basic_match.mask->n_proto) ||
	    !FLOW_MASK_VALID(&basic_match.mask->ip_proto) ||
	    (basic_match.key->n_proto != cpu_to_be16(ETH_P_IP) &&
	    basic_match.key->n_proto != cpu_to_be16(ETH_P_IPV6)) ||
	    (basic_match.key->ip_proto != IPPROTO_TCP &&
	     basic_match.key->ip_proto != IPPROTO_UDP)) {
		ys_tc_debug("flow basic valid failed, n_proto %x/%x ip_proto %x/%x\n",
			    basic_match.key->n_proto, basic_match.mask->n_proto,
			    basic_match.key->ip_proto, basic_match.mask->ip_proto);
		return -EINVAL;
	}
	flow_md->proto = basic_match.key->ip_proto;

	/* eth */
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		ys_tc_debug("flow need support eth addrs\n");
		return -EINVAL;
	}
	flow_rule_match_eth_addrs(rule, &eth_match);
	if (!FLOW_MASK_VALID(eth_match.mask)) {
		ys_tc_debug("flow eth addrs valid failed\n");
		return -EINVAL;
	}
	ether_addr_copy(flow_md->src_eth, eth_match.key->src);
	ether_addr_copy(flow_md->dst_eth, eth_match.key->dst);

	/* vlan */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan vlan_match;

		flow_rule_match_vlan(rule, &vlan_match);
		if (vlan_match.mask->vlan_id != 0xfff) {
			ys_tc_debug("flow vlan_id mask valid failed\n");
			return -EINVAL;
		}
		flow_md->vlan_id = vlan_match.key->vlan_id;
	}

	/* cvlan */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan cvlan_match;

		flow_rule_match_cvlan(rule, &cvlan_match);
		if (cvlan_match.mask->vlan_id != 0xfff) {
			ys_tc_debug("flow cvlan_id mask valid failed\n");
			return -EINVAL;
		}
		flow_md->cvlan_id = cvlan_match.key->vlan_id;
	}

	/* control */
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		ys_tc_debug("flow need support control\n");
		return -EINVAL;
	}
	flow_rule_match_control(rule, &ctrl_match);
	if (ctrl_match.mask->addr_type != 0xffff ||
	    (ctrl_match.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	     ctrl_match.key->addr_type != FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		ys_tc_debug("flow not support control addr_type %x/%x\n",
			    ctrl_match.key->addr_type, ctrl_match.mask->addr_type);
		return -EINVAL;
	}
	if ((ctrl_match.key->flags & FLOW_DIS_IS_FRAGMENT) &&
	    (ctrl_match.key->flags & FLOW_DIS_FIRST_FRAG))
		flow_md->frag_type = YS_TC_FRAG_FIRST;
	else if (ctrl_match.key->flags & FLOW_DIS_IS_FRAGMENT)
		flow_md->frag_type = YS_TC_FRAG_LATER;
	else
		flow_md->frag_type = YS_TC_FRAG_NONE;

	if ((ctrl_match.key->flags & FLOW_DIS_IS_FRAGMENT) &&
	    ctrl_match.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS)
		return -EOPNOTSUPP;

	/* ipv4 */
	if (ctrl_match.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs ipv4_match;

		flow_rule_match_ipv4_addrs(rule, &ipv4_match);
		if (!FLOW_MASK_VALID(ipv4_match.mask)) {
			ys_tc_debug("flow ipv4 mask valid failed\n");
			return -EINVAL;
		}
		flow_md->src_addr.is_ipv6 = false;
		flow_md->src_addr.ipv4 = ipv4_match.key->src;
		flow_md->dst_addr.is_ipv6 = false;
		flow_md->dst_addr.ipv4 = ipv4_match.key->dst;
	}

	/* ipv6 */
	if (ctrl_match.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs ipv6_match;

		flow_rule_match_ipv6_addrs(rule, &ipv6_match);
		if (!FLOW_MASK_VALID(ipv6_match.mask)) {
			ys_tc_debug("flow ipv6 mask valid failed\n");
			return -EINVAL;
		}
		flow_md->src_addr.is_ipv6 = true;
		flow_md->src_addr.ipv6 = ipv6_match.key->src;
		flow_md->dst_addr.is_ipv6 = true;
		flow_md->dst_addr.ipv6 = ipv6_match.key->dst;
	}

	/* ports */
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS) &&
	    !(ctrl_match.key->flags & FLOW_DIS_IS_FRAGMENT)) {
		ys_tc_debug("flow ports mask valid failed\n");
		return -EINVAL;
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports ports_match;

		flow_rule_match_ports(rule, &ports_match);
		if (!FLOW_MASK_VALID(ports_match.mask)) {
			ys_tc_debug("flow ports mask valid failed\n");
			return -EINVAL;
		}
		flow_md->src_port = ports_match.key->src;
		flow_md->dst_port = ports_match.key->dst;
	}

	flow_md->tun_type = YS_TC_TUNNEL_NONE;
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID))
		goto out;

	/* enc control */
	flow_rule_match_enc_control(rule, &enc_ctrl_match);
	if (enc_ctrl_match.mask->addr_type != 0xffff ||
	    (enc_ctrl_match.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	     enc_ctrl_match.key->addr_type != FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		ys_tc_debug("flow not support enc control addr_type %x/%x\n",
			    enc_ctrl_match.key->addr_type,
			    ctrl_match.mask->addr_type);
		return -EINVAL;
	}

	if (enc_ctrl_match.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs enc_ipv4_match;

		flow_rule_match_enc_ipv4_addrs(rule, &enc_ipv4_match);
		if (!FLOW_MASK_VALID(enc_ipv4_match.mask)) {
			ys_tc_debug("flow ipv6 mask valid failed\n");
			return -EINVAL;
		}
		flow_md->tun_src_addr.is_ipv6 = false;
		flow_md->tun_src_addr.ipv4 = enc_ipv4_match.key->src;
		flow_md->tun_dst_addr.is_ipv6 = false;
		flow_md->tun_dst_addr.ipv4 = enc_ipv4_match.key->dst;
	}

	if (enc_ctrl_match.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs enc_ipv6_match;

		flow_rule_match_enc_ipv6_addrs(rule, &enc_ipv6_match);
		if (!FLOW_MASK_VALID(enc_ipv6_match.mask)) {
			ys_tc_debug("flow ipv6 mask valid failed\n");
			return -EINVAL;
		}
		flow_md->tun_src_addr.is_ipv6 = true;
		flow_md->tun_src_addr.ipv6 = enc_ipv6_match.key->src;
		flow_md->tun_dst_addr.is_ipv6 = true;
		flow_md->tun_dst_addr.ipv6 = enc_ipv6_match.key->dst;
	}

	flow_rule_match_enc_keyid(rule, &enc_keyid_match);
	if (enc_keyid_match.mask->keyid != cpu_to_be32(0xffffffff)) {
		ys_tc_debug("flow enc keyid mask invalid\n");
		return -EINVAL;
	}
	flow_md->tun_id = enc_keyid_match.key->keyid;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		ys_tc_debug("flow need support enc ports\n");
		return -EINVAL;
	}
	flow_rule_match_enc_ports(rule, &enc_ports_match);
	if (!FLOW_MASK_VALID(&enc_ports_match.mask->dst)) {
		ys_tc_debug("flow enc ports mask valid failed\n");
		return -EINVAL;
	}
	flow_md->tun_src_port = enc_ports_match.key->src;
	flow_md->tun_dst_port = enc_ports_match.key->dst;

	switch (flow_md->tun_dst_port) {
	case cpu_to_be16(IANA_VXLAN_UDP_PORT):
		flow_md->tun_type = YS_TC_TUNNEL_VXLAN;
		break;

	case cpu_to_be16(GENEVE_UDP_PORT):
		flow_md->tun_type = YS_TC_TUNNEL_GENEVE;
		break;
	default:
		return -EOPNOTSUPP;
	}

	ret = ys_tc_flow_valid_tunnel_opt(tc_priv, rule, flow_md);
	if (ret) {
		ys_tc_debug("flow valid tunnel opt failed\n");
		return ret;
	}

	flow_md->in_ndev = ys_tc_flow_ndev_get(tc_priv, &flow_md->tun_dst_addr,
					       &flow_md->tun_src_addr);
	if (flow_md->in_ndev && netif_is_lag_master(flow_md->in_ndev)) {
		rcu_read_lock();
		for_each_netdev_in_bond_rcu(flow_md->in_ndev, netdev_tmp) {
			if (netdev_tmp == tc_priv->ndev) {
				rcu_read_unlock();
				return 0;
			}
		}
		rcu_read_unlock();
	}

	if (!flow_md->in_ndev || flow_md->in_ndev != tc_priv->ndev) {
		ys_tc_debug("flow in_ndev not found or not equel\n");
		return -ENODEV;
	}

out:
	return 0;
}

static int ys_tc_flow_compile_match(struct ys_tc_priv *tc_priv,
				    struct ys_tc_flow *flow,
				    const struct ys_tc_flow_metadata *md)
{
	struct ys_tc_priv *in_tc_priv;
	struct ys_tc_key_ipv4 *ipv4;
	struct ys_tc_key_ipv6 *ipv6;

	if (!ys_tc_dev_valid(md->in_ndev) && !netif_is_lag_master(md->in_ndev)) {
		ys_tc_debug("flow in_ndev not valid\n");
		return -EINVAL;
	}

	if (netif_is_lag_master(md->in_ndev)) {
		if (!ys_tc_lag_can_offload(tc_priv, md->in_ndev))
			return -EINVAL;
	}

	in_tc_priv = tc_priv;

	if (!md->src_addr.is_ipv6) {
		ipv4 = (struct ys_tc_key_ipv4 *)(flow->table_entry->data);
		ether_addr_copy(ipv4->src_eth, md->src_eth);
		ether_addr_copy(ipv4->dst_eth, md->dst_eth);

		ipv4->protocol = md->proto;
		ipv4->src_ip = md->src_addr.ipv4;
		ipv4->dst_ip = md->dst_addr.ipv4;
		ipv4->src_port = md->src_port;
		ipv4->dst_port = md->dst_port;
		ipv4->fragment = md->frag_type;

		ipv4->vlan_id = cpu_to_be16(md->vlan_id);

		ipv4->tenant_id = md->tun_id;

		ipv4->tun_type = md->tun_type;
		ipv4->src_qset = cpu_to_be16(in_tc_priv->qset);
	} else {
		ipv6 = (struct ys_tc_key_ipv6 *)(flow->table_entry->data);
		ether_addr_copy(ipv6->src_eth, md->src_eth);
		ether_addr_copy(ipv6->dst_eth, md->dst_eth);

		ipv6->protocol = md->proto;
		memcpy(ipv6->src_ip, &md->src_addr.ipv6,
		       YS_TC_KEY_IPV6_ADDR_LEN);
		memcpy(ipv6->dst_ip, &md->dst_addr.ipv6,
		       YS_TC_KEY_IPV6_ADDR_LEN);
		ipv6->src_port = md->src_port;
		ipv6->dst_port = md->dst_port;
		ipv6->fragment = md->frag_type;

		ipv6->vlan_id = cpu_to_be16(md->vlan_id);

		ipv6->tenant_id = md->tun_id;

		ipv6->tun_type = md->tun_type;
		ipv6->src_qset = cpu_to_be16(in_tc_priv->qset);
	}

	return 0;
}

static struct ys_tc_flow *ys_tc_flow_alloc(struct ys_tc_priv *tc_priv,
					   const struct ys_tc_flow_metadata *flow_meta)
{
	struct ys_tc_flow *flow;
	enum ys_tc_table_id table_id;

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	if (!flow)
		return NULL;

	table_id = (flow_meta->src_addr.is_ipv6) ?
			YS_TC_TABLE_ID_IPV6_FLOW : YS_TC_TABLE_ID_IPV4_FLOW;
	flow->table_entry = ys_tc_table_alloc(tc_priv, table_id, NULL, NULL);
	if (!flow->table_entry) {
		kfree(flow);
		return NULL;
	}
	flow->tc_priv = tc_priv;

	INIT_LIST_HEAD(&flow->tbl_entry_head);
	refcount_set(&flow->refcnt, 1);
	return flow;
}

static void ys_tc_flow_free(struct ys_tc_priv *tc_priv, struct ys_tc_flow *flow)
{
	struct ys_tc_table_entry_node *entry_node = NULL;
	struct ys_tc_table_entry_node *node_tmp = NULL;
	__u16 group_id;
	__u32 null_qset_bitmap[YS_K2ULAN_TC_MC_GROUP_QBMP_LEN] = {0};
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	struct ys_ndev_priv *ndev_priv = NULL;

	if (flow->group_entry && refcount_dec_and_test(&flow->group_entry->refcnt)) {
		ndev_priv = netdev_priv(tc_priv->ndev);
		group_id = flow->group_entry->group_id;
		ys_tc_info("release mc group_id %d.\n", group_id);
		if (ndev_priv->ys_ndev_hw && ndev_priv->ys_ndev_hw->ys_set_tc_mc_group)
			ndev_priv->ys_ndev_hw->ys_set_tc_mc_group(tc_priv->ndev,
								  group_id, null_qset_bitmap);

		bitmap_clear(switchdev->group_id_bitmap, group_id, 1);
		WARN_ON(rhashtable_remove_fast(&switchdev->multicast_ht,
					       &flow->group_entry->node,
					       *switchdev->multicast_ht_params));
		atomic_dec(&switchdev->group_id_used);

		kfree(flow->group_entry);
	}
	flow->group_entry = NULL;

	list_for_each_entry_safe(entry_node, node_tmp, &flow->tbl_entry_head, flow_node) {
		ys_tc_table_del_and_free(tc_priv, entry_node->tbl_entry);
		kfree(entry_node);
	}

	ys_tc_table_free(tc_priv, flow->table_entry);
	kfree_rcu(flow, rcu_head);
}

static int ys_tc_flow_compile_action(struct ys_tc_priv *tc_priv,
				     struct flow_cls_offload *cls_flower,
				     struct ys_tc_flow *flow,
				     const struct ys_tc_flow_metadata *flow_meta)
{
	int i, ret;
	struct flow_action_entry *act = NULL;
	struct ys_tc_table_entry *tbl_entry = NULL;

	struct ys_tc_action_ctx ctx = {
		.flow_meta = flow_meta,
		.action_meta = {0},
		.flow = flow,
		.action_buf = {0},
		.mirror_tbl_entry = NULL,
		.mirror_buf = {0},
		.encap_buf = NULL,
	};
	struct ys_tc_action_meta *action_meta = &ctx.action_meta;
	struct ys_tc_action_buf *action_buf = &ctx.action_buf;

	if (test_bit(YS_TC_FLOW_FLAG_HIGHPRI, &flow->flags))
		action_meta->flags |= YS_TC_FLAG_HIGHPRI;

	ys_tc_action_add(YS_TC_ACTION_COUNT, action_meta);

	flow_action_for_each(i, act, &cls_flower->rule->action) {
		if (!ys_tc_ops_flow_acts[act->id].parse) {
			ys_tc_debug("flow action not support\n");
			return -EOPNOTSUPP;
		}

		ret = ys_tc_ops_flow_acts[act->id].parse(tc_priv, act, flow_meta, action_meta);
		if (ret)
			return ret;
	}
	ys_tc_action_add(YS_TC_ACTION_END, action_meta);
	/*
	 * OVS actions="push_vlan:0x8100,set_field:0x11F4->vlan_vid,output=vxlan1"
	 * For current tunnel conf, tc kernel would offload action:
	 * encap / push vlan / output(vxlan_4789).
	 * In such case, encap should be placed to very end.
	 */
	ys_tc_action_order_tune(action_meta);

	tbl_entry = flow->table_entry;
	action_buf->data = tbl_entry->data + ys_tc_table_get_keylen(tbl_entry->table);
	action_buf->size = ys_tc_table_get_valuelen(flow->table_entry->table);
	action_buf->offset = 0;
	ret = ys_tc_action_compile(tc_priv, &ctx);
	if (ret)
		return ret;

	return 0;
}

static int ys_tc_flow_add(struct ys_tc_priv *tc_priv, struct ys_tc_flow *flow)
{
	int ret;

	ret = ys_tc_table_add(tc_priv, flow->table_entry);
	if (ret) {
		ys_tc_err("failed to add flow table, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

static void ys_tc_flow_del_and_free(struct ys_tc_priv *tc_priv, struct ys_tc_flow *flow)
{
	ys_tc_table_del_and_free(tc_priv, flow->table_entry);
	flow->table_entry = NULL;

	ys_tc_flow_free(tc_priv, flow);
}

static void ys_tc_flow_put(struct ys_tc_priv *tc_priv, struct ys_tc_flow *flow)
{
	if (refcount_dec_and_test(&flow->refcnt))
		ys_tc_flow_del_and_free(tc_priv, flow);
}

/* ystc flow end */

int ys_tc_add_flower(struct ys_tc_priv *tc_priv,
		     struct flow_cls_offload *cls_flower)
{
	int ret;
	struct ys_tc_flow *flow;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	struct ys_tc_flow_metadata flow_meta = {0};

	flow = rhashtable_lookup_fast(&tc_priv->tc_ht, &cls_flower->cookie,
				      *tc_priv->tc_ht_params);
	if (flow) {
		ys_tc_debug("flow already exists\n");
		return -EEXIST;
	}

	ret = ys_tc_flow_valid(tc_priv, cls_flower, &flow_meta);
	if (ret) {
		ys_tc_debug("flow valid failed\n");
		return ret;
	}

	flow = ys_tc_flow_alloc(tc_priv, &flow_meta);
	if (!flow) {
		ys_tc_debug("flow table alloc failed\n");
		return -ENOMEM;
	}
	flow->cookie = cls_flower->cookie;

	if (atomic_read(&switchdev->priority_flow_nb) < YS_TC_FLOW_HIGHPRI_MAX_NUM)
		__set_bit(YS_TC_FLOW_FLAG_HIGHPRI, &flow->flags);

	ret = ys_tc_flow_compile_match(tc_priv, flow, &flow_meta);
	if (ret) {
		ys_tc_debug("flow compile match failed\n");
		ys_tc_flow_free(tc_priv, flow);
		return ret;
	}

	ret = ys_tc_flow_compile_action(tc_priv, cls_flower, flow, &flow_meta);
	if (ret) {
		ys_tc_debug("flow compile action failed, ret = %d\n", ret);
		ys_tc_flow_free(tc_priv, flow);
		return ret;
	}

	ret = ys_tc_flow_add(tc_priv, flow);
	if (ret) {
		ys_tc_debug("flow add failed, ret = %d\n", ret);
		ys_tc_flow_free(tc_priv, flow);
		return ret;
	}

	ret = rhashtable_insert_fast(&tc_priv->tc_ht, &flow->node,
				     *tc_priv->tc_ht_params);
	if (ret) {
		ys_tc_err("failed to add flow to hash table\n");
		ys_tc_flow_put(tc_priv, flow);
		return ret;
	}

	if (test_bit(YS_TC_FLOW_FLAG_HIGHPRI, &flow->flags))
		atomic_inc(&switchdev->priority_flow_nb);

	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_FLOW_ADD_TOTAL]);
	return 0;
}

int ys_tc_del_flower(struct ys_tc_priv *tc_priv,
		     struct flow_cls_offload *cls_flower)
{
	struct ys_tc_flow *flow;
	int ret = 0;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	rcu_read_lock();
	flow = rhashtable_lookup(&tc_priv->tc_ht, &cls_flower->cookie, *tc_priv->tc_ht_params);
	if (!flow) {
		ys_tc_debug("flow not exists\n");
		ret = -ENOENT;
		goto fail;
	}

	if (test_and_set_bit(YS_TC_FLOW_FLAG_DELETED, &flow->flags)) {
		ret = -EINVAL;
		goto fail;
	}

	rhashtable_remove_fast(&tc_priv->tc_ht, &flow->node, *tc_priv->tc_ht_params);
	rcu_read_unlock();

	if (test_bit(YS_TC_FLOW_FLAG_HIGHPRI, &flow->flags))
		atomic_dec(&switchdev->priority_flow_nb);

	ys_tc_flow_put(tc_priv, flow);
	atomic64_inc(&switchdev->metrics[YS_TC_METRICS_FLOW_DEL_TOTAL]);
	return 0;

fail:
	rcu_read_unlock();
	return ret;
}

int ys_tc_stat_flower(struct ys_tc_priv *tc_priv,
		      struct flow_cls_offload *cls_flower)
{
	struct ys_tc_flow *flow = NULL;
	struct ys_tc_table_entry *cnt_entry = NULL;
	struct ys_tc_table_commcnt_data *data = NULL;
	int ret = 0;

	__u64 delta_pkts = 0;
	__u64 delta_bytes = 0;
	__u64 used = 0;
	__u64 cur_cpu_pkts = 0;
	__u64 cur_cpu_bytes = 0;

	rcu_read_lock();
	flow = rhashtable_lookup(&tc_priv->tc_ht, &cls_flower->cookie,
				 *tc_priv->tc_ht_params);

	if (!flow || !refcount_inc_not_zero(&flow->refcnt)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	rcu_read_unlock();

	if (IS_ERR(flow)) {
		ys_tc_err("error flow found.\n");
		return PTR_ERR(flow);
	}

	cnt_entry = flow->cnt_entry;
	if (!cnt_entry) {
		ys_tc_err("flow not countable\n");
		ret = -ENOENT;
		goto out;
	}

	delta_pkts = 0;
	data = (struct ys_tc_table_commcnt_data *)(cnt_entry->data);
	spin_lock(&data->cache_slock);
	cur_cpu_pkts = be64_to_cpu(data->be_pkts);
	cur_cpu_bytes = be64_to_cpu(data->be_bytes);

	if (cur_cpu_pkts > data->last_pkts && cur_cpu_bytes > data->last_bytes) {
		delta_pkts = cur_cpu_pkts - data->last_pkts;
		delta_bytes = cur_cpu_bytes - data->last_bytes;

		/* update the history data. */
		data->last_pkts = cur_cpu_pkts;
		data->last_bytes = cur_cpu_bytes;
		used = data->used;
	}
	spin_unlock(&data->cache_slock);

	// The API flow_stats_update needs delta value.
	if (!delta_pkts)
		goto out;

	flow_stats_update(&cls_flower->stats, delta_bytes, delta_pkts, 0, used,
			  FLOW_ACTION_HW_STATS_DELAYED);

out:
	ys_tc_flow_put(tc_priv, flow);
	return ret;
}

static const int miss_action_item[] = { YS_TC_ACTION_COUNT, YS_TC_ACTION_END };
static const int basic_action_item[] = { YS_TC_ACTION_COUNT, YS_TC_ACTION_JUMP, YS_TC_ACTION_END };

static const int vxlan_action_item[] = {
					YS_TC_ACTION_COUNT,
					YS_TC_ACTION_VXLAN_DECAP,
					YS_TC_ACTION_JUMP,
					YS_TC_ACTION_END,
};

static const int geneve_action_item[] = {
					YS_TC_ACTION_COUNT,
					YS_TC_ACTION_GENEVE_DECAP,
					YS_TC_ACTION_JUMP,
					YS_TC_ACTION_END,
};

static const enum ys_tc_table_id ipv4_jump_id = YS_TC_TABLE_ID_IPV4_FLOW;
static const enum ys_tc_table_id ipv6_jump_id = YS_TC_TABLE_ID_IPV6_FLOW;

struct ys_tc_flow_default_item {
	const int *action_list;
	const size_t nb_actions;
	const enum ys_tc_table_id id;
	const int idx;
	bool high_pri;
	const enum ys_tc_table_id *jump_id;
};

static struct ys_tc_flow_default_item ys_tc_flow_default_items[] = {
	{
		.action_list = miss_action_item,
		.nb_actions = ARRAY_SIZE(miss_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 0,
		.high_pri = true,
	}, {
		.action_list = basic_action_item,
		.nb_actions = ARRAY_SIZE(basic_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 1,
		.high_pri = true,
		.jump_id = &ipv4_jump_id,
	}, {
		.action_list = basic_action_item,
		.nb_actions = ARRAY_SIZE(basic_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 2,
		.high_pri = true,
		.jump_id = &ipv6_jump_id,
	}, {
		.action_list = vxlan_action_item,
		.nb_actions = ARRAY_SIZE(vxlan_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 3,
		.high_pri = true,
		.jump_id = &ipv4_jump_id,
	}, {
		.action_list = vxlan_action_item,
		.nb_actions = ARRAY_SIZE(vxlan_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 4,
		.high_pri = true,
		.jump_id = &ipv6_jump_id,
	}, {
		.action_list = vxlan_action_item,
		.nb_actions = ARRAY_SIZE(vxlan_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 5,
		.high_pri = true,
		.jump_id = &ipv4_jump_id,
	}, {
		.action_list = vxlan_action_item,
		.nb_actions = ARRAY_SIZE(vxlan_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 6,
		.high_pri = true,
		.jump_id = &ipv6_jump_id,
	}, {
		.action_list = geneve_action_item,
		.nb_actions = ARRAY_SIZE(geneve_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 7,
		.high_pri = true,
		.jump_id = &ipv4_jump_id,
	}, {
		.action_list = geneve_action_item,
		.nb_actions = ARRAY_SIZE(geneve_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 8,
		.high_pri = true,
		.jump_id = &ipv6_jump_id,
	}, {
		.action_list = geneve_action_item,
		.nb_actions = ARRAY_SIZE(geneve_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 9,
		.high_pri = true,
		.jump_id = &ipv4_jump_id,
	}, {
		.action_list = geneve_action_item,
		.nb_actions = ARRAY_SIZE(geneve_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 10,
		.high_pri = true,
		.jump_id = &ipv6_jump_id,
	}, {
		.action_list = basic_action_item,
		.nb_actions = ARRAY_SIZE(basic_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 11,
		.high_pri = true,
		.jump_id = &ipv4_jump_id,
	}, {
		.action_list = basic_action_item,
		.nb_actions = ARRAY_SIZE(basic_action_item),
		.id = YS_TC_TABLE_ID_L3PROTO,
		.idx = 12,
		.high_pri = true,
		.jump_id = &ipv6_jump_id,
	},
};

static int ys_tc_flow_default_add(struct ys_tc_priv *tc_priv,
				  struct ys_tc_flow_default_item *item)
{
	size_t i = 0;
	int ret = 0;
	struct ys_tc_table_entry *entry = NULL;

	struct ys_tc_action_ctx ctx = {0};
	struct ys_tc_action_meta *action_meta = &ctx.action_meta;
	struct ys_tc_action_buf *action_buf = &ctx.action_buf;

	entry = ys_tc_table_alloc(tc_priv, item->id, &item->idx, NULL);
	if (!entry)
		return -ENOENT;

	action_buf->data = entry->data;
	action_buf->size = ys_tc_table_get_valuelen(entry->table);
	action_buf->offset = 0;

	for (i = 0; i < item->nb_actions; i++)
		ys_tc_action_add(item->action_list[i], action_meta);

	if (ys_tc_action_exists(YS_TC_ACTION_JUMP, action_meta)) {
		if (!item->jump_id) {
			ret = -EINVAL;
			goto failed;
		}
		action_meta->jump_id = *item->jump_id;
	}

	action_meta->flags = YS_TC_FLAG_REALDECAP;
	if (item->high_pri)
		action_meta->flags |= YS_TC_FLAG_HIGHPRI;

	ret = ys_tc_action_compile(tc_priv, &ctx);
	if (ret)
		goto failed;

	ret = ys_tc_table_add(tc_priv, entry);
	if (ret)
		goto failed;

	return 0;

failed:
	if (entry)
		ys_tc_table_free(tc_priv, entry);
	return ret;
}

static int ys_tc_flow_default_init(struct ys_tc_priv *tc_priv)
{
	int ret, i;
	struct ys_tc_table *table = NULL;

	for (i = 0; i < ARRAY_SIZE(ys_tc_flow_default_items); i++) {
		ret = ys_tc_flow_default_add(tc_priv,
					     &ys_tc_flow_default_items[i]);
		if (ret) {
			ys_tc_err("failed to add flow default item\n");
			goto failed;
		}
	}

	for (i = 0; i < YS_TC_TABLES_NUM; i++) {
		struct ys_tc_flow_default_item miss_item =
			(struct ys_tc_flow_default_item) {
				.action_list = miss_action_item,
				.nb_actions = ARRAY_SIZE(miss_action_item),
				.id = YS_TC_TABLE_ID_MISS,
				.idx = i,
				.jump_id = NULL,
			};

		table = ys_tc_table_find(tc_priv, i);
		if (table)
			miss_item.high_pri = true;
		ret = ys_tc_flow_default_add(tc_priv, &miss_item);
		if (ret) {
			ys_tc_err("failed to add flow default item\n");
			goto failed;
		}
	}

	return 0;

failed:
	return ret;
}

static struct rhashtable_params tc_ht_params = {
	.head_offset = offsetof(struct ys_tc_flow, node),
	.key_offset = offsetof(struct ys_tc_flow, cookie),
	.key_len = sizeof_field(struct ys_tc_flow, cookie),
	.automatic_shrinking = true,
};

static struct rhashtable_params multicast_ht_params = {
	.head_offset = offsetof(struct ys_tc_group_entry, node),
	.key_offset = offsetof(struct ys_tc_group_entry, bitmap),
	.key_len = sizeof_field(struct ys_tc_group_entry, bitmap),
	.automatic_shrinking = true,
};

int ys_tc_flow_init(struct ys_tc_priv *tc_priv)
{
	int ret;
	const struct ysif_ops *ops = ysif_get_ops();

	ret = ops->rhashtable_init(&tc_priv->tc_ht, &tc_ht_params);
	if (ret != 0) {
		ys_tc_err("create tc flow hashtable failed\n");
		return ret;
	}
	tc_priv->tc_ht_params = &tc_ht_params;

	return 0;
}

int ys_tc_flow_once_init(struct ys_tc_priv *tc_priv)
{
	int ret = 0;

	ret = ys_tc_flow_default_init(tc_priv);
	if (ret) {
		ys_tc_err("failed to init flow default\n");
		return ret;
	}

	return 0;
}

static int ys_tc_debug_mc_grp_show(struct seq_file *seq, void *data)
{
	struct ys_tc_switchdev *switchdev = seq->private;
	struct rhashtable_iter iter;
	struct ys_tc_group_entry *group_entry;
	struct rhashtable *ht = &switchdev->multicast_ht;

	rhashtable_walk_enter(ht, &iter);
	rhashtable_walk_start(&iter);

	seq_printf(seq, "used %d\n", atomic_read(&switchdev->group_id_used));
	while ((group_entry = rhashtable_walk_next(&iter))) {
		if (IS_ERR(group_entry)) {
			if (PTR_ERR(group_entry) == -EAGAIN)
				continue;
			break;
		}
		seq_printf(seq, "group id: %d, refcnt: %d\n",
			   group_entry->group_id,
			   group_entry->refcnt.refs.counter);
		seq_hex_dump(seq, "bitmap : ", DUMP_PREFIX_NONE, 32, 1,
			     group_entry->bitmap, sizeof(group_entry->bitmap), false);
		seq_puts(seq, "\n");
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ys_tc_debug_mc_grp);

int ys_tc_multicast_init(struct ys_tc_priv *tc_priv)
{
	int ret;
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	atomic_set(&switchdev->group_id_used, 0);
	ret = rhashtable_init(&switchdev->multicast_ht, &multicast_ht_params);
	if (ret != 0) {
		ys_tc_err("create tc multicast group hashtable failed\n");
		return ret;
	}
	switchdev->multicast_ht_params = &multicast_ht_params;

	// Create mc_grp debugfs
	debugfs_create_file("mc_grp", 0400, switchdev->debugfs_root, switchdev,
			    &ys_tc_debug_mc_grp_fops);

	return 0;
}

static void tc_ht_release(void *ptr, void *arg)
{
	struct ys_tc_flow *flow = ptr;
	struct ys_tc_priv *tc_priv = flow->tc_priv;

	ys_tc_flow_del_and_free(tc_priv, flow);
}

void ys_tc_flow_exit(struct ys_tc_priv *tc_priv)
{
	rhashtable_free_and_destroy(&tc_priv->tc_ht, tc_ht_release, NULL);
}

void ys_tc_multicast_exit(struct ys_tc_priv *tc_priv)
{
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	rhashtable_free_and_destroy(&switchdev->multicast_ht, NULL, NULL);
}
