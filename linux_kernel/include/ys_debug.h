/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_DEBUG_H_
#define __YS_DEBUG_H_

#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/pkt_cls.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "ys_utils.h"

#define ys_err(f, arg...) pr_err("%s: " f, YS_HW_NAME, ##arg)
#define ys_info(f, arg...) pr_info("%s: " f, YS_HW_NAME, ##arg)
#define ys_warn(f, arg...) pr_warn("%s: " f, YS_HW_NAME, ##arg)
#define ys_debug(f, arg...) \
	pr_debug("%s:[%s:%d]: " f, YS_HW_NAME, __func__, __LINE__, ##arg)

#define ys_net_err(f, arg...) \
	netdev_err(ndev_priv->ndev, "%s: " f, YS_HW_NAME, ##arg)
#define ys_net_info(f, arg...) \
	netdev_info(ndev_priv->ndev, "%s: " f, YS_HW_NAME, ##arg)
#define ys_net_warn(f, arg...) \
	netdev_warn(ndev_priv->ndev, "%s: " f, YS_HW_NAME, ##arg)
#define ys_net_debug(f, arg...)                                            \
	netdev_dbg(ndev_priv->ndev, "%s:[%s:%d]: " f, YS_HW_NAME, __func__, \
		   __LINE__, ##arg)

#define ys_dev_err(f, arg...) \
	dev_err(pdev_priv->dev, "%s: " f, YS_HW_NAME, ##arg)
#define ys_dev_info(f, arg...) \
	dev_info(pdev_priv->dev, "%s: " f, YS_HW_NAME, ##arg)
#define ys_dev_warn(f, arg...) \
	dev_warn(pdev_priv->dev, "%s: " f, YS_HW_NAME, ##arg)
#define ys_dev_debug(f, arg...)                                          \
	dev_dbg(pdev_priv->dev, "%s:[%s:%d]: " f, YS_HW_NAME, __func__, \
		__LINE__, ##arg)

#define ys_tc_err(f, arg...) \
	netdev_err(tc_priv->ndev, "TC: %s: " f, YS_HW_NAME, ##arg)
#define ys_tc_info(f, arg...) \
	netdev_info(tc_priv->ndev, "TC: %s: " f, YS_HW_NAME, ##arg)
#define ys_tc_warn(f, arg...) \
	netdev_warn(tc_priv->ndev, "TC: %s: " f, YS_HW_NAME, ##arg)
#define ys_tc_debug(f, arg...)                                            \
	netdev_dbg(tc_priv->ndev, "TC: %s:[%s:%d]: " f, YS_HW_NAME, __func__, \
		   __LINE__, ##arg)
#define ys_tc_hexdump(value, size, f, arg...)                           \
	do {                                                                   \
		netdev_dbg(tc_priv->ndev, "TC: %s: " f, YS_HW_NAME, ##arg);      \
		print_hex_dump_debug("TC: ", DUMP_PREFIX_NONE, 16, 1, \
				(value), (size), 1);                    \
	} while (0)

static inline void ys_dump_skb(struct sk_buff *skb,
			       struct net_device *ndev,
			       int queue_id)
{
	char prefix[30];

	scnprintf(prefix, sizeof(prefix), "%s: ", dev_name(&ndev->dev));

	netdev_dbg(ndev, "Dumping skb, queue: %d len: %d\n", queue_id, skb->len);
	print_hex_dump_debug(prefix, DUMP_PREFIX_NONE, 16, 1, skb->data,
			     skb->len, true);

	if (skb_vlan_tag_present(skb))
		ys_debug("VLAN Packet\n");

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		u8 *src_mac = skb->data;
		u8 *dest_mac = skb->data + ETH_ALEN;

		netdev_dbg(ndev, "Start IP Parse\n");
		netdev_dbg(ndev, "Source IP: %pI4, Destination IP: %pI4, Source MAC: %pM, Destination MAC: %pM\n",
			   &iph->saddr, &iph->daddr, src_mac, dest_mac);

		switch (iph->protocol) {
		case IPPROTO_ICMP:
			netdev_dbg(ndev, "Ping Packet\n");
			break;
		case IPPROTO_TCP: {
			struct tcphdr *tcph = tcp_hdr(skb);

			netdev_dbg(ndev, "TCP Packet: Source Port: %u, Destination Port: %u\n",
				   ntohs(tcph->source), ntohs(tcph->dest));
		} break;
		case IPPROTO_UDP: {
			struct udphdr *udph = udp_hdr(skb);

			netdev_dbg(ndev, "UDP Packet: Source Port: %u, Destination Port: %u\n",
				   ntohs(udph->source), ntohs(udph->dest));
		} break;
		default:
			netdev_dbg(ndev, "Protocol type is %d\n", iph->protocol);
			break;
		}
		netdev_dbg(ndev, "Stop IP Parse\n");
	}
}

#endif /* __YS_DEBUG_H_ */
