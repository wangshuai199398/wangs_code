// SPDX-License-Identifier: GPL-2.0
#include "ys_k2u_doe_core.h"
#include "ys_k2u_doe_mm.h"

#define YS_K2U_DOE_ADDRMAP_BASE		0xB00000

#define YS_K2U_DOE_PAGEMAP_BASE		(YS_K2U_DOE_ADDRMAP_BASE + 0x0)
#define YS_K2U_DOE_PAGEMAP_SPACE	0x8
#define YS_K2U_DOE_PAGEMAP_ENTRY(num) \
	(YS_K2U_DOE_PAGEMAP_BASE + (YS_K2U_DOE_PAGEMAP_SPACE * (num)))
#define YS_K2U_DOE_PAGEMAP_ADDR_L	0x0
#define YS_K2U_DOE_PAGEMAP_ADDR_H	0x4

#define YS_K2U_DOE_PAGEINFO_BASE	(YS_K2U_DOE_ADDRMAP_BASE + 0x2000)
#define YS_K2U_DOE_PAGEINFO_SPACE	0x100
#define YS_K2U_DOE_PAGEINFO_ENTRY(num) \
	(YS_K2U_DOE_PAGEINFO_BASE + (YS_K2U_DOE_PAGEINFO_SPACE * (num)))
#define YS_K2U_DOE_PAGEINFO_ENTRY_LIMIT 11
#define YS_K2U_DOE_PAGE_VALID		0x0
#define YS_K2U_DOE_PAGE_SIZE		0x4
#define YS_K2U_DOE_BEGIN_ADDR		0x8
#define YS_K2U_DOE_END_ADDR		0xC
#define YS_K2U_DOE_RANGE_BASE		0x10

#define YS_K2U_DOE_ADDRMAP_ENABLE	(YS_K2U_DOE_ADDRMAP_BASE + 0x2a00)
#define YS_K2U_DOE_ADDRMAP_PFID		(YS_K2U_DOE_ADDRMAP_BASE + 0x2800)

#define YS_K2U_DOE_ADDRINFO_PAGE_2M	(2 * 1024 * 1024LU)
#define YS_K2U_DOE_ADDRINFO_PAGE_4M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_2M)
#define YS_K2U_DOE_ADDRINFO_PAGE_8M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_4M)
#define YS_K2U_DOE_ADDRINFO_PAGE_16M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_8M)
#define YS_K2U_DOE_ADDRINFO_PAGE_32M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_16M)
#define YS_K2U_DOE_ADDRINFO_PAGE_64M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_32M)
#define YS_K2U_DOE_ADDRINFO_PAGE_128M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_64M)
#define YS_K2U_DOE_ADDRINFO_PAGE_256M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_128M)
#define YS_K2U_DOE_ADDRINFO_PAGE_512M	(2 * YS_K2U_DOE_ADDRINFO_PAGE_256M)
#define YS_K2U_DOE_ADDRINFO_PAGE_1G	(2 * YS_K2U_DOE_ADDRINFO_PAGE_512M)

#define YS_K2U_DOE_ADDRMAP_MEM_TOTAL	(2 * 1024 * 1024 * 1024LU)
#define YS_K2U_DOE_ADDRMAP_PAGE_SIZE	YS_K2U_DOE_ADDRINFO_PAGE_2M
#define YS_K2U_DOE_ADDRMAP_PAGE_LIMIT	1024

static void ys_k2u_doe_set_page(struct ys_k2u_doe_device *ys_k2u_doe,
				u64 dma_base, u32 page_num)
{
	u32 dma_addr = 0;
	u32 reg_addr = 0;

	dma_addr = dma_base & 0xFFFFFFFF;
	reg_addr = YS_K2U_DOE_PAGEMAP_ENTRY(page_num) + YS_K2U_DOE_PAGEMAP_ADDR_L;
	ys_wr32(ys_k2u_doe->doe_base, reg_addr, dma_addr);

	dma_addr = dma_base >> 32;
	reg_addr = YS_K2U_DOE_PAGEMAP_ENTRY(page_num) + YS_K2U_DOE_PAGEMAP_ADDR_H;
	ys_wr32(ys_k2u_doe->doe_base, reg_addr, dma_addr);
}

static inline u32 ys_k2u_page_size_to_magic(u32 page_size)
{
	u32 i = 0;

	page_size /= 4096;
	for (i = 0; (page_size >> i) > 1; i++)
		;

	return i;
}

static void ys_k2u_doe_set_page_info(struct ys_k2u_doe_device *ys_k2u_doe, u32 entry_num, bool on,
				     u32 page_size, u32 start_addr, u32 end_addr, u32 range_base)
{
	u32 reg_addr = 0;

	reg_addr = YS_K2U_DOE_PAGEINFO_ENTRY(entry_num) + YS_K2U_DOE_PAGE_VALID;
	ys_wr32(ys_k2u_doe->doe_base, reg_addr, on);

	reg_addr = YS_K2U_DOE_PAGEINFO_ENTRY(entry_num) + YS_K2U_DOE_PAGE_SIZE;
	ys_wr32(ys_k2u_doe->doe_base, reg_addr, ys_k2u_page_size_to_magic(page_size));

	start_addr = start_addr >> 12;
	reg_addr = YS_K2U_DOE_PAGEINFO_ENTRY(entry_num) + YS_K2U_DOE_BEGIN_ADDR;
	ys_wr32(ys_k2u_doe->doe_base, reg_addr, start_addr);

	end_addr = end_addr >> 12;
	reg_addr = YS_K2U_DOE_PAGEINFO_ENTRY(entry_num) + YS_K2U_DOE_END_ADDR;
	ys_wr32(ys_k2u_doe->doe_base, reg_addr, end_addr);

	reg_addr = YS_K2U_DOE_PAGEINFO_ENTRY(entry_num) + YS_K2U_DOE_RANGE_BASE;
	ys_wr32(ys_k2u_doe->doe_base, reg_addr, range_base);
}

int ys_k2u_doe_addrmap_init(struct ys_k2u_doe_device *ys_k2u_doe)
{
	struct ys_k2u_doe_mm *ymm = NULL;
	struct ys_pdev_priv *pdev_priv = NULL;
	struct device *dev = NULL;
	int i = 0;
	s64 ret_addr = 0;
	s64 try_alloc_size = 0;
	s64 alloc_total = 0;
	u32 array_limit_max = 0;
	u32 page_num = 0;
	u32 entry_num = 0;
	u32 start_addr = 0;
	u32 end_addr = 0;
	u32 range_base = 0;
	bool has_xxM_mem = false;

	pdev_priv = pci_get_drvdata(ys_k2u_doe->pdev);
	dev = &pdev_priv->pdev->dev;
	ys_k2u_doe->ddrh = kzalloc(sizeof(struct ys_k2u_doe_mm *) *
				   YS_K2U_DOE_ADDRMAP_PAGE_LIMIT, GFP_KERNEL);
	if (!ys_k2u_doe->ddrh)
		return -ENOMEM;

	ys_k2u_doe->manage_host = kzalloc(sizeof(struct ys_k2u_doe_mm *) *
					  YS_K2U_DOE_ADDRMAP_PAGE_LIMIT, GFP_KERNEL);
	if (!ys_k2u_doe->manage_host) {
		kfree(ys_k2u_doe->ddrh);
		return -ENOMEM;
	}

	for (i = 0; i < YS_K2U_DOE_ADDRMAP_PAGE_LIMIT; i++) {
		ymm = ys_k2u_doe_mm_init(dev, 0, YS_K2U_DOE_ADDRINFO_PAGE_2M, true, 64, "2M");
		if (IS_ERR(ymm))
			break;

		ys_k2u_doe->ddrh[i] = ymm;
		alloc_total += YS_K2U_DOE_ADDRINFO_PAGE_2M;
	}
	ys_dev_info("DOE alloc host memory:0x%llx bytes\n", alloc_total);
	ys_k2u_doe->host_ddr_size = alloc_total;

	array_limit_max = i;
	ys_k2u_doe->ddrh_array_max = array_limit_max;
	ys_k2u_doe_mm_sort(ys_k2u_doe->ddrh, array_limit_max);

	ret_addr = ys_k2u_doe_mm_merge(ys_k2u_doe->manage_host, ys_k2u_doe->ddrh, array_limit_max);
	if (ret_addr < 0)
		return -ENOMEM;
	ys_k2u_doe->manage_host_max = ret_addr;

	page_num = 0;
	entry_num = 0;
	start_addr = 0;
	end_addr = 0;
	range_base = 0;
	try_alloc_size = YS_K2U_DOE_ADDRMAP_PAGE_SIZE;
	//alloc_total = YS_K2U_DOE_ADDRMAP_MEM_TOTAL;
	while (alloc_total > 0)	{
		for (i = 0; i < array_limit_max; i++) {
			ret_addr = ys_k2u_doe_malloc(ys_k2u_doe->ddrh[i], try_alloc_size);
			if (ret_addr >= 0) {
				ret_addr = ys_k2u_doe->ddrh[i]->dma_base;
				ys_k2u_doe_set_page(ys_k2u_doe, (u64)ret_addr, page_num++);
				alloc_total -= try_alloc_size;
				end_addr += try_alloc_size;
				has_xxM_mem = true;
				continue;
			}
		}
		if (i >= array_limit_max) {
			if (has_xxM_mem) {
				ys_k2u_doe_set_page_info(ys_k2u_doe, entry_num++, true,
							 try_alloc_size, start_addr,
							 end_addr, range_base);
				range_base = page_num;
				start_addr = end_addr;
			}

			try_alloc_size = try_alloc_size / 2;
			has_xxM_mem = false;
			if (try_alloc_size < YS_K2U_DOE_ADDRINFO_PAGE_2M)
				break;
		}
	}

	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_ADDRMAP_PFID, pdev_priv->pf_id << 9);
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_ADDRMAP_ENABLE, 1);

	return 0;
}

void ys_k2u_doe_addrmap_uninit(struct ys_k2u_doe_device *ys_k2u_doe)
{
	int i = 0;

	if (!ys_k2u_doe->ddrh || !ys_k2u_doe->manage_host)
		goto err_with_addrmap;

	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_ADDRMAP_ENABLE, 0);

	for (i = 0; i < YS_K2U_DOE_ADDRMAP_PAGE_LIMIT; i++)
		ys_k2u_doe_set_page(ys_k2u_doe, (u64)0, i);

	for (i = 0; i < YS_K2U_DOE_PAGEINFO_ENTRY_LIMIT; i++)
		ys_k2u_doe_set_page_info(ys_k2u_doe, i, false, 0, 0, 0, 0);

	for (i = 0; i < YS_K2U_DOE_ADDRMAP_PAGE_LIMIT; i++) {
		if (ys_k2u_doe->ddrh[i])
			ys_k2u_doe_mm_uninit(ys_k2u_doe->ddrh[i]);

		if (ys_k2u_doe->manage_host[i])
			ys_k2u_doe_mm_uninit(ys_k2u_doe->manage_host[i]);
	}

err_with_addrmap:
	ys_wr32(ys_k2u_doe->doe_base, YS_K2U_DOE_ADDRMAP_ENABLE, 0);
	kfree(ys_k2u_doe->manage_host);
	kfree(ys_k2u_doe->ddrh);
}
