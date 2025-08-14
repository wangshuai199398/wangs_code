/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_UTILS_H_
#define __YS_UTILS_H_

#include <linux/err.h>
#include <linux/fs.h>

#include "../ver.h"
#include "../lib/kernel_compat.h"

#define STRINGIZE(a) a
#define YS_HW_STRING(prefix, name) STRINGIZE(prefix name)

static inline u32 ys_get_file_exist(const char *path)
{
	struct file *file;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return 0;

	filp_close(file, NULL);
	return 1;
}

/* cal Greatest Common Divisor */
static inline int cal_gcd(int x, int y)
{
	int a;

	if (x < y) {
		a = x;
		x = y;
		y = a;
	}
	while (x % y != 0) {
		a = x % y;
		x = y;
		y = a;
	}
	return y;
}

#endif /* __YS_UTILS_H_ */
