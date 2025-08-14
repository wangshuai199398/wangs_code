/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YS_I2C_H_
#define __YS_I2C_H_

#include <linux/pci.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

#include "ys_auxiliary.h"

#define YS_I2C_MAX_I2C_DEVICES (8)
#define YS_I2C_DEV_NAME_LEN (16)
#define YS_I2C_BUF_SIZE_PER_DEVICE (1024)
#define YS_EEPROM_CKSUM_START (252)

/* sfp rate  */
#define YS_I2C_SFP_BIT_RATE             12
#define YS_I2C_SFP_BIT_RATE_MAX         66
/* sfp speed */
#define YS_I2C_SFP_10G			0x2
#define YS_I2C_SFP_25G			0

enum {
	I2C_EEPROM,
	I2C_SFP,
};

struct ys_i2c_dev {
	struct i2c_adapter adapter;
	struct i2c_algo_bit_data bit_data;

	u32 __iomem *gpio_regs;
	u8 gpio_index;
	u8 dev_addr;
	u16 data_len;
	char name[YS_I2C_DEV_NAME_LEN];

	u8 *data;
	u8 type;
};

struct ys_i2c {
	struct pci_dev *pdev;
	/* i2c lock */
	struct mutex i2c_lock;

	u32 idev_num;
	u8 sfp_base_index;
	struct ys_i2c_dev idev[YS_I2C_MAX_I2C_DEVICES];
};

int ys_aux_i2c_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id);
void ys_aux_i2c_remove(struct auxiliary_device *auxdev);

u32 ys_i2c_get_sfp_rate(struct ys_i2c_dev *idev);
int ys_i2c_read(struct ys_i2c_dev *idev, u8 regaddr, u8 *buffer, size_t size);
int ys_i2c_write(struct ys_i2c_dev *idev, u8 regaddr, u8 *buffer, size_t size);
int ys_i2c_eeprom_checksum(struct ys_i2c_dev *idev, u32 start, u32 len);

#endif /* __YS_I2C_H_ */
