// SPDX-License-Identifier: GPL-2.0

#include <linux/ethtool.h>
#include <linux/kobject.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>

#include "ys_i2c.h"
#include "ys_pdev.h"

#include "ys_reg_ops.h"

u32 ys_i2c_get_sfp_rate(struct ys_i2c_dev *idev)
{
	u8 *i2c_data;
	u32 rate = 0;

	if (unlikely(!strstr(idev->name, "sfp"))) {
		ys_err("i2c %s get error", idev->name);
		return YS_I2C_SFP_10G;
	}

	mdelay(120);
	ys_i2c_read(idev, 0, idev->data, idev->data_len);
	i2c_data = idev->data;

	if (i2c_data[YS_I2C_SFP_BIT_RATE] == 0xff)
		rate = i2c_data[YS_I2C_SFP_BIT_RATE_MAX] * 250;
	else
		rate = i2c_data[YS_I2C_SFP_BIT_RATE] * 100;

	return (rate >= SPEED_25000 ? YS_I2C_SFP_25G : YS_I2C_SFP_10G);
}

int ys_i2c_read(struct ys_i2c_dev *idev, u8 regaddr, u8 *buffer, size_t size)
{
	struct i2c_msg msg[2];
	int ret = 0;

	msg[0].addr = idev->dev_addr >> 1;
	msg[0].flags = 0;
	msg[0].len = 1;
	msg[0].buf = &regaddr;
	msg[1].addr = idev->dev_addr >> 1;
	msg[1].flags = I2C_M_RD;
	msg[1].len = size;
	msg[1].buf = buffer;
	ret = i2c_transfer(&idev->adapter, msg, 2);

	if (ret < 2)
		ret = -EIO;

	return ret;
}

int ys_i2c_write(struct ys_i2c_dev *idev, u8 regaddr, u8 *buffer, size_t size)
{
	struct i2c_msg msg[2];
	int ret = 0;

	msg[0].addr = idev->dev_addr >> 1;
	msg[0].flags = 0;
	msg[0].len = 1;
	msg[0].buf = &regaddr;
	msg[1].addr = 0;
	msg[1].flags = I2C_M_NOSTART;
	msg[1].len = size;
	msg[1].buf = buffer;
	ret = i2c_transfer(&idev->adapter, msg, 2);

	if (ret < 2)
		ret = -EIO;

	return ret;
}

int ys_i2c_eeprom_checksum(struct ys_i2c_dev *idev, u32 start, u32 len)
{
	u32 checksum = 0;
	u8 temp[32] = {0};
	u32 i = 0;

	if (start > YS_EEPROM_CKSUM_START)
		return -1;
	if ((ys_i2c_read(idev, start, temp, len)) < 0)
		return -1;
	for (i = 0; i < len; i++)
		checksum += temp[i];

	return checksum;
}

int ys_aux_i2c_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_i2c *i2c = NULL;
	struct i2c_adapter *adap;
	int ret;
	int i;

	i2c = kzalloc(sizeof(*i2c), GFP_KERNEL);
	if (IS_ERR_OR_NULL(i2c))
		goto i2c_fail;

	adev->adev_priv = (void *)i2c;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_i2c_init)) {
		ret = pdev_priv->ops->hw_adp_i2c_init(pdev_priv->pdev);
		if (ret) {
			ys_dev_err("hw_adp_i2c_init failed, ret=%d", ret);
			goto i2c_fail;
		}
	} else {
		ys_dev_err("hw_adp_i2c_init is NULL");
		goto i2c_fail;
	}

	if (i2c->idev_num == 0) {
		ys_dev_warn("hw_adp_i2c_init return idev_num = 0");
		goto i2c_fail;
	}

	for (i = 0; i < i2c->idev_num; i++) {
		i2c->idev[i].data = kmalloc(YS_I2C_BUF_SIZE_PER_DEVICE, GFP_KERNEL);
		if (IS_ERR_OR_NULL(i2c->idev[i].data)) {
			ys_dev_err("kmalloc i2c->buf failed!\n");
			goto i2c_fail;
		}

		adap = &i2c->idev[i].adapter;
		adap->owner = THIS_MODULE;
		adap->dev.parent = &pdev_priv->pdev->dev;
		adap->algo_data = &i2c->idev[i].bit_data;
		memcpy(adap->name, i2c->idev[i].name, YS_I2C_DEV_NAME_LEN);

		/* register bus */
		ret = i2c_bit_add_bus(adap);
		if (ret < 0)
			goto i2c_fail;
	}

	mutex_init(&i2c->i2c_lock);

	return 0;

i2c_fail:
	ys_aux_i2c_remove(auxdev);

	return -ENOMEM;
}

void ys_aux_i2c_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_i2c *i2c = NULL;
	int i;

	i2c = (struct ys_i2c *)adev->adev_priv;

	if (!IS_ERR_OR_NULL(i2c)) {
		for (i = 0; i < i2c->idev_num; i++) {
			i2c_del_adapter(&i2c->idev[i].adapter);
			kfree(i2c->idev[i].data);
			i2c->idev[i].data = NULL;
		}
		i2c->idev_num = 0;
		kfree(i2c);
	}

	adev->adev_priv = NULL;
}
