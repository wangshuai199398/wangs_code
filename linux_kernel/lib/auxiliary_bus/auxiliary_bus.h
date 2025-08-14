/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2020 Intel Corporation
 *
 * Please see Documentation/driver-api/auxiliary_bus.rst for more information.
 */

#ifndef _AUXILIARY_BUS_H_
#define _AUXILIARY_BUS_H_

#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/device.h>

#include "../kernel_compat.h"

#ifdef YS_HAVE_AUXILIARY_ID
#include <linux/mod_devicetable.h>
#else
#define AUXILIARY_NAME_SIZE 32
#define AUXILIARY_MODULE_PREFIX "auxiliary:"
struct auxiliary_device_id {
	char name[AUXILIARY_NAME_SIZE];
	unsigned long driver_data;
};
#endif /* YS_HAVE_AUXILIARY_ID */

struct auxiliary_device {
	struct device dev;
	const char *name;
	u32 id;
};

struct auxiliary_driver {
	int (*probe)(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id);
	void (*remove)(struct auxiliary_device *auxdev);
	void (*shutdown)(struct auxiliary_device *auxdev);
	int (*suspend)(struct auxiliary_device *auxdev, pm_message_t state);
	int (*resume)(struct auxiliary_device *auxdev);
	const char *name;
	struct device_driver driver;
	const struct auxiliary_device_id *id_table;
};

static inline void *auxiliary_get_drvdata(struct auxiliary_device *auxdev)
{
	return dev_get_drvdata(&auxdev->dev);
}

static inline void auxiliary_set_drvdata(struct auxiliary_device *auxdev, void *data)
{
	dev_set_drvdata(&auxdev->dev, data);
}

static inline struct auxiliary_device *to_auxiliary_dev(struct device *dev)
{
	return container_of(dev, struct auxiliary_device, dev);
}

static inline struct auxiliary_driver *to_auxiliary_drv(struct device_driver *drv)
{
	return container_of(drv, struct auxiliary_driver, driver);
}

int auxiliary_device_init(struct auxiliary_device *auxdev);
int __auxiliary_device_add(struct auxiliary_device *auxdev, const char *modname);
#define auxiliary_device_add(auxdev) __auxiliary_device_add(auxdev, KBUILD_MODNAME)

static inline void auxiliary_device_uninit(struct auxiliary_device *auxdev)
{
	put_device(&auxdev->dev);
}

static inline void auxiliary_device_delete(struct auxiliary_device *auxdev)
{
	device_del(&auxdev->dev);
}

int __auxiliary_driver_register(struct auxiliary_driver *auxdrv, struct module *owner,
				const char *modname);
#define auxiliary_driver_register(auxdrv) \
	__auxiliary_driver_register(auxdrv, THIS_MODULE, KBUILD_MODNAME)

void auxiliary_driver_unregister(struct auxiliary_driver *auxdrv);

#define module_auxiliary_driver(__auxiliary_driver) \
	module_driver(__auxiliary_driver, auxiliary_driver_register, auxiliary_driver_unregister)

struct auxiliary_device *auxiliary_find_device(struct device *start,
					       const void *data,
					       int (*match)(struct device *dev, const void *data));

#endif /* _AUXILIARY_BUS_H_ */
