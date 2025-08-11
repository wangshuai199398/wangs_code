#include "ws_ndev.h"

#include "ws_log.h"

int ws_aux_eth_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
    pr_info("Probing auxiliary device %s\n", adev->dev.kobj.name);

}

void ws_aux_eth_remove(struct auxiliary_device *adev)
{
    pr_info("Removing auxiliary device %s\n", adev->dev.kobj.name);
}