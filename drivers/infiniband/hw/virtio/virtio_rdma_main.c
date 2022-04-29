// SPDX-License-Identifier: GPL-2.0-only
/*
 * RoCE support for virtio network device
 *
 * Copyright (C) 2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Xie Yongji <xieyongji@bytedance.com>
 *         Wei Junji <weijunji@bytedance.com>
 */

#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <uapi/linux/virtio_ids.h>

#include "virtio_rdma_verbs.h"

#define DRV_AUTHOR   "Yongji Xie <xieyongji@bytedance.com>, \
		      Junji Wei <weijunji@bytedance.com>"
#define DRV_DESC     "RoCE support for virtio network device"
#define DRV_LICENSE  "GPL v2"

static void virtio_rdma_cq_ack(struct virtnet_adev *vadev, struct virtqueue *vq)
{
        struct virtio_rdma_dev *rdev = dev_get_drvdata(&vadev->adev.dev);
        struct virtio_rdma_cq *vcq;

        // FIXME: get how many vq used in net, not only -2
        vcq = rdev->cqs[vq->index - 1 - 2];

        if (vcq && vcq->ibcq.comp_handler)
                vcq->ibcq.comp_handler(&vcq->ibcq, vcq->ibcq.cq_context);
}

static int virtio_rdma_probe(struct auxiliary_device *adev,
			     const struct auxiliary_device_id *id)
{
	struct virtio_rdma_dev *ri;
	struct virtnet_adev* vadev;
	int rc = -EIO;

	vadev = to_vnet_adev(adev);

	ri = ib_alloc_device(virtio_rdma_dev, ib_dev);
	if (!ri) {
		pr_err("Failed to allocate IB device\n");
		return -ENOMEM;
	}
	dev_set_drvdata(&adev->dev, ri);
	virtnet_set_cq_cb(vadev, virtio_rdma_cq_ack);

	// TODO: support fast doorbell
	ri->fast_doorbell = false;

	ri->vdev = vadev->vdev;
	ri->netdev = vadev->ndev;

	ri->mtu = ri->netdev->mtu;

	spin_lock_init(&ri->ctrl_lock);

	ri->cq_vqs = vadev->cq_vqs;
	ri->max_cq = vadev->max_cq;
	ri->cqs = kcalloc(ri->max_cq, sizeof(*ri->cqs), GFP_KERNEL);

	ri->qp_vqs = vadev->qp_vqs;
	ri->max_qp = vadev->max_qp;
	ri->qps = kcalloc(ri->max_qp, sizeof(*ri->qps), GFP_KERNEL);

	rc = virtio_rdma_register_ib_device(ri);
	if (rc) {
		pr_err("Fail to connect to IB layer\n");
		goto err;
	}
	return 0;
err:
	kfree(ri->cqs);
	kfree(ri->qps);
	ib_dealloc_device(&ri->ib_dev);
	dev_set_drvdata(&adev->dev, NULL);

	return rc;
}

static void virtio_rdma_remove(struct auxiliary_device *adev)
{
	struct virtio_rdma_dev *ri = dev_get_drvdata(&adev->dev);

	if (!ri)
		return;

	dev_set_drvdata(&adev->dev, NULL);

	virtio_rdma_unregister_ib_device(ri);

	kfree(ri->cqs);
	kfree(ri->qps);
	ib_dealloc_device(&ri->ib_dev);
}

static const struct auxiliary_device_id vnetr_id_table[] = {
	{ .name = VNET_ADEV_NAME ".roce", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, vnetr_id_table);

static struct auxiliary_driver vnetr_driver = {
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.name = "roce",
	.id_table = vnetr_id_table,
	.probe = virtio_rdma_probe,
	.remove = virtio_rdma_remove,
};

static int __init virtio_rdma_init(void)
{
	int rc;

	rc = auxiliary_driver_register(&vnetr_driver);
	if (rc) {
		pr_err("Fail to register virtio rdma driver: %d\n", rc);
		return rc;
	}
	return 0;
}

static void __exit virtio_rdma_fini(void)
{
	auxiliary_driver_unregister(&vnetr_driver);
}

module_init(virtio_rdma_init);
module_exit(virtio_rdma_fini);

MODULE_LICENSE(DRV_LICENSE);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_DESCRIPTION(DRV_DESC);
