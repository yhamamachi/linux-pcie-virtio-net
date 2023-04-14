// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-console device
 * functionality.
 */
#include <linux/pci-epf.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_console.h>
#include <linux/virtio_ring.h>

#include "pci-epf-virtio.h"

static int virtio_queue_size = 0x100;
module_param(virtio_queue_size, int, 0444);
MODULE_PARM_DESC(virtio_queue_size, "A length of virtqueue");

struct epf_vcon {
	/* To access virtqueues on remote host */
	struct epf_virtio evio;
	struct vringh_kiov *rdev_iovs;

	/* To register a local virtio bus */
	struct virtio_device vdev;

	/* To access virtqueus of local host driver */
	struct vringh *vdev_vrhs;
	struct vringh_kiov *vdev_iovs;
	struct virtqueue **vdev_vqs;

	/* For transportation and notification */
	struct workqueue_struct *task_wq;
	struct work_struct raise_irq_work, rx_work, tx_work;

	/* To retain virtio features. It is commonly used local and remote. */
	u64 features;

	/* To show a status whether this driver is ready and the remote is connected */
	bool connected;
};

enum {
	VCON_VIRTQUEUE_RX,
	VCON_VIRTQUEUE_TX,
	// Should be end of enum
	VCON_VIRTQUEUE_NUM
};

static struct epf_vcon *vdev_to_vcon(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vcon, vdev);
}

static unsigned int epf_vcon_get_nvq(struct epf_vcon *vcon)
{
	/* This is a minimum implementation. Doesn't support any features of
	 * virtio console. It means driver and device use just 2 virtuque for tx
	 * and rx.
	 */
	return VCON_VIRTQUEUE_NUM;
}

static void epf_vcon_rx_handler(struct work_struct *work)
{
	struct epf_vcon *vcon = container_of(work, struct epf_vcon, rx_work);
	struct epf_virtio *evio = &vcon->evio;
	struct vringh *dvrh;
	struct vringh_kiov *siov, *diov;
	int ret;

	if (unlikely(!vcon->connected))
		return;

	dvrh = &vcon->vdev_vrhs[VCON_VIRTQUEUE_RX];
	siov = &vcon->rdev_iovs[VCON_VIRTQUEUE_TX];
	diov = &vcon->vdev_iovs[VCON_VIRTQUEUE_RX];

	do {
		u16 shead, dhead;
		size_t total_len;

		ret = epf_virtio_getdesc(evio, VCON_VIRTQUEUE_TX, siov, NULL,
					 &shead);
		if (ret <= 0)
			continue;

		ret = vringh_getdesc_kern(dvrh, NULL, diov, &dhead, GFP_KERNEL);
		if (ret <= 0) {
			epf_virtio_abandon(evio, VCON_VIRTQUEUE_TX, 1);
			continue;
		}

		total_len = vringh_kiov_length(siov);

		ret = epf_virtio_memcpy_kiov2kiov(evio, siov, diov,
						  DMA_DEV_TO_MEM);
		if (ret < 0)
			continue;

		epf_virtio_iov_complete(evio, VCON_VIRTQUEUE_TX, shead,
					total_len);
		vringh_complete_kern(dvrh, dhead, total_len);

	} while (ret > 0);

	vring_interrupt(0, vcon->vdev_vqs[VCON_VIRTQUEUE_RX]);
}

static void epf_vcon_tx_handler(struct work_struct *work)
{
	struct epf_vcon *vcon = container_of(work, struct epf_vcon, tx_work);
	struct epf_virtio *evio = &vcon->evio;
	struct vringh *svrh;
	struct vringh_kiov *siov, *diov;
	int ret;

	if (unlikely(!vcon->connected))
		return;

	svrh = &vcon->vdev_vrhs[VCON_VIRTQUEUE_TX];
	siov = &vcon->vdev_iovs[VCON_VIRTQUEUE_TX];
	diov = &vcon->rdev_iovs[VCON_VIRTQUEUE_RX];

	do {
		u16 shead, dhead;
		size_t total_len;

		ret = vringh_getdesc_kern(svrh, siov, NULL, &shead, GFP_KERNEL);
		if (ret <= 0)
			continue;

		ret = epf_virtio_getdesc(evio, VCON_VIRTQUEUE_RX, NULL, diov,
					 &dhead);
		if (ret <= 0) {
			vringh_abandon_kern(svrh, 1);
			continue;
		}

		total_len = vringh_kiov_length(siov);

		ret = epf_virtio_memcpy_kiov2kiov(evio, siov, diov,
						  DMA_MEM_TO_DEV);
		if (ret < 0)
			continue;

		vringh_complete_kern(svrh, shead, total_len);
		epf_virtio_iov_complete(evio, VCON_VIRTQUEUE_RX, dhead,
					total_len);

	} while (ret > 0);

	queue_work(vcon->task_wq, &vcon->raise_irq_work);
}

static void epf_vcon_raise_irq_handler(struct work_struct *work)
{
	struct epf_vcon *vcon =
		container_of(work, struct epf_vcon, raise_irq_work);
	struct pci_epf *epf = vcon->evio.epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_EPC_IRQ_INTX, 0);
}

static int epf_vcon_setup_common(struct epf_vcon *vcon)
{
	vcon->features = 0;
	vcon->connected = false;

	vcon->task_wq =
		alloc_workqueue("pci-epf-vcon/task-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vcon->task_wq)
		return -ENOMEM;

	INIT_WORK(&vcon->rx_work, epf_vcon_rx_handler);
	INIT_WORK(&vcon->tx_work, epf_vcon_tx_handler);
	INIT_WORK(&vcon->raise_irq_work, epf_vcon_raise_irq_handler);

	return 0;
}

static void epf_vcon_cleanup_common(struct epf_vcon *vcon)
{
	/* Should do first to stop polling in other kernel thread */
	vcon->connected = false;

	flush_work(&vcon->raise_irq_work);
	flush_work(&vcon->tx_work);
	flush_work(&vcon->rx_work);

	destroy_workqueue(vcon->task_wq);
}

static void epf_vcon_qnotify_callback(void *param)
{
	struct epf_vcon *vcon = param;

	queue_work(vcon->task_wq, &vcon->rx_work);
}

static void epf_vcon_initialize_complete(void *param)
{
	struct epf_vcon *vcon = param;

	pr_debug("Remote host has connected\n");

	vcon->connected = true;

	/* send filled buffer */
	queue_work(vcon->task_wq, &vcon->tx_work);
}

static struct pci_epf_header epf_vcon_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_CONSOLE,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_CONSOLE,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_COMMUNICATION,
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

static int epf_vcon_setup_ep_func(struct epf_vcon *vcon, struct pci_epf *epf)
{
	int err;
	struct epf_virtio *evio = &vcon->evio;
	unsigned int nvq = epf_vcon_get_nvq(vcon);

	vcon->rdev_iovs =
		kmalloc_array(nvq, sizeof(vcon->rdev_iovs[0]), GFP_KERNEL);
	if (!vcon->rdev_iovs)
		return -ENOMEM;

	for (int i = 0; i < nvq; i++)
		vringh_kiov_init(&vcon->rdev_iovs[i], NULL, 0);

	evio->epf = epf;
	evio->features = vcon->features;
	evio->nvq = nvq;
	evio->vqlen = virtio_queue_size;

	evio->qn_callback = epf_vcon_qnotify_callback;
	evio->qn_param = vcon;

	evio->ic_callback = epf_vcon_initialize_complete;
	evio->ic_param = vcon;

	err = epf_virtio_init(evio, &epf_vcon_pci_header, 0);
	if (err)
		goto err_cleanup_kiov;

	err = epf_virtio_launch_bgtask(evio);
	if (err)
		goto err_virtio_final;

	return 0;

err_virtio_final:
	epf_virtio_final(evio);

err_cleanup_kiov:
	for (int i = 0; i < nvq; i++)
		vringh_kiov_cleanup(&vcon->rdev_iovs[i]);

	kfree(vcon->rdev_iovs);

	return err;
}

static void epf_vcon_cleanup_ep_func(struct epf_vcon *vcon)
{
	epf_virtio_terminate_bgtask(&vcon->evio);

	epf_virtio_final(&vcon->evio);

	kfree(vcon->rdev_iovs);
}

/*
 * Functions for local virtio device operation
 */
static u64 epf_vcon_vdev_get_features(struct virtio_device *vdev)
{
	struct epf_vcon *vcon = vdev_to_vcon(vdev);

	return vcon->features;
}

static int epf_vcon_vdev_finalize_features(struct virtio_device *vdev)
{
	struct epf_vcon *vcon = vdev_to_vcon(vdev);

	return vdev->features != vcon->features;
}

static void epf_vcon_vdev_get_config(struct virtio_device *vdev,
				     unsigned int offset, void *buf,
				     unsigned int len)
{
	/* There is no config for virtio console because this console device
	 * doesn't any support features
	 */
	memset(buf, 0x00, len);
}

static void epf_vcon_vdev_set_config(struct virtio_device *vdev,
				     unsigned int offset, const void *buf,
				     unsigned int len)
{
	/* Do nothing because this console device doesn't any support features */
}

static u8 epf_vcon_vdev_get_status(struct virtio_device *vdev)
{
	return 0;
}

static void epf_vcon_vdev_set_status(struct virtio_device *vdev, u8 status)
{
	if (status & VIRTIO_CONFIG_S_FAILED)
		pr_debug("driver failed to setup this device\n");
}

static void epf_vcon_vdev_reset(struct virtio_device *vdev)
{
	struct epf_vcon *vcon = vdev_to_vcon(vdev);

	epf_virtio_reset(&vcon->evio);
}

static bool epf_vcon_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vcon *vcon = vdev_to_vcon(vq->vdev);

	switch (vq->index) {
	case VCON_VIRTQUEUE_RX:
	case VCON_VIRTQUEUE_TX:
		queue_work(vcon->task_wq, &vcon->tx_work);
		break;
	default:
		return false;
	}

	return true;
}

static int epf_vcon_vdev_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
				  struct virtqueue *vqs[],
				  vq_callback_t *callback[],
				  const char *const names[], const bool *ctx,
				  struct irq_affinity *desc)
{
	struct epf_vcon *vcon = vdev_to_vcon(vdev);
	int err;
	int qidx, i;

	if (nvqs > epf_vcon_get_nvq(vcon))
		return -EINVAL;

	for (qidx = 0, i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		const struct vring *vring;

		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vq = vring_create_virtqueue(qidx++, virtio_queue_size,
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, ctx ? ctx[i] : false,
					    epf_vcon_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		vcon->vdev_vqs[i] = vq;

		vring = virtqueue_get_vring(vq);
		err = vringh_init_kern(&vcon->vdev_vrhs[i], vcon->features,
				       virtio_queue_size, false, vring->desc,
				       vring->avail, vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}
	}

	return 0;

err_del_vqs:
	for (; i >= 0; i--) {
		if (!names[i])
			continue;

		if (!vqs[i])
			continue;

		vring_del_virtqueue(vqs[i]);
	}
	return err;
}

static void epf_vcon_vdev_del_vqs(struct virtio_device *vdev)
{
	struct epf_vcon *vcon = vdev_to_vcon(vdev);

	for (int i = 0; i < epf_vcon_get_nvq(vcon); i++) {
		if (!vcon->vdev_vqs[i])
			continue;

		vring_del_virtqueue(vcon->vdev_vqs[i]);
	}
}

static const struct virtio_config_ops epf_vcon_vdev_config_ops = {
	.get_features = epf_vcon_vdev_get_features,
	.finalize_features = epf_vcon_vdev_finalize_features,
	.get = epf_vcon_vdev_get_config,
	.set = epf_vcon_vdev_set_config,
	.get_status = epf_vcon_vdev_get_status,
	.set_status = epf_vcon_vdev_set_status,
	.reset = epf_vcon_vdev_reset,
	.find_vqs = epf_vcon_vdev_find_vqs,
	.del_vqs = epf_vcon_vdev_del_vqs,
};

static void epf_vcon_vdev_release(struct device *dev)
{
	/* Do nothing, because the struct virtio_device will be reused. */
}

static int epf_vcon_setup_vdev(struct epf_vcon *vcon, struct device *parent)
{
	int err;
	struct virtio_device *vdev = &vcon->vdev;
	const unsigned int nvq = epf_vcon_get_nvq(vcon);

	vcon->vdev_vrhs =
		kmalloc_array(nvq, sizeof(vcon->vdev_vrhs[0]), GFP_KERNEL);
	if (!vcon->vdev_vrhs)
		return -ENOMEM;

	vcon->vdev_iovs =
		kmalloc_array(nvq, sizeof(vcon->vdev_iovs[0]), GFP_KERNEL);
	if (!vcon->vdev_iovs) {
		err = -ENOMEM;
		goto err_free_vrhs;
	}

	for (int i = 0; i < nvq; i++)
		vringh_kiov_init(&vcon->vdev_iovs[i], NULL, 0);

	vcon->vdev_vqs =
		kmalloc_array(nvq, sizeof(vcon->vdev_vrhs[0]), GFP_KERNEL);
	if (!vcon->vdev_vqs) {
		err = -ENOMEM;
		goto err_cleanup_kiov;
	}

	vdev->dev.parent = parent;
	vdev->dev.release = epf_vcon_vdev_release;
	vdev->config = &epf_vcon_vdev_config_ops;
	vdev->id.vendor = PCI_VENDOR_ID_REDHAT_QUMRANET;
	vdev->id.device = VIRTIO_ID_CONSOLE;

	err = register_virtio_device(vdev);
	if (err)
		goto err_free_vdev_vqs;

	return 0;

err_free_vdev_vqs:
	kfree(vcon->vdev_vqs);

err_cleanup_kiov:
	for (int i = 0; i < nvq; i++)
		vringh_kiov_cleanup(&vcon->vdev_iovs[i]);

	kfree(vcon->vdev_iovs);

err_free_vrhs:
	kfree(vcon->vdev_vrhs);

	return err;
}

static void epf_vcon_cleanup_vdev(struct epf_vcon *vcon)
{
	unregister_virtio_device(&vcon->vdev);
	/* Cleanup struct virtio_device that has kobject, otherwise error occures when
	 * reregister the virtio device.
	 */
	memset(&vcon->vdev, 0x00, sizeof(vcon->vdev));

	kfree(vcon->vdev_vqs);

	for (int i = 0; i < epf_vcon_get_nvq(vcon); i++)
		vringh_kiov_cleanup(&vcon->vdev_iovs[i]);

	kfree(vcon->vdev_iovs);
	kfree(vcon->vdev_vrhs);
}

static int epf_vcon_bind(struct pci_epf *epf)
{
	struct epf_vcon *vcon = epf_get_drvdata(epf);
	int err;

	err = epf_vcon_setup_common(vcon);
	if (err)
		return err;

	err = epf_vcon_setup_ep_func(vcon, epf);
	if (err)
		goto err_cleanup_common;

	err = epf_vcon_setup_vdev(vcon, epf->epc->dev.parent);
	if (err)
		goto err_cleanup_ep_func;

	return 0;

err_cleanup_common:
	epf_vcon_cleanup_common(vcon);

err_cleanup_ep_func:
	epf_vcon_cleanup_ep_func(vcon);

	return err;
}

static void epf_vcon_unbind(struct pci_epf *epf)
{
	struct epf_vcon *vcon = epf_get_drvdata(epf);

	epf_vcon_cleanup_common(vcon);
	epf_vcon_cleanup_ep_func(vcon);
	epf_vcon_cleanup_vdev(vcon);
}

static struct pci_epf_ops epf_vcon_ops = {
	.bind = epf_vcon_bind,
	.unbind = epf_vcon_unbind,
};

static const struct pci_epf_device_id epf_vcon_ids[] = {
	{ .name = "pci_epf_vcon" },
	{}
};

static int epf_vcon_probe(struct pci_epf *epf, const struct pci_epf_device_id *id)
{
	struct epf_vcon *vcon;

	vcon = devm_kzalloc(&epf->dev, sizeof(*vcon), GFP_KERNEL);
	if (!vcon)
		return -ENOMEM;

	epf_set_drvdata(epf, vcon);

	return 0;
}

static struct pci_epf_driver epf_vcon_drv = {
	.driver.name = "pci_epf_vcon",
	.ops = &epf_vcon_ops,
	.id_table = epf_vcon_ids,
	.probe = epf_vcon_probe,
	.owner = THIS_MODULE,
};

static int __init epf_vcon_init(void)
{
	int err;

	err = pci_epf_register_driver(&epf_vcon_drv);
	if (err)
		pr_err("Failed to register PCI EP virtio-console function\n");

	return 0;
}
module_init(epf_vcon_init);

static void epf_vcon_exit(void)
{
	pci_epf_unregister_driver(&epf_vcon_drv);
}
module_exit(epf_vcon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shunsuke Mie <mie@igel.co.jp>");
