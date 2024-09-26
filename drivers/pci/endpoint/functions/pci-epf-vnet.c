// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 */

#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/virtio_config.h>
#include <linux/virtio_net.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>
#include <linux/dmaengine.h>

#include "pci-epf-virtio.h"

static int virtio_queue_size = 0x100;
module_param(virtio_queue_size, int, 0444);
MODULE_PARM_DESC(virtio_queue_size, "A length of virtqueue");

struct epf_vnet {
	/* virtio feature and configurations for virtio-net. It is commonly used
	 * local and remote. */
	struct virtio_net_config vnet_cfg;
	struct virtio_net_config vdev_vnet_cfg;
	u64 features;

	struct dma_chan *tx_dma_chan, *rx_dma_chan;

	/* To access virtqueues on remote host */
	struct epf_virtio evio;
	struct vringh_kiov *rdev_iovs;

	/* To register a local virtio bus */
	struct virtio_device vdev;

	/* To access virtqueus of local host driver */
	struct vringh *vdev_vrhs;
	struct vringh_kiov *vdev_iovs;
	struct virtqueue **vdev_vqs;

	struct workqueue_struct *task_wq;
	struct work_struct raise_irq_work, rx_work, tx_work;
	struct work_struct vdev_ctrl_work, ep_ctrl_work;

#define EPF_VNET_INIT_COMPLETE_VDEV BIT(0)
#define EPF_VNET_INIT_COMPLETE_EP_FUNC BIT(1)
	u8 initialized;
	bool enable_edma;
};

static inline struct epf_vnet *vdev_to_vnet(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vnet, vdev);
}

static u16 epf_vnet_get_nvq(struct epf_vnet *vnet)
{
	/* tx and rx queue pair and control queue. */
	return vnet->vnet_cfg.max_virtqueue_pairs * 2 +
	       !!(vnet->features & BIT(VIRTIO_NET_F_CTRL_VQ));
}

static void epf_vnet_qnotify_callback(void *param)
{
	struct epf_vnet *vnet = param;

	queue_work(vnet->task_wq, &vnet->rx_work);
	queue_work(vnet->task_wq, &vnet->ep_ctrl_work);
}

static void epf_vnet_vdev_announce_linkup(struct epf_vnet *vnet);

static void epf_vnet_ep_announce_linkup(struct epf_vnet *vnet)
{
	struct epf_virtio *evio = &vnet->evio;

	epf_virtio_cfg_set16(evio,
			     VIRTIO_PCI_CONFIG_OFF(false) +
				     offsetof(struct virtio_net_config, status),
			     VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	epf_virtio_cfg_set16(evio, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_CONFIG);

	queue_work(vnet->task_wq, &vnet->raise_irq_work);
}

static void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from)
{
	vnet->initialized |= from;

	if (!(vnet->initialized & EPF_VNET_INIT_COMPLETE_VDEV))
		return;

	if (!(vnet->initialized & EPF_VNET_INIT_COMPLETE_EP_FUNC))
		return;

	epf_vnet_vdev_announce_linkup(vnet);
	epf_vnet_ep_announce_linkup(vnet);
}

static void epf_vnet_ep_init_complete(void *param)
{
	struct epf_vnet *vnet = param;
	epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_EP_FUNC);
}

static struct pci_epf_header epf_vnet_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_NET,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_NET,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_NETWORK,
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

static void epf_vnet_setup_pci_cfgs(struct epf_vnet *vnet,
				    struct epf_virtio *evio)
{
	epf_virtio_cfg_memcpy_toio(evio, VIRTIO_PCI_CONFIG_OFF(false),
				   &vnet->vnet_cfg, sizeof(vnet->vnet_cfg));
}

static int epf_vnet_setup_ep_func(struct epf_vnet *vnet, struct pci_epf *epf)
{
	struct epf_virtio *evio = &vnet->evio;
	u16 nvq = epf_vnet_get_nvq(vnet);
	int err;

	vnet->rdev_iovs =
		kmalloc_array(sizeof(vnet->rdev_iovs[0]), nvq, GFP_KERNEL);
	if (!vnet->rdev_iovs)
		return -ENOMEM;

	for (int i = 0; i < nvq; i++)
		vringh_kiov_init(&vnet->rdev_iovs[i], NULL, 0);

	evio->epf = epf;
	evio->features = vnet->features;
	evio->nvq = nvq;
	evio->vqlen = virtio_queue_size;

	evio->qn_callback = epf_vnet_qnotify_callback;
	evio->qn_param = vnet;

	evio->ic_callback = epf_vnet_ep_init_complete;
	evio->ic_param = vnet;

	err = epf_virtio_init(evio, &epf_vnet_pci_header, 0);
	if (err)
		goto err_cleanup_kiov;

	epf_vnet_setup_pci_cfgs(vnet, evio);

	err = epf_virtio_launch_bgtask(evio);
	if (err)
		goto err_virtio_final;

	return 0;

err_cleanup_kiov:
err_virtio_final:

	return err;
}

static void epf_vnet_cleanup_ep_func(struct epf_vnet *vnet)
{
}

enum {
	VNET_VIRTQUEUE_RX,
	VNET_VIRTQUEUE_TX,
	VNET_VIRTQUEUE_CTRL,
};

struct epf_vnet_dma_done_param {
	struct epf_vnet *vnet;
	struct virtqueue *vq;
	struct vringh *kvrh;
	struct epf_virtio *evio;
	size_t total_len;
	int vq_index;
	u16 khead, ehead;
};

static void epf_vnet_dma_done(void *param)
{
	struct epf_vnet_dma_done_param *p = param;
	struct epf_vnet *vnet = p->vnet;

	vringh_complete_kern(p->kvrh, p->khead, p->total_len);
	epf_virtio_iov_complete(p->evio, p->vq_index, p->ehead, p->total_len);

	vring_interrupt(0, p->vq);
	queue_work(vnet->task_wq, &vnet->raise_irq_work);

	kfree(p);
}

static struct epf_vnet_dma_done_param *
epf_vnet_edma_create_cb_param(struct epf_vnet *vnet, size_t total_len,
			      struct vringh *vrh, struct epf_virtio *evio,
			      u16 khead, u16 ehead,
			      enum dma_transfer_direction dir)
{
	struct epf_vnet_dma_done_param *dma_done_param;
	unsigned local_vq_index, remote_vq_index;

	if (dir == DMA_MEM_TO_DEV) {
		local_vq_index = VNET_VIRTQUEUE_TX;
		remote_vq_index = VNET_VIRTQUEUE_RX;
	} else {
		local_vq_index = VNET_VIRTQUEUE_RX;
		remote_vq_index = VNET_VIRTQUEUE_TX;
	}

	dma_done_param = kmalloc(sizeof(*dma_done_param), GFP_KERNEL);
	if (!dma_done_param)
		return ERR_PTR(-ENOMEM);

	dma_done_param->vnet = vnet;
	dma_done_param->vq = vnet->vdev_vqs[local_vq_index];
	dma_done_param->total_len = total_len;
	dma_done_param->kvrh = vrh;
	dma_done_param->evio = evio;
	dma_done_param->vq_index = remote_vq_index;
	dma_done_param->khead = khead;
	dma_done_param->ehead = ehead;

	return dma_done_param;
}

static void epf_vnet_rx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet = container_of(work, struct epf_vnet, rx_work);
	struct epf_virtio *evio = &vnet->evio;
	struct vringh *dvrh;
	struct vringh_kiov *siov, *diov;
	int ret;

	dvrh = &vnet->vdev_vrhs[VNET_VIRTQUEUE_RX];
	siov = &vnet->rdev_iovs[VNET_VIRTQUEUE_TX];
	diov = &vnet->vdev_iovs[VNET_VIRTQUEUE_RX];

	do {
		u16 shead, dhead;
		size_t total_len;
		struct epf_vnet_dma_done_param *dma_done_param;

		ret = epf_virtio_getdesc(evio, VNET_VIRTQUEUE_TX, siov, NULL,
					 &shead);
		if (ret <= 0)
			continue;

		ret = vringh_getdesc_kern(dvrh, NULL, diov, &dhead, GFP_KERNEL);
		if (ret <= 0) {
			epf_virtio_abandon(evio, VNET_VIRTQUEUE_TX, 1);
			continue;
		}

		total_len = vringh_kiov_length(siov);

		if (vnet->enable_edma) {
			dma_done_param = epf_vnet_edma_create_cb_param(
				vnet, total_len, dvrh, evio, dhead, shead,
				DMA_DEV_TO_MEM);
			if (IS_ERR(dma_done_param)) {
				pr_err("Failed to setup dma callback: %ld\n",
				       PTR_ERR(dma_done_param));
				return;
			}

			ret = epf_virtio_dma_kiov2kiov(vnet->rx_dma_chan, siov,
						       diov, epf_vnet_dma_done,
						       dma_done_param,
						       DMA_DEV_TO_MEM);
			if (!ret)
				ret = 1;
		} else {
			epf_virtio_memcpy_kiov2kiov(evio, siov, diov,
						    DMA_DEV_TO_MEM);

			epf_virtio_iov_complete(evio, VNET_VIRTQUEUE_TX, shead,
						total_len);
			vringh_complete_kern(dvrh, dhead, total_len);

			vring_interrupt(0, vnet->vdev_vqs[VNET_VIRTQUEUE_RX]);
		}
	} while (ret > 0);
}

static void epf_vnet_tx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet = container_of(work, struct epf_vnet, tx_work);
	struct epf_virtio *evio = &vnet->evio;
	struct vringh *svrh;
	struct vringh_kiov *siov, *diov;
	struct epf_vnet_dma_done_param *dma_done_param;
	int ret;

	svrh = &vnet->vdev_vrhs[VNET_VIRTQUEUE_TX];
	siov = &vnet->vdev_iovs[VNET_VIRTQUEUE_TX];
	diov = &vnet->rdev_iovs[VNET_VIRTQUEUE_RX];

	do {
		u16 shead, dhead;
		size_t total_len;

		ret = vringh_getdesc_kern(svrh, siov, NULL, &shead, GFP_KERNEL);
		if (ret <= 0)
			continue;

		ret = epf_virtio_getdesc(evio, VNET_VIRTQUEUE_RX, NULL, diov,
					 &dhead);
		if (ret <= 0) {
			vringh_abandon_kern(svrh, 1);
			continue;
		}

		total_len = vringh_kiov_length(siov);

		if (vnet->enable_edma) {
			dma_done_param = epf_vnet_edma_create_cb_param(
				vnet, total_len, svrh, evio, shead, dhead,
				DMA_MEM_TO_DEV);
			if (IS_ERR(dma_done_param)) {
				pr_err("Failed to setup dma callback: %ld\n",
				       PTR_ERR(dma_done_param));
				return;
			}

			ret = epf_virtio_dma_kiov2kiov(vnet->tx_dma_chan, siov,
						       diov, epf_vnet_dma_done,
						       dma_done_param,
						       DMA_MEM_TO_DEV);
			if (!ret)
				ret = 1;
		} else {
			epf_virtio_memcpy_kiov2kiov(evio, siov, diov,
						    DMA_MEM_TO_DEV);

			epf_virtio_iov_complete(evio, VNET_VIRTQUEUE_RX, dhead,
						total_len);
			vringh_complete_kern(svrh, shead, total_len);

			vring_interrupt(0, vnet->vdev_vqs[VNET_VIRTQUEUE_TX]);
			queue_work(vnet->task_wq, &vnet->raise_irq_work);
		}
	} while (ret > 0);
}

static void epf_vnet_ep_ctrl_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, ep_ctrl_work);
	struct epf_virtio *evio = &vnet->evio;
	struct vringh_kiov riov, wiov;
	struct vringh *vrh = &evio->vrhs[VNET_VIRTQUEUE_CTRL]->vrh;
	struct pci_epf *epf = evio->epf;
	struct virtio_net_ctrl_hdr *hdr;
	int err;
	u16 head;
	size_t total_len, rlen, wlen;
	u8 class, cmd;
	void __iomem *rvirt, *wvirt;
	phys_addr_t rphys, wphys;

	vringh_kiov_init(&riov, NULL, 0);
	vringh_kiov_init(&wiov, NULL, 0);

	err = vringh_getdesc_iomem(vrh, &riov, &wiov, &head, GFP_KERNEL);
	if (err <= 0)
		return;

	total_len = vringh_kiov_length(&riov);

	rlen = riov.iov[riov.i].iov_len;
	rvirt = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)riov.iov[riov.i].iov_base, &rphys, rlen);
	if (IS_ERR(rvirt)) {
		err = PTR_ERR(rvirt);
		goto err_out;
	}

	wlen = wiov.iov[wiov.i].iov_len;
	wvirt = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)wiov.iov[wiov.i].iov_base, &wphys, wlen);
	if (IS_ERR(wvirt)) {
		err = PTR_ERR(wvirt);
		goto err_unmap_command;
	}

	hdr = rvirt;
	class = ioread8(&hdr->class);
	cmd = ioread8(&hdr->cmd);
	switch (class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_err("Found invalid command: announce: %d\n", cmd);
			break;
		}
		epf_virtio_cfg_clear16(
			evio,
			VIRTIO_PCI_CONFIG_OFF(false) +
				offsetof(struct virtio_net_config, status),
			VIRTIO_NET_S_ANNOUNCE);
		epf_virtio_cfg_clear16(evio, VIRTIO_PCI_ISR,
				       VIRTIO_PCI_ISR_CONFIG);

		iowrite8(VIRTIO_NET_OK, wvirt);
		break;
	default:
		pr_err("Found unsupported class in control queue: %d\n", class);
		break;
	}

	vringh_complete_iomem(vrh, head, total_len);
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, wphys, wvirt,
			   wlen);

	vringh_kiov_cleanup(&riov);
	vringh_kiov_cleanup(&wiov);

	return;

err_unmap_command:
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
err_out:
	return;
}

static void epf_vnet_vdev_cfg_set_status(struct epf_vnet *vnet, u16 status)
{
	vnet->vdev_vnet_cfg.status |= status;
}

static void epf_vnet_vdev_cfg_clear_status(struct epf_vnet *vnet, u16 status)
{
	vnet->vdev_vnet_cfg.status &= ~status;
}

static void epf_vnet_vdev_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_vdev_cfg_set_status(vnet, VIRTIO_NET_S_LINK_UP |
						   VIRTIO_NET_S_ANNOUNCE);
	virtio_config_changed(&vnet->vdev);
}

static void epf_vnet_vdev_ctrl_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, vdev_ctrl_work);

	struct vringh *vrh = &vnet->vdev_vrhs[VNET_VIRTQUEUE_CTRL];
	struct vringh_kiov riov, wiov;
	struct virtio_net_ctrl_hdr *hdr;
	virtio_net_ctrl_ack *ack;
	int err;
	u16 head;
	size_t len;

	vringh_kiov_init(&riov, NULL, 0);
	vringh_kiov_init(&wiov, NULL, 0);

	err = vringh_getdesc_kern(vrh, &riov, &wiov, &head, GFP_KERNEL);
	if (err <= 0)
		goto done;

	len = vringh_kiov_length(&riov);
	if (len < sizeof(*hdr)) {
		pr_debug("Command is too short: %ld\n", len);
		err = -EIO;
		goto done;
	}

	if (vringh_kiov_length(&wiov) < sizeof(*ack)) {
		pr_debug("Space for ack is not enough\n");
		err = -EIO;
		goto done;
	}

	hdr = phys_to_virt((unsigned long)riov.iov[riov.i].iov_base);
	ack = phys_to_virt((unsigned long)wiov.iov[wiov.i].iov_base);

	switch (hdr->class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (hdr->cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_debug("Invalid command: announce: %d\n", hdr->cmd);
			goto done;
		}

		epf_vnet_vdev_cfg_clear_status(vnet, VIRTIO_NET_S_ANNOUNCE);
		*ack = VIRTIO_NET_OK;
		break;
	default:
		pr_debug("Found not supported class: %d\n", hdr->class);
		err = -EIO;
	}

done:
	vringh_complete_kern(vrh, head, len);

	vringh_kiov_cleanup(&riov);
	vringh_kiov_cleanup(&wiov);
	return;
}

static void epf_vnet_raise_irq_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, raise_irq_work);
	struct pci_epf *epf = vnet->evio.epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_IRQ_INTX, 0);
}

static int epf_vnet_setup_common(struct epf_vnet *vnet)
{
#if 0
	vnet->features =
		BIT(VIRTIO_F_ACCESS_PLATFORM) | BIT(VIRTIO_NET_F_MTU) |
		BIT(VIRTIO_NET_F_STATUS) |
		/* Following features are to skip any of checking and offloading, Like a
		 * transmission between virtual machines on same system. Details are on
		 * section 5.1.5 in virtio specification.
		 */
		BIT(VIRTIO_NET_F_GUEST_CSUM) | BIT(VIRTIO_NET_F_GUEST_TSO4) |
		BIT(VIRTIO_NET_F_GUEST_TSO6) | BIT(VIRTIO_NET_F_GUEST_ECN) |
		BIT(VIRTIO_NET_F_GUEST_UFO) |
		/* The control queue is just used for linkup announcement. */
		BIT(VIRTIO_NET_F_CTRL_VQ);
#else
	vnet->features =
		BIT(VIRTIO_F_ACCESS_PLATFORM) | BIT(VIRTIO_NET_F_MTU) |
		BIT(VIRTIO_NET_F_STATUS) |
		/* Following features are to skip any of checking and offloading, Like a
		 * transmission between virtual machines on same system. Details are on
		 * section 5.1.5 in virtio specification.
		 */
		BIT(VIRTIO_NET_F_GUEST_CSUM) |
		/* The control queue is just used for linkup announcement. */
		BIT(VIRTIO_NET_F_CTRL_VQ);
#endif
	vnet->vnet_cfg.max_virtqueue_pairs = 1;
	vnet->vnet_cfg.status = 0;
	vnet->vnet_cfg.mtu = 4000;//PAGE_SIZE - ETH_HLEN;

	memcpy(&vnet->vdev_vnet_cfg, &vnet->vnet_cfg, sizeof(vnet->vnet_cfg));

	vnet->task_wq =
		alloc_workqueue("pci-epf-vnet/task-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->task_wq)
		return -ENOMEM;

	INIT_WORK(&vnet->rx_work, epf_vnet_rx_handler);
	INIT_WORK(&vnet->tx_work, epf_vnet_tx_handler);
	INIT_WORK(&vnet->ep_ctrl_work, epf_vnet_ep_ctrl_handler);
	INIT_WORK(&vnet->vdev_ctrl_work, epf_vnet_vdev_ctrl_handler);
	INIT_WORK(&vnet->raise_irq_work, epf_vnet_raise_irq_handler);

	return 0;
}

static void epf_vnet_cleanup_common(struct epf_vnet *vnet)
{
}

/*
 * Functions for local virtio device operation
 */
static u64 epf_vnet_vdev_get_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vnet->features;
}

static int epf_vnet_vdev_finalize_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vdev->features != vnet->features;
}

static void epf_vnet_vdev_get_config(struct virtio_device *vdev,
				     unsigned int offset, void *buf,
				     unsigned int len)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	const unsigned int mac_len = sizeof(vnet->vdev_vnet_cfg.mac);
	const unsigned int status_len = sizeof(vnet->vdev_vnet_cfg.status);
	unsigned int copy_len;

	switch (offset) {
	case offsetof(struct virtio_net_config, mac):
		/* This PCIe EP function doesn't provide a VIRTIO_NET_F_MAC feature, so just
		 * clear the buffer.
		 */
		copy_len = len >= mac_len ? mac_len : len;
		memset(buf, 0x00, copy_len);
		len -= copy_len;
		buf += copy_len;
		fallthrough;
	case offsetof(struct virtio_net_config, status):
		copy_len = len >= status_len ? status_len : len;
		memcpy(buf, &vnet->vdev_vnet_cfg.status, copy_len);
		len -= copy_len;
		buf += copy_len;
		fallthrough;
	default:
		if (offset > sizeof(vnet->vdev_vnet_cfg)) {
			memset(buf, 0x00, len);
			break;
		}
		memcpy(buf, (void *)&vnet->vdev_vnet_cfg + offset, len);
	}
}

static void epf_vnet_vdev_set_config(struct virtio_device *vdev,
				     unsigned int offset, const void *buf,
				     unsigned int len)
{
	/* Do nothing because this console device doesn't any support features */
}

static u8 epf_vnet_vdev_get_status(struct virtio_device *vdev)
{
	return 0;
}

static void epf_vnet_vdev_set_status(struct virtio_device *vdev, u8 status)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	if (status & VIRTIO_CONFIG_S_DRIVER_OK)
		epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_VDEV);
}

static void epf_vnet_vdev_reset(struct virtio_device *vdev)
{
	pr_debug("doesn't support yet");
}

static bool epf_vnet_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vnet *vnet = vdev_to_vnet(vq->vdev);

	/* Support only one queue pair */
	switch (vq->index) {
	case VNET_VIRTQUEUE_RX:
		break;
	case VNET_VIRTQUEUE_TX:
		queue_work(vnet->task_wq, &vnet->tx_work);
		break;
	case VNET_VIRTQUEUE_CTRL:
		queue_work(vnet->task_wq, &vnet->vdev_ctrl_work);
		break;
	default:
		return false;
	}

	return true;
}

static int epf_vnet_vdev_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
				  struct virtqueue *vqs[], struct virtqueue_info *vq_info,
				  struct irq_affinity *desc)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	int i;
	int err;
	int qidx;

	if (nvqs > epf_vnet_get_nvq(vnet))
		return -EINVAL;

	for (qidx = 0, i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		const struct vring *vring;

		if (!vq_info[i].name) {
			vqs[i] = NULL;
			continue;
		}

		vq = vring_create_virtqueue(qidx++, virtio_queue_size,
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, vq_info[i].ctx ? vq_info[i].ctx : false,
					    epf_vnet_vdev_vq_notify,
					    vq_info[i].callback, vq_info[i].name);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		vnet->vdev_vqs[i] = vq;
		vring = virtqueue_get_vring(vq);

		err = vringh_init_kern(&vnet->vdev_vrhs[i], vnet->features,
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
		if (!vq_info[i].name)
			continue;

		if (!vqs[i])
			continue;

		vring_del_virtqueue(vqs[i]);
	}
	return err;
}

static void epf_vnet_vdev_del_vqs(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	for (int i = 0; i < epf_vnet_get_nvq(vnet); i++) {
		if (!vnet->vdev_vqs[i])
			continue;

		vring_del_virtqueue(vnet->vdev_vqs[i]);
	}
}

static void epf_vnet_vdev_release(struct device *dev)
{
	/* Do nothing, because the struct virtio_device will be reused. */
}

static const struct virtio_config_ops epf_vnet_vdev_config_ops = {
	.get_features = epf_vnet_vdev_get_features,
	.finalize_features = epf_vnet_vdev_finalize_features,
	.get = epf_vnet_vdev_get_config,
	.set = epf_vnet_vdev_set_config,
	.get_status = epf_vnet_vdev_get_status,
	.set_status = epf_vnet_vdev_set_status,
	.reset = epf_vnet_vdev_reset,
	.find_vqs = epf_vnet_vdev_find_vqs,
	.del_vqs = epf_vnet_vdev_del_vqs,
};

static int epf_vnet_setup_vdev(struct epf_vnet *vnet, struct device *parent)
{
	u16 nvq = epf_vnet_get_nvq(vnet);
	struct virtio_device *vdev = &vnet->vdev;
	int err;

	vnet->vdev_vrhs =
		kmalloc_array(nvq, sizeof(vnet->vdev_vrhs[0]), GFP_KERNEL);
	if (!vnet->vdev_vrhs)
		return -ENOMEM;

	vnet->vdev_iovs =
		kmalloc_array(nvq, sizeof(vnet->vdev_iovs[0]), GFP_KERNEL);
	if (!vnet->vdev_iovs) {
		err = -ENOMEM;
		goto err_free_vrhs;
	}

	for (int i = 0; i < nvq; i++)
		vringh_kiov_init(&vnet->vdev_iovs[i], NULL, 0);

	vnet->vdev_vqs =
		kmalloc_array(nvq, sizeof(vnet->vdev_vrhs[0]), GFP_KERNEL);
	if (!vnet->vdev_vqs) {
		err = -ENOMEM;
		goto err_cleanup_kiov;
	}

	vdev->dev.parent = parent;
	vdev->dev.release = epf_vnet_vdev_release;
	vdev->config = &epf_vnet_vdev_config_ops;
	vdev->id.vendor = PCI_VENDOR_ID_REDHAT_QUMRANET;
	vdev->id.device = VIRTIO_ID_NET;

	err = register_virtio_device(vdev);
	if (err)
		goto err_free_vdev_vqs;

	return 0;

err_free_vdev_vqs:
	kfree(vnet->vdev_vqs);

err_cleanup_kiov:
	for (int i = 0; i < nvq; i++)
		vringh_kiov_cleanup(&vnet->vdev_iovs[i]);

	kfree(vnet->vdev_iovs);

err_free_vrhs:
	kfree(vnet->vdev_vrhs);

	return err;
}

static void epf_vnet_cleanup_vdev(struct epf_vnet *vnet)
{
	unregister_virtio_device(&vnet->vdev);
	/* Cleanup struct virtio_device that has kobject, otherwise error occures when
	 * reregister the virtio device. */
	memset(&vnet->vdev, 0x00, sizeof(vnet->vdev));

	kfree(vnet->vdev_vqs);

	for (int i = 0; i < epf_vnet_get_nvq(vnet); i++)
		vringh_kiov_cleanup(&vnet->vdev_iovs[i]);

	kfree(vnet->vdev_iovs);
	kfree(vnet->vdev_vrhs);
}

static int epf_vnet_setup_edma(struct epf_vnet *vnet, struct device *dma_dev)
{
	int err;

	vnet->tx_dma_chan = epf_request_dma_chan(dma_dev, DMA_MEM_TO_DEV);
	if (!vnet->tx_dma_chan)
		return -EOPNOTSUPP;

	vnet->rx_dma_chan = epf_request_dma_chan(dma_dev, DMA_DEV_TO_MEM);
	if (!vnet->rx_dma_chan) {
		goto err_release_tx_chan;
		err = -EOPNOTSUPP;
	}

	return 0;

err_release_tx_chan:
	dma_release_channel(vnet->tx_dma_chan);

	return err;
}

static void epf_vnet_cleanup_edma(struct epf_vnet *vnet)
{
	dma_release_channel(vnet->tx_dma_chan);
	dma_release_channel(vnet->rx_dma_chan);
}

static int epf_vnet_bind(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);
	int err;

	err = epf_vnet_setup_common(vnet);
	if (err)
		return err;

	err = epf_vnet_setup_edma(vnet, epf->epc->dev.parent);
	if (err) {
		pr_info("PCIe embedded DMAC wasn't found. Rollback to cpu transfer\n");
		vnet->enable_edma = false;
	} else {
		vnet->enable_edma = true;
	}

	err = epf_vnet_setup_ep_func(vnet, epf);
	if (err)
		goto err_cleanup_edma;

	err = epf_vnet_setup_vdev(vnet, epf->epc->dev.parent);
	if (err)
		goto err_cleanup_ep_func;

err_cleanup_ep_func:
	epf_vnet_cleanup_ep_func(vnet);

err_cleanup_edma:
	epf_vnet_cleanup_edma(vnet);

	return err;
}

static void epf_vnet_unbind(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	epf_vnet_cleanup_common(vnet);
	epf_vnet_cleanup_ep_func(vnet);
	epf_vnet_cleanup_vdev(vnet);
}

static struct pci_epf_ops epf_vnet_ops = {
	.bind = epf_vnet_bind,
	.unbind = epf_vnet_unbind,
};

static const struct pci_epf_device_id epf_vnet_ids[] = {
	{ .name = "pci_epf_vnet" },
	{}
};

static int epf_vnet_probe(struct pci_epf *epf, const struct pci_epf_device_id *id)
{
	struct epf_vnet *vnet;

	vnet = devm_kzalloc(&epf->dev, sizeof(*vnet), GFP_KERNEL);
	if (!vnet)
		return -ENOMEM;

	epf_set_drvdata(epf, vnet);

	return 0;
}

static struct pci_epf_driver epf_vnet_drv = {
	.driver.name = "pci_epf_vnet",
	.ops = &epf_vnet_ops,
	.id_table = epf_vnet_ids,
	.probe = epf_vnet_probe,
	.owner = THIS_MODULE,
};

static int __init epf_vnet_init(void)
{
	int err;

	err = pci_epf_register_driver(&epf_vnet_drv);
	if (err) {
		pr_err("Failed to register epf vnet driver\n");
		return err;
	}

	return 0;
}
module_init(epf_vnet_init);

static void epf_vnet_exit(void)
{
	pci_epf_unregister_driver(&epf_vnet_drv);
}
module_exit(epf_vnet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shunsuke Mie <mie@igel.co.jp>");
MODULE_DESCRIPTION("PCI endpoint function acts as virtio net device");
