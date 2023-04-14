// SPDX-License-Identifier: GPL-2.0
/*
 * Helpers to implement PCIe virtio EP function.
 */
#include <linux/kthread.h>
#include <linux/virtio_config.h>
#include <linux/virtio_pci.h>
#include <linux/vringh.h>

#include "pci-epf-virtio.h"

static void epf_virtio_unmap_vq(struct pci_epf *epf, void __iomem *vq_virt,
				phys_addr_t vq_phys, unsigned int num)
{
	size_t vq_size = vring_size(num, VIRTIO_PCI_VRING_ALIGN);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, vq_phys,
			   vq_virt, vq_size);
}

static void __iomem *epf_virtio_map_vq(struct pci_epf *epf,
				       phys_addr_t vq_pci_addr,
				       unsigned int num, phys_addr_t *vq_phys)
{
	size_t vq_size;

	vq_size = vring_size(num, VIRTIO_PCI_VRING_ALIGN);

	return pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				   vq_pci_addr, vq_phys, vq_size);
}

static void epf_virtio_free_vringh(struct pci_epf *epf, struct epf_vringh *evrh)
{
	epf_virtio_unmap_vq(epf, evrh->virt, evrh->phys, evrh->num);
	kfree(evrh);
}

static struct epf_vringh *epf_virtio_alloc_vringh(struct pci_epf *epf,
						  u64 features,
						  phys_addr_t pci_addr,
						  unsigned int num)
{
	int err;
	struct vring vring;
	struct epf_vringh *evrh;

	evrh = kmalloc(sizeof(*evrh), GFP_KERNEL);
	if (!evrh) {
		err = -ENOMEM;
		goto err_unmap_vq;
	}

	evrh->num = num;

	evrh->virt = epf_virtio_map_vq(epf, pci_addr, num, &evrh->phys);
	if (IS_ERR(evrh->virt)) {
		err = PTR_ERR(evrh->virt);
		dev_err(&epf->dev, "Failed to map virtqueue to local");
		goto err_unmap_vq;
	}

	vring_init(&vring, num, evrh->virt, VIRTIO_PCI_VRING_ALIGN);

	err = vringh_init_iomem(&evrh->vrh, features, num, false, vring.desc,
				vring.avail, vring.used);
	if (err)
		goto err_free_epf_vq;

	return evrh;

err_free_epf_vq:
	kfree(evrh);

err_unmap_vq:
	epf_virtio_unmap_vq(epf, evrh->virt, evrh->phys, evrh->num);

	return ERR_PTR(err);
}

#define VIRTIO_PCI_LEGACY_CFG_BAR 0

static void __iomem *epf_virtio_alloc_bar(struct pci_epf *epf, size_t size)
{
	struct pci_epf_bar *config_bar = &epf->bar[VIRTIO_PCI_LEGACY_CFG_BAR];
	const struct pci_epc_features *features;
	void __iomem *bar;
	struct device *dev = &epf->dev;
	int err;

	features = pci_epc_get_features(epf->epc, epf->func_no, epf->vfunc_no);
	if (!features) {
		dev_dbg(dev, "Failed to get PCI EPC features\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (features->bar[VIRTIO_PCI_LEGACY_CFG_BAR].type == BAR_RESERVED) {
		dev_dbg(dev, "Cannot use the PCI BAR for legacy virtio pci\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (features->bar[VIRTIO_PCI_LEGACY_CFG_BAR].type == BAR_FIXED) {
		if (size >
		    features->bar[VIRTIO_PCI_LEGACY_CFG_BAR].fixed_size) {
			dev_dbg(dev, "PCI BAR size is not enough\n");
			return ERR_PTR(-ENOMEM);
		}
	}

	bar = pci_epf_alloc_space(epf, size, VIRTIO_PCI_LEGACY_CFG_BAR,
			   features, PRIMARY_INTERFACE);
	if (!bar) {
		dev_dbg(dev, "Failed to allocate virtio-net config memory\n");
		return ERR_PTR(-ENOMEM);
	}

	config_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;
	err = pci_epc_set_bar(epf->epc, epf->func_no, epf->vfunc_no,
			      config_bar);
	if (err) {
		dev_dbg(dev, "Failed to set PCI BAR");
		goto err_free_space;
	}

	return bar;

err_free_space:

	pci_epf_free_space(epf, bar, VIRTIO_PCI_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);

	return ERR_PTR(err);
}

static void epf_virtio_free_bar(struct pci_epf *epf, void __iomem *bar)
{
	struct pci_epf_bar *config_bar = &epf->bar[VIRTIO_PCI_LEGACY_CFG_BAR];

	pci_epc_clear_bar(epf->epc, epf->func_no, epf->vfunc_no, config_bar);
	pci_epf_free_space(epf, bar, VIRTIO_PCI_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);
}

static void epf_virtio_init_bar(struct epf_virtio *evio, void __iomem *bar)
{
	evio->bar = bar;

	epf_virtio_cfg_write32(evio, VIRTIO_PCI_HOST_FEATURES, evio->features);
	epf_virtio_cfg_write16(evio, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_QUEUE);
	epf_virtio_cfg_write16(evio, VIRTIO_PCI_QUEUE_NUM, evio->vqlen);
	epf_virtio_cfg_write16(evio, VIRTIO_PCI_QUEUE_NOTIFY, evio->nvq);
	epf_virtio_cfg_write8(evio, VIRTIO_PCI_STATUS, 0);
}

/**
 * epf_virtio_init - initialize struct epf_virtio and setup BAR for virtio
 * @evio: struct epf_virtio to initialize.
 * @hdr: PCI configuration space to show remote host.
 * @bar_size: PCI BAR size it depends on the virtio device type.
 *
 * Returns zero or a negative error.
 */
int epf_virtio_init(struct epf_virtio *evio, struct pci_epf_header *hdr,
		    size_t bar_size)
{
	struct pci_epf *epf = evio->epf;
	void __iomem *bar;
	int err;

	err = pci_epc_write_header(epf->epc, epf->func_no, epf->vfunc_no, hdr);
	if (err)
		return err;

	bar = epf_virtio_alloc_bar(epf, bar_size);
	if (IS_ERR(bar))
		return PTR_ERR(bar);

	epf_virtio_init_bar(evio, bar);

	return 0;
}
EXPORT_SYMBOL_GPL(epf_virtio_init);

/**
 * epf_virtio_final - finalize struct epf_virtio. it frees BAR and memories
 * @evio: struct epf_virtio to finalize.
 */
void epf_virtio_final(struct epf_virtio *evio)
{
	epf_virtio_free_bar(evio->epf, evio->bar);

	for (int i = 0; i < evio->nvq; i++)
		epf_virtio_free_vringh(evio->epf, evio->vrhs[i]);

	kfree(evio->vrhs);
}
EXPORT_SYMBOL_GPL(epf_virtio_final);

static int epf_virtio_negotiate_vq(struct epf_virtio *evio)
{
	u32 pfn;
	u16 sel;
	int i = 0;
	struct _pair {
		u32 pfn;
		u16 sel;
	} *tmp;
	int err = 0;
	size_t nvq = evio->nvq;

	tmp = kmalloc_array(nvq, sizeof(tmp[0]), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	/*
	 * PCIe EP framework has no capability to hook access PCI BAR space from
	 * remote host driver, so poll the specific register, queue pfn to detect
	 * the writing from the driver.
	 *
	 * This implementation assumes that the address of each virtqueue is
	 * written only once.
	 */
	for (i = 0; i < nvq; i++) {
		while (!(pfn = epf_virtio_cfg_read32(evio,
						     VIRTIO_PCI_QUEUE_PFN)) &&
		       evio->running)
			;

		sel = epf_virtio_cfg_read16(evio, VIRTIO_PCI_QUEUE_SEL);

		epf_virtio_cfg_write32(evio, VIRTIO_PCI_QUEUE_PFN, 0);

		tmp[i].pfn = pfn;
		tmp[i].sel = sel;
	}

	if (!evio->running)
		goto err_out;

	evio->vrhs = kmalloc_array(nvq, sizeof(evio->vrhs[0]), GFP_KERNEL);
	if (!evio->vrhs) {
		err = -ENOMEM;
		goto err_out;
	}

	for (i = 0; i < nvq; i++) {
		phys_addr_t pci = tmp[i].pfn << VIRTIO_PCI_QUEUE_ADDR_SHIFT;

		evio->vrhs[i] = epf_virtio_alloc_vringh(
			evio->epf, evio->features, pci, evio->vqlen);
		if (IS_ERR(evio->vrhs[i])) {
			err = PTR_ERR(evio->vrhs[i]);
			goto err_free_evrhs;
		}
	}

	kfree(tmp);

	return 0;

err_free_evrhs:
	for (i -= 1; i > 0; i--)
		epf_virtio_free_vringh(evio->epf, evio->vrhs[i]);

	kfree(evio->vrhs);

err_out:
	kfree(tmp);

	return err;
}

static void epf_virtio_monitor_qnotify(struct epf_virtio *evio)
{
	const u16 qn_default = evio->nvq;
	u16 tmp;

	/*
	 * Since there is no way to synchronize between the host and EP functions,
	 * it is possible to miss multiple notifications.
	 */
	while (evio->running) {
		tmp = epf_virtio_cfg_read16(evio, VIRTIO_PCI_QUEUE_NOTIFY);
		if (tmp == qn_default)
			continue;

		epf_virtio_cfg_write16(evio, VIRTIO_PCI_QUEUE_NOTIFY,
				       qn_default);

		evio->qn_callback(evio->qn_param);
	}
}

static int epf_virtio_bgtask(void *param)
{
	struct epf_virtio *evio = param;
	struct device *dev = &evio->epf->dev;
	int err;

	err = epf_virtio_negotiate_vq(evio);
	if (err < 0) {
		dev_err(dev, "Failed to negotiate configs with driver\n");
		return err;
	}

	while (!(epf_virtio_cfg_read8(evio, VIRTIO_PCI_STATUS) &
		 VIRTIO_CONFIG_S_DRIVER_OK) &&
	       evio->running)
		;

	if (evio->ic_callback && evio->running)
		evio->ic_callback(evio->ic_param);

	epf_virtio_monitor_qnotify(evio);

	return 0;
}

/**
 * epf_virtio_launch_bgtask - spawn a kthread that emulates virtio device
 * operations.
 * @evio: It should be initialized prior with epf_virtio_init().
 *
 * Returns zero or a negative error.
 */
int epf_virtio_launch_bgtask(struct epf_virtio *evio)
{
	evio->bgtask = kthread_create(epf_virtio_bgtask, evio,
				      "pci-epf-virtio/bgtask");
	if (IS_ERR(evio->bgtask))
		return PTR_ERR(evio->bgtask);

	evio->running = true;

	sched_set_fifo(evio->bgtask);
	wake_up_process(evio->bgtask);

	return 0;
}
EXPORT_SYMBOL_GPL(epf_virtio_launch_bgtask);

/**
 * epf_virtio_terminate_bgtask - shutdown a device emulation kthread.
 * @evio: struct epf_virtio it already launched bgtask.
 */
void epf_virtio_terminate_bgtask(struct epf_virtio *evio)
{
	evio->running = false;

	kthread_stop(evio->bgtask);
}
EXPORT_SYMBOL_GPL(epf_virtio_terminate_bgtask);

/**
 * epf_virtio_reset - reset virtio status
 * @evio: struct epf_virtio to reset
 *
 * Returns zero or a negative error.
 */
int epf_virtio_reset(struct epf_virtio *evio)
{
	epf_virtio_terminate_bgtask(evio);
	epf_virtio_init_bar(evio, evio->bar);

	return epf_virtio_launch_bgtask(evio);
}
EXPORT_SYMBOL_GPL(epf_virtio_reset);

int epf_virtio_getdesc(struct epf_virtio *evio, int index,
		       struct vringh_kiov *riov, struct vringh_kiov *wiov,
		       u16 *head)
{
	struct vringh *vrh = &evio->vrhs[index]->vrh;

	return vringh_getdesc_iomem(vrh, riov, wiov, head, GFP_KERNEL);
}

void epf_virtio_abandon(struct epf_virtio *evio, int index, int num)
{
	struct vringh *vrh = &evio->vrhs[index]->vrh;

	vringh_abandon_iomem(vrh, num);
}

void epf_virtio_iov_complete(struct epf_virtio *evio, int index, u16 head,
			     size_t total_len)
{
	struct vringh *vrh = &evio->vrhs[index]->vrh;

	vringh_complete_iomem(vrh, head, total_len);
}

int epf_virtio_memcpy_kiov2kiov(struct epf_virtio *evio,
				struct vringh_kiov *siov,
				struct vringh_kiov *diov,
				enum dma_transfer_direction dir)
{
	struct pci_epf *epf = evio->epf;
	size_t slen, dlen;
	u64 sbase, dbase;
	phys_addr_t phys;
	void *dst, *src;
	struct device *dev = &epf->dev;

	for (; siov->i < siov->used; siov->i++, diov->i++) {
		slen = siov->iov[siov->i].iov_len;
		sbase = (u64)siov->iov[siov->i].iov_base;
		dlen = diov->iov[diov->i].iov_len;
		dbase = (u64)diov->iov[diov->i].iov_base;

		if (dlen < slen) {
			dev_err(dev, "Opponent hasn't enough buffer to transfer\n");
			return -EINVAL;
		}

		if (dir == DMA_MEM_TO_DEV) {
			src = phys_to_virt(sbase);

			dst = pci_epc_map_aligned(epf->epc, epf->func_no,
					       epf->vfunc_no, dbase, &phys,
					       slen);
			if (IS_ERR(dst)) {
				dev_err(dev, "Failed to map pci memory space to local\n");
				return PTR_ERR(dst);
			}
		} else {
			src = pci_epc_map_aligned(epf->epc, epf->func_no,
					       epf->vfunc_no, sbase, &phys,
					       slen);
			if (IS_ERR(src)) {
				dev_err(dev, "Failed to map pci memory space to local\n");
				return PTR_ERR(src);
			}

			dst = phys_to_virt(dbase);
		}

		memcpy_fromio(dst, src, slen);

		if (dir == DMA_MEM_TO_DEV) {
			pci_epc_unmap_aligned(epf->epc, epf->func_no,
					   epf->vfunc_no, phys, dst, slen);
		} else {
			pci_epc_unmap_aligned(epf->epc, epf->func_no,
					   epf->vfunc_no, phys, src, slen);
		}
	}

	return 0;
}

MODULE_LICENSE("GPL");
