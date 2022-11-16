/*
 * Endpoint function driver to implement pci virtio-net functionality.
 *
 */

#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_net.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/vringh.h>
#include <linux/dmaengine.h>

//TODO care for native endianess
struct virtio_common_config {
	uint32_t dev_feat;
	uint32_t drv_feat;
	uint32_t q_addr;
	uint16_t q_size;
	uint16_t q_select;
	uint16_t q_notify;
	uint8_t dev_status;
	uint8_t isr_status;
} __packed;

struct epf_virtnet {
	struct pci_epf *epf;
	struct net_device *ndev;
	struct {
		struct virtio_common_config common_cfg;
		struct virtio_net_config net_cfg;
	} __packed *pci_config;
	struct task_struct *monitor_config_task;
	struct task_struct *monitor_notify_task;
	void **rx_bufs;
	size_t rx_bufs_idx, rx_bufs_used_idx;
	struct workqueue_struct *tx_wq, *rx_wq, *irq_wq;
	struct vringh rx_vrh, tx_vrh;
	struct vringh_kiov txiov, rxiov;
	struct vring_used_elem *rx_used_elems;

	void __iomem *tx_epc_mem, *rx_epc_mem;
	struct work_struct raise_irq_work;
	struct work_struct tx_work, rx_work;

	struct sk_buff_head txq;
	struct sk_buff_head rxq;

	dma_addr_t dma_hdr_addr;
	struct dma_chan *tx_dma_chan, *rx_dma_chan;
};

struct local_ndev_adapter {
	struct net_device *dev;
	struct epf_virtnet *vnet;
	struct napi_struct napi;
};

static int epf_virtnet_setup_bar(struct pci_epf *epf,
				 const struct pci_epc_features *epc_features)
{
	struct pci_epc *epc = epf->epc;
	const enum pci_barno cfg_bar = BAR_0;
	struct pci_epf_bar *virt_cfg_bar = &epf->bar[cfg_bar];
	struct epf_virtnet *vnet = epf_get_drvdata(epf);
	size_t cfg_bar_size = sizeof(struct virtio_common_config) +
			      sizeof(struct virtio_net_config);
	void *cfg_base;
	int ret;

	if (!!(epc_features->reserved_bar & (1 << cfg_bar)))
		return -EOPNOTSUPP;

	if (epc_features->bar_fixed_size[cfg_bar]) {
		if (cfg_bar_size > epc_features->bar_fixed_size[cfg_bar])
			return -ENOMEM;

		cfg_bar_size = epc_features->bar_fixed_size[cfg_bar];
	}

	virt_cfg_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	cfg_base = pci_epf_alloc_space(epf, cfg_bar_size, cfg_bar,
				       epc_features->align, PRIMARY_INTERFACE);
	if (!cfg_base) {
		pr_err("Failed to allocate PCI BAR memory\n");
		return -ENOMEM;
	}
	vnet->pci_config = cfg_base;

	ret = pci_epc_set_bar(epc, epf->func_no, epf->vfunc_no, virt_cfg_bar);
	if (ret) {
		pr_err("Failed to set PCI BAR\n");
		return ret;
	}

	return 0;
}

#define EPF_VIRTNET_Q_SIZE 0x100
#define EPF_VIRTNET_Q_MASK 0x0ff

static u16 epf_virtnet_get_nvq(struct epf_virtnet *vnet)
{
	return vnet->pci_config->net_cfg.max_virtqueue_pairs * 2;
}

static void epf_virtnet_init_config(struct pci_epf *epf)
{
	struct epf_virtnet *vnet = epf_get_drvdata(epf);
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	struct virtio_net_config *net_cfg = &vnet->pci_config->net_cfg;

	//TODO consider the device feature
	//TODO care about endianness (must be guest(root complex) endianness)
	common_cfg->dev_feat =
		BIT(VIRTIO_NET_F_MAC) | BIT(VIRTIO_NET_F_GUEST_CSUM) |
		BIT(VIRTIO_NET_F_MTU) | BIT(VIRTIO_NET_F_MRG_RXBUF) |
		BIT(VIRTIO_NET_F_STATUS);

	/*
	 * Initialy indicates out of ranged index to detect changing from host.
	 * See the `epf_virtnet_config_monitor()` to get details.
	 */
	common_cfg->q_select = epf_virtnet_get_nvq(vnet);
	common_cfg->q_addr = 0;
	common_cfg->q_size = EPF_VIRTNET_Q_SIZE;
	common_cfg->q_notify = 2;
	common_cfg->isr_status = 1;

	net_cfg->max_virtqueue_pairs = 1;
	net_cfg->status = VIRTIO_NET_S_LINK_UP;
	net_cfg->mtu = PAGE_SIZE - ETH_HLEN;

	eth_random_addr(net_cfg->mac);
}

static void __iomem *epf_virtnet_map_host_vq(struct epf_virtnet *vnet, u32 pfn)
{
	void __iomem *ioaddr;
	phys_addr_t vq_addr;
	phys_addr_t phys_addr;
	int ret;
	size_t vq_size;
	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;

	vq_addr = (phys_addr_t)pfn << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
	/* XXX: by a virtio spec and an impl(vring_size) returns sufficient size,
	 * but we cannot access the avail_index located end of the ring correctly.
	 * probably, the epc map has problem.
	 */
	vq_size = vring_size(EPF_VIRTNET_Q_SIZE, VIRTIO_PCI_VRING_ALIGN)
		+ 100;

	ioaddr = pci_epc_mem_alloc_addr(epc, &phys_addr, vq_size);
	if (!ioaddr) {
		pr_err("Failed to allocate epc memory area\n");
		return NULL;
	}

	ret = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no, phys_addr,
			       vq_addr, vq_size);
	if (ret) {
		pr_err("failed to map virtqueue address\n");
		goto err_alloc;
	}

	return ioaddr;

err_alloc:
	pci_epc_mem_free_addr(epc, phys_addr, ioaddr, vq_size);

	return NULL;
}

static int epf_virtnet_rx_packets(struct epf_virtnet *vnet);
static void epf_virtnet_rx_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, rx_work);
	int err;


	while((err = epf_virtnet_rx_packets(vnet)) > 0)
		;
	if (err < 0)
		pr_err("failed to receive packet\n");
}

static int epf_virtnet_notify_monitor(void *data)
{
	struct epf_virtnet *vnet = data;
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;

	while (true) {

		/* polling q_notify register, but sometimes it missed to read
		 * the register.  */
		while (ioread16(&common_cfg->q_notify) == 2)
			;
		iowrite16(2, &common_cfg->q_notify);

		queue_work(vnet->rx_wq, &vnet->rx_work);
		queue_work(vnet->tx_wq, &vnet->tx_work);
	}

	return 0;
}

static int epf_virtnet_spawn_notify_monitor(struct epf_virtnet *vnet)
{
	vnet->monitor_notify_task = kthread_create(epf_virtnet_notify_monitor,
						   vnet, "epf-vnet/nmonit");
	if (IS_ERR(vnet->monitor_notify_task)) {
		pr_err("failed to create a kernel thread (notify monitor)\n");
		return PTR_ERR(vnet->monitor_notify_task);
	}

	sched_set_fifo(vnet->monitor_notify_task);
	wake_up_process(vnet->monitor_notify_task);

	return 0;
}

static int _epf_virtnet_config_monitor(struct epf_virtnet *vnet, u32 *txpfn,
				       u32 *rxpfn)
{
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	const u16 qsel_default = epf_virtnet_get_nvq(vnet);
	register u32 sel, pfn;
	u32 tx_pfn, rx_pfn;

	tx_pfn = rx_pfn = 0;
	while (true) {
		pfn = ioread32(&common_cfg->q_addr);
		if (pfn == 0)
			continue;

		iowrite32(0, &common_cfg->q_addr);

		sel = ioread16(&common_cfg->q_select);
		if (sel == qsel_default)
			continue;

		switch (sel) {
		case 0:
			tx_pfn = pfn;
			break;
		case 1:
			rx_pfn = pfn;
			break;
		default:
			pr_warn("driver tries to use invalid queue: %d\n", sel);
		}

		if (tx_pfn && rx_pfn)
			break;
	}

	while (!(ioread8(&common_cfg->dev_status) & VIRTIO_CONFIG_S_DRIVER_OK))
		;

	*txpfn = tx_pfn;
	*rxpfn = rx_pfn;

	return 0;
}

static int epf_virtnet_config_monitor(void *data)
{
	struct epf_virtnet *vnet = data;
	u32 txpfn, rxpfn;
	int ret;
	struct vring vring;
	struct kvec *kvec;
	void __iomem *tmp;

	while(_epf_virtnet_config_monitor(vnet, &txpfn, &rxpfn))
		;

	sched_set_normal(vnet->monitor_config_task, 19);

	/*
	 * setup virtqueues
	 */
	tmp = epf_virtnet_map_host_vq(vnet, txpfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vring, EPF_VIRTNET_Q_SIZE, tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	ret = vringh_init_kern(&vnet->tx_vrh, BIT(VIRTIO_RING_F_EVENT_IDX), EPF_VIRTNET_Q_SIZE, false,
			       vring.desc, vring.avail, vring.used);
	if (ret) {
		pr_err("failed to init tx vringh\n");
		return ret;
	}

	kvec = kmalloc_array(EPF_VIRTNET_Q_SIZE, sizeof *kvec, GFP_KERNEL);
	vringh_kiov_init(&vnet->txiov, kvec, EPF_VIRTNET_Q_SIZE);

	/* rx */
	tmp = epf_virtnet_map_host_vq(vnet, rxpfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vring, EPF_VIRTNET_Q_SIZE, tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	ret = vringh_init_kern(&vnet->rx_vrh, BIT(VIRTIO_RING_F_EVENT_IDX), EPF_VIRTNET_Q_SIZE, false,
			       vring.desc, vring.avail, vring.used);
	if (ret) {
		pr_err("failed to init rx virtio ring\n");
		return ret;
	}

	kvec = kmalloc_array(EPF_VIRTNET_Q_SIZE, sizeof kvec[0], GFP_KERNEL);
	if (!kvec) {
		pr_err("failed malloc\n");
		return -ENOMEM;
	}
	vringh_kiov_init(&vnet->rxiov, kvec, EPF_VIRTNET_Q_SIZE);

	vnet->rx_used_elems = kmalloc_array(4, sizeof vnet->rx_used_elems[0], GFP_KERNEL);
	if (!vnet->rx_used_elems) {
		pr_err("failed malloc\n");
		return -ENOMEM;
	}

	vringh_notify_enable_iomem(&vnet->tx_vrh);
	vringh_notify_enable_iomem(&vnet->rx_vrh);

	// TODO spawn kernel thread for monitoring queue_notify
	ret = epf_virtnet_spawn_notify_monitor(vnet);
	if (ret) {
		// stop tasks
		return ret;
	}

	// this call should be after an rc configuration
	netif_carrier_on(vnet->ndev);

	return 0;
}

static int epf_virtnet_spawn_config_monitor(struct pci_epf *epf)
{
	struct epf_virtnet *vnet = epf_get_drvdata(epf);

	vnet->monitor_config_task = kthread_create(epf_virtnet_config_monitor,
						   vnet, "epf-vnet/cmonit");
	if (IS_ERR(vnet->monitor_config_task)) {
		pr_err("Run pci configuration monitor failed\n");
		return PTR_ERR(vnet->monitor_config_task);
	}

	sched_set_fifo(vnet->monitor_config_task);
	wake_up_process(vnet->monitor_config_task);

	return 0;
}

static int local_ndev_open(struct net_device *dev)
{
	struct local_ndev_adapter *adapter = netdev_priv(dev);
	pr_debug("net_device_ops: open\n");

	napi_enable(&adapter->napi);
	// 	XXX:
	netif_start_queue(dev);

	return 0;
}

static int local_ndev_close(struct net_device *dev)
{
	return 0;
}

static int epf_virtnet_dma_single(struct epf_virtnet *vnet, phys_addr_t pci,
				  dma_addr_t dma, size_t len,
				  void (*callback)(void *param), void *param,
				  enum dma_transfer_direction dir)
{
	struct dma_async_tx_descriptor *desc;
	int err;
	dma_cookie_t cookie;
	unsigned long flags = DMA_PREP_FENCE;
	struct dma_chan *chan = vnet->tx_dma_chan;
	struct dma_slave_config sconf = {.dst_addr = pci};

	err = dmaengine_slave_config(chan, &sconf);
	if (err)
		goto failed;

	if (callback)
		flags |= DMA_PREP_INTERRUPT;

	desc = dmaengine_prep_slave_single(chan, dma, len, dir, flags);
	if (!desc) {
		err = -EIO;
		goto failed;
	}

	desc->callback = callback;
	desc->callback_param = param;

	cookie = dmaengine_submit(desc);

	err = dma_submit_error(cookie);
	if (err)
		goto failed;

	dma_async_issue_pending(chan);

	return 0;

failed:
	return err;
}

struct epf_virtnet_tx_cb_param {
	struct epf_virtnet *vnet;
	dma_addr_t dma_data, dma_hdr;
	struct vring_used_elem *used_elems;
	unsigned num_elems;
	size_t dma_data_size;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
};

struct epf_virtnet_skb_cb {
	struct epf_virtnet_tx_cb_param *param;
};

static void epf_virtnet_tx_cb(void *p)
{
	struct sk_buff *skb = container_of(p, struct sk_buff, cb);
	struct epf_virtnet_skb_cb *cb = p;
	struct epf_virtnet_tx_cb_param *param = cb->param;
	struct epf_virtnet *vnet = param->vnet;
	struct device *dma_dev = vnet->epf->epc->dev.parent;

	vringh_complete_multi_iomem(&vnet->tx_vrh, param->used_elems,
				    param->num_elems);

	vringh_notify_enable_iomem(&vnet->tx_vrh);

	napi_consume_skb(skb, 0);

	if (vringh_need_notify_iomem(&vnet->tx_vrh) && !work_busy(&vnet->raise_irq_work))
		queue_work(vnet->irq_wq, &vnet->raise_irq_work);

	dma_unmap_single(dma_dev, param->dma_data, param->dma_data_size,
			 DMA_MEM_TO_DEV);
	dma_unmap_single(dma_dev, param->dma_hdr,
			 sizeof(struct virtio_net_hdr_mrg_rxbuf),
			 DMA_MEM_TO_DEV);

	kfree(param->used_elems);
	kfree(param);
}

static int epf_virtnet_send_packet(struct epf_virtnet *vnet,
				   struct sk_buff *skb)
{
	int err, remain;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	u64 head_pci_addr;
	struct device *dma_dev = vnet->epf->epc->dev.parent;
	dma_addr_t dma_local, dma_data, dma_hdr_addr;
	struct vring_used_elem *tx_used_elems;
	struct epf_virtnet_tx_cb_param *param;
	struct epf_virtnet_skb_cb *cb = (struct epf_virtnet_skb_cb *)skb->cb;

	param = kmalloc(sizeof *param, GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	cb->param = param;

	hdr = kzalloc(sizeof *hdr, GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;

	tx_used_elems = kmalloc_array(8, sizeof *tx_used_elems, GFP_KERNEL);
	if (!tx_used_elems)
		return -ENOMEM;

	dma_data = dma_local =
		dma_map_single(dma_dev, skb->data, skb->len, DMA_MEM_TO_DEV);
	if (dma_mapping_error(dma_dev, dma_local))
		return -ENOMEM;

	hdr->num_buffers = 0;
	hdr->hdr.flags = 0;
	hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;

	remain = skb->len;
	while (remain) {
		u32 desc_len, data_len, offset, copy_len;
		u64 addr;
		u16 head;

		err = vringh_getdesc_iomem(&vnet->tx_vrh, NULL, &vnet->txiov,
					   &head, GFP_KERNEL);
		if (err < 0) {
			pr_err("failed the vringh_getesc_iomem\n");
			return err;
		} else if (!err) {
			dma_unmap_page(dma_dev, dma_data, skb->len, DMA_MEM_TO_DEV);
			kfree(hdr);
			kfree(tx_used_elems);
			vringh_abandon_iomem(&vnet->tx_vrh, hdr->num_buffers);
			return -EAGAIN;
		}

		addr = (u64)vnet->txiov.iov[vnet->txiov.i].iov_base;
		desc_len = vnet->txiov.iov[vnet->txiov.i].iov_len;

		if (hdr->num_buffers == 0)
			head_pci_addr = addr;

		offset = hdr->num_buffers == 0 ? sizeof *hdr : 0;
		copy_len = desc_len - offset;
		if (copy_len > remain)
			copy_len = remain;

		err = epf_virtnet_dma_single(vnet, addr + offset, dma_local,
						copy_len, NULL, NULL, DMA_MEM_TO_DEV);
		if (err)
			return err;

		data_len = copy_len + offset;

		dma_local += copy_len;
		remain -= copy_len;

		tx_used_elems[hdr->num_buffers].id = head;
		tx_used_elems[hdr->num_buffers].len = data_len;

		hdr->num_buffers++;
	}

	dma_hdr_addr = dma_map_single(dma_dev, hdr, sizeof *hdr, DMA_MEM_TO_DEV);
	if (dma_mapping_error(dma_dev, dma_hdr_addr))
		return -ENOMEM;

	param->vnet = vnet;
	param->used_elems = tx_used_elems;
	param->num_elems = hdr->num_buffers;
	param->dma_data = dma_data;
	param->dma_data_size = skb->len;
	param->dma_hdr = dma_hdr_addr;

	if (hdr->num_buffers > 8)
		pr_err("not enough used_elems buffer\n");

	skb_tx_timestamp(skb);
	return epf_virtnet_dma_single(vnet, head_pci_addr,
					 dma_hdr_addr, sizeof *hdr,
					 epf_virtnet_tx_cb, cb, DMA_MEM_TO_DEV);
}

static void epf_virtnet_tx_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, tx_work);
	struct sk_buff *skb;
	int res = 0;
	while ((skb = skb_dequeue(&vnet->txq))) {
		res = epf_virtnet_send_packet(vnet, skb);
		if (res == -EAGAIN) {
			skb_queue_head(&vnet->txq, skb);
			netif_stop_queue(vnet->ndev);
			queue_work(vnet->irq_wq, &vnet->raise_irq_work);
			break;
		} else if (res < 0) {
			pr_info("unknown error occured: %d\n", res);
		}
	}

	if (!res && netif_queue_stopped(vnet->ndev))
		netif_wake_queue(vnet->ndev);

}

static netdev_tx_t local_ndev_start_xmit(struct sk_buff *skb,
					 struct net_device *dev)
{
	struct local_ndev_adapter *adapter = netdev_priv(dev);
	struct epf_virtnet *vnet = adapter->vnet;

	skb_queue_tail(&vnet->txq, skb);

	queue_work(vnet->tx_wq, &vnet->tx_work);

	return NETDEV_TX_OK;
}

static const struct net_device_ops epf_virtnet_ndev_ops = {
	.ndo_open = local_ndev_open,
	.ndo_stop = local_ndev_close,
	.ndo_start_xmit = local_ndev_start_xmit,
	// 	.ndo_get_stats64 = virtnet_stats,
};

struct epf_virtnet_rx_cb_param {
	struct epf_virtnet *vnet;
	u16 head;
	u32 total_len;
	struct _bufs {
		struct page* page;
		dma_addr_t dma_addr;
		u32 len;
	} *bufs;
	u16 bufs_len;
};

static void dma_async_rx_callback(void *p)
{
	struct epf_virtnet_rx_cb_param *param = p;
	struct sk_buff *skb = NULL;
	struct epf_virtnet *vnet = param->vnet;
	struct device *dma_dev = vnet->epf->epc->dev.parent;
	struct local_ndev_adapter *adapter = netdev_priv(vnet->ndev);

	vringh_complete_iomem(&vnet->rx_vrh, param->head, param->total_len);
	vringh_notify_enable_iomem(&vnet->rx_vrh);

	if (vringh_need_notify_iomem(&vnet->rx_vrh) && !work_busy(&vnet->raise_irq_work))
		queue_work(vnet->irq_wq, &vnet->raise_irq_work);

	for (int i = 0; i < param->bufs_len; i++) {
		struct _bufs *buf = &param->bufs[i];

		dma_unmap_page(dma_dev, buf->dma_addr, PAGE_SIZE,
			       DMA_DEV_TO_MEM);

		if (!skb) {
			skb = napi_build_skb(
				page_address(buf->page),
				SKB_DATA_ALIGN(buf->len) +
					SKB_DATA_ALIGN(sizeof(
						struct skb_shared_info)));
			if (!skb) {
				pr_err("failed to build skb\n");
				return;
			}
		} else {
			BUG();
			skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
					buf->page, 0, buf->len, PAGE_SIZE);
		}
	}

	skb_put(skb, param->total_len);
	skb_record_rx_queue(skb, 0);
	skb->protocol = eth_type_trans(skb, adapter->dev);

	skb_queue_tail(&vnet->rxq, skb);
	napi_schedule(&adapter->napi);

	kfree(param->bufs);
	kfree(param);
}

static int epf_virtnet_rx_packets(struct epf_virtnet *vnet)
{
	u16 head;
	int err;
	struct page *page;
	struct vringh_kiov *riov = &vnet->rxiov;
	u32 len, total_len = 0;
	u64 addr;
	dma_addr_t dma_addr;
	struct epf_virtnet_rx_cb_param *param;
	struct device *dma_dev = vnet->epf->epc->dev.parent;

	err = vringh_getdesc_iomem(&vnet->rx_vrh, riov, NULL, &head,
				   GFP_KERNEL);
	if (err < 0) {
		pr_err("Failed the vringh_getdesc\n");
		return -EIO;
	} else if (!err) {
		return 0;
	}

	len = riov->iov[riov->i].iov_len;
	/* this code assumes that the first descriptor just has virtio-net header. */
	if (len != sizeof (struct virtio_net_hdr_mrg_rxbuf)) {
		BUG();
	}

	riov->i++;

	param = kmalloc(sizeof(struct epf_virtnet_rx_cb_param *), GFP_KERNEL);
	if (!param) {
		pr_err("failed to allocate memory (param)\n");
		return -ENOMEM;
	}

	param->vnet = vnet;
	param->head = head;

	param->bufs_len = riov->used - riov->i;

	param->bufs = kmalloc_array(sizeof param->bufs[0], param->bufs_len, GFP_KERNEL);
	if (!param->bufs) {
		pr_err("failed to allocate memory");
		return -ENOMEM;
	}

	for (int i = 0; riov->i < riov->used; riov->i++, i++) {
		addr = (u64)riov->iov[riov->i].iov_base;
		len = riov->iov[riov->i].iov_len;
		total_len += len;

		page = alloc_pages(GFP_KERNEL, 1);
		if (!page)
			return -ENOMEM;

		dma_addr = dma_map_page(dma_dev, page, 0, PAGE_SIZE, DMA_DEV_TO_MEM);

		param->bufs[i].page = page;
		param->bufs[i].len = len;
		param->bufs[i].dma_addr = dma_addr;

		{
			struct dma_async_tx_descriptor *tx;
			struct dma_slave_config sconf = {
				.src_addr = addr,
				.direction = DMA_DEV_TO_MEM,
			};
			enum dma_ctrl_flags flags = DMA_CTRL_ACK |
				DMA_PREP_INTERRUPT |	DMA_PREP_FENCE;
			dma_cookie_t cookie;

			if (dmaengine_slave_config(vnet->rx_dma_chan, &sconf)) {
				pr_err("DMA slave config fail\n");
				return -EIO;
			}
			tx = dmaengine_prep_slave_single(vnet->rx_dma_chan,
					dma_addr, len,
					DMA_DEV_TO_MEM, flags);
			if (!tx) {
				pr_err("dmaengine_prep_slave_single err");
				return -EIO;
			}

			if (riov->i == riov->used - 1) {
				tx->callback = dma_async_rx_callback;
				param->total_len = total_len;
			}

			tx->callback_param = param;

			cookie = dmaengine_submit(tx);
			err = dma_submit_error(cookie);
			if (err) {
				pr_err("dma submittion error\n");
				return err;
			}

			dma_async_issue_pending(vnet->rx_dma_chan);
		}
	}

	return 1;
}

static int local_ndev_rx_poll(struct napi_struct *napi, int budget)
{
 	struct local_ndev_adapter *adapter = container_of(napi, struct local_ndev_adapter, napi);
 	struct epf_virtnet *vnet = adapter->vnet;

	struct sk_buff *skb;
	int n_rx = 0;

	while((skb = skb_dequeue(&vnet->rxq))) {
		napi_gro_receive(&adapter->napi, skb);

		n_rx++;
	}

	if (n_rx < budget)
		napi_complete_done(&adapter->napi, n_rx);

	return n_rx;
}

static void epf_virtnet_raise_irq_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, raise_irq_work);

	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;

	pci_epc_raise_irq(epc, epf->func_no, epf->vfunc_no, PCI_EPC_IRQ_LEGACY, 0);
}

static int epf_virtnet_get_link_ksettings(struct net_device *ndev,
		struct ethtool_link_ksettings *cmd)
{
	cmd->base.speed = SPEED_1000;
	cmd->base.duplex = DUPLEX_HALF;
	cmd->base.port = PORT_OTHER;

	return 0;
}

static const struct ethtool_ops epf_virtnet_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_link_ksettings = epf_virtnet_get_link_ksettings,
};

static int epf_virtnet_create_netdev(struct pci_epf *epf)
{
	int err;
	struct net_device *ndev;
	struct local_ndev_adapter *ndev_adapter;
	struct epf_virtnet *vnet = epf_get_drvdata(epf);
	struct virtio_net_config *net_cfg = &vnet->pci_config->net_cfg;

	ndev = alloc_etherdev_mq(0, net_cfg->max_virtqueue_pairs);
	if (!ndev)
		return -ENOMEM;

	ndev_adapter = netdev_priv(ndev);
	ndev_adapter->dev = ndev;
	ndev_adapter->vnet = vnet;
	vnet->ndev = ndev;

	ndev->priv_flags = 0;
	ndev->netdev_ops = &epf_virtnet_ndev_ops;

	ndev->ethtool_ops = &epf_virtnet_ethtool_ops;

	// setup hardware features
	SET_NETDEV_DEV(ndev, &epf->dev);

	ndev->hw_features = 0;
	ndev->features = 0;

	ndev->vlan_features = ndev->features;

	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = PAGE_SIZE - ETH_HLEN;

	eth_hw_addr_random(ndev);

	ndev->mtu = ndev->max_mtu;

	ndev->needed_headroom = sizeof (struct virtio_net_hdr_mrg_rxbuf);

	// pci-epc core uses mutex.
	err = dev_set_threaded(ndev, true);
	if (err) {
		pr_err("network devince threading failed\n");
		return err;
	}

	netif_napi_add(ndev, &ndev_adapter->napi, local_ndev_rx_poll, NAPI_POLL_WEIGHT);

	netif_carrier_off(ndev);

	INIT_WORK(&vnet->raise_irq_work, epf_virtnet_raise_irq_handler);
	INIT_WORK(&vnet->tx_work, epf_virtnet_tx_handler);
	INIT_WORK(&vnet->rx_work, epf_virtnet_rx_handler);

	skb_queue_head_init(&vnet->txq);
	skb_queue_head_init(&vnet->rxq);

	err = register_netdev(ndev);
	if (err) {
		pr_err("registering net device failed");
		return err;
	}

	return 0;
}

struct epf_dma_filter_param {
	struct device *dev;
	u32 dma_mask;
};

static bool epf_virtnet_dma_filter(struct dma_chan *chan, void *param)
{
	struct epf_dma_filter_param *fparam = param;
	struct dma_slave_caps caps;

	memset(&caps, 0, sizeof caps);
	dma_get_slave_caps(chan, &caps);

	return chan->device->dev == fparam->dev &&
	       (fparam->dma_mask & caps.directions);
}

static int epf_virtnet_init_edma(struct epf_virtnet *vnet)
{
	dma_cap_mask_t mask;
	struct epf_dma_filter_param param;
	struct device *dma_dev;

	dma_dev = vnet->epf->epc->dev.parent;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	param.dev = vnet->epf->epc->dev.parent;
	param.dma_mask = BIT(DMA_MEM_TO_DEV);

	vnet->tx_dma_chan = dma_request_channel(mask, epf_virtnet_dma_filter, &param);

	param.dma_mask = BIT(DMA_DEV_TO_MEM);

	vnet->rx_dma_chan = dma_request_channel(mask, epf_virtnet_dma_filter, &param);

	return 0;
}

static int epf_virtnet_init_dma(struct epf_virtnet *vnet)
{
	int err;

	err = epf_virtnet_init_edma(vnet);
	if (!err)
		goto done;

	// 	err = epf_virtnet_init_memcpy_dma(vnet);

done:
	return err;
}

static int epf_virtnet_bind(struct pci_epf *epf)
{
	int ret;
	struct pci_epc *epc = epf->epc;
	const struct pci_epc_features *epc_features;
	struct epf_virtnet *vnet = epf_get_drvdata(epf);

	ret = pci_epc_write_header(epc, epf->func_no, epf->vfunc_no,
				   epf->header);
	if (ret) {
		pr_err("Configuration header write failed\n");
		return ret;
	}

	epc_features = pci_epc_get_features(epc, epf->func_no, epf->vfunc_no);
	if (!epc_features) {
		pr_err("epc_features not implemented\n");
		return -EOPNOTSUPP;
	}

	ret = epf_virtnet_setup_bar(epf, epc_features);
	if (ret) {
		pr_err("PCI bar set failed\n");
		return ret;
	}

	epf_virtnet_init_config(epf);

	ret = epf_virtnet_init_dma(vnet);
	if (ret)
		pr_err("failed to setup dma\n");

	ret = epf_virtnet_create_netdev(epf);
	if (ret) {
		pr_err("Network device creation failed\n");
		return ret;
	}

	ret = epf_virtnet_spawn_config_monitor(epf);
	if (ret) {
		pr_err("PCI config monitor task run failed\n");
		return ret;
	}

	return 0;
}

static void epf_virtnet_unbind(struct pci_epf *epf)
{
}

static struct pci_epf_ops epf_virtnet_ops = {
	.bind = epf_virtnet_bind,
	.unbind = epf_virtnet_unbind,
};

static struct pci_epf_header epf_virtnet_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_NET,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_NET,
	.revid = 0,
 	.baseclass_code = PCI_BASE_CLASS_NETWORK, //TODO consider
// 	.subclass_code = , //TODO add subclasse? like 00 ethernet
	.interrupt_pin = PCI_INTERRUPT_INTA,
};

static int epf_virtnet_probe(struct pci_epf *epf)
{
	struct epf_virtnet *vnet;
	struct device *dev;

	dev = &epf->dev;

	vnet = devm_kzalloc(dev, sizeof(*vnet), GFP_KERNEL);
	if (!vnet)
		return -ENOMEM;

	epf->header = &epf_virtnet_header;
	vnet->epf = epf;
	epf_set_drvdata(epf, vnet);

	vnet->tx_wq = alloc_workqueue("epf-vnet/tx-wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->tx_wq) {
		pr_err("failed to create workqueue\n");
		return -ENOMEM;
	}

	vnet->rx_wq = alloc_workqueue("epf-vnet/rx-wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rx_wq) {
		pr_err("failed to create workqueue\n");
		return -ENOMEM;
	}

	vnet->irq_wq = alloc_workqueue("epf-vnet/irq-wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->irq_wq) {
		return -ENOMEM;
	}

	return 0;
}

static const struct pci_epf_device_id epf_virtnet_ids[] = {
	{
		.name = "pci_epf_virtio_net"
	},
	{},
};

static struct pci_epf_driver virtnet_driver = {
	.driver.name = "pci_epf_virtio_net",
	.ops = &epf_virtnet_ops,
	.id_table = epf_virtnet_ids,
	.probe = epf_virtnet_probe,
	.owner = THIS_MODULE
};

static int __init epf_virtnet_init(void)
{
	int ret;

	ret = pci_epf_register_driver(&virtnet_driver);
	if (ret) {
		pr_err("Failed to register pci epf virtio-net driver: %d\n",
		       ret);
		return ret;
	}

	return 0;
}
module_init(epf_virtnet_init);

static void epf_virtnet_exit(void)
{
	pci_epf_unregister_driver(&virtnet_driver);
}
module_exit(epf_virtnet_exit);

MODULE_LICENSE("GPL");
