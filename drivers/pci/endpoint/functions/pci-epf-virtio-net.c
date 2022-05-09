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
	struct workqueue_struct *tx_wq, *irq_wq;
	struct vringh rx_vrh, tx_vrh;
	struct vringh_kiov txiov, rxiov;
	struct vring_used_elem *tx_used_elems, *rx_used_elems;

	void __iomem *tx_epc_mem, *rx_epc_mem;
	struct work_struct raise_irq_work;
	struct work_struct tx_work;

	struct sk_buff_head txq;
	struct sk_buff_head rxq;
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
	vq_size = vring_size(EPF_VIRTNET_Q_SIZE, VIRTIO_PCI_VRING_ALIGN);

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
static int epf_virtnet_notify_monitor(void *data)
{
	struct epf_virtnet *vnet = data;
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	int err;

	while (true) {

		/* polling q_notify register, but sometimes it missed to read
		 * the register.  */
		while (ioread16(&common_cfg->q_notify) == 2)
			;
		iowrite16(2, &common_cfg->q_notify);

		// check rx packets
		while((err = epf_virtnet_rx_packets(vnet)) > 0)
			;
		if (err < 0) {
			pr_err("failed to receive packet\n");
			return -1;
		}

		// try to tx packet
		if (skb_queue_len_lockless(&vnet->txq))
			queue_work(vnet->tx_wq, &vnet->tx_work);
	}

	return 0;
}

static int epf_virtnet_spawn_notify_monitor(struct epf_virtnet *vnet)
{
	vnet->monitor_notify_task = kthread_create(epf_virtnet_notify_monitor,
						   vnet, "notify monitor");
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

	ret = vringh_init_kern(&vnet->tx_vrh, 0, EPF_VIRTNET_Q_SIZE, false,
			       vring.desc, vring.avail, vring.used);
	if (ret) {
		pr_err("failed to init tx vringh\n");
		return ret;
	}

	kvec = kmalloc_array(EPF_VIRTNET_Q_SIZE, sizeof *kvec, GFP_KERNEL);
	vringh_kiov_init(&vnet->txiov, kvec, EPF_VIRTNET_Q_SIZE);

	vnet->tx_used_elems = kmalloc_array(4, sizeof vnet->tx_used_elems[0], GFP_KERNEL);
	if (!vnet->tx_used_elems) {
		pr_err("failed malloc\n");
		return -ENOMEM;
	}

	/* rx */
	tmp = epf_virtnet_map_host_vq(vnet, rxpfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vring, EPF_VIRTNET_Q_SIZE, tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	ret = vringh_init_kern(&vnet->rx_vrh, 0, EPF_VIRTNET_Q_SIZE, false,
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
						   vnet, "config monitor");
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

static int epf_virtnet_epc_xfer(struct epf_virtnet *vnet, phys_addr_t pci, void *buf,
				size_t size, bool write)
{
	void __iomem *epc_mem;
	phys_addr_t epc_phys;
	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;
	u64 aaddr, pcioff;
	size_t asize;
	int err;

	err = pci_epc_mem_align(epc, pci, size, &aaddr, &asize);
	if (err) {
		pr_err("invalid address\n");
		return -EIO;
	}
	pcioff = pci - aaddr;

	epc_mem = pci_epc_mem_alloc_addr(epc, &epc_phys, asize);
	if (!epc_mem)
		return -ENOMEM;

	err = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no,
			epc_phys, aaddr, asize);
	if (err)
		return err;

	if (write)
		memcpy_toio(epc_mem + pcioff, buf, size);
	else
		memcpy_fromio(buf, epc_mem + pcioff, size);

	pci_epc_unmap_addr(epc, epf->func_no, epf->vfunc_no, epc_phys);

	pci_epc_mem_free_addr(epc, epc_phys, epc_mem, asize);

	return 0;
}

static int epf_virtnet_send_packet(struct epf_virtnet *vnet, void *buf,
				   size_t len)
{
	int err, remain;
	struct virtio_net_hdr_mrg_rxbuf hdr = {
		.hdr.flags = 0,
		.hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE,
		.num_buffers = 0,
	};
	u64 hdr_addr;

	remain = len;
	while (remain) {
		u32 desc_len, data_len, offset, copy_len;
		u64 addr;
		u16 head;

		err = vringh_getdesc_iomem(&vnet->tx_vrh, NULL, &vnet->txiov, &head, GFP_KERNEL);
		if (err < 0 ) {
			pr_err("failed the vringh_getesc_iomem\n");
			return err;
		} else if (!err) {
			pr_debug("buffer full\n");
			return -EAGAIN;
		}

		addr = (u64)vnet->txiov.iov[vnet->txiov.i].iov_base;
		desc_len = vnet->txiov.iov[vnet->txiov.i].iov_len;

		if (hdr.num_buffers == 0)
			hdr_addr = addr;

		offset = hdr.num_buffers == 0 ? sizeof hdr : 0;
		copy_len = desc_len - offset;
		if (copy_len > remain) {
			copy_len = remain;
		}

		err = epf_virtnet_epc_xfer(vnet, addr + offset, buf, copy_len, true);
		if (err)
			return -EIO;

		data_len = copy_len + offset;

		buf += copy_len;
		remain -= copy_len;

		vnet->tx_used_elems[hdr.num_buffers].id = head;
		vnet->tx_used_elems[hdr.num_buffers].len = data_len;

		hdr.num_buffers++;
	}

	err = epf_virtnet_epc_xfer(vnet, hdr_addr, &hdr, sizeof hdr, true);
	if (err)
		return -EIO;

	if(hdr.num_buffers > 4)
		pr_err("not enough buffers\n");

	vringh_complete_multi_iomem(&vnet->tx_vrh, vnet->tx_used_elems, hdr.num_buffers);

	return 0;
}

static void epf_virtnet_tx_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, tx_work);
	struct sk_buff *skb;
	int res = 0;
	bool is_send = false;

	while((skb = skb_dequeue(&vnet->txq))) {

		res = epf_virtnet_send_packet(vnet, skb->data, skb->len);
		if (res == -EAGAIN) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		napi_consume_skb(skb, 0);
		is_send = true;
	}

	if (is_send)
		queue_work(vnet->irq_wq, &vnet->raise_irq_work);
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

static void *local_ndev_receive(struct epf_virtnet *vnet, size_t *total_size)
{
	void *buf, *cur;
	int ret;
	size_t size = 0;
	struct vringh_kiov *riov = &vnet->rxiov;
	u16 head;
	int err;

	buf = vnet->rx_bufs[vnet->rx_bufs_idx];
	vnet->rx_bufs_idx = (vnet->rx_bufs_idx + 1) & EPF_VIRTNET_Q_MASK;

	ret = vringh_getdesc_iomem(&vnet->rx_vrh, riov, NULL, &head,
				   GFP_KERNEL);
	if (ret < 0) {
		pr_err("Failed the vringh_getdesc\n");
		return NULL;
	} else if (!ret) {
		return NULL;
	}

	for (; riov->i < riov->used; riov->i++) {
		u64 addr = (u64)riov->iov[riov->i].iov_base;
		u32 len = riov->iov[riov->i].iov_len;

		cur = buf + size;

		err = epf_virtnet_epc_xfer(vnet, addr, cur, len, false);
		if (err)
			return NULL;

		size += len;
	}

	vringh_complete_iomem(&vnet->rx_vrh, head, size);

	*total_size = size;

	return buf;
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

static void epf_virtnet_refill_rx_bufs(struct epf_virtnet *vnet)
{
	size_t u_idx = vnet->rx_bufs_used_idx;
	size_t idx = vnet->rx_bufs_idx;

	while(u_idx != idx) {
		struct page* p = dev_alloc_pages(1);
		if (!p) {
			pr_err("failed to allocate rx buffer");
			return;
		}

		vnet->rx_bufs[u_idx] = page_address(p);


		u_idx = (u_idx + 1) & EPF_VIRTNET_Q_MASK;
	}

	vnet->rx_bufs_used_idx = u_idx;
}

static int epf_virtnet_rx_packets(struct epf_virtnet *vnet)
{
	void *buf;
	struct local_ndev_adapter *adapter = netdev_priv(vnet->ndev);
	struct net_device *dev = adapter->dev;
	struct sk_buff *skb;

	unsigned int len;
	size_t total_len;

	buf = local_ndev_receive(vnet, &total_len);
	if (!buf) {
		return 0;
	}

	len = SKB_DATA_ALIGN(total_len) +
	      SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	skb = napi_build_skb(buf, len);
	if (!skb) {
		pr_err("failed to build skb");
		return -1;
	}

	skb_reserve(skb, sizeof(struct virtio_net_hdr_mrg_rxbuf));
	skb_put(skb, total_len - sizeof(struct virtio_net_hdr_mrg_rxbuf));

	skb->protocol = eth_type_trans(skb, dev);

	skb_queue_tail(&vnet->rxq, skb);

	napi_schedule(&adapter->napi);

	{
		const size_t rx_bufs_refill_threshold = 16;
		int diff = vnet->rx_bufs_idx - vnet->rx_bufs_used_idx;
		if (diff < 0)
			diff += EPF_VIRTNET_Q_SIZE;

		if (diff > rx_bufs_refill_threshold)
			epf_virtnet_refill_rx_bufs(vnet);
	}

	return 1;
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

	// TODO examine GFP frags GFP_ATOMIC or GFP_KERNEL
	vnet->rx_bufs = kmalloc_array(sizeof (void *), EPF_VIRTNET_Q_SIZE, GFP_ATOMIC);
	if (!vnet->rx_bufs) {
		pr_err("failed to allocate rx buffer");
		return -ENOMEM;
	}

	for(int i=0; i< EPF_VIRTNET_Q_SIZE; ++i) {
		struct page* p = dev_alloc_pages(1);
		if (!p) {
			pr_err("failed to allocate rx buffer");
			return -ENOMEM;
		}
		vnet->rx_bufs[i] = page_address(p);
	}

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

	skb_queue_head_init(&vnet->txq);
	skb_queue_head_init(&vnet->rxq);

	err = register_netdev(ndev);
	if (err) {
		pr_err("registering net device failed");
		return err;
	}

	return 0;
}

static int epf_virtnet_bind(struct pci_epf *epf)
{
	int ret;
	struct pci_epc *epc = epf->epc;
	const struct pci_epc_features *epc_features;

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

	vnet->tx_wq = alloc_workqueue("epf-vnet-tx-wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!vnet->tx_wq) {
		pr_err("failed to create workqueue\n");
		return -ENOMEM;
	}

	vnet->irq_wq = alloc_workqueue("epf-vnet-irq-wq", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
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
