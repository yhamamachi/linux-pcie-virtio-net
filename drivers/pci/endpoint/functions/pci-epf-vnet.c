// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 */

#include <linux/module.h>
#include <linux/pci-epc.h>
#include <linux/pci-epf.h>
#include <linux/virtio_config.h>
#include <linux/virtio_net.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>
#include <linux/dmaengine.h>
#include <rdma/ib_verbs.h>
#include <rdma/virtio_rdma_abi.h>

#include "pci-epf-virtio.h"

static int virtio_queue_size = 0x400;
module_param(virtio_queue_size, int, 0444);
MODULE_PARM_DESC(virtio_queue_size, "A length of virtqueue");

#define dbg pr_info("%s:%d\n", __func__, __LINE__);

enum epf_vnet_rdma_mr_type {
	EPF_VNET_RDMA_MR_TYPE_DMA,
	EPF_VNET_RDMA_MR_TYPE_MR,
};

struct epf_vnet_rdma_mr {
	enum epf_vnet_rdma_mr_type type;
	int mrn;
	u64 virt_addr;
	u64 length;
	u32 npages;
	u64 *pages;
};

struct epf_vnet_rdma_pd {
	int pdn;
};

struct epf_vnet_rdma_qp {
	u32 qpn;
	u32 dest_qpn;
	u32 svq, rvq;
	u32 rcq, scq;
	enum ib_qp_state state;
	u8 type;
};

struct epf_vnet_rdma_cq {
	u32 cqn;
	u32 vqn;
	void *buf;
	u64 buf_phys;
};

struct epf_vnet_rdma {
#define EPF_VNET_ROCE_GID_TBL_LEN 512
	union ib_gid gid_tbl[EPF_VNET_ROCE_GID_TBL_LEN];

#define EPF_VNET_RDMA_MAX_PD 32
	struct epf_vnet_rdma_pd *pds[EPF_VNET_RDMA_MAX_PD];
	struct kmem_cache *pd_slab;

#define EPF_VNET_RDMA_MAX_MR 32
	struct epf_vnet_rdma_mr *mrs[EPF_VNET_RDMA_MAX_MR];
	struct kmem_cache *mr_slab;

#define EPF_VNET_RDMA_MAX_QP 3
	struct epf_vnet_rdma_qp *qps[EPF_VNET_RDMA_MAX_QP];
	struct kmem_cache *qp_slab;

#define EPF_VNET_RDMA_MAX_CQ 3
	struct epf_vnet_rdma_cq *cqs[EPF_VNET_RDMA_MAX_QP];
	struct kmem_cache *cq_slab;
};

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

	/* for RDMA */
	struct work_struct roce_rx_work;
	struct work_struct ep_roce_tx_work;

#define EPF_VNET_INIT_COMPLETE_VDEV BIT(0)
#define EPF_VNET_INIT_COMPLETE_EP_FUNC BIT(1)
	u8 initialized;
	bool enable_edma;

	struct epf_vnet_rdma vdev_roce, ep_roce;

	unsigned nah;
	unsigned ep_npd, ep_nah;

#define EPF_VNET_RDMA_MAX_AH 32
	struct virtio_rdma_ack_query_device rdma_attr;
};

enum {
	VNET_VIRTQUEUE_RX,
	VNET_VIRTQUEUE_TX,
	VNET_VIRTQUEUE_CTRL,
	VNET_VIRTQUEUE_RDMA_CQ0,
	VNET_VIRTQUEUE_RDMA_CQ1,
	VNET_VIRTQUEUE_RDMA_CQ2,
	VNET_VIRTQUEUE_RDMA_SQ0, // SGI
	VNET_VIRTQUEUE_RDMA_RQ0,
	VNET_VIRTQUEUE_RDMA_SQ1, // GSI
	VNET_VIRTQUEUE_RDMA_RQ1,
	VNET_VIRTQUEUE_RDMA_SQ2, // for user
	VNET_VIRTQUEUE_RDMA_RQ2,

	VNET_VIRTQUEUE_NUM,
};

#define vqpn2sqpn(vqn) ((vqn - VNET_VIRTQUEUE_RDMA_SQ0) / 2)

static inline struct epf_vnet *vdev_to_vnet(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vnet, vdev);
}

/* TODO This nvq is fixed value so I can use cache */
static u16 epf_vnet_get_nvq(struct epf_vnet *vnet)
{
	u16 nvq;

	nvq = vnet->vnet_cfg.max_virtqueue_pairs * 2;

	if (vnet->features & BIT(VIRTIO_NET_F_CTRL_VQ))
		nvq++;

	if (vnet->features & BIT(VIRTIO_NET_F_ROCE)) {
		nvq += vnet->vnet_cfg.max_rdma_cqs;
		nvq += vnet->vnet_cfg.max_rdma_qps * 2;
	}

	return nvq;
}

static int epf_vnet_rdma_init_pd(struct epf_vnet_rdma_pd *pd)
{
	return 0;
}

static struct epf_vnet_rdma_pd *epf_vnet_alloc_pd(struct epf_vnet_rdma *rdma)
{
	struct epf_vnet_rdma_pd *pd;

	for (int i = 0; i < EPF_VNET_RDMA_MAX_PD; i++) {
		if (rdma->pds[i])
			continue;

		pd = kmem_cache_alloc(rdma->pd_slab, GFP_KERNEL);

		rdma->pds[i] = pd;
		pd->pdn = i;

		return pd;
	}

	return NULL;
}

static int epf_vnet_dealloc_pd(struct epf_vnet_rdma *rdma, int pdi)
{
	if (pdi >= EPF_VNET_RDMA_MAX_PD)
		return -EINVAL;

	if (!rdma->pds[pdi])
		return -EINVAL;

	kmem_cache_free(rdma->pd_slab, rdma->pds[pdi]);
	rdma->pds[pdi] = NULL;

	return 0;
}

static struct epf_vnet_rdma_pd *
epf_vnet_rdma_lookup_pd(struct epf_vnet_rdma *rdma, int index)
{
	return index < EPF_VNET_RDMA_MAX_PD ? rdma->pds[index] : NULL;
}

static struct epf_vnet_rdma_mr *epf_vnet_alloc_mr(struct epf_vnet_rdma *rdma)
{
	struct epf_vnet_rdma_mr *mr;

	for (int i = 0; i < EPF_VNET_RDMA_MAX_MR; i++) {
		if (rdma->mrs[i])
			continue;

		mr = kmem_cache_alloc(rdma->mr_slab, GFP_KERNEL);

		mr->mrn = i;
		rdma->mrs[i] = mr;

		return mr;
	}

	return NULL;
}

static int epf_vnet_dealloc_mr(struct epf_vnet_rdma *rdma, int index)
{
	if (index >= EPF_VNET_RDMA_MAX_MR)
		return -EINVAL;

	if (!rdma->mrs[index])
		return -EINVAL;

	kmem_cache_free(rdma->mr_slab, rdma->mrs[index]);

	rdma->mrs[index] = NULL;

	return 0;
}

static struct epf_vnet_rdma_mr *epf_vnet_lookup_mr(struct epf_vnet_rdma *rdma,
						   int index)
{
	return index < EPF_VNET_RDMA_MAX_MR ? rdma->mrs[index] : NULL;
}

static struct epf_vnet_rdma_qp *epf_vnet_alloc_qp(struct epf_vnet_rdma *rdma)
{
	struct epf_vnet_rdma_qp *qp;

	for (int i = 0; i < EPF_VNET_RDMA_MAX_QP; i++) {
		if (rdma->qps[i])
			continue;

		qp = kmem_cache_alloc(rdma->qp_slab, GFP_KERNEL);

		rdma->qps[i] = qp;
		qp->qpn = i;

		return qp;
	}

	return NULL;
}

static int epf_vnet_dealloc_qp(struct epf_vnet_rdma *rdma, int qpi)
{
	if (qpi >= EPF_VNET_RDMA_MAX_QP)
		return -EINVAL;

	if (!rdma->qps[qpi])
		return -EINVAL;

	kmem_cache_free(rdma->qp_slab, rdma->qps[qpi]);
	rdma->qps[qpi] = NULL;

	return 0;
}

static struct epf_vnet_rdma_qp *epf_vnet_lookup_qp(struct epf_vnet_rdma *rdma,
						   int index)
{
	return index < EPF_VNET_RDMA_MAX_QP ? rdma->qps[index] : NULL;
}

static struct epf_vnet_rdma_cq *epf_vnet_alloc_cq(struct epf_vnet_rdma *rdma)
{
	struct epf_vnet_rdma_cq *cq;

	for (int i = 0; i < EPF_VNET_RDMA_MAX_CQ; i++) {
		if (rdma->cqs[i])
			continue;

		cq = kmem_cache_alloc(rdma->cq_slab, GFP_KERNEL);

		rdma->cqs[i] = cq;
		cq->cqn = i;
		cq->vqn = VNET_VIRTQUEUE_RDMA_CQ0 + i;

		return cq;
	}

	return NULL;
}

static int epf_vnet_dealloc_cq(struct epf_vnet_rdma *rdma, int index)
{
	if (index >= EPF_VNET_RDMA_MAX_CQ)
		return -EINVAL;

	if (!rdma->cqs[index])
		return -EINVAL;

	kmem_cache_free(rdma->cq_slab, rdma->cqs[index]);
	rdma->cqs[index] = NULL;

	return 0;
}

static struct epf_vnet_rdma_cq *epf_vnet_lookup_cq(struct epf_vnet_rdma *rdma,
						   int index)
{
	return index < EPF_VNET_RDMA_MAX_CQ ? rdma->cqs[index] : NULL;
}

static int epf_vnet_load_gid(struct epf_vnet_rdma *rdma, int gid_idx, union ib_gid *dst)
{
	if (gid_idx > EPF_VNET_ROCE_GID_TBL_LEN)
		return -EINVAL;

	{
		pr_info("%s: gid %08llx %08llx\n", __func__, rdma->gid_tbl[gid_idx].global.interface_id
					, rdma->gid_tbl[gid_idx].global.subnet_prefix);
	}
	memcpy(dst, rdma->gid_tbl[gid_idx].raw, sizeof(rdma->gid_tbl[0]));

	return 0;
}

static int epf_vnet_init_rdma(struct device *dev, struct epf_vnet_rdma *rdma,
			      const char *base)
{
	char *pd_name, *mr_name, *qp_name, *cq_name;
	struct epf_vnet_rdma_qp *qp;

	pd_name = devm_kasprintf(dev, GFP_KERNEL, "epf-vnet-rdma-%s-pd", base);
	mr_name = devm_kasprintf(dev, GFP_KERNEL, "epf-vnet-rdma-%s-mr", base);
	qp_name = devm_kasprintf(dev, GFP_KERNEL, "epf-vnet-rdma-%s-qp", base);
	cq_name = devm_kasprintf(dev, GFP_KERNEL, "epf-vnet-rdma-%s-cq", base);

	rdma->pd_slab = kmem_cache_create(
		pd_name, sizeof(struct epf_vnet_rdma_pd), 0, 0, NULL);
	if (IS_ERR(rdma->pd_slab))
		return PTR_ERR(rdma->pd_slab);

	rdma->mr_slab = kmem_cache_create(
		mr_name, sizeof(struct epf_vnet_rdma_mr), 0, 0, NULL);
	if (IS_ERR(rdma->mr_slab))
		return PTR_ERR(rdma->mr_slab);

	rdma->qp_slab = kmem_cache_create(
		qp_name, sizeof(struct epf_vnet_rdma_qp), 0, 0, NULL);
	if (IS_ERR(rdma->qp_slab))
		return PTR_ERR(rdma->qp_slab);

	rdma->cq_slab = kmem_cache_create(
		cq_name, sizeof(struct epf_vnet_rdma_cq), 0, 0, NULL);
	if (IS_ERR(rdma->cq_slab))
		return PTR_ERR(rdma->cq_slab);

	devm_kfree(dev, pd_name);
	devm_kfree(dev, mr_name);
	devm_kfree(dev, qp_name);
	devm_kfree(dev, cq_name);

	// QP for SMI
	qp = epf_vnet_alloc_qp(rdma);
	if (!qp && qp->qpn != 0)
		return -ENOMEM;

	qp->svq = VNET_VIRTQUEUE_RDMA_SQ0;
	qp->rvq = VNET_VIRTQUEUE_RDMA_RQ0;

	// QP for GSI
	qp = epf_vnet_alloc_qp(rdma);
	if (!qp && qp->qpn != 1)
		return -ENOMEM;

	qp->svq = VNET_VIRTQUEUE_RDMA_SQ1;
	qp->rvq = VNET_VIRTQUEUE_RDMA_RQ1;

	return 0;
}

static void epf_vnet_qnotify_callback(void *param)
{
	struct epf_vnet *vnet = param;

	queue_work(vnet->task_wq, &vnet->rx_work);
	queue_work(vnet->task_wq, &vnet->ep_ctrl_work);
	queue_work(vnet->task_wq, &vnet->ep_roce_tx_work);
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

	err = epf_virtio_init(evio, &epf_vnet_pci_header,
			      sizeof(vnet->vnet_cfg));
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

static int epf_vnet_roce_ep_completion(struct epf_vnet *vnet, u32 cqn,
																			 struct virtio_rdma_cq_req *cqe)
{
	struct vringh_kiov *cqiov;
	size_t cqlen;
	u64 cq_pci;
	u16 head;
	phys_addr_t cq_phys;
	void __iomem *cqdst;
	int ret;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	struct epf_vnet_rdma_cq *cq;

	cq = epf_vnet_lookup_cq(&vnet->ep_roce, cqn);
	if (!cq) {
		pr_err("epf_vnet_lookup_cq: ep_roce: %d\n", cqn);
		return -EINVAL;
	}

	cqiov = &vnet->rdev_iovs[cq->vqn];

	ret = epf_virtio_getdesc(evio, cq->vqn, NULL,
							 						cqiov, &head);
	if (ret <= 0) {
		pr_err("%s:%d epf_virtio_getdesc: %d\n",
				 __func__, __LINE__, ret);
		return ret;
	}

	cq_pci = (u64)cqiov->iov[cqiov->i].iov_base;
	cqlen = cqiov->iov[cqiov->i].iov_len;
	if (sizeof(*cqe) > cqlen) {
		pr_err("not enough size: %ld > %ld\n",
				 sizeof(*cqe), cqlen);
		return -EINVAL;
	}

	cqdst = pci_epc_map_aligned(
		epf->epc, epf->func_no, epf->vfunc_no,
		cq_pci, &cq_phys, sizeof(*cqe));
	if (IS_ERR(cqdst)) {
		pr_err("Failed to map cqdst\n");
		return -EINVAL;
	}

	memcpy_toio(cqdst, cqe, sizeof(*cqe));

	pci_epc_unmap_aligned(epf->epc, epf->func_no,
						      		 epf->vfunc_no, cq_phys,
						      		 cqdst, sizeof(*cqe));

	epf_virtio_iov_complete(evio, cq->vqn, head, sizeof(*cqe));

	pr_info("ep %d(%d) completion head %d\n", cq->vqn, cqn, head);
	queue_work(vnet->task_wq, &vnet->raise_irq_work);

	return 0;
}

static int epf_vnet_roce_vdev_completion(struct epf_vnet *vnet, u32 cqn, struct virtio_rdma_cq_req *cqe)
{
	struct vringh *vrh;
	struct vringh_kiov *cqiov;
	u16 head;
	int err;
	struct virtqueue *cvq;
	struct epf_vnet_rdma_cq *cq;
	void *buf;

	cq = epf_vnet_lookup_cq(&vnet->vdev_roce, cqn);
	if (!cq) {
		pr_err("epf_vnet_lookup_cq: vdev_roce: %d\n", cqn);
		return -EINVAL;
	}

	vrh = &vnet->vdev_vrhs[cq->vqn];
	cqiov = &vnet->vdev_iovs[cq->vqn];
	cvq = vnet->vdev_vqs[cq->vqn];

	err = vringh_getdesc_kern(vrh, NULL, cqiov, &head,
													 GFP_KERNEL);
	pr_info("last_avail_idx %d %d\n", vrh->last_avail_idx, head);
	if (err <= 0) {
		pr_err("failed to get desc for send completion from %d: %d\n",
				 cq->vqn, err);
		return -EINVAL;
	}
	pr_info("vdev %d(%d) completion head %d\n", cq->vqn, cqn, head);

	if (cqiov->iov[cqiov->i].iov_len < sizeof(*cqe)) {
		pr_err("not enough size: %ld < %ld\n",
				 cqiov->iov[cqiov->i].iov_len,
				 sizeof(*cqe));
		return -EINVAL;
	}

	buf = memremap((resource_size_t)cqiov->iov[cqiov->i].iov_base, sizeof(*cqe), MEMREMAP_WB);

	if (!buf) {
		pr_err("failed to memremap\n");
		return -ENOMEM;
	}

	memcpy(buf, cqe, sizeof(*cqe));

	memunmap(buf);

	flush_cache_all();

	err = vringh_complete_kern(vrh, head, sizeof(*cqe));
	if (err)
		pr_err("failed to completion kern vrh\n");
	vring_interrupt(0, cvq);

	return 0;
}

static int epf_vnet_ep_handle_roce_query_device(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_device *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(ack);
	}

	memcpy_toio(ack, &vnet->rdma_attr, sizeof(vnet->rdma_attr));

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_roce_query_port(struct epf_vnet *vnet,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_port *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(ack);
	}

	iowrite32(EPF_VNET_ROCE_GID_TBL_LEN, &ack->gid_tbl_len);
	//TODO remove magic number
	iowrite32(0x800000, &ack->max_msg_sz);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);
	return 0;
}

static int epf_vnet_ep_handle_create_cq(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_cq *cmd;
	struct virtio_rdma_ack_create_cq *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t clen, alen;
	int err = 0;
	phys_addr_t cphys, aphys;
	struct epf_vnet_rdma_cq *cq;

	clen = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &cphys, clen);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	alen = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &aphys, alen);
	if (IS_ERR(ack)) {
		err = PTR_ERR(ack);
		pr_err("failed to map for cq\n");
		goto unmap_cmd;
	}

	if (ioread32(&cmd->cqe) > virtio_queue_size) {
		err = -EINVAL;
		pr_err("invalid size for cq: %d > %d\n", ioread32(&cmd->cqe),
		       virtio_queue_size);
		goto unmap_ack;
	}

	cq = epf_vnet_alloc_cq(&vnet->ep_roce);
	if (!cq) {
		err = -ENOSPC;
		pr_err("Failed to allocate CQ\n");
		goto unmap_ack;
	}

	epf_virtio_vringh_reset(evio, cq->vqn);

	iowrite32(cq->cqn, &ack->cqn);

unmap_ack:
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, aphys, ack,
			   alen);
unmap_cmd:
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, cphys, cmd,
			   clen);
	return err;
}

static int epf_vnet_ep_handle_destroy_cq(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_cq *cmd;
	struct pci_epf *epf = vnet->evio.epf;
	phys_addr_t phys;
	size_t len;
	struct epf_vnet_rdma_cq *cq;
	int err = 0;

	len = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &phys, len);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	cq = epf_vnet_lookup_cq(&vnet->ep_roce, ioread32(&cmd->cqn));
	if (!cq) {
		err = -EINVAL;
		goto out;
	}

	epf_virtio_vringh_reset(&vnet->evio, cq->vqn);

	epf_vnet_dealloc_cq(&vnet->ep_roce, ioread32(&cmd->cqn));

out:
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd,
			   len);

	return err;
}

static int epf_vnet_ep_handle_create_pd(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_create_pd *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(ack);
	}

	iowrite32(vnet->ep_npd++, &ack->pdn);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_destroy_pd(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	vnet->ep_npd--;
	return 0;
}

static int epf_vnet_ep_handle_get_dma_mr(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_get_dma_mr *cmd;
	struct virtio_rdma_ack_get_dma_mr *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;
	struct epf_vnet_rdma_mr *mr;

	mr = epf_vnet_alloc_mr(&vnet->ep_roce);
	if (!mr)
		return -EIO;

	mr->type = EPF_VNET_RDMA_MR_TYPE_DMA;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(ack);
	}

	iowrite32(mr->mrn, &ack->mrn);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_reg_user_mr(struct epf_vnet *vnet,
					  struct vringh_kiov *riov,
					  struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_reg_user_mr *cmd;
	struct virtio_rdma_ack_reg_user_mr *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t clen, alen;
	phys_addr_t aphys, cphys;
	struct epf_vnet_rdma_mr *mr;

	clen = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &cphys, clen);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	mr = epf_vnet_alloc_mr(&vnet->ep_roce);
	if (!mr)
		return -EIO;

	mr->type = EPF_VNET_RDMA_MR_TYPE_MR;

	mr->virt_addr = ioread64(&cmd->virt_addr);
	mr->length = ioread64(&cmd->length);
	mr->npages = ioread32(&cmd->npages);
	mr->pages =
		kmalloc_array(cmd->npages, sizeof(mr->pages[0]), GFP_KERNEL);

	memcpy_fromio(mr->pages, cmd->pages, sizeof(mr->pages[0]) * mr->npages);

	alen = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &aphys, alen);
	if (IS_ERR(ack)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(ack);
	}

	//if (cmd->access_flags & VIRTIO_IB_ACCESS_LOCAL_WRITE)
	iowrite32(mr->mrn, &ack->lkey);

	//if (cmd->access_flags & VIRTIO_IB_ACCESS_REMOTE_WRITE ||
	//    cmd->access_flags & VIRTIO_IB_ACCESS_REMOTE_READ)
	iowrite32(mr->mrn, &ack->rkey);

	iowrite32(mr->mrn, &ack->mrn);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, cphys, cmd,
			   clen);
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, aphys, ack,
			   alen);
	return 0;
}

static int epf_vnet_ep_handle_dereg_mr(struct epf_vnet *vnet,
				       struct vringh_kiov *riov,
				       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_dereg_mr *cmd;
	size_t len;
	phys_addr_t phys;
	struct pci_epf *epf = vnet->evio.epf;
	struct epf_vnet_rdma_mr *mr;
	int err = 0;

	len = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &phys, len);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	mr = epf_vnet_lookup_mr(&vnet->ep_roce, ioread32(&cmd->mrn));
	if (!mr) {
		pr_err("mrn %d is not found\n", ioread32(&cmd->mrn));
		err = -EINVAL;
		goto out;
	}

	kfree(mr->pages);

	epf_vnet_dealloc_mr(&vnet->ep_roce, ioread32(&cmd->mrn));

out:
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_create_qp(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_qp __iomem *cmd;
	struct virtio_rdma_ack_create_qp __iomem *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t clen, alen;
	phys_addr_t aphys, cphys;
	struct epf_vnet_rdma_qp *qp;
	u8 qp_type;

	clen = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &cphys, clen);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	qp_type = ioread8(&cmd->qp_type);

	switch (qp_type) {
	case VIRTIO_IB_QPT_SMI:
		qp = epf_vnet_lookup_qp(&vnet->ep_roce, 0);
		if (!qp)
			return -EIO;
		qp->type = qp_type;
		break;
	case VIRTIO_IB_QPT_GSI:
		qp = epf_vnet_lookup_qp(&vnet->ep_roce, 1);
		if (!qp)
			return -EIO;
		qp->type = qp_type;
		break;
	case VIRTIO_IB_QPT_UD:
	case VIRTIO_IB_QPT_RC:
		qp = epf_vnet_alloc_qp(&vnet->ep_roce);
		if (!qp)
			return -EIO;
		qp->type = qp_type;

		//TODO check
		qp->svq = VNET_VIRTQUEUE_RDMA_SQ0 + qp->qpn * 2;
		qp->rvq = VNET_VIRTQUEUE_RDMA_SQ0 + qp->qpn * 2 + 1;
		break;
	default:
		return -ENOTSUPP;
	}

	qp->scq = ioread32(&cmd->send_cqn);
	qp->rcq = ioread32(&cmd->recv_cqn);

	pr_info("ep qpn %d, scq %d, rcq %d\n", qp->qpn, qp->scq, qp->rcq);

	if (qp->rvq >= VNET_VIRTQUEUE_NUM) {
		epf_vnet_dealloc_qp(&vnet->ep_roce, qp->qpn);
		return -EINVAL;
	}

	alen = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &aphys, alen);
	if (IS_ERR(ack)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(ack);
	}

	epf_virtio_vringh_reset(evio, qp->svq);
	epf_virtio_vringh_reset(evio, qp->rvq);

	iowrite32(qp->qpn, ack);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, cphys, cmd,
			   clen);
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, aphys, ack,
			   alen);
	return 0;
}

static int epf_vnet_ep_handle_modify_qp(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_modify_qp cmd;
	void __iomem *cmd_ptr;
	phys_addr_t phys;
	struct epf_vnet_rdma_qp *qp;
	size_t len;
	struct pci_epf *epf = vnet->evio.epf;
	struct virtio_rdma_cq_req cqe;
	int err;

	len = riov->iov[riov->i].iov_len;
	cmd_ptr = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				   (u64)riov->iov[riov->i].iov_base, &phys,
				   len);
	if (IS_ERR(cmd_ptr)) {
		pr_err("ep: failed to map command range for destry qp\n");
		return PTR_ERR(cmd_ptr);
	}

	memcpy_fromio(&cmd, cmd_ptr, sizeof(cmd));

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd_ptr,
			   len);

	qp = epf_vnet_lookup_qp(&vnet->ep_roce, cmd.qpn);
	if (!qp) {
		pr_err("invalid qpn found: %d\n", cmd.qpn);
		return -EINVAL;
	}

	if (cmd.attr_mask & VIRTIO_IB_QP_STATE) {
		qp->state = cmd.qp_state;

		if (cmd.qp_state == VIRTIO_IB_QPS_ERR) {
			pr_info("The qp state moves into QPS_ERR\n");
			memset(&cqe, 0x00, sizeof(cqe));
			cqe.status = VIRTIO_IB_WC_WR_FLUSH_ERR;
			err = epf_vnet_roce_ep_completion(vnet, qp->scq, &cqe);
			if (err) {
				pr_err("failed to send err completion\n");
				return -1;
			}
		}
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_CUR_STATE) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_ACCESS_FLAGS) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_QKEY) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_AV) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_PATH_MTU) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_TIMEOUT) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_RETRY_CNT) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_RNR_RETRY) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_RQ_PSN) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_MAX_QP_RD_ATOMIC) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_MIN_RNR_TIMER) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_SQ_PSN) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_CAP) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_DEST_QPN) {
		qp->dest_qpn = cmd.dest_qp_num;
	}
	if (cmd.attr_mask & VIRTIO_IB_QP_RATE_LIMIT) {
		pr_info("%s:%d not supported yet\n", __func__, __LINE__);
	}

	return 0;
}

static int epf_vnet_ep_handle_query_qp(struct epf_vnet *vnet,
				       struct vringh_kiov *riov,
				       struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_query_qp *cmd;
	// 	struct virtio_rdma_ack_query_qp *ack;
	return 0;
}

static int epf_vnet_ep_handle_destroy_qp(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_qp __iomem *cmd;
	struct pci_epf *epf = vnet->evio.epf;
	size_t len;
	phys_addr_t phys;
	struct epf_vnet_rdma_qp *qp;
	// 	struct epf_virtio *evio = &vnet->evio;
	u32 qpn;

	len = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &phys, len);
	if (IS_ERR(cmd)) {
		pr_err("ep: failed to map command range for destry qp\n");
		return PTR_ERR(cmd);
	}
	qpn = ioread32(&cmd->qpn);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd,
			   len);

	qp = epf_vnet_lookup_qp(&vnet->ep_roce, qpn);
	if (!qp)
		return -EINVAL;

	epf_vnet_dealloc_qp(&vnet->ep_roce, qpn);

	return 0;
}

static int epf_vnet_ep_handle_create_ah(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_ah *cmd;
	struct virtio_rdma_ack_create_ah *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t clen, alen;
	int err = 0;
	phys_addr_t cphys, aphys;

	clen = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &cphys, clen);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	alen = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &aphys, alen);
	if (IS_ERR(ack)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		err = PTR_ERR(ack);
		goto unmap_cmd;
	}

	iowrite32(vnet->ep_nah++, &ack->ah);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, aphys, ack,
			   alen);
unmap_cmd:
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, cphys, cmd,
			   clen);

	return err;
}

static int epf_vnet_ep_handle_destroy_ah(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	vnet->ep_nah--;
	return 0;
}

static int epf_vnet_ep_handle_roce_add_gid(struct epf_vnet *vnet,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_add_gid __iomem *cmd;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;
	u16 index;

	len = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &phys, len);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	index = ioread16(&cmd->index);

	memcpy_fromio(&vnet->ep_roce.gid_tbl[index], cmd->gid,
		      sizeof(cmd->gid));

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_roce_del_gid(struct epf_vnet *vnet,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_del_gid *cmd;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;
	u16 index;

	len = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &phys, len);
	if (IS_ERR(cmd)) {
		pr_err("%s:%d\n", __func__, __LINE__);
		return PTR_ERR(cmd);
	}

	index = ioread16(&cmd->index);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_roce_req_notify_cq(struct epf_vnet *vnet,
						 struct vringh_kiov *riov,
						 struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_req_notify *cmd;

	return 0;
}

static int (*virtio_rdma_ep_cmd_handler[])(struct epf_vnet *vnet,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov) = {
	[VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE] =
		epf_vnet_ep_handle_roce_query_device,
	[VIRTIO_NET_CTRL_ROCE_QUERY_PORT] = epf_vnet_ep_handle_roce_query_port,
	[VIRTIO_NET_CTRL_ROCE_CREATE_CQ] = epf_vnet_ep_handle_create_cq,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_CQ] = epf_vnet_ep_handle_destroy_cq,
	[VIRTIO_NET_CTRL_ROCE_CREATE_PD] = epf_vnet_ep_handle_create_pd,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_PD] = epf_vnet_ep_handle_destroy_pd,
	[VIRTIO_NET_CTRL_ROCE_GET_DMA_MR] = epf_vnet_ep_handle_get_dma_mr,
	[VIRTIO_NET_CTRL_ROCE_REG_USER_MR] = epf_vnet_ep_handle_reg_user_mr,
	[VIRTIO_NET_CTRL_ROCE_DEREG_MR] = epf_vnet_ep_handle_dereg_mr,
	[VIRTIO_NET_CTRL_ROCE_CREATE_QP] = epf_vnet_ep_handle_create_qp,
	[VIRTIO_NET_CTRL_ROCE_MODIFY_QP] = epf_vnet_ep_handle_modify_qp,
	[VIRTIO_NET_CTRL_ROCE_QUERY_QP] = epf_vnet_ep_handle_query_qp,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_QP] = epf_vnet_ep_handle_destroy_qp,
	[VIRTIO_NET_CTRL_ROCE_CREATE_AH] = epf_vnet_ep_handle_create_ah,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_AH] = epf_vnet_ep_handle_destroy_ah,
	[VIRTIO_NET_CTRL_ROCE_ADD_GID] = epf_vnet_ep_handle_roce_add_gid,
	[VIRTIO_NET_CTRL_ROCE_DEL_GID] = epf_vnet_ep_handle_roce_del_gid,
	[VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ] =
		epf_vnet_ep_handle_roce_req_notify_cq,
};

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
	virtio_net_ctrl_ack __iomem *ack;

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
		pr_info("pci_epc_map failed for cmd range\n");
		err = PTR_ERR(rvirt);
		goto err_out;
	}

	wlen = wiov.iov[wiov.i].iov_len;
	wvirt = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)wiov.iov[wiov.i].iov_base, &wphys, wlen);
	if (IS_ERR(wvirt)) {
		pr_info("pci_epc_map failed for ack range\n");
		err = PTR_ERR(wvirt);
		goto err_unmap_command;
	}
	ack = wvirt;

	riov.i++;
	wiov.i++;

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

		iowrite8(VIRTIO_NET_OK, ack);
		break;
	case VIRTIO_NET_CTRL_ROCE:
		if (ARRAY_SIZE(virtio_rdma_ep_cmd_handler) < hdr->cmd) {
			err = -EIO;
			pr_debug("found invalid command\n");
			break;
		}
		// TODO this is for debug, finally should be deleted.
		if (!virtio_rdma_ep_cmd_handler[hdr->cmd]) {
			pr_info("A handler for cmd %d is not yet implemented\n",
				hdr->cmd);
			err = -ENOTSUPP;
			iowrite8(VIRTIO_NET_ERR, ack);
			break;
		}

		err = virtio_rdma_ep_cmd_handler[hdr->cmd](vnet, &riov, &wiov);
		iowrite8(err ? VIRTIO_NET_ERR : VIRTIO_NET_OK, ack);
		break;
	default:
		pr_err("Found unsupported class in control queue: %d\n", class);
		break;
	}

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, wphys, wvirt,
			   wlen);

	vringh_complete_iomem(vrh, head, total_len);

	vringh_kiov_cleanup(&riov);
	vringh_kiov_cleanup(&wiov);

	return;

err_unmap_command:
	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
err_out:
	return;
}

#if 1

static int epf_vnet_roce_handle_ep_rdma_write(struct epf_vnet *vnet, u32 vqn,
																							struct virtio_rdma_sq_req *sreq)
{
	struct epf_vnet_rdma_mr *dst_mr;
	void *dst;
	struct pci_epf *epf = vnet->evio.epf;
	struct virtio_rdma_cq_req cqe;
	struct epf_vnet_rdma_qp *qp;
	u32 qpn;
	size_t total_len = 0;
	int err;

	dst_mr = epf_vnet_lookup_mr(&vnet->vdev_roce, sreq->rdma.rkey);
	if (!dst_mr)
		return -EINVAL;

	// TODO: PAGE_SIZE is not good. sge has a size for rdma write, so it should be used.
	switch(dst_mr->type) {
		case EPF_VNET_RDMA_MR_TYPE_DMA:
			dst = memremap(sreq->rdma.remote_addr, PAGE_SIZE, MEMREMAP_WB);
			break;
		case EPF_VNET_RDMA_MR_TYPE_MR:
			dst = memremap(dst_mr->pages[0], PAGE_SIZE, MEMREMAP_WB);
			if (!dst) {
				pr_err("failed to remap dst\n");
				return -ENOMEM;
			}
			break;
		default:
			pr_err("found invalid mr type: %d\n", dst_mr->type);
			return -EINVAL;
	}

	for(int i = 0; i < sreq->num_sge; i++) {
		struct epf_vnet_rdma_mr *src_mr;
		void __iomem *src;
		struct virtio_rdma_sge *src_sge = &sreq->sg_list[i];
		phys_addr_t src_phys;

		src_mr = epf_vnet_lookup_mr(&vnet->ep_roce, src_sge->lkey);
		if (!src_mr) {
			pr_err("failed to lookup mr\n");
			return -EINVAL;
		}

		switch(src_mr->type) {
			case EPF_VNET_RDMA_MR_TYPE_DMA:
				src = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       									src_sge->addr, &src_phys, src_sge->length);
				if (!src) {
					pr_err("failed to map src\n");
					return -EINVAL;
				}
				break;
			case EPF_VNET_RDMA_MR_TYPE_MR:
			{
				size_t off = src_sge->addr & (PAGE_SIZE - 1);
				src = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       									src_mr->pages[0] + off, &src_phys, src_sge->length);
				if (!src) {
					pr_err("failed to map src\n");
					return -EINVAL;
				}
				break;
			}
			default:
				pr_err("found invalid mr type: %d\n", src_mr->type);
				return -EINVAL;
		}

		memcpy_fromio(dst + total_len, src, src_sge->length);

		pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, src_phys, src, src_sge->length);
		total_len = src_sge->length;
	}

	memunmap(dst);

	memset(&cqe, 0x0, sizeof(cqe));

	qpn = (vqn - VNET_VIRTQUEUE_RDMA_SQ0) / 2;
	qp = epf_vnet_lookup_qp(&vnet->vdev_roce, qpn);
	if (!qp)
		return -EINVAL;

	cqe.wr_id = sreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = qpn;
	cqe.opcode = VIRTIO_IB_WC_RDMA_WRITE;
	cqe.byte_len = total_len;

	err = epf_vnet_roce_ep_completion(vnet, qp->scq, &cqe);
	if (err < 0) {
		pr_err("failed to completion for ep\n");
		return err;
	}
	pr_info("A rdma write from ep was completed\n");

	return 0;
}

#else
static int epf_vnet_roce_handle_ep_rdma_write(struct epf_vnet *vnet, u32 vqn,
				struct virtio_rdma_sq_req *sreq,
				u64 sreq_pci)
{
	struct epf_vnet_rdma_qp *qp;
	struct epf_vnet_rdma_mr *src_mr, *dst_mr;
	void *dst;
	void __iomem *src;
	void __iomem *sge_tmp;
	struct virtio_rdma_sge sge;
	int err;
	phys_addr_t src_phys, sge_phys;
	struct pci_epf *epf = vnet->evio.epf;
	u32 qpn;

	qpn = (vqn - VNET_VIRTQUEUE_RDMA_SQ0) / 2;
	qp = epf_vnet_lookup_qp(&vnet->vdev_roce, qpn);
	if (!qp)
		return -EINVAL;

	dst_mr = epf_vnet_lookup_mr(&vnet->vdev_roce, sreq->rdma.rkey);
	if (!dst_mr)
		return -EINVAL;

	if (dst_mr->type != EPF_VNET_RDMA_MR_TYPE_MR)
		return -EINVAL;

	if (dst_mr->npages < 1)
		return -EINVAL;

	dst = phys_to_virt(dst_mr->pages[0]);

	if (sreq->num_sge != 1) {
		pr_err("Currently supports num_sge is equal to 1");
		return -EINVAL;
	}

	sge_tmp = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			sreq_pci + offsetof(struct virtio_rdma_sq_req, sg_list) , &sge_phys,
				   sizeof(sreq->sg_list[0]) * sreq->num_sge);

	memcpy_fromio(&sge, sge_tmp, sizeof(sge));

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, sge_phys,
			   sge_tmp, sizeof(sge) * sreq->num_sge);

	src_mr = epf_vnet_lookup_mr(&vnet->ep_roce, sge.lkey);
	if (!src_mr)
		return -EINVAL;

	src = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       dst_mr->pages[0], &src_phys, sge.length);
	if (!src)
		return -EINVAL;

	memcpy_fromio(dst, src, sge.length);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, src_phys, src,
			   sge.length);

	// completion
	{
		struct epf_vnet_rdma_cq *cq;
		struct vringh_kiov *iov;
		u16 head;
		struct epf_virtio *evio = &vnet->evio;
		struct virtio_rdma_cq_req __iomem *cqe;
		struct virtio_rdma_cq_req cqe_tmp;
		u64 cqe_pci;
		phys_addr_t cqe_phys;

		cq = epf_vnet_lookup_cq(&vnet->ep_roce, qp->scq);
		if (!cq) {
			pr_err("failed to lookup cq\n");
			err = -EINVAL;
			return err;
		}

		iov = &vnet->rdev_iovs[cq->vqn];

		err = epf_virtio_getdesc(evio, cq->vqn, NULL, iov, &head);
		if (err <= 0) {
			pr_err("%s:%d epf_virtio_getdesc: %d\n", __func__,
			       __LINE__, err);
			return err;
		}

		if (iov->iov[iov->i].iov_len < sizeof(*cqe)) {
			pr_err("not enough buffer size\n");
			return err;
		}

		cqe_pci = (u64)iov->iov[iov->i].iov_base;

		cqe = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				       cqe_pci, &cqe_phys, sizeof(*cqe));
		if (IS_ERR(cqe)) {
			pr_err("failed to map addr for cqe\n");
			err = PTR_ERR(cqe);
			return err;
		}

		cqe_tmp.wr_id = ioread64(&sreq->wr_id);
		cqe_tmp.status = VIRTIO_IB_WC_SUCCESS;
		cqe_tmp.opcode = sreq->opcode;
		cqe_tmp.byte_len = sge.length;
		cqe_tmp.qp_num = qp->qpn;

		memcpy_toio(cqe, &cqe_tmp, sizeof(cqe_tmp));

		epf_virtio_iov_complete(evio, cq->vqn, head, sizeof(*cqe));

		pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				   cqe_phys, cqe, sizeof(*cqe));
		queue_work(vnet->task_wq, &vnet->raise_irq_work);
	}

	return 0;
}
#endif

static int epf_vnet_roce_handle_ep_rdma_read(struct epf_vnet *vnet, u32 vqn,
				struct virtio_rdma_sq_req *sreq)
{
	struct epf_vnet_rdma_mr *src_mr;
	struct pci_epf *epf = vnet->evio.epf;
	struct virtio_rdma_cq_req cqe;
	//struct epf_vnet_rdma_cq *cq;
	struct epf_vnet_rdma_qp *qp;
	void *src;
	size_t total_len = 0;
	u32 qpn;
	int err;

	// if (sreq->send_flags & VIRTIO_IB_SEND_SIGNALED)
	// if (sreq->send_flags & VIRTIO_IB_SEND_FENCE)
	// if (sreq->send_flags & VIRTIO_IB_SEND_SOLICITED)
	// if (sreq->send_flags & VIRTIO_IB_SEND_INLINE)
	pr_info("sreq %px\n", sreq);

	src_mr = epf_vnet_lookup_mr(&vnet->vdev_roce, sreq->rdma.rkey);
	if (!src_mr) {
		pr_err("failed to look up mr for rdma src\n");
		return -EINVAL;
	}

	switch(src_mr->type) {
		case EPF_VNET_RDMA_MR_TYPE_DMA:
			pr_info("remote addr 0x%llx\n", sreq->rdma.remote_addr);
			src = memremap(sreq->rdma.remote_addr, PAGE_SIZE, MEMREMAP_WB);
			if (!src) {
				pr_err("failed to remap memory\n");
				return -EINVAL;
			}
			break;
		case EPF_VNET_RDMA_MR_TYPE_MR:
			src = memremap(src_mr->pages[0], PAGE_SIZE, MEMREMAP_WB);
			if (!src) {
				pr_err("failed to remap src memory\n");
				return -EINVAL;
			}
			break;
		default:
			pr_err("invalid mr type %d\n", src_mr->type);
			return -EINVAL;
	}
	

	for(int i = 0; i < sreq->num_sge; i++) {
		struct virtio_rdma_sge *dst_sge = &sreq->sg_list[i];
		struct epf_vnet_rdma_mr *dst_mr;
		size_t offset = dst_sge->addr & (PAGE_SIZE - 1);
		void __iomem *dst;
		phys_addr_t dst_phys;

		dst_mr = epf_vnet_lookup_mr(&vnet->ep_roce, dst_sge->lkey);
		if (!dst_mr) {
			pr_err("Failed to lookup mr\n");
			break;
		}

		switch(dst_mr->type) {
			case EPF_VNET_RDMA_MR_TYPE_DMA:
				pr_err("%s:%d not yet supported\n", __func__, __LINE__);
				return -ENOTSUPP;
			case EPF_VNET_RDMA_MR_TYPE_MR:
				dst = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
					dst_mr->pages[0] + offset, &dst_phys, dst_sge->length);
				break;
			default:
				pr_err("%s:%d invalid mr type found\n", __func__, __LINE__);
				return -ENOTSUPP;
		}

		memcpy_toio(dst, src, dst_sge->length);

		pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, dst_phys, dst, dst_sge->length);

		src += dst_sge->length;
		total_len += dst_sge->length;
	}

	memset(&cqe, 0x0, sizeof(cqe));

	qpn = (vqn - VNET_VIRTQUEUE_RDMA_SQ0) / 2;
	qp = epf_vnet_lookup_qp(&vnet->vdev_roce, qpn);
	if (!qp)
		return -EINVAL;

	cqe.wr_id = sreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = qpn;
	cqe.opcode = VIRTIO_IB_WC_RDMA_READ;
	cqe.byte_len = total_len;
	// cqe.wc_flags = VIRTIO_IB_WC_GRH;

	err = epf_vnet_roce_ep_completion(vnet, qp->rcq, &cqe);
	if (err < 0) {
		pr_err("failed to completion for ep\n");
		goto err_out;
	}

	return 0;

err_out:
	return err;
}

static int epf_vnet_roce_get_dest_qpn(struct epf_vnet_rdma_qp *qp, struct virtio_rdma_sq_req *req)
{
	switch (qp->type) {
		case VIRTIO_IB_QPT_GSI:
		case VIRTIO_IB_QPT_UD:
			return req->ud.remote_qpn;
		case VIRTIO_IB_QPT_RC:
			return qp->dest_qpn;
		case VIRTIO_IB_QPT_SMI:
		case VIRTIO_IB_QPT_UC:
			pr_info("The qp type (%d) is not yet supported\n",
					 qp->type);
			return -EINVAL;
		default:
			pr_info("invalid qp type found\n");
			return -EINVAL;
	}
}

static int epf_vnet_roce_handle_ep_send_wr(struct epf_vnet *vnet, u32 vqn,
				struct virtio_rdma_sq_req *sreq)
{
	u32 sqpn, dqpn;
	struct epf_vnet_rdma_qp *sqp, *dqp;
	struct vringh *dst_vrh;
	struct vringh_kiov *iov;
	u16 head;
	int err;
	struct virtio_rdma_rq_req *rreq;
	struct virtio_rdma_sge *dst_sge;
	struct epf_vnet_rdma_mr *dst_mr;
	void *dst;
	struct pci_epf *epf = vnet->evio.epf;
	size_t offset = 0;
	struct virtio_rdma_cq_req cqe;
	bool is_grh = false;

	pr_info("%s:%d\n", __func__, __LINE__);

	if (sreq->send_flags & VIRTIO_IB_SEND_INLINE) {
		pr_err("not supported yet: payload inlining\n");
		return -ENOTSUPP;
	}

	sqpn = vqpn2sqpn(vqn);

	sqp = epf_vnet_lookup_qp(&vnet->ep_roce, sqpn);
	if (!sqp) {
		pr_err("failed to look up qp: %d\n", sqpn);
		return -EINVAL;
	}

	dqpn = epf_vnet_roce_get_dest_qpn(sqp, sreq);
	if (dqpn < 0) {
		pr_err("Failed to lookup qp: %d\n", dqpn);
	}

	dqp = epf_vnet_lookup_qp(&vnet->vdev_roce, dqpn);
	if (!dqp) {
		pr_err("failed to look up qp: %d\n", dqpn);
		return -EINVAL;
	}

	dst_vrh = &vnet->vdev_vrhs[dqp->rvq];
	iov = &vnet->vdev_iovs[dqp->rvq];

	err = vringh_getdesc_kern(dst_vrh, iov, NULL, &head,
						  						 GFP_KERNEL);
	if (err < 0) {
		pr_err("ep: failed to get desc for dest\n");
		return err;
	}
	if (!err) {
		pr_err("ep: not found an entry(rcv)\n");
		return 0;
	}

	rreq = memremap((resource_size_t)iov->iov[iov->i].iov_base,
								 iov->iov[iov->i].iov_len, MEMREMAP_WB);
	if (!rreq) {
		pr_err("%s:%d failed to memremap\n", __func__, __LINE__);
		return -ENOMEM;
	}

	dst_sge = &rreq->sg_list[0];

	dst_mr = epf_vnet_lookup_mr(&vnet->vdev_roce,
						    						 dst_sge->lkey);
	if (!dst_mr) {
		pr_err("ep: invalid lkey found\n");
		err = -EINVAL;
		goto err_rreq_memunmap;
	}

	switch(dst_mr->type) {
		case EPF_VNET_RDMA_MR_TYPE_DMA:
			dst = memremap(dst_sge->addr, dst_sge->length, MEMREMAP_WB);
			if (!dst) {
				pr_err("failed to remap dst space\n");
				err = -ENOMEM;
				goto err_rreq_memunmap;
			}
			break;
		case EPF_VNET_RDMA_MR_TYPE_MR:
		{
			size_t off = dst_sge->addr & (PAGE_SIZE - 1);
			dst = memremap(dst_mr->pages[0] + off, dst_sge->length, MEMREMAP_WB);
			if (!dst) {
				pr_err("failed to remap dst space\n");
				err = -ENOMEM;
				goto err_rreq_memunmap;
			}
			break;
		}
		default:
			pr_err("found an invalid memory region type\n");
			err = -EINVAL;
			goto err_rreq_memunmap;
	}

	if (sqp->type == VIRTIO_IB_QPT_GSI || sqp->type == VIRTIO_IB_QPT_UD) {
		union rdma_network_hdr *hdr = dst;
		struct iphdr *ip4h = &hdr->roce4grh;
		union ib_gid gid;
		is_grh = true;

		ip4h->version = 4;
		epf_vnet_load_gid(&vnet->vdev_roce, 1, &gid);
		ip4h->daddr = gid.global.interface_id >> 32;
		epf_vnet_load_gid(&vnet->ep_roce, 1, &gid);
		ip4h->saddr = gid.global.interface_id >> 32;

		offset += sizeof(struct ib_grh);
	}

	for(int i = 0; i < sreq->num_sge; i++) {
		struct virtio_rdma_sge *src_sge = &sreq->sg_list[i];
		struct epf_vnet_rdma_mr *src_mr;
		void __iomem *src;
		phys_addr_t src_phys;

		src_mr = epf_vnet_lookup_mr(&vnet->ep_roce, src_sge->lkey);
		if (!src_mr) {
			pr_err("Failed to found mr: %d\n", src_sge->lkey);
			err = -EINVAL;
			goto err_dst_memunmap;
		}

		switch (src_mr->type) {
		case EPF_VNET_RDMA_MR_TYPE_DMA:
			src = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
														 src_sge->addr, &src_phys, src_sge->length);
			if (IS_ERR(src)) {
				pr_err("failed to map pci memory\n");
				err = -ENOMEM;
				goto err_dst_memunmap;
			}
			break;
		case EPF_VNET_RDMA_MR_TYPE_MR:
		{
			size_t off = src_sge->addr & (PAGE_SIZE - 1);
			src = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				src_mr->pages[0] + off, &src_phys, src_sge->length);
			break;
		}
		default:
			pr_err("invalid mr type: %d\n", src_mr->type);
			err = -EINVAL;
			goto err_dst_memunmap;
		}

		memcpy_fromio(dst + offset, src, src_sge->length);

		pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, src_phys, src, src_sge->length);

		offset += src_sge->length;
		pr_info("ep sent size %d\n", src_sge->length);
	}

	vringh_complete_kern(dst_vrh, head, offset);

	memunmap(dst);

	memset(&cqe, 0x0, sizeof(cqe));

	pr_info("vdev:rreq: cqe wr_id 0x%llx\n", rreq->wr_id);
	cqe.wr_id = rreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = dqp->qpn;
	cqe.opcode = VIRTIO_IB_WC_RECV;
	cqe.byte_len = offset;
	if (is_grh)
		cqe.wc_flags = VIRTIO_IB_WC_GRH;
	//TODO if IMM, should be setted VIRTIO_IB_WC_WITH_IMM to wc_flags.

	err = epf_vnet_roce_vdev_completion(vnet, dqp->rcq, &cqe);
	if (err < 0) {
		pr_err("failed to completion for ep\n");
		goto err_dst_memunmap;
	}
	pr_info("send ep -> vdev: add cqe and notifed\n");

	memset(&cqe, 0x00, sizeof(cqe));
	cqe.wr_id = sreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.opcode = VIRTIO_IB_WC_SEND;
	cqe.byte_len = offset;
	cqe.qp_num = sqp->qpn;

	err = epf_vnet_roce_ep_completion(vnet, sqp->scq, &cqe);
	if (err < 0) {
		pr_err("failed to completion for vdev\n");
		goto err_dst_memunmap;
	}

	memunmap(rreq);

	return 0;

err_dst_memunmap:
	memunmap(dst);
err_rreq_memunmap:
	memunmap(rreq);

	return err;
}

static void epf_vnet_ep_roce_unload_sreq(struct virtio_rdma_sq_req *sreq)
{
	kfree(sreq);
}

static int epf_vnet_ep_roce_load_sreq(struct epf_vnet *vnet, struct vringh_kiov *iov, struct virtio_rdma_sq_req **sreq)
{
	phys_addr_t sreq_pci;
	size_t sreq_len;
	void __iomem *mapped_sreq;
	phys_addr_t sreq_phys;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;

	sreq_pci = (phys_addr_t)iov->iov[iov->i].iov_base;
	sreq_len = iov->iov[iov->i].iov_len;

	mapped_sreq = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
																	 sreq_pci, &sreq_phys, sreq_len);
	if (IS_ERR(mapped_sreq)) {
		pr_err("Failed to map sreq\n");
		return PTR_ERR(mapped_sreq);
	}

	*sreq = kmalloc(sreq_len, GFP_KERNEL);
	if (!*sreq)  {
		pr_err("Failed to allocate memory\n");
		return -ENOMEM;
	}

	memcpy(*sreq, mapped_sreq, sreq_len);

	pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no,
				   						 sreq_phys, mapped_sreq, sreq_len);

	return 0;
}

static void epf_vnet_ep_roce_tx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, ep_roce_tx_work);
	struct vringh_kiov *iov;
	struct epf_virtio *evio = &vnet->evio;
	struct virtio_rdma_sq_req *sreq = NULL;
	int err;

	for (int i = 0; i < 3; i++) {
		u32 vqn = VNET_VIRTQUEUE_RDMA_SQ0 + i * 2;
		u16 head;
		
		iov = &vnet->vdev_iovs[vqn];

		err = epf_virtio_getdesc(evio, vqn, iov, NULL, &head);
		if (!err)
			continue;

		if (err < 0) {
			pr_err("err on epf_virtio_getdesc: %d\n", err);
			break;
		}

		err = epf_vnet_ep_roce_load_sreq(vnet, iov, &sreq);
		if (err) {
			pr_err("ailed to load sreq\n");
			break;
		}

		switch (sreq->opcode) {
		case VIRTIO_IB_WR_RDMA_WRITE:
			err = epf_vnet_roce_handle_ep_rdma_write(vnet, vqn, sreq);
			if (err)
				pr_err("Failed to process rdma write %d\n", err);
			break;
		case VIRTIO_IB_WR_SEND:
			err = epf_vnet_roce_handle_ep_send_wr(
				vnet, vqn, sreq);
			if (err)
				pr_err("[%d] failed to process send work request: %d\n",
				       i, err);
			break;
		case VIRTIO_IB_WR_RDMA_READ:
			err = epf_vnet_roce_handle_ep_rdma_read(vnet, vqn, sreq);
			if (err)
					pr_err("Failed to process rdma read: %d\n", err);
			break;
			//TODO
			// 	case VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM:
			// 	case VIRTIO_IB_WR_SEND_WITH_IMM:
			// 		break;
		default:
			pr_err("ep: Found unsupported work request type %d\n",
			       sreq->opcode);
		}

		epf_virtio_iov_complete(evio, vqn, head,
					sizeof(*sreq) +
						sizeof(struct virtio_rdma_sge) *
							sreq->num_sge);
	}

	epf_vnet_ep_roce_unload_sreq(sreq);
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

static int epf_vnet_vdev_handle_roce_query_device(struct epf_vnet *vnet,
						  struct vringh_kiov *riov,
						  struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_device *ack;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	memcpy(ack, &vnet->rdma_attr, sizeof(vnet->rdma_attr));

	return 0;
}

static int epf_vnet_vdev_handle_roce_query_port(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_port *ack;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);
	ack->gid_tbl_len = EPF_VNET_ROCE_GID_TBL_LEN;
	ack->max_msg_sz = 0x800000;

	return 0;
}

static int epf_vnet_vdev_handle_roce_create_cq(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_cq *cmd;
	struct virtio_rdma_ack_create_cq *ack;
	struct epf_vnet_rdma_cq *cq;
	struct vringh *vrh;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	if (cmd->cqe > virtio_queue_size)
		return 1;

	cq = epf_vnet_alloc_cq(&vnet->vdev_roce);
	if (!cq) {
		pr_err("failed to allocate cq\n");
		return -EIO;
	}

	cq->buf = (void *)cmd->virt;
	cq->buf_phys = cmd->phys;
	pr_info("%s phys 0x%llx, virt 0x%llx\n", __func__, cmd->phys, cmd->virt);

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);
	ack->cqn = cq->cqn;

	vrh = &vnet->vdev_vrhs[cq->vqn];
	vringh_reset_kern(vrh);

	return 0;
}

static int epf_vnet_vdev_handle_roce_destroy_cq(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_cq *cmd;
	//struct epf_vnet_rdma_cq *cq;
	//struct vringh *vrh;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	return epf_vnet_dealloc_cq(&vnet->vdev_roce, cmd->cqn);
}

static int epf_vnet_vdev_handle_roce_create_pd(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_create_pd *ack;
	struct epf_vnet_rdma_pd *pd;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	pd = epf_vnet_alloc_pd(&vnet->vdev_roce);
	if (!pd)
		return -ENOMEM;

	epf_vnet_rdma_init_pd(pd);

	ack->pdn = pd->pdn;

	return 0;
}

static int epf_vnet_vdev_handle_roce_destroy_pd(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_pd *cmd;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	return epf_vnet_dealloc_pd(&vnet->vdev_roce, cmd->pdn);
}

static int epf_vnet_vdev_handle_roce_dma_mr(struct epf_vnet *vnet,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_get_dma_mr *cmd;
	struct virtio_rdma_ack_get_dma_mr *ack;
	struct epf_vnet_rdma_mr *mr;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	mr = epf_vnet_alloc_mr(&vnet->vdev_roce);
	if (!mr)
		return -EINVAL;

	mr->type = EPF_VNET_RDMA_MR_TYPE_DMA;

	ack->lkey = mr->mrn;
	ack->rkey = mr->mrn;
	ack->mrn = mr->mrn;

	return 0;
}

static int epf_vnet_vdev_handle_roce_reg_user_mr(struct epf_vnet *vnet,
						 struct vringh_kiov *riov,
						 struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_reg_user_mr *cmd;
	struct virtio_rdma_ack_reg_user_mr *ack;
	struct epf_vnet_rdma_pd *pd;
	struct epf_vnet_rdma_mr *mr;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	pd = epf_vnet_rdma_lookup_pd(&vnet->vdev_roce, cmd->pdn);
	if (!pd)
		return -EINVAL;

	mr = epf_vnet_alloc_mr(&vnet->vdev_roce);
	if (!mr)
		return -EINVAL;

	mr->type = EPF_VNET_RDMA_MR_TYPE_MR;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->lkey = mr->mrn;
	ack->rkey = mr->mrn;

	mr->virt_addr = cmd->virt_addr;
	mr->length = cmd->length;
	mr->npages = cmd->npages;
	mr->pages =
		kmalloc_array(cmd->npages, sizeof(mr->pages[0]), GFP_KERNEL);

	memcpy(mr->pages, cmd->pages, sizeof(mr->pages[0]) * mr->npages);

	ack->mrn = mr->mrn;

	return 0;
}

static int epf_vnet_vdev_handle_roce_dereg_mr(struct epf_vnet *vnet,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_dereg_mr *cmd;
	struct epf_vnet_rdma_mr *mr;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	mr = epf_vnet_lookup_mr(&vnet->vdev_roce, cmd->mrn);

	switch (mr->type) {
	case EPF_VNET_RDMA_MR_TYPE_MR:
		kfree(mr->pages);
		break;
	case EPF_VNET_RDMA_MR_TYPE_DMA:
		break;
	default:
		pr_err("found invalid mr type\n");
		return -EINVAL;
	}

	return epf_vnet_dealloc_mr(&vnet->vdev_roce, cmd->mrn);
}

static int epf_vnet_vdev_handle_roce_create_qp(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_qp *cmd;
	struct virtio_rdma_ack_create_qp *ack;
	struct epf_vnet_rdma_qp *qp;
	struct vringh *vrh;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	switch (cmd->qp_type) {
	case VIRTIO_IB_QPT_SMI:
		qp = epf_vnet_lookup_qp(&vnet->vdev_roce, 0);
		if (!qp)
			return -EIO;
		qp->type = VIRTIO_IB_QPT_SMI;
		break;
	case VIRTIO_IB_QPT_GSI:
		qp = epf_vnet_lookup_qp(&vnet->vdev_roce, 1);
		if (!qp)
			return -EIO;
		qp->type = VIRTIO_IB_QPT_GSI;
		break;
	case VIRTIO_IB_QPT_UD:
	case VIRTIO_IB_QPT_RC:
		qp = epf_vnet_alloc_qp(&vnet->vdev_roce);
		if (!qp)
			return -EIO;

		qp->type = cmd->qp_type;

		//TODO check
		qp->svq = VNET_VIRTQUEUE_RDMA_SQ0 + qp->qpn * 2;
		qp->rvq = VNET_VIRTQUEUE_RDMA_SQ0 + qp->qpn * 2 + 1;
		break;
	default:
		return -ENOTSUPP;
	}

	qp->scq = cmd->send_cqn;
	qp->rcq = cmd->recv_cqn;
	pr_info("vdev qpn %d, scq %d, rcq %d\n", qp->qpn, qp->scq, qp->rcq);

	if (qp->rvq >= VNET_VIRTQUEUE_NUM) {
		epf_vnet_dealloc_qp(&vnet->vdev_roce, qp->qpn);
		return -EINVAL;
	}

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->qpn = qp->qpn;

	vrh = &vnet->vdev_vrhs[qp->svq];
	vringh_reset_kern(vrh);
	vrh = &vnet->vdev_vrhs[qp->rvq];
	vringh_reset_kern(vrh);

	return 0;
}

static int epf_vnet_vdev_handle_roce_modify_qp(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_modify_qp *cmd;
	struct epf_vnet_rdma_qp *qp;
	struct virtio_rdma_cq_req cqe;
	int err;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	qp = epf_vnet_lookup_qp(&vnet->vdev_roce, cmd->qpn);
	if (!qp)
		return -EINVAL;

	if (cmd->attr_mask & VIRTIO_IB_QP_STATE) {
		pr_info("change qp state: %x -> %x\n", cmd->cur_qp_state,
			cmd->qp_state);

		if (cmd->qp_state == VIRTIO_IB_QPS_ERR) {
			pr_info("The qp state moves into QPS_ERR\n");
			memset(&cqe, 0x00, sizeof(cqe));
			cqe.status = VIRTIO_IB_WC_WR_FLUSH_ERR;
			err = epf_vnet_roce_vdev_completion(vnet, qp->scq, &cqe);
			if (err) {
				pr_err("failed to send err completion\n");
				return -1;
			}
		}
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CUR_STATE) {
		pr_info("%s:%d\n", __func__, __LINE__);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_ACCESS_FLAGS) {
		pr_info("%s:%d access_flags 0x%x\n", __func__, __LINE__,
			cmd->qp_access_flags);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_QKEY) {
		pr_info("set queue key 0x%x\n", cmd->qkey);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_AV) {
		pr_info("modify address vector\n");
		// TODO Should be saved the address vector to qp struct
		// 		cmd->ah_attr;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_PATH_MTU) {
		pr_info("set mtu to %d\n", cmd->path_mtu);
		// TODO This value should be converted to enum virtio_ib_mtu;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_TIMEOUT) {
		pr_info("timeout %d\n", cmd->timeout);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RETRY_CNT) {
		pr_info("retry cnd: %d\n", cmd->retry_cnt);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RNR_RETRY) {
		pr_info("rnr retry %d\n", cmd->rnr_retry);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RQ_PSN) {
		pr_info("set qp psn for rq: %d\n", cmd->rq_psn);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_QP_RD_ATOMIC) {
		pr_info("set max qp rd atomic: %d\n", cmd->max_rd_atomic);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MIN_RNR_TIMER) {
		pr_info("set rnr timer %d\n", cmd->min_rnr_timer);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_SQ_PSN) {
		pr_info("set psn for sq: %d\n", cmd->sq_psn);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC) {
		pr_info("set max dest rd atomic: %d", cmd->max_dest_rd_atomic);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CAP) {
		pr_info("%s:%d\n", __func__, __LINE__);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_DEST_QPN) {
		pr_info("dest qpn %d\n", cmd->dest_qp_num);
		qp->dest_qpn = cmd->dest_qp_num;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RATE_LIMIT) {
		pr_info("%s:%d\n", __func__, __LINE__);
		goto err_out;
	}

	return 0;

err_out:
	return 1;
}

static int epf_vnet_vdev_handle_roce_query_qp(struct epf_vnet *vnet,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_query_qp *cmd;
	struct virtio_rdma_ack_query_qp *ack;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	if (cmd->attr_mask & VIRTIO_IB_QP_STATE) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_STATE);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CUR_STATE) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_CUR_STATE);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_ACCESS_FLAGS) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_ACCESS_FLAGS);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_QKEY) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_QKEY);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_AV) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_AV);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_PATH_MTU) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_PATH_MTU);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_TIMEOUT) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_TIMEOUT);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RETRY_CNT) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RETRY_CNT);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RNR_RETRY) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RNR_RETRY);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RQ_PSN) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RQ_PSN);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_QP_RD_ATOMIC) {
		pr_info("not yet implemented 0x%x",
			VIRTIO_IB_QP_MAX_QP_RD_ATOMIC);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MIN_RNR_TIMER) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_MIN_RNR_TIMER);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_SQ_PSN) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_SQ_PSN);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC) {
		pr_info("not yet implemented 0x%x",
			VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CAP) {
		pr_info("qp cap 0x%x\n", VIRTIO_IB_QP_CAP);
		// TODO these are temporary and should be updated.
		ack->cap.max_send_wr = 100;
		ack->cap.max_send_sge = 32;
		ack->cap.max_inline_data = 32 * sizeof(struct virtio_rdma_sge);
		ack->cap.max_recv_wr = 100;
		ack->cap.max_recv_sge = 32;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_DEST_QPN) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_DEST_QPN);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RATE_LIMIT) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RATE_LIMIT);
		goto err_out;
	}

	return 0;

err_out:
	return 1;
}

static int epf_vnet_vdev_handle_roce_destroy_qp(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_qp *cmd;
	struct epf_vnet_rdma_qp *qp;
	struct vringh *svrh, *rvrh;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	qp = epf_vnet_lookup_qp(&vnet->vdev_roce, cmd->qpn);
	if (!qp) {
		pr_info("invalid qpn found: %d\n", cmd->qpn);
		return -EINVAL;
	}

	svrh = &vnet->vdev_vrhs[qp->svq];
	rvrh = &vnet->vdev_vrhs[qp->rvq];

	vringh_reset_kern(svrh);
	vringh_reset_kern(rvrh);

	return epf_vnet_dealloc_qp(&vnet->vdev_roce, cmd->qpn);
}

static int epf_vnet_vdev_handle_roce_create_ah(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_ah *cmd;
	struct virtio_rdma_ack_create_ah *ack;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->ah = vnet->nah++;

	return 0;
}

static int epf_vnet_vdev_handle_roce_destroy_ah(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	vnet->nah--;
	return 0;
}

static int epf_vnet_vdev_handle_roce_add_gid(struct epf_vnet *vnet,
					     struct vringh_kiov *riov,
					     struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_add_gid *cmd;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);
	if (cmd->index >= EPF_VNET_ROCE_GID_TBL_LEN)
		return -EINVAL;

	memcpy(vnet->vdev_roce.gid_tbl[cmd->index].raw, cmd->gid,
	       sizeof(cmd->gid));

	return 0;
}

static int epf_vnet_vdev_handle_roce_del_gid(struct epf_vnet *vnet,
					     struct vringh_kiov *riov,
					     struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_vdev_handle_roce_notify_cq(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	return 0;
}

static int (*virtio_rdma_vdev_cmd_handler[])(struct epf_vnet *vnet,
					     struct vringh_kiov *riov,
					     struct vringh_kiov *wiov) = {
	[VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE] =
		epf_vnet_vdev_handle_roce_query_device,
	[VIRTIO_NET_CTRL_ROCE_QUERY_PORT] = epf_vnet_vdev_handle_roce_query_port,
	[VIRTIO_NET_CTRL_ROCE_CREATE_CQ] = epf_vnet_vdev_handle_roce_create_cq,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_CQ] = epf_vnet_vdev_handle_roce_destroy_cq,
	[VIRTIO_NET_CTRL_ROCE_CREATE_PD] = epf_vnet_vdev_handle_roce_create_pd,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_PD] = epf_vnet_vdev_handle_roce_destroy_pd,
	[VIRTIO_NET_CTRL_ROCE_GET_DMA_MR] = epf_vnet_vdev_handle_roce_dma_mr,
	[VIRTIO_NET_CTRL_ROCE_REG_USER_MR] =
		epf_vnet_vdev_handle_roce_reg_user_mr,
	[VIRTIO_NET_CTRL_ROCE_DEREG_MR] = epf_vnet_vdev_handle_roce_dereg_mr,
	[VIRTIO_NET_CTRL_ROCE_CREATE_QP] = epf_vnet_vdev_handle_roce_create_qp,
	[VIRTIO_NET_CTRL_ROCE_MODIFY_QP] = epf_vnet_vdev_handle_roce_modify_qp,
	[VIRTIO_NET_CTRL_ROCE_QUERY_QP] = epf_vnet_vdev_handle_roce_query_qp,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_QP] = epf_vnet_vdev_handle_roce_destroy_qp,
	[VIRTIO_NET_CTRL_ROCE_CREATE_AH] = epf_vnet_vdev_handle_roce_create_ah,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_AH] = epf_vnet_vdev_handle_roce_destroy_ah,
	[VIRTIO_NET_CTRL_ROCE_ADD_GID] = epf_vnet_vdev_handle_roce_add_gid,
	[VIRTIO_NET_CTRL_ROCE_DEL_GID] = epf_vnet_vdev_handle_roce_del_gid,
	[VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ] =
		epf_vnet_vdev_handle_roce_notify_cq,
};

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
		goto err_cleanup;

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

	riov.i++;
	wiov.i++;

	switch (hdr->class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (hdr->cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_debug("Invalid command: announce: %d\n", hdr->cmd);
			goto done;
		}

		epf_vnet_vdev_cfg_clear_status(vnet, VIRTIO_NET_S_ANNOUNCE);
		*ack = VIRTIO_NET_OK;
		break;
	case VIRTIO_NET_CTRL_ROCE:
		if (ARRAY_SIZE(virtio_rdma_vdev_cmd_handler) < hdr->cmd) {
			err = -EIO;
			pr_debug("found invalid command\n");
			break;
		}
		// TODO this is for debug, finally should be deleted.
		if (!virtio_rdma_vdev_cmd_handler[hdr->cmd]) {
			pr_info("A handler for cmd %d is not yet implemented\n",
				hdr->cmd);
			err = -ENOTSUPP;
			*ack = VIRTIO_NET_ERR;
			break;
		}

		err = virtio_rdma_vdev_cmd_handler[hdr->cmd](vnet, &riov,
							     &wiov);
		*ack = err ? VIRTIO_NET_ERR : VIRTIO_NET_OK;
		break;
	default:
		pr_debug("Found not supported class: %d\n", hdr->class);
		err = -EIO;
	}

done:
	vringh_complete_kern(vrh, head, len);

err_cleanup:
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
			  PCI_EPC_IRQ_INTX, 0);
}

static void epf_vnet_roce_rx_handler(struct work_struct *work)
{
	// 	struct epf_vnet *vnet =
	// 		container_of(work, struct epf_vnet, roce_rx_work);

	pr_info("Should operate a receive work request\n");
}



static struct virtio_rdma_rq_req *epf_vnet_roce_load_rreq(struct epf_vnet *vnet, 
																													 struct vringh_kiov *iov)
{
	struct virtio_rdma_rq_req __iomem *iorreq, *rreq;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	phys_addr_t rreq_phys;
	phys_addr_t pci_addr = (phys_addr_t)iov->iov[iov->i].iov_base;
	size_t rreq_size = iov->iov[iov->i].iov_len;

	pr_info("rreq size 0x%ld (0x%ld)\n", rreq_size, sizeof(*rreq));
	iorreq = pci_epc_map_aligned(epf->epc, epf->func_no,
						   epf->vfunc_no, pci_addr, &rreq_phys, rreq_size);
	if (IS_ERR(iorreq)) {
		pr_err("faild to map rreq\n");
		return NULL;
	}

	rreq = kmalloc(rreq_size, GFP_KERNEL);
	if (!rreq)
		return NULL;

	memcpy_fromio(rreq, iorreq, rreq_size);

	pci_epc_unmap_aligned(epf->epc, epf->func_no,
					      			 epf->vfunc_no, rreq_phys, iorreq,
					      			 rreq_size);

	return rreq;
}

static void __iomem *epf_vnet_map_addr(struct epf_vnet *vnet, struct virtio_rdma_sge *sge, phys_addr_t *phys)
{
	struct epf_vnet_rdma_mr *mr;
	void __iomem *target;
	struct pci_epf *epf = vnet->evio.epf;

	mr = epf_vnet_lookup_mr(&vnet->ep_roce, sge->lkey);
	if (!mr) {
		pr_info("ep: failed to lookup mr\n");
		return ERR_PTR(-EINVAL);
	}

	if (sge->lkey != 0)
		pr_info("mr %d length %lld\n", sge->lkey, mr->length);

	pr_info("%s lkey %d, mr type %d\n", __func__, sge->lkey, mr->type);
	switch (mr->type) {
		case EPF_VNET_RDMA_MR_TYPE_DMA:
			target = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
														 sge->addr, phys, sge->length);
			if (IS_ERR(target)) {
				pr_err("failed to map dst\n");
				return ERR_PTR(-EINVAL);
			}
			break;
		case EPF_VNET_RDMA_MR_TYPE_MR:
			if (mr->npages != 1) {
				pr_err("multiple pages of mr are not supporeted\n");
				return ERR_PTR(ENOTSUPP);
			}
			target = pci_epc_map_aligned(epf->epc, epf->func_no,
														 epf->vfunc_no, mr->pages[0],
														 phys, sge->length);
			if (IS_ERR(target)) {
				pr_err("Failed to map dst\n");
				return ERR_PTR(-EINVAL);
			}
			break;
		default:
			pr_err("invalid mr type found\n");
			return ERR_PTR(-EINVAL);
	}

	return target;
}

static void epf_vnet_unmap_addr(struct epf_vnet *vnet, void __iomem* target, phys_addr_t phys, size_t length)
{
	struct pci_epf *epf = vnet->evio.epf;

	pci_epc_unmap_aligned(epf->epc, epf->func_no,
					      				epf->vfunc_no, phys, target,
					      				length);
}

static int epf_vnet_roce_calc_addr(struct epf_vnet_rdma_mr *mr, size_t offset, phys_addr_t raddr, phys_addr_t *addr)
{
	int pg_idx = offset / PAGE_SIZE;
	size_t inpage_off = offset & (PAGE_SIZE - 1);

	switch(mr->type) {
		case EPF_VNET_RDMA_MR_TYPE_MR:
			*addr = mr->pages[pg_idx] + inpage_off;
			break;
		case EPF_VNET_RDMA_MR_TYPE_DMA:
			*addr = raddr + offset;
			break;
		default:
			pr_err("found invalid mr type: %x\n", mr->type);
			return -1;
	}

	return 0;
}

#if 1
static int epf_vnet_roce_vdev_handle_send_wr(struct epf_vnet *vnet,
					     struct virtio_rdma_sq_req *sreq,
					     struct virtqueue *vq)
{
	struct epf_virtio *evio = &vnet->evio;
	// struct pci_epf *epf = evio->epf;
	struct vringh_kiov *iov;
	struct epf_vnet_rdma_qp *dst_qp, *src_qp;
	int ret;
	u16 rhead;
	size_t total_len = 0;
	size_t offset = 0;
	struct virtio_rdma_rq_req *rreq;
	phys_addr_t dst_phys;
	struct virtio_rdma_cq_req cqe;
	struct virtio_rdma_sge *dst_sge;
	void __iomem *dst;
	unsigned dst_sge_idx = 0;
	bool is_grh = false;

	if (sreq->send_flags & VIRTIO_IB_SEND_INLINE) {
		pr_err("inline data is not supported\n");
		return -ENOTSUPP;
	}

	src_qp = epf_vnet_lookup_qp(&vnet->vdev_roce,
				    (vq->index - VNET_VIRTQUEUE_RDMA_SQ0) / 2);
	if (!src_qp){
		pr_err("failed to lookup src qp\n");
		return -EINVAL;
	}

	dst_qp = epf_vnet_lookup_qp(&vnet->ep_roce, epf_vnet_roce_get_dest_qpn(src_qp, sreq));
	if (!dst_qp) {
		pr_err("failed to lookup dest qp\n");
		return -EINVAL;
	}

	iov = &vnet->rdev_iovs[dst_qp->rvq];
	ret = epf_virtio_getdesc(evio, dst_qp->rvq, iov, NULL, &rhead);
	if (ret <= 0) {
		if (!ret)
			pr_info("not found recv wr at RC side\n");

		return ret;
	}

	rreq = epf_vnet_roce_load_rreq(vnet, iov);
	if (!rreq) {
		pr_err("Failed to load rreq\n");
		return -EINVAL;
	}
	pr_info("%s:%d dst num_sge %d\n", __func__, __LINE__, rreq->num_sge);

	dst_sge = &rreq->sg_list[dst_sge_idx];
	dst = epf_vnet_map_addr(vnet, dst_sge, &dst_phys);
	
	if (src_qp->type == VIRTIO_IB_QPT_GSI || src_qp->type == VIRTIO_IB_QPT_UD) {
		// struct ib_grh *grh = dst;
		union rdma_network_hdr *hdr = dst;
		struct iphdr *ip4h = &hdr->roce4grh;
		union ib_gid gid;

		is_grh = true;

		ip4h->version = 4;
		epf_vnet_load_gid(&vnet->vdev_roce, 1, &gid);
		ip4h->saddr = gid.global.interface_id >> 32;
		epf_vnet_load_gid(&vnet->ep_roce, 1, &gid);
		ip4h->daddr = gid.global.interface_id >> 32;

		dst += sizeof(struct ib_grh);
		offset += sizeof(struct ib_grh);
	}

	for (int i = 0; i < sreq->num_sge; i++) {
		struct virtio_rdma_sge *src_sge = &sreq->sg_list[i];
		struct epf_vnet_rdma_mr *src_mr;
		void *src;
		phys_addr_t src_phys;

		total_len += src_sge->length;

		pr_info("src_sge->lkey %d, addr 0x%llx\n", src_sge->lkey, src_sge->addr);
		src_mr = epf_vnet_lookup_mr(&vnet->vdev_roce, src_sge->lkey);
		if (!src_mr) {
			pr_err("failed to lookup memory region\n");
			return -EINVAL;
		}

		ret = epf_vnet_roce_calc_addr(src_mr, 0, src_sge->addr, &src_phys);
		if (ret) {
			pr_err("failed to get src data address\n");
			return -EINVAL;
		}

		src = memremap(src_phys, src_sge->length, MEMREMAP_WB);
		if (!src) {
			pr_err("failed to remap src buffer\n");
			return -EINVAL;
		}

		// switch (src_mr->type) {
		// 	case EPF_VNET_RDMA_MR_TYPE_DMA:
		// 		src = memremap(src_sge->addr, src_sge->length,
		// 		       		 MEMREMAP_WB);
		// 		if (!src) {
		// 			pr_err("%s:%d failed to memremap\n", __func__,
		// 		    __LINE__);
		// 			return -ENOMEM;
		// 		}
		// 		break;
		// 	case EPF_VNET_RDMA_MR_TYPE_MR:
		// 		src = memremap(src_mr->pages[0], src_sge->length,
		// 		       		 MEMREMAP_WB);
		// 		if (!src) {
		// 			pr_err("%s:%d failed to memremap\n", __func__,
		// 		    __LINE__);
		// 			return -ENOMEM;
		// 		}
		// 		break;
		// 	default:
		// 		pr_err("unexpected mr type found: %d\n", src_mr->type);
		// 		return -EINVAL;
		// }

		if (dst_sge->length - offset == 0) {

			epf_vnet_unmap_addr(vnet, dst, dst_phys, rreq->sg_list[dst_sge_idx].length);
			dst_sge_idx++;
			if (dst_sge_idx > rreq->num_sge) {
				pr_err("a lack of sge: %d > %d\n", dst_sge_idx, rreq->num_sge);
				return -EINVAL;
			}
			dst = epf_vnet_map_addr(vnet, &rreq->sg_list[dst_sge_idx], &dst_phys);
			if (IS_ERR(dst)) {
				pr_err("failed to map dst range: %ld\n", PTR_ERR(dst));
				return PTR_ERR(dst);
			}

			if (rreq->sg_list[dst_sge_idx].length < src_sge->length){
				pr_err("not enough size: %d < %d\n", rreq->sg_list[dst_sge_idx].length, src_sge->length);
				return -EINVAL;
			}

			offset = 0;
		}

		pr_info("dst 0x%px, src 0x%px length 0x%x\n", dst, src, src_sge->length);
		memcpy_toio(dst, src, src_sge->length);

		memunmap(src);

		offset += src_sge->length;
		dst += src_sge->length;
	}

	epf_vnet_unmap_addr(vnet, dst, dst_phys, rreq->sg_list[dst_sge_idx].length);
	// pci_epc_unmap_aligned(epf->epc, epf->func_no,
	// 				      				epf->vfunc_no, dst_phys, dst,
	// 				      				dst_sge->length);

	memset(&cqe, 0x0, sizeof(cqe));

	cqe.wr_id = rreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = dst_qp->qpn;
	cqe.opcode = VIRTIO_IB_WC_RECV;
	cqe.byte_len = total_len;
	if (is_grh)
		cqe.wc_flags = VIRTIO_IB_WC_GRH;
	//TODO if IMM, should be setted VIRTIO_IB_WC_WITH_IMM to wc_flags.

	ret = epf_vnet_roce_ep_completion(vnet, dst_qp->rcq, &cqe);
	if (ret < 0) {
		pr_err("failed to completion for ep\n");
		return ret;
	}
	pr_info("send vdev -> ep: add cqe and notifed\n");

	memset(&cqe, 0x00, sizeof(cqe));
	pr_info("vdev:sreq: cqe wr_id 0x%llx\n", sreq->wr_id);
	cqe.wr_id = sreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.opcode = VIRTIO_IB_WC_SEND;
	cqe.byte_len = total_len;
	cqe.qp_num = src_qp->qpn;

	ret = epf_vnet_roce_vdev_completion(vnet, src_qp->scq, &cqe);
	if (ret < 0) {
		pr_err("failed to completion for vdev\n");
		return ret;
	}

	epf_virtio_iov_complete(evio, dst_qp->rvq, rhead, iov->iov[iov->i].iov_len);
	kfree(rreq);

	return 0;
}

#else

static int epf_vnet_roce_vdev_handle_send_wr(struct epf_vnet *vnet,
					     struct virtio_rdma_sq_req *sreq,
					     struct virtqueue *vq)
{
	int err;
	struct epf_vnet_rdma_qp *src_qp, *dst_qp;
	struct virtio_rdma_rq_req rreq;
	struct vringh *vrh;
	struct vringh_kiov *iov;
	u16 rreq_head;
	struct pci_epf *epf = vnet->evio.epf;
	phys_addr_t rreq_phys;
	int dst_sge_idx = 0;
	size_t dst_offset = 0;
	struct virtio_rdma_cq_req cqe;
	size_t total_copy_length = 0;
	struct virtio_rdma_rq_req __iomem *rreq_base;

	src_qp = epf_vnet_lookup_qp(&vnet->vdev_roce,
				    								 (vq->index - VNET_VIRTQUEUE_RDMA_SQ0) / 2);
	if (!src_qp){
		pr_err("failed to lookup src qp\n");
		return -EINVAL;
	}

	dst_qp = epf_vnet_lookup_qp(&vnet->ep_roce, epf_vnet_roce_get_dest_qpn(src_qp, sreq));
	if (!dst_qp) {
		pr_err("failed to lookup dest qp\n");
		return -EINVAL;
	}

	vrh = &vnet->vdev_vrhs[dst_qp->rvq];
	iov = &vnet->vdev_iovs[dst_qp->rvq];

	err = epf_virtio_getdesc(&vnet->evio, dst_qp->rvq, iov, NULL, &rreq_head);
	if (err <= 0) {
		if (err < 0)
			pr_err("err on vringh_getdesc_kern: %d\n", err);
		else
			pr_info("not found any entries\n");
		return err;
	}

	pr_info("%s: rreq size %lx\n", __func__, iov->iov[iov->i].iov_len);

	rreq_base = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)iov->iov[iov->i].iov_base, &rreq_phys, iov->iov[iov->i].iov_len);
	if (IS_ERR(rreq_base)) {
		pr_err("Failed to map rreq\n");
		return PTR_ERR(rreq_base);
	}

	memcpy_fromio(&rreq, rreq_base, iov->iov[iov->i].iov_len);

	for (int i = 0; i < sreq->num_sge; i++) {
		struct virtio_rdma_sge *src_sge = &sreq->sg_list[i];
		struct epf_vnet_rdma_mr *src_mr, *dst_mr;
		void *src;
		phys_addr_t src_phys, dst_phys;
		phys_addr_t dst_pci;
		struct virtio_rdma_sge dst_sge;
		void __iomem *dst;
		size_t copy_len;
		size_t sge_offset = 0;

		src_mr = epf_vnet_lookup_mr(&vnet->vdev_roce, src_sge->lkey);
		if (!src_mr) {
			pr_err("Failed to lookup src mr\n");
			return -EINVAL;
		}

		err = epf_vnet_roce_calc_addr(src_mr, 0, src_sge->addr, &src_phys);
		if (err) {
			pr_err("failed to get src data address\n");
			return -EINVAL;
		}

		src = memremap(src_phys, src_sge->length, MEMREMAP_WB);
		if (!src) {
			pr_err("failed to remap src buffer\n");
			return -EINVAL;
		}

		while(src_sge->length != sge_offset) {
			if (dst_sge_idx >= rreq.num_sge) {
				pr_err("should be read the next receive workrequest, but it is not yet implemented\n");
				return -EINVAL;
			}

			memcpy_fromio(&dst_sge, &rreq_base->sg_list[dst_sge_idx], sizeof(dst_sge));

			pr_info("%s: [src: %d] len: 0x%x, off: 0x%lx, [dst: %d] len: 0x%x, off: 0x%lx\n", __func__,
					 i, src_sge->length, sge_offset, dst_sge_idx, dst_sge.length, dst_offset);
			if (src_sge->length - sge_offset > dst_sge.length - dst_offset) {
				copy_len = dst_sge.length - dst_offset;
				dst_offset = 0;
				dst_sge_idx++;
			} else {
				copy_len = src_sge->length;
			}
			sge_offset += copy_len;

			dst_mr = epf_vnet_lookup_mr(&vnet->ep_roce, dst_sge.lkey);
			if (!dst_mr) {
				pr_err("failed to lookup dst mr\n");
				return -EINVAL;
			}

			err = epf_vnet_roce_calc_addr(dst_mr, dst_offset, dst_sge.addr, &dst_pci);
			if (err) {
				pr_err("failed to calculate dst address\n");
				return -EINVAL;
			}

			dst = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no,
			       								 dst_pci, &dst_phys, copy_len);

			memcpy_toio(dst, src, copy_len);

			pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, dst_phys, dst, copy_len);
		}

		memunmap(src);
		total_copy_length += src_sge->length;
	}

	cqe.wr_id = sreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = src_qp->qpn;
	cqe.opcode = sreq->opcode;
	cqe.byte_len = total_copy_length;

	err = epf_vnet_roce_vdev_completion(vnet, src_qp->scq, &cqe);
	if (err) {
		pr_err("failed to complete for src\n");
		return -EINVAL;
	}

	cqe.wr_id = rreq.wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = dst_qp->qpn;
	cqe.opcode = VIRTIO_IB_WC_RECV;
	cqe.byte_len = total_copy_length;

	err = epf_vnet_roce_vdev_completion(vnet, dst_qp->rcq, &cqe);
	if (err) {
		pr_err("failed to complete for dst\n");
		return -EINVAL;
	}

	epf_virtio_iov_complete(&vnet->evio, dst_qp->rvq, rreq_head, iov->iov[iov->i].iov_len);

	return 0;
}
#endif

static int epf_vnet_roce_vdev_handle_rdma_write(struct epf_vnet *vnet,
					     struct virtio_rdma_sq_req *sreq,
					     struct virtqueue *vq)
{
	struct epf_vnet_rdma_qp *qp;
	struct epf_vnet_rdma_mr *dst_mr;
	int err;
	phys_addr_t dst_phys, src_phys;
	size_t offset = 0;
	struct virtio_rdma_cq_req cqe;

	qp = epf_vnet_lookup_qp(&vnet->vdev_roce,
				    (vq->index - VNET_VIRTQUEUE_RDMA_SQ0) / 2);
	if (!qp)
		return -EINVAL;

	dst_mr = epf_vnet_lookup_mr(&vnet->ep_roce, sreq->rdma.rkey);
	if (!dst_mr)
		return -EINVAL;

	for(int i = 0; i < sreq->num_sge; i++) {
		struct virtio_rdma_sge *sge = &sreq->sg_list[i];
		struct epf_vnet_rdma_mr *src_mr = epf_vnet_lookup_mr(&vnet->vdev_roce, sge->lkey);
		void *src;
		phys_addr_t dst_pci;
		void __iomem *dst;
		struct pci_epf *epf = vnet->evio.epf;

		err = epf_vnet_roce_calc_addr(src_mr, 0, sge->addr, &src_phys);
		if (err) {
			break;
		}

		src = memremap(src_phys, sge->length, MEMREMAP_WB);

		err = epf_vnet_roce_calc_addr(dst_mr, offset, sreq->rdma.remote_addr, &dst_pci);
		if (err) {
			return -EINVAL;
		}

		dst = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no, dst_pci, &dst_phys,
														sge->length);
		if (IS_ERR(src)) {
			pr_err("%s:%d failed to map src region\n", __func__, __LINE__);
			return -EINVAL;
		}

		memcpy_toio(dst, src, sge->length);

		memunmap(src);

		pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, dst_phys, dst, sge->length);

		offset += sge->length;
	}

	cqe.wr_id = sreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = qp->qpn;
	cqe.opcode = sreq->opcode;
	cqe.byte_len = offset;

	return epf_vnet_roce_vdev_completion(vnet, qp->scq, &cqe);
}

static int epf_vnet_roce_vdev_handle_rdma_read(struct epf_vnet *vnet,
					     struct virtio_rdma_sq_req *sreq,
					     struct virtqueue *vq)
{
	struct epf_vnet_rdma_qp *qp;
	struct epf_vnet_rdma_mr *src_mr;
	phys_addr_t src_phys;
	void __iomem *src;
	struct pci_epf *epf = vnet->evio.epf;
	size_t offset = 0;
	int err;
	phys_addr_t src_pci;
	struct virtio_rdma_cq_req cqe;

	qp = epf_vnet_lookup_qp(&vnet->vdev_roce,
				    (vq->index - VNET_VIRTQUEUE_RDMA_SQ0) / 2);
	if (!qp)
		return -EINVAL;

	src_mr = epf_vnet_lookup_mr(&vnet->ep_roce, sreq->rdma.rkey);
	if (!src_mr)
		return -EINVAL;

	for(int i = 0; i < sreq->num_sge; i++) {
		struct virtio_rdma_sge *sge = &sreq->sg_list[i];
		struct epf_vnet_rdma_mr *dst_mr = epf_vnet_lookup_mr(&vnet->vdev_roce, sge->lkey);
		phys_addr_t dst_phys;
		void *dst;

		err = epf_vnet_roce_calc_addr(dst_mr, 0, sge->addr, &dst_phys);
		if (err) {
			break;
		}

		dst = memremap(dst_phys, sge->length, MEMREMAP_WB);

		err = epf_vnet_roce_calc_addr(src_mr, offset, sreq->rdma.remote_addr, &src_pci);
		if (err) {
			return -EINVAL;
		}

		src = pci_epc_map_aligned(epf->epc, epf->func_no, epf->vfunc_no, src_pci, &src_phys,
														sge->length);
		if (IS_ERR(src)) {
			pr_err("%s:%d failed to map src region\n", __func__, __LINE__);
			return -EINVAL;
		}

		memcpy_fromio(dst, src, sge->length);

		memunmap(dst);
		pci_epc_unmap_aligned(epf->epc, epf->func_no, epf->vfunc_no, src_phys, src, sge->length);

		offset += sge->length;
	}

	cqe.wr_id = sreq->wr_id;
	cqe.status = VIRTIO_IB_WC_SUCCESS;
	cqe.qp_num = qp->qpn;
	cqe.opcode = sreq->opcode;
	cqe.byte_len = offset;

	return epf_vnet_roce_vdev_completion(vnet, qp->scq, &cqe);
}

static int epf_vnet_vdev_roce_tx_handler(struct epf_vnet *vnet, struct virtqueue *vq)
{
	struct vringh *vrh;
	struct vringh_kiov *iov;
	int err = 0;
	u16 head;
	struct virtio_rdma_sq_req *sreq;

	vrh = &vnet->vdev_vrhs[vq->index];
	iov = &vnet->vdev_iovs[vq->index];

	err = vringh_getdesc_kern(vrh, iov, NULL, &head, GFP_KERNEL);
	if (err <= 0) {
		if (err < 0)
			pr_err("err on vringh_getdesc_kern: %d\n", err);
		else
			pr_info("not found any entries\n");
		return err;
	}

	sreq = memremap((resource_size_t)iov->iov[iov->i].iov_base,
								 iov->iov[iov->i].iov_len, MEMREMAP_WB);
	if (!sreq) {
		pr_err("%s:%d failed to memremap\n", __func__, __LINE__);
		return -ENOMEM;
	}

	switch (sreq->opcode) {
	case VIRTIO_IB_WR_RDMA_WRITE:
		err = epf_vnet_roce_vdev_handle_rdma_write(vnet, sreq, vq);
		if (err)
			pr_err("failed to process rdma write work request: %d\n",
			       err);
		break;
	case VIRTIO_IB_WR_SEND:
		err = epf_vnet_roce_vdev_handle_send_wr(vnet, sreq, vq);
		if (err)
			pr_err("failed to process send work request: %d\n",
			       err);
		break;
	case VIRTIO_IB_WR_RDMA_READ:
		err = epf_vnet_roce_vdev_handle_rdma_read(vnet, sreq, vq);
		if (err)
			pr_err("failed to process rdma read work request: %d\n", err);
		break;
	default:
		pr_err("vdev: Found unsupported work request type %d\n",
		       sreq->opcode);
		err = -EINVAL;
	}

	memunmap(sreq);

	vringh_complete_kern(vrh, head, iov->iov[iov->i].iov_len);

	return err;
}

static int epf_vnet_setup_common(struct epf_vnet *vnet, struct device *dev)
{
	int err;

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
		BIT(VIRTIO_NET_F_CTRL_VQ) | BIT(VIRTIO_NET_F_ROCE);

	vnet->vnet_cfg.max_virtqueue_pairs = 1;
	vnet->vnet_cfg.status = 0;
	/* GSI is used 1 qps and cq */
	vnet->vnet_cfg.max_rdma_qps = EPF_VNET_RDMA_MAX_QP;
	vnet->vnet_cfg.max_rdma_cqs = EPF_VNET_RDMA_MAX_CQ;
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
	INIT_WORK(&vnet->ep_roce_tx_work, epf_vnet_ep_roce_tx_handler);
	INIT_WORK(&vnet->vdev_ctrl_work, epf_vnet_vdev_ctrl_handler);
	INIT_WORK(&vnet->raise_irq_work, epf_vnet_raise_irq_handler);

	INIT_WORK(&vnet->roce_rx_work, epf_vnet_roce_rx_handler);

	err = epf_vnet_init_rdma(dev, &vnet->vdev_roce, "vdev");
	if (err)
		return err;

	err = epf_vnet_init_rdma(dev, &vnet->ep_roce, "ep");
	if (err)
		return err;

	// *1 There is no resone for the value.
	vnet->rdma_attr.device_cap_flags = 0;
	vnet->rdma_attr.max_mr_size = 1 << 30;
	vnet->rdma_attr.page_size_cap = 0xfffff000;
	vnet->rdma_attr.hw_ver = 0xdeafbeaf;
	vnet->rdma_attr.max_qp_wr = virtio_queue_size;
	vnet->rdma_attr.max_send_sge = 32; // *1
	vnet->rdma_attr.max_recv_sge = 32; // *1
	vnet->rdma_attr.max_sge_rd = 32; // *1
	vnet->rdma_attr.max_cqe = virtio_queue_size;
	vnet->rdma_attr.max_mr = EPF_VNET_RDMA_MAX_MR;
	vnet->rdma_attr.max_pd = EPF_VNET_RDMA_MAX_PD;
	vnet->rdma_attr.max_qp_rd_atom = 32; // *1
	vnet->rdma_attr.max_qp_init_rd_atom = 32; // *1
	vnet->rdma_attr.max_ah = EPF_VNET_RDMA_MAX_AH;
	vnet->rdma_attr.local_ca_ack_delay = 15;

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
	int err;
	bool ret = true;

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
	/* Follsing cases are extended for VirtIO-RDMA */
	case VNET_VIRTQUEUE_RDMA_SQ1:
	case VNET_VIRTQUEUE_RDMA_SQ2:
		err = epf_vnet_vdev_roce_tx_handler(vnet, vq);
		if (err) {
			pr_err("failed to tx for vq %d\n", vq->index);
			ret = false;
		}
		break;
	case VNET_VIRTQUEUE_RDMA_RQ1:
	case VNET_VIRTQUEUE_RDMA_RQ2:
		queue_work(vnet->task_wq, &vnet->roce_rx_work);
		break;
	default:
		pr_info("Found unsupported notify for vq %d\n", vq->index);
		return false;
	}

	return ret;
}

static int epf_vnet_vdev_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
				  struct virtqueue *vqs[],
				  vq_callback_t *callback[],
				  const char *const names[], const bool *ctx,
				  struct irq_affinity *desc)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	int i;
	int err;

	if (nvqs > epf_vnet_get_nvq(vnet)) {
		pr_info("Number of queue is too much: %d > %d\n", nvqs,
			epf_vnet_get_nvq(vnet));
		return -EINVAL;
	}

	for (i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		const struct vring *vring;

		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vq = vring_create_virtqueue(i, virtio_queue_size,
					    SMP_CACHE_BYTES, vdev, true, false,
					    ctx ? ctx[i] : false,
					    epf_vnet_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		vnet->vdev_vqs[i] = vq;
		vring = virtqueue_get_vring(vq);

		err = vringh_init_kern(&vnet->vdev_vrhs[i], vnet->features,
				       virtio_queue_size, true, vring->desc,
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

static void epf_vnet_vdev_del_vqs(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	for (int i = 0; i < epf_vnet_get_nvq(vnet); i++) {
		if (!vnet->vdev_vqs[i])
			continue;

		vring_del_virtqueue(vnet->vdev_vqs[i]);
		vnet->vdev_vqs[i] = NULL;
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
		kmalloc_array(nvq, sizeof(vnet->vdev_vqs[0]), GFP_KERNEL);
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
		err = -EOPNOTSUPP;
		goto err_release_tx_chan;
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

	err = epf_vnet_setup_common(vnet, &epf->dev);
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
