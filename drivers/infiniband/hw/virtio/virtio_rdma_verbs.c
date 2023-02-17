// SPDX-License-Identifier: GPL-2.0-only
/*
 * RoCE support for virtio network device
 *
 * Copyright (C) 2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Xie Yongji <xieyongji@bytedance.com>
 *         Wei Junji <weijunji@bytedance.com>
 */

#include <linux/scatterlist.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_net.h>
#include <net/addrconf.h>
#include <uapi/linux/virtio_net.h>
#include <rdma/ib_mad.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_addr.h>

#include "virtio_rdma_verbs.h"

static const char* cmd_name[] = {
	[VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE] = "VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE",
	[VIRTIO_NET_CTRL_ROCE_QUERY_PORT] = "VIRTIO_NET_CTRL_ROCE_QUERY_PORT",
	[VIRTIO_NET_CTRL_ROCE_CREATE_CQ] = "VIRTIO_NET_CTRL_ROCE_CREATE_CQ",
	[VIRTIO_NET_CTRL_ROCE_DESTROY_CQ] = "VIRTIO_NET_CTRL_ROCE_DESTROY_CQ",
	[VIRTIO_NET_CTRL_ROCE_CREATE_PD] = "VIRTIO_NET_CTRL_ROCE_CREATE_PD",
	[VIRTIO_NET_CTRL_ROCE_DESTROY_PD] = "VIRTIO_NET_CTRL_ROCE_DESTROY_PD",
	[VIRTIO_NET_CTRL_ROCE_GET_DMA_MR] = "VIRTIO_NET_CTRL_ROCE_GET_DMA_MR",
	[VIRTIO_NET_CTRL_ROCE_REG_USER_MR] = "VIRTIO_NET_CTRL_ROCE_REG_USER_MR",
	[VIRTIO_NET_CTRL_ROCE_DEREG_MR] = "VIRTIO_NET_CTRL_ROCE_DEREG_MR",
	[VIRTIO_NET_CTRL_ROCE_CREATE_QP] = "VIRTIO_NET_CTRL_ROCE_CREATE_QP",
	[VIRTIO_NET_CTRL_ROCE_MODIFY_QP] = "VIRTIO_NET_CTRL_ROCE_MODIFY_QP",
	[VIRTIO_NET_CTRL_ROCE_QUERY_QP] = "VIRTIO_NET_CTRL_ROCE_QUERY_QP",
	[VIRTIO_NET_CTRL_ROCE_DESTROY_QP] = "VIRTIO_NET_CTRL_ROCE_DESTROY_QP",
	[VIRTIO_NET_CTRL_ROCE_CREATE_AH] = "VIRTIO_NET_CTRL_ROCE_CREATE_AH",
	[VIRTIO_NET_CTRL_ROCE_DESTROY_AH] = "VIRTIO_NET_CTRL_ROCE_DESTROY_AH",
	[VIRTIO_NET_CTRL_ROCE_ADD_GID] = "VIRTIO_NET_CTRL_ROCE_ADD_GID",
	[VIRTIO_NET_CTRL_ROCE_DEL_GID] = "VIRTIO_NET_CTRL_ROCE_DEL_GID",
	[VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ] = "VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ",
};

static void ib_qp_cap_to_virtio_rdma(struct virtio_rdma_qp_cap *dst, const struct ib_qp_cap *src)
{
	dst->max_send_wr = src->max_send_wr;
	dst->max_recv_wr = src->max_recv_wr;
	dst->max_send_sge = src->max_send_sge;
	dst->max_recv_sge = src->max_recv_sge;
	dst->max_inline_data = src->max_inline_data;
}

static void virtio_rdma_to_ib_qp_cap(struct ib_qp_cap *dst, const struct virtio_rdma_qp_cap *src)
{
	dst->max_send_wr = src->max_send_wr;
	dst->max_recv_wr = src->max_recv_wr;
	dst->max_send_sge = src->max_send_sge;
	dst->max_recv_sge = src->max_recv_sge;
	dst->max_inline_data = src->max_inline_data;
}

void ib_global_route_to_virtio_rdma(struct virtio_rdma_global_route *dst,
			       const struct ib_global_route *src)
{
	memcpy(&dst->dgid, &src->dgid, sizeof(src->dgid));
	dst->flow_label = src->flow_label;
	dst->sgid_index = src->sgid_index;
	dst->hop_limit = src->hop_limit;
	dst->traffic_class = src->traffic_class;
}

void virtio_rdma_to_ib_global_route(struct ib_global_route *dst,
			       const struct virtio_rdma_global_route *src)
{
	memcpy(&dst->dgid, &src->dgid, sizeof(src->dgid));
	dst->flow_label = src->flow_label;
	dst->sgid_index = src->sgid_index;
	dst->hop_limit = src->hop_limit;
	dst->traffic_class = src->traffic_class;
}

void rdma_ah_attr_to_virtio_rdma(struct virtio_rdma_ah_attr *dst,
			    const struct rdma_ah_attr *src)
{
	ib_global_route_to_virtio_rdma(&dst->grh, rdma_ah_read_grh(src));
	memcpy(dst->dmac, src->roce.dmac, ETH_ALEN);
}

void virtio_rdma_to_rdma_ah_attr(struct rdma_ah_attr *dst,
			    const struct virtio_rdma_ah_attr *src)
{
	virtio_rdma_to_ib_global_route(rdma_ah_retrieve_grh(dst), &src->grh);
	memcpy(dst->roce.dmac, src->dmac, ETH_ALEN);
}

static int virtio_rdma_exec_cmd(struct virtio_rdma_dev *di, int cmd,
				struct scatterlist *out,
				struct scatterlist *in)
{
	struct net_device *netdev = di->netdev;
	bool rc;

	pr_info("%s: cmd %d %s\n", __func__, cmd, cmd_name[cmd]);
	spin_lock(&di->ctrl_lock);

	rc = virtnet_send_command(netdev, VIRTIO_NET_CTRL_ROCE, cmd, out, in);

	pr_info("EXEC cmd %d %s, status %d\n", cmd, cmd_name[cmd], rc);

	spin_unlock(&di->ctrl_lock);

	return rc ? 0 : -EINVAL;
}

static int virtio_rdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct virtio_rdma_pd *vpd = to_vpd(pd);
	struct ib_device *ibdev = pd->device;
	struct virtio_rdma_cmd_destroy_pd *cmd;
	struct scatterlist out;

	pr_debug("%s:\n", __func__);

	cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->pdn = vpd->pd_handle;
	sg_init_one(&out, cmd, sizeof(*cmd));

	virtio_rdma_exec_cmd(to_vdev(ibdev),
			     VIRTIO_NET_CTRL_ROCE_DESTROY_PD,
			     &out, NULL);

	kfree(cmd);
	return 0;
}

static int virtio_rdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct virtio_rdma_pd *pd = to_vpd(ibpd);
	struct ib_device *ibdev = ibpd->device;
	struct virtio_rdma_ack_create_pd *rsp;
	struct scatterlist in;
	int rc;

	rsp = kzalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp) {
		return -ENOMEM;
	}

	sg_init_one(&in, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(ibdev),
				  VIRTIO_NET_CTRL_ROCE_CREATE_PD,
				  NULL, &in);
	if (rc)
		goto out;

	pd->pd_handle = rsp->pdn;

	if (udata) {
		struct virtio_rdma_alloc_pd_uresp uresp = {};
		if (ib_copy_to_udata(udata, &uresp, sizeof(uresp))) {
			pr_warn("failed to copy back protection domain\n");
			virtio_rdma_dealloc_pd(&pd->ibpd, udata);
			return -EFAULT;
		}
	}

	pr_info("%s: pd_handle=%d\n", __func__, pd->pd_handle);

out:
	kfree(rsp);
	return rc;
}

static int virtio_rdma_create_cq(struct ib_cq *ibcq,
				    const struct ib_cq_init_attr *attr,
				    struct ib_udata *udata)
{
	struct scatterlist in, out;
	struct virtio_rdma_cq *vcq = to_vcq(ibcq);
	struct virtio_rdma_dev *vdev = to_vdev(ibcq->device);
	struct virtio_rdma_cmd_create_cq *cmd;
	struct virtio_rdma_ack_create_cq *rsp;
	struct scatterlist sg;
	int i, rc = -ENOMEM;
	int entries = attr->cqe;
	size_t total_size;
	struct virtio_rdma_user_mmap_entry* entry = NULL;

	if (!atomic_add_unless(&vdev->num_cq, 1, ibcq->device->attrs.max_cq))
		return -ENOMEM;

	total_size = vcq->queue_size = PAGE_ALIGN(entries * sizeof(*vcq->queue));
	vcq->queue = dma_alloc_coherent(vdev->vdev->dev.parent, vcq->queue_size,
					&vcq->dma_addr, GFP_KERNEL);
	if (!vcq->queue)
		return -ENOMEM;

	cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		goto err_cmd;

	rsp = kzalloc(sizeof(*rsp), GFP_ATOMIC);
	if (!rsp)
		goto err_rsp;
	
	if (udata) {
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry)
			goto err;
	}

	cmd->cqe = attr->cqe;
	sg_init_one(&out, cmd, sizeof(*cmd));
	sg_init_one(&in, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(vdev, VIRTIO_NET_CTRL_ROCE_CREATE_CQ,
				  &out, &in);
	if (rc)
		goto err;

	vcq->cq_handle = rsp->cqn;
	vcq->ibcq.cqe = entries;
	vcq->vq = &vdev->cq_vqs[rsp->cqn];
	vcq->num_cqe = entries;
	vdev->cqs[rsp->cqn] = vcq;

	if (udata) {
		struct virtio_rdma_create_cq_uresp uresp = {};
		struct virtio_rdma_ucontext *uctx = rdma_udata_to_drv_context(udata,
			struct virtio_rdma_ucontext, ibucontext);

		entry->type = VIRTIO_RDMA_MMAP_CQ;
		entry->queue = vcq->vq->vq;
		entry->ubuf = vcq->queue;
		entry->ubuf_size = vcq->queue_size;

		uresp.used_off = virtqueue_get_used_addr(vcq->vq->vq) -
					virtqueue_get_desc_addr(vcq->vq->vq);

		uresp.vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(vcq->vq->vq), SMP_CACHE_BYTES));
		total_size += uresp.vq_size;

		rc = rdma_user_mmap_entry_insert(&uctx->ibucontext, &entry->rdma_entry,
						total_size);
		if (rc)
			goto err;

		uresp.offset = rdma_user_mmap_get_offset(&entry->rdma_entry);
		uresp.cq_phys_addr = virt_to_phys(vcq->queue);
		uresp.num_cqe = entries;
		uresp.num_cvqe = virtqueue_get_vring_size(vcq->vq->vq);
		uresp.cq_size = total_size;

		if (udata->outlen < sizeof(uresp)) {
			rc = -EINVAL;
			goto err;
		}
		rc = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rc)
			goto err;

		vcq->entry = &entry->rdma_entry;
	} else {
		for(i = 0; i < entries; i++) {
			sg_init_one(&sg, vcq->queue + i, sizeof(*vcq->queue));
			virtqueue_add_inbuf(vcq->vq->vq, &sg, 1, vcq->queue + i, GFP_KERNEL);
		}
		BUG_ON(virtqueue_unused(vcq->vq->vq) != vcq->num_cqe);
	}

	spin_lock_init(&vcq->lock);

	kfree(rsp);
	kfree(cmd);
	return 0;

err:
	if (entry)
		kfree(entry);
	kfree(rsp);
err_rsp:
	kfree(cmd);
err_cmd:
	dma_free_coherent(vdev->vdev->dev.parent, vcq->queue_size,
			  vcq->queue, vcq->dma_addr);
	return rc;
}

static int virtio_rdma_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
	struct virtio_rdma_cq *vcq = to_vcq(cq);
	struct virtio_rdma_dev *vdev = to_vdev(cq->device);
	struct scatterlist out;
	struct virtio_rdma_cmd_destroy_cq *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->cqn = vcq->cq_handle;
	sg_init_one(&out, cmd, sizeof(*cmd));

	virtqueue_disable_cb(vcq->vq->vq);

	virtio_rdma_exec_cmd(to_vdev(cq->device),
			     VIRTIO_NET_CTRL_ROCE_DESTROY_CQ,
			     &out, NULL);

	/* pop all from virtqueue, after host call virtqueue_drop_all,
	 * prepare for next use.
	 */
	if (!udata)
		while(virtqueue_detach_unused_buf(vcq->vq->vq));

	atomic_dec(&to_vdev(cq->device)->num_cq);
	virtqueue_enable_cb(vcq->vq->vq);

	virtqueue_reset_vring(vcq->vq->vq);

	if (vcq->entry)
		rdma_user_mmap_entry_remove(vcq->entry);

	to_vdev(cq->device)->cqs[vcq->cq_handle] = NULL;

	dma_free_coherent(vdev->vdev->dev.parent, vcq->queue_size,
					vcq->queue, vcq->dma_addr);
	kfree(cmd);
	return 0;
}

int virtio_rdma_req_notify_cq(struct ib_cq *ibcq,
			      enum ib_cq_notify_flags flags)
{
	struct virtio_rdma_cq *vcq = to_vcq(ibcq);
	struct virtio_rdma_cmd_req_notify *cmd;
	struct scatterlist out;
	int rc;

	if (flags & IB_CQ_SOLICITED_MASK) {
		cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
		if (!cmd)
			return -ENOMEM;

		cmd->cqn = vcq->cq_handle;
		cmd->flags = (flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED ?
			VIRTIO_IB_CQ_SOLICITED : VIRTIO_IB_CQ_NEXT_COMP;

		sg_init_one(&out, cmd, sizeof(*cmd));

		rc = virtio_rdma_exec_cmd(to_vdev(ibcq->device),
					  VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ,
					  &out, NULL);
		
		kfree(cmd);
		if (rc)
			return -EIO;
	}

	if (flags & IB_CQ_REPORT_MISSED_EVENTS) {
		return (vcq->num_cqe != virtqueue_unused(vcq->vq->vq));
	}

	return 0;
}

static inline int to_virtio_access_flags(int ib_flags)
{
	int virtio_flags = 0;

	if (ib_flags & IB_ACCESS_LOCAL_WRITE)
		virtio_flags |= VIRTIO_IB_ACCESS_LOCAL_WRITE;
	if (ib_flags & IB_ACCESS_REMOTE_WRITE)
		virtio_flags |= VIRTIO_IB_ACCESS_REMOTE_WRITE;
	if (ib_flags & IB_ACCESS_REMOTE_READ)
		virtio_flags |= VIRTIO_IB_ACCESS_REMOTE_READ;

	return virtio_flags;
}

static inline int to_ib_access_flags(int virtio_flags)
{
	int ib_flags = 0;

	if (virtio_flags & VIRTIO_IB_ACCESS_LOCAL_WRITE)
		ib_flags |= VIRTIO_IB_ACCESS_LOCAL_WRITE;
	if (virtio_flags & IB_ACCESS_REMOTE_WRITE)
		ib_flags |= VIRTIO_IB_ACCESS_REMOTE_WRITE;
	if (virtio_flags & IB_ACCESS_REMOTE_READ)
		ib_flags |= VIRTIO_IB_ACCESS_REMOTE_READ;

	return ib_flags;
}

struct ib_mr *virtio_rdma_get_dma_mr(struct ib_pd *pd, int flags)
{
	struct virtio_rdma_mr *mr;
	struct scatterlist in, out;
	struct virtio_rdma_cmd_get_dma_mr *cmd;
	struct virtio_rdma_ack_get_dma_mr *rsp;
	int rc;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		kfree(mr);
		return ERR_PTR(-ENOMEM);
	}

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (!cmd) {
		kfree(mr);
		kfree(cmd);
		return ERR_PTR(-ENOMEM);
	}

	cmd->pdn = to_vpd(pd)->pd_handle;
	cmd->access_flags = to_virtio_access_flags(flags);

	sg_init_one(&out, cmd, sizeof(*cmd));
	sg_init_one(&in, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(pd->device),
				  VIRTIO_NET_CTRL_ROCE_GET_DMA_MR,
				  &out, &in);
	if (rc) {
		kfree(rsp);
		kfree(mr);
		kfree(cmd);
		return ERR_PTR(rc);
	}

	mr->mr_handle = rsp->mrn;
	mr->ibmr.lkey = rsp->lkey;
	mr->ibmr.rkey = rsp->rkey;

	kfree(cmd);
	kfree(rsp);

	return &mr->ibmr;
}

struct ib_mr *virtio_rdma_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				      u64 virt_addr, int access_flags,
				      struct ib_udata *udata)
{
	struct virtio_rdma_mr *mr;
	struct ib_umem *umem;
	struct ib_mr *ret = ERR_PTR(-ENOMEM);
	struct scatterlist in, out;
	struct virtio_rdma_cmd_reg_user_mr *cmd;
	struct virtio_rdma_ack_reg_user_mr *rsp;
	struct ib_block_iter biter;
	int i = 0;
	size_t npages, cmd_sz;

	pr_info("%s: start %llx, len %llu, addr %llx\n", __func__, start, length,
	        virt_addr);

	umem = ib_umem_get(pd->device, start, length, access_flags);
	if (IS_ERR(umem)) {
		pr_err("could not get umem for mem region\n");
		ret = ERR_CAST(umem);
		goto out;
	}

	npages = ib_umem_num_pages(umem);
	if (npages < 0 || npages > 512 * 512) { // two level page table
		pr_err("bad npages");
		ret = ERR_PTR(-EINVAL);
		goto out;
	}

	cmd_sz = sizeof(*cmd) + npages * sizeof(uint64_t);
	cmd = alloc_pages_exact(cmd_sz, GFP_KERNEL);
	if (!cmd) 
		return ERR_PTR(-ENOMEM);

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (!rsp) {
		ret = ERR_PTR(-ENOMEM);
		goto err_rsp;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	rdma_umem_for_each_dma_block(umem, &biter, PAGE_SIZE)
		cmd->pages[i++] = rdma_block_iter_dma_address(&biter);

	mr->npages = npages;
	mr->iova = virt_addr;
	mr->size = length;
	mr->umem = umem;

	cmd->pdn = to_vpd(pd)->pd_handle;
	cmd->access_flags = to_virtio_access_flags(access_flags);
	cmd->length = length;
	cmd->virt_addr = virt_addr;
	cmd->npages = npages;

	sg_init_one(&out, cmd, sizeof(*cmd));
	sg_init_one(&in, rsp, sizeof(*rsp));

	if (virtio_rdma_exec_cmd(to_vdev(pd->device),
				 VIRTIO_NET_CTRL_ROCE_REG_USER_MR,
				 &out, &in)) {
		ib_umem_release(umem);
		kfree(mr);
		ret = ERR_PTR(-EIO);
		goto err;
	}

	mr->mr_handle = rsp->mrn;
	mr->ibmr.lkey = rsp->lkey;
	mr->ibmr.rkey = rsp->rkey;

	printk("%s: mr_handle=0x%x\n", __func__, mr->mr_handle);

	ret = &mr->ibmr;
err:
	free_pages_exact(cmd, cmd_sz);
err_rsp:
	kfree(rsp);
out:
	return ret;
}

int virtio_rdma_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct virtio_rdma_mr *mr = to_vmr(ibmr);
	struct scatterlist out;
	struct virtio_rdma_cmd_dereg_mr *cmd;
	int rc = -ENOMEM;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->mrn = mr->mr_handle;

	sg_init_one(&out, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(to_vdev(ibmr->device),
				  VIRTIO_NET_CTRL_ROCE_DEREG_MR,
	                          &out, NULL);
	if (rc) {
		rc = -EIO;
		goto out;
	}
	if (udata)
		ib_umem_release(mr->umem);

	kfree(mr);
out:
	kfree(cmd);
	return rc;
}

static void* virtio_rdma_init_mmap_entry(struct virtio_rdma_dev *vdev,
		struct virtqueue *vq,
		struct virtio_rdma_user_mmap_entry** entry_, int buf_size,
		struct virtio_rdma_ucontext* vctx, __u64* size, __u64* used_off,
		__u32* vq_size, dma_addr_t *dma_addr)
{
	void* buf = NULL;
	int rc;
	size_t total_size;
	struct virtio_rdma_user_mmap_entry* entry;

	total_size = PAGE_ALIGN(buf_size);
	buf = dma_alloc_coherent(vdev->vdev->dev.parent, total_size,
							dma_addr, GFP_KERNEL);
	if (!buf)
		return NULL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		dma_free_coherent(vdev->vdev->dev.parent, total_size,
						buf, *dma_addr);
		return NULL;
	}

	entry->type = VIRTIO_RDMA_MMAP_QP;
	entry->queue = vq;
	entry->ubuf = buf;
	entry->ubuf_size = PAGE_ALIGN(buf_size);

	*used_off = virtqueue_get_used_addr(vq) - virtqueue_get_desc_addr(vq);
	*vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(vq), SMP_CACHE_BYTES));
	total_size += *vq_size;

	if (vdev->fast_doorbell)
		total_size += PAGE_SIZE;

	rc = rdma_user_mmap_entry_insert(&vctx->ibucontext, &entry->rdma_entry,
			total_size);
	if (rc) {
		dma_free_coherent(vdev->vdev->dev.parent, total_size,
						buf, *dma_addr);
		return NULL;
	}

	*size = total_size;
	*entry_ = entry;
	return buf;
}

static int virtio_rdma_qp_chk_cap(struct virtio_rdma_dev *dev,
				  struct ib_qp_cap *cap, int has_srq)
{
	if (cap->max_send_wr > dev->attr.max_qp_wr) {
		pr_warn("invalid send wr = %d > %d\n",
			cap->max_send_wr, dev->attr.max_qp_wr);
		return -EINVAL;
	}

	if (cap->max_send_sge > dev->attr.max_send_sge) {
		pr_warn("invalid send sge = %d > %d\n",
			cap->max_send_sge, dev->attr.max_send_sge);
		return -EINVAL;
        }

	if (!has_srq) {
		if (cap->max_recv_wr > dev->attr.max_qp_wr) {
			pr_warn("invalid recv wr = %d > %d\n",
				cap->max_recv_wr, dev->attr.max_qp_wr);
			return -EINVAL;
		}

		if (cap->max_recv_sge > dev->attr.max_recv_sge) {
			pr_warn("invalid recv sge = %d > %d\n",
				cap->max_recv_sge, dev->attr.max_recv_sge);
			return -EINVAL;
		}
	}

	// TODO: check max_inline_data

	return 0;
}

static int virtio_rdma_qp_chk_init(struct virtio_rdma_dev *dev,
				   struct ib_qp_init_attr *init)
{
	struct ib_qp_cap *cap = &init->cap;
	int port_num = init->port_num;

	// TODO: check qp type
	switch (init->qp_type) {
	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UC:
	case IB_QPT_UD:
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!init->recv_cq || !init->send_cq) {
		pr_warn("missing cq\n");
		return -EINVAL;
	}

	if (virtio_rdma_qp_chk_cap(dev, cap, !!init->srq))
		return -EINVAL;

	if (init->qp_type == IB_QPT_SMI || init->qp_type == IB_QPT_GSI) {
		if (!rdma_is_port_valid(&dev->ib_dev, port_num)) {
			pr_warn("invalid port = %d\n", port_num);
			return -EINVAL;
		}
	}

	return 0;
}

static inline u8 to_virtio_qp_type(u8 type)
{
	switch (type) {
	case IB_QPT_SMI:
		return VIRTIO_IB_QPT_SMI;
	case IB_QPT_GSI:
		return VIRTIO_IB_QPT_GSI;
	case IB_QPT_RC:
		return VIRTIO_IB_QPT_RC;
	case IB_QPT_UC:
		return VIRTIO_IB_QPT_UC;
	case IB_QPT_UD:
		return VIRTIO_IB_QPT_UD;
	}
	return -1;
}
int virtio_rdma_create_qp(struct ib_qp *ibqp,
				    struct ib_qp_init_attr *attr,
				    struct ib_udata *udata)
{
	struct scatterlist in, out;
	struct virtio_rdma_dev *vdev = to_vdev(ibqp->device);
	struct virtio_rdma_cmd_create_qp *cmd;
	struct virtio_rdma_ack_create_qp *rsp;
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct ib_pd *ibpd = ibqp->pd;
	int rc, vqn, ret = 0;

	if (attr->srq) {
		pr_err("srq not supported now");
		return -EOPNOTSUPP;
	}

	if (!atomic_add_unless(&vdev->num_qp, 1, vdev->ib_dev.attrs.max_qp))
		return -ENOMEM;

	if (virtio_rdma_qp_chk_init(vdev, attr))
		return -EINVAL;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->pdn = to_vpd(ibpd)->pd_handle;
	cmd->qp_type = to_virtio_qp_type(attr->qp_type);
	cmd->sq_sig_all = (attr->sq_sig_type == IB_SIGNAL_ALL_WR);
	cmd->send_cqn = to_vcq(attr->send_cq)->cq_handle;
	cmd->recv_cqn = to_vcq(attr->recv_cq)->cq_handle;
	cmd->cap.max_send_wr = attr->cap.max_send_wr;
	cmd->cap.max_send_sge = attr->cap.max_send_sge;
	cmd->cap.max_recv_wr = attr->cap.max_recv_wr;
	cmd->cap.max_recv_sge = attr->cap.max_recv_sge;
	cmd->cap.max_inline_data = attr->cap.max_inline_data;

	sg_init_one(&out, cmd, sizeof(*cmd));
	printk("%s: pdn %d\n", __func__, cmd->pdn);

	sg_init_one(&in, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(vdev,
				  VIRTIO_NET_CTRL_ROCE_CREATE_QP,
				  &out, &in);
	if (rc) {
		ret = -EIO;
		goto out;
	}

	vqp->type = udata ? VIRTIO_RDMA_TYPE_USER : VIRTIO_RDMA_TYPE_KERNEL;
	vqp->port = attr->port_num;
	vqp->qp_handle = rsp->qpn;
	vqp->ibqp.qp_num = rsp->qpn;
	vqp->sq_sig_type = attr->sq_sig_type;
	vqp->cap = attr->cap;

	vqn = rsp->qpn;
	vqp->sq = &vdev->qp_vqs[vqn * 2];
	vqp->rq = &vdev->qp_vqs[vqn * 2 + 1];

	if (udata) {
		struct virtio_rdma_create_qp_uresp uresp = {};
		struct virtio_rdma_ucontext *uctx = rdma_udata_to_drv_context(udata,
			struct virtio_rdma_ucontext, ibucontext);
		uint32_t per_size;

		per_size = sizeof(struct virtio_rdma_sq_req) +
				   sizeof(struct virtio_rdma_sge) * attr->cap.max_send_sge;
		vqp->usq_buf_size = PAGE_ALIGN(per_size * attr->cap.max_send_wr);
		vqp->usq_buf = virtio_rdma_init_mmap_entry(vdev, vqp->sq->vq,
						&vqp->sq_entry, vqp->usq_buf_size, uctx,
						&uresp.sq_size, &uresp.svq_used_off,
						&uresp.svq_size, &vqp->usq_dma_addr);
		if (!vqp->usq_buf)
			goto out;

		per_size = sizeof(struct virtio_rdma_rq_req) +
				   sizeof(struct virtio_rdma_sge) * attr->cap.max_recv_sge;
		vqp->urq_buf_size = PAGE_ALIGN(per_size * attr->cap.max_recv_wr);
		vqp->urq_buf = virtio_rdma_init_mmap_entry(vdev, vqp->rq->vq,
						&vqp->rq_entry, vqp->urq_buf_size, uctx,
						&uresp.rq_size, &uresp.rvq_used_off,
						&uresp.rvq_size, &vqp->urq_dma_addr);
		if (!vqp->urq_buf) {
			// TODO: pop sq entry
			dma_free_coherent(vdev->vdev->dev.parent, vqp->usq_buf_size,
							vqp->usq_buf, vqp->usq_dma_addr);
			goto out;
		}

		uresp.sq_offset = rdma_user_mmap_get_offset(&vqp->sq_entry->rdma_entry);
		uresp.sq_phys_addr = vqp->usq_dma_addr;
		uresp.num_sqe = attr->cap.max_send_wr;
		uresp.num_svqe = virtqueue_get_vring_size(vqp->sq->vq);
		uresp.sq_idx = vqp->sq->vq->index;

		uresp.rq_offset = rdma_user_mmap_get_offset(&vqp->rq_entry->rdma_entry);
		uresp.rq_phys_addr = vqp->urq_dma_addr;
		uresp.num_rqe = attr->cap.max_recv_wr;
		uresp.num_rvqe = virtqueue_get_vring_size(vqp->rq->vq);
		uresp.rq_idx = vqp->rq->vq->index;

		uresp.notifier_size = vdev->fast_doorbell ? PAGE_SIZE : 0;
		uresp.qpn = vqp->qp_handle;

		if (udata->outlen < sizeof(uresp)) {
			rc = -EINVAL;
			goto out_err_u;
		}
		rc = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rc)
			goto out_err_u;
	}

	pr_info("%s: qpn 0x%x wq %d rq %d\n", __func__, rsp->qpn,
	        vqp->sq->vq->index, vqp->rq->vq->index);
	vdev->qps[rsp->qpn] = vqp;
	goto out;

out_err_u:
	dma_free_coherent(vdev->vdev->dev.parent, vqp->usq_buf_size,
					vqp->usq_buf, vqp->usq_dma_addr);
	dma_free_coherent(vdev->vdev->dev.parent, vqp->urq_buf_size,
					vqp->urq_buf, vqp->urq_dma_addr);
	rdma_user_mmap_entry_remove(&vqp->sq_entry->rdma_entry);
	rdma_user_mmap_entry_remove(&vqp->rq_entry->rdma_entry);
out:
	kfree(rsp);
	kfree(cmd);
	return ret;
}

int virtio_rdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct virtio_rdma_dev *vdev = to_vdev(ibqp->device);
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct scatterlist out;
	struct virtio_rdma_cmd_destroy_qp *cmd;
	int rc;

	pr_info("%s: qpn %d\n", __func__, vqp->qp_handle);

	cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd)
		return -ENOMEM;

	cmd->qpn = vqp->qp_handle;

	sg_init_one(&out, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(vdev,
				  VIRTIO_NET_CTRL_ROCE_DESTROY_QP,
	                          &out, NULL);

	if (udata) {
		dma_free_coherent(vdev->vdev->dev.parent, vqp->usq_buf_size,
						vqp->usq_buf, vqp->usq_dma_addr);
		dma_free_coherent(vdev->vdev->dev.parent, vqp->urq_buf_size,
						vqp->urq_buf, vqp->urq_dma_addr);
		rdma_user_mmap_entry_remove(&vqp->sq_entry->rdma_entry);
		rdma_user_mmap_entry_remove(&vqp->rq_entry->rdma_entry);
	}

	virtqueue_reset_vring(vqp->sq->vq);
	virtqueue_reset_vring(vqp->rq->vq);

	vdev->qps[cmd->qpn] = NULL;
	atomic_dec(&vdev->num_qp);

	kfree(cmd);
	return rc;
}

static inline u8 to_virtio_path_mtu(u8 mtu)
{
	switch (mtu) {
	case IB_MTU_256:
		return VIRTIO_IB_MTU_256;
	case IB_MTU_512:
		return VIRTIO_IB_MTU_512;
	case IB_MTU_1024:
		return VIRTIO_IB_MTU_1024;
	case IB_MTU_2048:
		return VIRTIO_IB_MTU_2048;
	case IB_MTU_4096:
		return VIRTIO_IB_MTU_4096;
	}
	return -1;
}

static inline u8 to_ib_path_mtu(u8 mtu)
{
	switch (mtu) {
	case VIRTIO_IB_MTU_256:
		return IB_MTU_256;
	case VIRTIO_IB_MTU_512:
		return IB_MTU_512;
	case VIRTIO_IB_MTU_1024:
		return IB_MTU_1024;
	case VIRTIO_IB_MTU_2048:
		return IB_MTU_2048;
	case VIRTIO_IB_MTU_4096:
		return IB_MTU_4096;
	}
	return -1;
}

static inline u8 to_virtio_qp_state(u8 state)
{
	switch (state) {
	case IB_QPS_RESET:
		return VIRTIO_IB_QPS_RESET;
	case IB_QPS_INIT:
		return VIRTIO_IB_QPS_INIT;
	case IB_QPS_RTR:
		return VIRTIO_IB_QPS_RTR;
	case IB_QPS_RTS:
		return VIRTIO_IB_QPS_RTS;
	case IB_QPS_SQD:
		return VIRTIO_IB_QPS_SQD;
	case IB_QPS_SQE:
		return VIRTIO_IB_QPS_SQE;
	case IB_QPS_ERR:
		return VIRTIO_IB_QPS_ERR;
	}
	return -1;
}

static inline u8 to_ib_qp_state(u8 state)
{
	switch (state) {
	case VIRTIO_IB_QPS_RESET:
		return IB_QPS_RESET;
	case VIRTIO_IB_QPS_INIT:
		return IB_QPS_INIT;
	case VIRTIO_IB_QPS_RTR:
		return IB_QPS_RTR;
	case VIRTIO_IB_QPS_RTS:
		return IB_QPS_RTS;
	case VIRTIO_IB_QPS_SQD:
		return IB_QPS_SQD;
	case VIRTIO_IB_QPS_SQE:
		return IB_QPS_SQE;
	case VIRTIO_IB_QPS_ERR:
		return IB_QPS_ERR;
	}
	return -1;
}

static inline u32 to_virtio_qp_attr_mask(u32 attr_mask)
{
	u32 virtio_attr_mask = 0;

	if (attr_mask & IB_QP_STATE)
		virtio_attr_mask |= VIRTIO_IB_QP_STATE;
	if (attr_mask & IB_QP_CUR_STATE)
		virtio_attr_mask |= VIRTIO_IB_QP_CUR_STATE;
	if (attr_mask & IB_QP_ACCESS_FLAGS)
		virtio_attr_mask |= VIRTIO_IB_QP_ACCESS_FLAGS;
	if (attr_mask & IB_QP_QKEY)
		virtio_attr_mask |= VIRTIO_IB_QP_QKEY;
	if (attr_mask & IB_QP_AV)
		virtio_attr_mask |= VIRTIO_IB_QP_AV;
	if (attr_mask & IB_QP_PATH_MTU)
		virtio_attr_mask |= VIRTIO_IB_QP_PATH_MTU;
	if (attr_mask & IB_QP_TIMEOUT)
		virtio_attr_mask |= VIRTIO_IB_QP_TIMEOUT;
	if (attr_mask & IB_QP_RETRY_CNT)
		virtio_attr_mask |= VIRTIO_IB_QP_RETRY_CNT;
	if (attr_mask & IB_QP_RNR_RETRY)
		virtio_attr_mask |= VIRTIO_IB_QP_RNR_RETRY;
	if (attr_mask & IB_QP_RQ_PSN)
		virtio_attr_mask |= VIRTIO_IB_QP_RQ_PSN;
	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC)
		virtio_attr_mask |= VIRTIO_IB_QP_MAX_QP_RD_ATOMIC;
	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		virtio_attr_mask |= VIRTIO_IB_QP_MIN_RNR_TIMER;
	if (attr_mask & IB_QP_SQ_PSN)
		virtio_attr_mask |= VIRTIO_IB_QP_SQ_PSN;
	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		virtio_attr_mask |= VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC;
	if (attr_mask & IB_QP_CAP)
		virtio_attr_mask |= VIRTIO_IB_QP_CAP;
	if (attr_mask & IB_QP_DEST_QPN)
		virtio_attr_mask |= VIRTIO_IB_QP_DEST_QPN;
	if (attr_mask & IB_QP_RATE_LIMIT)
		virtio_attr_mask |= VIRTIO_IB_QP_RATE_LIMIT;

	return virtio_attr_mask;
}

int virtio_rdma_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			  int attr_mask, struct ib_udata *udata)
{
	struct scatterlist out;
	struct virtio_rdma_cmd_modify_qp *cmd;
	int rc;

	pr_info("%s: qpn %d\n", __func__, to_vqp(ibqp)->qp_handle);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->qpn = to_vqp(ibqp)->qp_handle;
	cmd->attr_mask = to_virtio_qp_attr_mask(attr_mask);

	// TODO: attr mask validation
	cmd->qp_state = to_virtio_qp_state(attr->qp_state);
	cmd->cur_qp_state = to_virtio_qp_state(attr->cur_qp_state);
	cmd->path_mtu = to_virtio_path_mtu(attr->path_mtu);
	cmd->qkey = attr->qkey;
	cmd->rq_psn = attr->rq_psn;
	cmd->sq_psn = attr->sq_psn;
	cmd->dest_qp_num = attr->dest_qp_num;
	cmd->qp_access_flags = to_virtio_access_flags(attr->qp_access_flags);
	cmd->max_rd_atomic = attr->max_rd_atomic;
	cmd->max_dest_rd_atomic = attr->max_dest_rd_atomic;
	cmd->min_rnr_timer = attr->min_rnr_timer;
	cmd->timeout = attr->timeout;
	cmd->retry_cnt = attr->retry_cnt;
	cmd->rnr_retry = attr->rnr_retry;
	ib_qp_cap_to_virtio_rdma(&cmd->cap, &attr->cap);
	rdma_ah_attr_to_virtio_rdma(&cmd->ah_attr, &attr->ah_attr);

	sg_init_one(&out, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(to_vdev(ibqp->device),
				  VIRTIO_NET_CTRL_ROCE_MODIFY_QP,
	                          &out, NULL);

	kfree(cmd);
	return rc;
}

int virtio_rdma_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct scatterlist in, out;
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct virtio_rdma_dev *vdev = to_vdev(ibqp->device);
	struct virtio_rdma_cmd_query_qp *cmd;
	struct virtio_rdma_ack_query_qp *rsp;
	int rc;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	cmd->qpn = vqp->qp_handle;
	cmd->attr_mask = to_virtio_qp_attr_mask(attr_mask);

	sg_init_one(&out, cmd, sizeof(*cmd));
	sg_init_one(&in, rsp, sizeof(*rsp));
	rc = virtio_rdma_exec_cmd(vdev,
				  VIRTIO_NET_CTRL_ROCE_QUERY_QP,
	                          &out, &in);

	if (rc)
		goto out;

	attr->qp_state = to_ib_qp_state(rsp->qp_state);
	attr->path_mtu = to_ib_path_mtu(rsp->path_mtu);
	attr->qkey = rsp->qkey;
	attr->rq_psn = rsp->rq_psn;
	attr->sq_psn = rsp->sq_psn;
	attr->dest_qp_num = rsp->dest_qp_num;
	attr->qp_access_flags = rsp->qp_access_flags;
	attr->sq_draining = rsp->sq_draining;
	attr->max_rd_atomic = rsp->max_rd_atomic;
	attr->max_dest_rd_atomic = rsp->max_dest_rd_atomic;
	attr->min_rnr_timer = rsp->min_rnr_timer;
	attr->timeout = rsp->timeout;
	attr->retry_cnt = rsp->retry_cnt;
	attr->rnr_retry = rsp->rnr_retry;
	attr->rate_limit = rsp->rate_limit;
	attr->pkey_index = 0;
	virtio_rdma_to_ib_qp_cap(&attr->cap, &rsp->cap);
	virtio_rdma_to_rdma_ah_attr(&attr->ah_attr, &rsp->ah_attr);

out:
	init_attr->event_handler = vqp->ibqp.event_handler;
	init_attr->qp_context = vqp->ibqp.qp_context;
	init_attr->send_cq = vqp->ibqp.send_cq;
	init_attr->recv_cq = vqp->ibqp.recv_cq;
	init_attr->srq = vqp->ibqp.srq;
	init_attr->xrcd = NULL;
	init_attr->cap = vqp->cap;
	// FIXME: not zero
	init_attr->sq_sig_type = vqp->sq_sig_type;
	init_attr->qp_type = vqp->ibqp.qp_type;
	init_attr->port_num = vqp->port;

	kfree(cmd);
	kfree(rsp);
	return rc;
}

static int virtio_rdma_mmap(struct ib_ucontext *ctx,
			    struct vm_area_struct *vma)
{
	struct virtio_rdma_ucontext *uctx = to_vucontext(ctx);
	size_t size = vma->vm_end - vma->vm_start;
	struct rdma_user_mmap_entry *rdma_entry;
	struct virtio_rdma_user_mmap_entry *entry;
	uint64_t vq_size;
	int rc = -EINVAL;

	if (vma->vm_start & (PAGE_SIZE - 1)) {
		pr_warn("mmap not page aligned\n");
		return -EINVAL;
	}

	rdma_entry = rdma_user_mmap_entry_get(&uctx->ibucontext, vma);
	if (!rdma_entry) {
		pr_err("mmap lookup failed: %lu, %#zx\n", vma->vm_pgoff, size);
		return -EINVAL;
	}

	entry = to_ventry(rdma_entry);
	vq_size = PAGE_ALIGN(vring_size(virtqueue_get_vring_size(entry->queue),
			     SMP_CACHE_BYTES));

	if (entry->type == VIRTIO_RDMA_MMAP_CQ) {
		WARN_ON(vq_size + entry->ubuf_size !=
			vma->vm_end - vma->vm_start);

		// vring
		rc = remap_pfn_range(vma, vma->vm_start,
				     page_to_pfn(virt_to_page(
				     virtqueue_get_vring(entry->queue)->desc)),
				     vq_size, vma->vm_page_prot);

		// user buffer
		rc = remap_pfn_range(vma, vma->vm_start + vq_size,
				     page_to_pfn(virt_to_page(entry->ubuf)),
				     entry->ubuf_size, vma->vm_page_prot);
		if (rc) {
			pr_warn("remap_pfn_range failed: %lu, %zu\n",
				vma->vm_pgoff, size);
			goto out;
		}
	} else if (entry->type == VIRTIO_RDMA_MMAP_QP) {
		uint64_t total_size = vq_size + entry->ubuf_size;

		if (uctx->dev->fast_doorbell)
			total_size += PAGE_SIZE;

		WARN_ON(total_size != vma->vm_end - vma->vm_start);

		// vring
		rc = remap_pfn_range(vma, vma->vm_start,
				     page_to_pfn(virt_to_page(
				     virtqueue_get_vring(entry->queue)->desc)),
				     vq_size, vma->vm_page_prot);

		// user buffer
		rc = remap_pfn_range(vma, vma->vm_start + vq_size,
				     page_to_pfn(virt_to_page(entry->ubuf)),
				     entry->ubuf_size, vma->vm_page_prot);

		// doorbell
		if (uctx->dev->fast_doorbell) {
			rc = io_remap_pfn_range(vma, vma->vm_start + vq_size +
						entry->ubuf_size,
			vmalloc_to_pfn(entry->queue->priv), PAGE_SIZE,
				       vma->vm_page_prot);
		}

		if (rc) {
			pr_warn("remap_pfn_range failed: %lu, %zu\n",
				vma->vm_pgoff, size);
			goto out;
		}
	} else {
		pr_err("Invalid type");
	}
out:
	rdma_user_mmap_entry_put(rdma_entry);

	return rc;
}

static void virtio_rdma_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct virtio_rdma_user_mmap_entry *entry = to_ventry(rdma_entry);

	kfree(entry);
}

static int virtio_rdma_add_gid(const struct ib_gid_attr *attr, void **context)
{
	struct virtio_rdma_cmd_add_gid *cmd;
	struct scatterlist out;
	int rc;

	if (attr->port_num != 1)
		return -EINVAL;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->index = attr->index;
	memcpy(cmd->gid, attr->gid.raw, sizeof(cmd->gid));

	sg_init_one(&out, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(to_vdev(attr->device),
				  VIRTIO_NET_CTRL_ROCE_ADD_GID,
				  &out, NULL);

	printk("%s: add gid %d\n", __func__, attr->index);

	kfree(cmd);
	return rc;
}

static int virtio_rdma_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct virtio_rdma_cmd_del_gid *cmd;
	struct scatterlist out;
	int rc;

	if (attr->port_num != 1)
		return -EINVAL;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->index = attr->index;

	sg_init_one(&out, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(to_vdev(attr->device),
				  VIRTIO_NET_CTRL_ROCE_DEL_GID,
				  &out, NULL);

	printk("%s: del gid %d\n", __func__, attr->index);

	kfree(cmd);
	return rc;
}

int virtio_rdma_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	struct virtio_rdma_ucontext *vuc = to_vucontext(uctx);

	vuc->dev = to_vdev(uctx->device);

	return 0;
}

static void virtio_rdma_dealloc_ucontext(struct ib_ucontext *ibcontext)
{

}

static int virtio_rdma_create_ah(struct ib_ah *ibah,
				 struct rdma_ah_init_attr *init_attr,
				 struct ib_udata *udata)
{
	struct virtio_rdma_dev *vdev = to_vdev(ibah->device);
	struct virtio_rdma_ah *ah = to_vah(ibah);
	struct virtio_rdma_create_ah_uresp uresp = {};
	const struct ib_global_route *grh;
	struct virtio_rdma_cmd_create_ah *cmd;
	struct virtio_rdma_ack_create_ah *rsp;
	struct scatterlist in, out;
	int rc, alloc_flags;

	if (!(rdma_ah_get_ah_flags(init_attr->ah_attr) & IB_AH_GRH))
		return -EINVAL;

	alloc_flags = (init_attr->flags & RDMA_CREATE_AH_SLEEPABLE) ?
		      GFP_KERNEL : GFP_ATOMIC;

	cmd = kzalloc(sizeof(*cmd), alloc_flags);
	if (!cmd)
		return -ENOMEM;

	rsp = kzalloc(sizeof(*rsp), alloc_flags);
	if (!rsp) {
		kfree(cmd);
		return -ENOMEM;
	}

	grh = rdma_ah_read_grh(init_attr->ah_attr);

	cmd->ah_attr.grh.flow_label = grh->flow_label;
	cmd->ah_attr.grh.sgid_index = grh->sgid_index;
	cmd->ah_attr.grh.hop_limit = grh->hop_limit;
	cmd->ah_attr.grh.traffic_class = grh->traffic_class;
	memcpy(cmd->ah_attr.grh.dgid, grh->dgid.raw, 16);
	memcpy(cmd->ah_attr.dmac, init_attr->ah_attr->roce.dmac, ETH_ALEN);

	cmd->pdn = to_vpd(ibah->pd)->pd_handle;

	sg_init_one(&out, cmd, sizeof(*cmd));
	sg_init_one(&in, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(vdev,
				  VIRTIO_NET_CTRL_ROCE_CREATE_AH,
				  &out, &in);
	uresp.ah = ah->ah_num = rsp->ah;

	if (udata)
		rc = ib_copy_to_udata(udata, &uresp, sizeof(uresp));

	printk("%s: create ah %d\n", __func__, rsp->ah);

	kfree(cmd);
	kfree(rsp);
	return rc;
}

static int virtio_rdma_destroy_ah(struct ib_ah *ibah, u32 flags)
{
	struct virtio_rdma_dev *vdev = to_vdev(ibah->device);
	struct virtio_rdma_ah *ah = to_vah(ibah);
	struct virtio_rdma_cmd_destroy_ah *cmd;
	struct scatterlist out;
	int rc;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->pdn = to_vpd(ibah->pd)->pd_handle;
	cmd->ah = ah->ah_num;

	sg_init_one(&out, cmd, sizeof(*cmd));

	rc = virtio_rdma_exec_cmd(vdev,
				  VIRTIO_NET_CTRL_ROCE_DESTROY_AH,
				  &out, NULL);

	printk("%s:\n", __func__);
	kfree(cmd);

	return rc;
}

static int virtio_rdma_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
				  u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = IB_DEFAULT_PKEY_FULL;
	return 0;
}

static inline u8 to_ib_status(u8 status)
{
	switch (status) {
	case VIRTIO_IB_WC_SUCCESS:
		return IB_WC_SUCCESS;
	case VIRTIO_IB_WC_LOC_LEN_ERR:
		return IB_WC_LOC_LEN_ERR;
	case VIRTIO_IB_WC_LOC_QP_OP_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case VIRTIO_IB_WC_LOC_PROT_ERR:
		return IB_WC_LOC_PROT_ERR;
	case VIRTIO_IB_WC_WR_FLUSH_ERR:
		return IB_WC_WR_FLUSH_ERR;
	case VIRTIO_IB_WC_BAD_RESP_ERR:
		return IB_WC_BAD_RESP_ERR;
	case VIRTIO_IB_WC_LOC_ACCESS_ERR:
		return IB_WC_LOC_ACCESS_ERR;
	case VIRTIO_IB_WC_REM_INV_REQ_ERR:
		return IB_WC_REM_INV_REQ_ERR;
	case VIRTIO_IB_WC_REM_ACCESS_ERR:
		return IB_WC_REM_ACCESS_ERR;
	case VIRTIO_IB_WC_REM_OP_ERR:
		return IB_WC_REM_OP_ERR;
	case VIRTIO_IB_WC_RETRY_EXC_ERR:
		return IB_WC_RETRY_EXC_ERR;
	case VIRTIO_IB_WC_RNR_RETRY_EXC_ERR:
		return IB_WC_RNR_RETRY_EXC_ERR;
	case VIRTIO_IB_WC_REM_ABORT_ERR:
		return IB_WC_REM_ABORT_ERR;
	case VIRTIO_IB_WC_FATAL_ERR:
		return IB_WC_FATAL_ERR;
	case VIRTIO_IB_WC_RESP_TIMEOUT_ERR:
		return IB_WC_RESP_TIMEOUT_ERR;
	case VIRTIO_IB_WC_GENERAL_ERR:
		return IB_WC_GENERAL_ERR;
	}
	return -1;
}

static inline u8 to_ib_wc_opcode(u8 opcode)
{
	switch (opcode) {
	case VIRTIO_IB_WC_SEND:
		return IB_WC_SEND;
	case VIRTIO_IB_WC_RDMA_WRITE:
		return IB_WC_RDMA_WRITE;
	case VIRTIO_IB_WC_RDMA_READ:
		return IB_WC_RDMA_READ;
	case VIRTIO_IB_WC_RECV:
		return IB_WC_RECV;
	case VIRTIO_IB_WC_RECV_RDMA_WITH_IMM:
		return IB_WC_RECV_RDMA_WITH_IMM;
	}
	return -1;
}

static inline u8 to_virtio_wr_opcode(u8 opcode)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:
		return VIRTIO_IB_WR_RDMA_WRITE;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		return VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM;
	case IB_WR_SEND:
		return VIRTIO_IB_WR_SEND;
	case IB_WR_SEND_WITH_IMM:
		return VIRTIO_IB_WR_SEND_WITH_IMM;
	case IB_WR_RDMA_READ:
		return VIRTIO_IB_WR_RDMA_READ;
	}
	return -1;
}

static inline u8 to_ib_wc_flags(u8 flags)
{
	switch (flags) {
	case VIRTIO_IB_WC_GRH:
		return IB_WC_GRH;
	case VIRTIO_IB_WC_WITH_IMM:
		return IB_WC_WITH_IMM;
	}
	return -1;
}

int virtio_rdma_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct virtio_rdma_dev *vdev = to_vdev(ibcq->device);
	struct virtio_rdma_cq *vcq = to_vcq(ibcq);
	struct virtio_rdma_cq_req *req;
	int i = 0;
	unsigned long flags;
	unsigned int tmp;
	struct scatterlist sg;
	struct virtqueue *vq = vcq->vq->vq;

	spin_lock_irqsave(&vcq->lock, flags);
	while (i < num_entries) {
		req = virtqueue_get_buf(vq, &tmp);
		if (!req)
			break;

		wc[i].wr_id = req->wr_id;
		wc[i].status = to_ib_status(req->status);
		wc[i].opcode = to_ib_wc_opcode(req->opcode);
		wc[i].vendor_err = req->vendor_err;
		wc[i].byte_len = req->byte_len;
		wc[i].qp = &vdev->qps[req->qp_num]->ibqp;
		wc[i].ex.imm_data = req->imm_data;
		wc[i].src_qp = req->src_qp;
		wc[i].wc_flags = to_ib_wc_flags(req->wc_flags);
		wc[i].pkey_index = 0;

		sg_init_one(&sg, req, sizeof(*req));
		virtqueue_add_inbuf(vq, &sg, 1, req, GFP_KERNEL);
		i++;
	}
	spin_unlock_irqrestore(&vcq->lock, flags);
	return i;
}

int virtio_rdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
			  const struct ib_recv_wr **bad_wr)
{
	struct scatterlist *sgs[1], hdr;
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct virtio_rdma_rq_req *req = NULL;
	int rc = 0, tmp;
	unsigned int sgl_len;
	void* ptr;

	if (vqp->type == VIRTIO_RDMA_TYPE_USER)
		goto kick_vq;

	if (vqp->ibqp.qp_type == IB_QPT_SMI)
		return -EOPNOTSUPP;

	spin_lock(&vqp->rq->lock);

	// TODO: check bad wr
	while (wr) {
		while ((ptr = virtqueue_get_buf(vqp->rq->vq, &tmp)) != NULL) {
			kfree(ptr);
		}

		sgl_len = sizeof(struct virtio_rdma_sge) * wr->num_sge;
		req = kzalloc(sizeof(*req) + sgl_len, GFP_KERNEL);
		if (!req) {
			rc = -ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		req->num_sge = wr->num_sge;
		req->wr_id = wr->wr_id;
		memcpy(req->sg_list, wr->sg_list, sgl_len);

		sg_init_one(&hdr, req, sizeof(*req) + sgl_len);
		sgs[0] = &hdr;

		rc = virtqueue_add_sgs(vqp->rq->vq, sgs, 1, 0, req, GFP_KERNEL);
		if (rc) {
			pr_err("post recv err %d", rc);
			*bad_wr = wr;
			goto out;
		}
		wr = wr->next;
		req = NULL;
	}

out:
	spin_unlock(&vqp->rq->lock);

	kfree(req);
kick_vq:
	virtqueue_kick(vqp->rq->vq);
	return rc;
}

static void copy_inline_data_to_wqe(struct virtio_rdma_sq_req *req,
				    const struct ib_send_wr *ibwr)
{
	struct ib_sge *sge = ibwr->sg_list;
	char *p = (char *)req->inline_data;
	int i;

	for (i = 0; i < ibwr->num_sge; i++, sge++) {
		memcpy(p, (void *)(uintptr_t)sge->addr, sge->length);
		p += sge->length;
		req->inline_len += sge->length;
	}
}

static inline u8 to_virtio_send_flags(u8 flags)
{
	switch (flags) {
	case IB_SEND_FENCE:
		return VIRTIO_IB_SEND_FENCE;
	case IB_SEND_SIGNALED:
		return VIRTIO_IB_SEND_SIGNALED;
	case IB_SEND_SOLICITED:
		return VIRTIO_IB_SEND_SOLICITED;
	case IB_SEND_INLINE:
		return VIRTIO_IB_SEND_INLINE;
	}
	return -1;
}

int virtio_rdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			  const struct ib_send_wr **bad_wr)
{
	struct scatterlist *sgs[1], hdr;
	struct virtio_rdma_qp *vqp = to_vqp(ibqp);
	struct virtio_rdma_sq_req *req = NULL;
	int rc = 0;
	unsigned tmp;
	unsigned int sgl_len = 0;
	void* ptr;

	if (vqp->type == VIRTIO_RDMA_TYPE_USER)
		goto kick_vq;

	spin_lock(&vqp->sq->lock);

	while (wr) {
		while ((ptr = virtqueue_get_buf(vqp->rq->vq, &tmp)) != NULL) {
			kfree(ptr);
		}

		if (!(wr->send_flags & IB_SEND_INLINE))
			sgl_len = sizeof(struct virtio_rdma_sge) * wr->num_sge;

		req = kzalloc(sizeof(*req) + sgl_len, GFP_KERNEL);
		if (!req) {
			*bad_wr = wr;
			rc = -ENOMEM;
			goto out;
		}

		req->num_sge = wr->num_sge;
		req->send_flags = to_virtio_send_flags(wr->send_flags);
		req->opcode = to_virtio_wr_opcode(wr->opcode);
		req->wr_id = wr->wr_id;
		req->imm_data = wr->ex.imm_data;

		switch (ibqp->qp_type) {
		case IB_QPT_GSI:
		case IB_QPT_UD:
			if (unlikely(!ud_wr(wr)->ah)) {
				pr_warn("invalid address handle\n");
				*bad_wr = wr;
				rc = -EINVAL;
				goto out;
			}
			req->ud.remote_qpn = ud_wr(wr)->remote_qpn;
			req->ud.remote_qkey = ud_wr(wr)->remote_qkey;
			req->ud.ah = to_vah(ud_wr(wr)->ah)->ah_num;
			break;
		case IB_QPT_RC:
			switch (wr->opcode) {
			case IB_WR_RDMA_READ:
			case IB_WR_RDMA_WRITE:
			case IB_WR_RDMA_WRITE_WITH_IMM:
				req->rdma.remote_addr =
					rdma_wr(wr)->remote_addr;
				req->rdma.rkey = rdma_wr(wr)->rkey;
				break;
			default:
				rc = -EOPNOTSUPP;
				goto out;
			}
			break;
		default:
			pr_err("Bad qp type\n");
			rc = -EINVAL;
			goto out;
		}

		// TODO: check max_inline_data
		if (unlikely(wr->send_flags & IB_SEND_INLINE))
			copy_inline_data_to_wqe(req, wr);
		else
			memcpy(req->sg_list, wr->sg_list, sgl_len);

		sg_init_one(&hdr, req, sizeof(*req) + sgl_len);
		sgs[0] = &hdr;

		rc = virtqueue_add_sgs(vqp->sq->vq, sgs, 1, 0, req, GFP_KERNEL);
		if (rc) {
			pr_err("post send err %d", rc);
			*bad_wr = wr;
			goto out;
		}
		req = NULL;
		wr = wr->next;
	}

out:
	spin_unlock(&vqp->sq->lock);
	kfree(req);
kick_vq:
	virtqueue_kick(vqp->sq->vq);
	return rc;
}

static int virtio_rdma_port_immutable(struct ib_device *ibdev, u32 port_num,
				      struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int rc;

	rc = ib_query_port(ibdev, port_num, &attr);
	if (rc)
		return rc;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

static int virtio_rdma_query_device(struct ib_device *ibdev,
				    struct ib_device_attr *props,
				    struct ib_udata *uhw)
{
	struct virtio_rdma_dev *ri = to_vdev(ibdev);
	struct virtio_rdma_ack_query_device *rsp;
	struct scatterlist in;
	int rc;

	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	sg_init_one(&in, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(ibdev),
				  VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE,
				  NULL, &in);
	if (rc)
		goto out;

	props->hw_ver = rsp->hw_ver;
	props->max_mr_size = rsp->max_mr_size;
	props->page_size_cap = rsp->page_size_cap;
	props->max_qp_wr = rsp->max_qp_wr;
	props->device_cap_flags = IB_DEVICE_SYS_IMAGE_GUID;
	if (rsp->device_cap_flags & VIRTIO_IB_DEVICE_RC_RNR_NAK_GEN)
		props->device_cap_flags |= IB_DEVICE_RC_RNR_NAK_GEN;
	props->max_send_sge = rsp->max_send_sge;
	props->max_recv_sge = rsp->max_recv_sge;
	props->max_sge_rd = rsp->max_sge_rd;
	props->max_cqe = rsp->max_cqe;
	props->max_mr = rsp->max_mr;
	props->max_pd = rsp->max_pd;
	props->max_qp_rd_atom = rsp->max_qp_rd_atom;
	props->max_qp_init_rd_atom = rsp->max_qp_init_rd_atom;
	props->max_ah = rsp->max_ah;
	props->local_ca_ack_delay = rsp->local_ca_ack_delay;

	props->max_qp = ri->max_qp;
	props->max_cq = ri->max_cq;
	props->vendor_id = ri->vdev->id.vendor;
	props->vendor_part_id = ri->vdev->id.device;
	props->max_pkeys = 1;
	addrconf_addr_eui48((unsigned char *)&props->sys_image_guid,
				ri->netdev->dev_addr);

	memcpy(&ri->attr, props, sizeof(ri->attr));
out:
	kfree(rsp);
	return rc;
}

static int virtio_rdma_query_port(struct ib_device *ibdev, u32 port,
				  struct ib_port_attr *props)
{
	struct virtio_rdma_dev *ri = to_vdev(ibdev);
	struct virtio_rdma_ack_query_port *rsp;
	struct scatterlist out;
	int rc;

	if (port != 1)
		return -EINVAL;

	rsp = kzalloc(sizeof(*rsp), GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	sg_init_one(&out, rsp, sizeof(*rsp));

	rc = virtio_rdma_exec_cmd(to_vdev(ibdev),
				  VIRTIO_NET_CTRL_ROCE_QUERY_PORT,
				  NULL, &out);
	if (rc)
		goto out;

	props->gid_tbl_len = rsp->gid_tbl_len;
	props->max_msg_sz = rsp->max_msg_sz;

	props->state = IB_PORT_ACTIVE;
	props->max_mtu = ib_mtu_int_to_enum(ri->mtu);
	props->active_mtu = ib_mtu_int_to_enum(ri->mtu);
	props->ip_gids = 1;
	props->port_cap_flags = IB_PORT_CM_SUP;
	props->pkey_tbl_len = 1;
	props->max_vl_num = 1;
	props->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	ib_get_eth_speed(ibdev, port, &props->active_speed,
			 &props->active_width);
out:
	kfree(rsp);

	return rc;
}

static struct net_device *virtio_rdma_get_netdev(struct ib_device *ibdev,
						 u32 port_num)
{
	struct virtio_rdma_dev *ri = to_vdev(ibdev);
	return ri->netdev;
}

static void virtio_rdma_get_fw_ver_str(struct ib_device *device, char *str)
{
	snprintf(str, IB_FW_VERSION_NAME_MAX, "%d.%d.%d\n", 1, 0, 0);
}

static enum rdma_link_layer
virtio_rdma_port_link_layer(struct ib_device *ibdev, u32 port)
{
	return IB_LINK_LAYER_ETHERNET;
}

static const struct ib_device_ops virtio_rdma_dev_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = VIRTIO_RDMA_ABI_VERSION,
	.driver_id = RDMA_DRIVER_VIRTIO,

	.get_port_immutable = virtio_rdma_port_immutable,
	.query_device = virtio_rdma_query_device,
	.query_port = virtio_rdma_query_port,
	.get_netdev = virtio_rdma_get_netdev,
	.create_cq = virtio_rdma_create_cq,
	.destroy_cq = virtio_rdma_destroy_cq,
	.alloc_pd = virtio_rdma_alloc_pd,
	.dealloc_pd = virtio_rdma_dealloc_pd,
	.get_dma_mr = virtio_rdma_get_dma_mr,
	.create_qp = virtio_rdma_create_qp,
	.add_gid = virtio_rdma_add_gid,
	.alloc_ucontext = virtio_rdma_alloc_ucontext,
	.create_ah = virtio_rdma_create_ah,
	.create_user_ah = virtio_rdma_create_ah,
	.dealloc_ucontext = virtio_rdma_dealloc_ucontext,
	.del_gid = virtio_rdma_del_gid,
	.dereg_mr = virtio_rdma_dereg_mr,
	.destroy_ah = virtio_rdma_destroy_ah,
	.destroy_qp = virtio_rdma_destroy_qp,
	.get_dev_fw_str = virtio_rdma_get_fw_ver_str,
	.get_link_layer = virtio_rdma_port_link_layer,
	.mmap = virtio_rdma_mmap,
	.mmap_free = virtio_rdma_mmap_free,
	.modify_qp = virtio_rdma_modify_qp,
	.poll_cq = virtio_rdma_poll_cq,
	.post_recv = virtio_rdma_post_recv,
	.post_send = virtio_rdma_post_send,
	.query_device = virtio_rdma_query_device,
	.query_pkey = virtio_rdma_query_pkey,
	.query_qp = virtio_rdma_query_qp,
	.reg_user_mr = virtio_rdma_reg_user_mr,
	.req_notify_cq = virtio_rdma_req_notify_cq,

	INIT_RDMA_OBJ_SIZE(ib_ah, virtio_rdma_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, virtio_rdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, virtio_rdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_qp, virtio_rdma_qp, ibqp),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, virtio_rdma_ucontext, ibucontext),
};

int virtio_rdma_register_ib_device(struct virtio_rdma_dev *ri)
{
	int rc;
	struct ib_device *dev =  &ri->ib_dev;

	strlcpy(dev->node_desc, "VirtIO RDMA", sizeof(dev->node_desc));

	dev->phys_port_cnt = 1;
	dev->num_comp_vectors = 1;
	dev->dev.parent = ri->vdev->dev.parent;
	dev->node_type = RDMA_NODE_IB_CA;
	dev->uverbs_cmd_mask = BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT)
	| BIT_ULL(IB_USER_VERBS_CMD_ALLOC_PD)
	| BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_PD)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_MODIFY_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_DESTROY_QP)
	| BIT_ULL(IB_USER_VERBS_CMD_POST_SEND)
	| BIT_ULL(IB_USER_VERBS_CMD_POST_RECV)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_DESTROY_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_POLL_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ)
	| BIT_ULL(IB_USER_VERBS_CMD_REG_MR)
	| BIT_ULL(IB_USER_VERBS_CMD_DEREG_MR)
	| BIT_ULL(IB_USER_VERBS_CMD_CREATE_AH)
	| BIT_ULL(IB_USER_VERBS_CMD_MODIFY_AH)
	| BIT_ULL(IB_USER_VERBS_CMD_QUERY_AH)
	| BIT_ULL(IB_USER_VERBS_CMD_DESTROY_AH);

	ib_set_device_ops(dev, &virtio_rdma_dev_ops);
	ib_device_set_netdev(dev, ri->netdev, 1);

	rc = ib_register_device(dev, "virtio_rdma_%d", ri->vdev->dev.parent);

	memcpy(&dev->node_guid, dev->name, 6);
	return rc;
}

void virtio_rdma_unregister_ib_device(struct virtio_rdma_dev *ri)
{
	ib_unregister_device(&ri->ib_dev);
}
