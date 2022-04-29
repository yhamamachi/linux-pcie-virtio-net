// SPDX-License-Identifier: GPL-2.0-only
/*
 * RoCE support for virtio network device
 *
 * Copyright (C) 2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Xie Yongji <xieyongji@bytedance.com>
 *         Wei Junji <weijunji@bytedance.com>
 */

#ifndef __VIRTIO_RDMA_VERBS__
#define __VIRTIO_RDMA_VERBS__

#include <linux/types.h>
#include <linux/virtio_config.h>
#include <linux/virtio_net.h>

#include <rdma/ib_verbs.h>
#include <uapi/rdma/virtio_rdma_abi.h>

enum virtio_rdma_type {
	VIRTIO_RDMA_TYPE_USER,
	VIRTIO_RDMA_TYPE_KERNEL
};

struct virtio_rdma_pd {
	struct ib_pd ibpd;
	u32 pd_handle;
};

struct virtio_rdma_mr {
	struct ib_mr ibmr;
	struct ib_umem *umem;

	u32 mr_handle;
	u64 iova;
	u64 size;
	u32 npages;
};

struct virtio_rdma_cq {
	struct ib_cq ibcq;
	u32 cq_handle;

	struct virtio_rdma_vq *vq;

	struct rdma_user_mmap_entry *entry;

	spinlock_t lock;
	struct virtio_rdma_cq_req *queue;
	size_t queue_size;
	dma_addr_t dma_addr;
	u32 num_cqe;
};

struct virtio_rdma_qp {
	struct ib_qp ibqp;
	u32 qp_handle;
	enum virtio_rdma_type type;
	u8 port;
	u8 sq_sig_type;
	struct ib_qp_cap cap;

	struct virtio_rdma_vq *sq;
	void* usq_buf;
	size_t usq_buf_size;
	dma_addr_t usq_dma_addr;

	struct virtio_rdma_vq *rq;
	void* urq_buf;
	size_t urq_buf_size;
	dma_addr_t urq_dma_addr;

	struct virtio_rdma_user_mmap_entry* sq_entry;
	struct virtio_rdma_user_mmap_entry* rq_entry;
};

struct virtio_rdma_user_mmap_entry {
	struct rdma_user_mmap_entry rdma_entry;
#define VIRTIO_RDMA_MMAP_CQ 1
#define VIRTIO_RDMA_MMAP_QP 2
	uint8_t type;
	struct virtqueue *queue;
	void *ubuf;
	uint64_t ubuf_size;
};

struct virtio_rdma_ucontext {
	struct ib_ucontext ibucontext;
	struct virtio_rdma_dev *dev;
};

struct virtio_rdma_ah {
	struct ib_ah ibah;
	u32 ah_num;
};

struct virtio_rdma_dev {
	struct ib_device ib_dev;
	struct ib_device_attr attr;

	struct virtio_device *vdev;

	/* To protect the vq operations for the controlq */
	spinlock_t ctrl_lock;

	struct net_device *netdev;
	int mtu;

	struct virtio_rdma_vq* cq_vqs;
	struct virtio_rdma_cq** cqs;
	uint32_t max_cq;

	struct virtio_rdma_vq* qp_vqs;
	struct virtio_rdma_qp** qps;
	uint32_t max_qp;

	atomic_t num_qp;
	atomic_t num_cq;

	bool fast_doorbell;
};

static inline struct virtio_rdma_ah *to_vah(struct ib_ah *ibah)
{
	return container_of(ibah, struct virtio_rdma_ah, ibah);
}

static inline struct virtio_rdma_pd *to_vpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct virtio_rdma_pd, ibpd);
}

static inline struct virtio_rdma_cq *to_vcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct virtio_rdma_cq, ibcq);
}

static inline struct virtio_rdma_qp *to_vqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct virtio_rdma_qp, ibqp);
}

static inline struct virtio_rdma_mr *to_vmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct virtio_rdma_mr, ibmr);
}

static inline struct virtio_rdma_user_mmap_entry *
to_ventry(struct rdma_user_mmap_entry *rdma_entry) {
	return container_of(rdma_entry, struct virtio_rdma_user_mmap_entry,
			    rdma_entry);
}

static inline struct virtio_rdma_ucontext *
to_vucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct virtio_rdma_ucontext,
			    ibucontext);
}

static inline struct virtio_rdma_dev *to_vdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct virtio_rdma_dev, ib_dev);
}

int virtio_rdma_register_ib_device(struct virtio_rdma_dev *ri);
void virtio_rdma_unregister_ib_device(struct virtio_rdma_dev *ri);

#endif
