/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PCI_EPF_VIRTIO_H__
#define __PCI_EPF_VIRTIO_H__

#include <linux/dmaengine.h>
#include <linux/pci-epc.h>
#include <linux/pci-epf.h>
#include <linux/vringh.h>

struct epf_vringh {
	struct vringh vrh;
	void __iomem *virt;
	phys_addr_t phys;
	unsigned int num;
};

struct epf_virtio {
	/* Base PCI Endpoint function */
	struct pci_epf *epf;

	/* Virtio parameters */
	u64 features;
	size_t bar_size;
	size_t nvq;
	size_t vqlen;

	/* struct to access virtqueue on remote host */
	struct epf_vringh **vrhs;

	/* struct for thread to emulate virtio device */
	struct task_struct *bgtask;

	/* Virtual address of PCI configuration space */
	void __iomem *bar;

	/*
	 * Callback function and parameter for queue notifcation
	 * Note: PCI EP function cannot detect qnotify accurately, therefore this
	 * callback function should check all of virtqueue's changes.
	 */
	void (*qn_callback)(void *param);
	void *qn_param;

	/* Callback function and parameter for initialize complete */
	void (*ic_callback)(void *param);
	void *ic_param;

	bool running;
};

#define DEFINE_EPF_VIRTIO_CFG_READ(size)                 \
	static inline u##size epf_virtio_cfg_read##size( \
		struct epf_virtio *evio, size_t offset)  \
	{                                                \
		void __iomem *base = evio->bar + offset; \
		return ioread##size(base);               \
	}

DEFINE_EPF_VIRTIO_CFG_READ(8)
DEFINE_EPF_VIRTIO_CFG_READ(16)
DEFINE_EPF_VIRTIO_CFG_READ(32)

#define DEFINE_EPF_VIRTIO_CFG_WRITE(size)                              \
	static inline void epf_virtio_cfg_write##size(                 \
		struct epf_virtio *evio, size_t offset, u##size value) \
	{                                                              \
		void __iomem *base = evio->bar + offset;               \
		iowrite##size(value, base);                            \
	}

DEFINE_EPF_VIRTIO_CFG_WRITE(8);
DEFINE_EPF_VIRTIO_CFG_WRITE(16);
DEFINE_EPF_VIRTIO_CFG_WRITE(32);

#define DEFINE_EPF_VIRTIO_CFG_SET(size)                                \
	static inline void epf_virtio_cfg_set##size(                   \
		struct epf_virtio *evio, size_t offset, u##size value) \
	{                                                              \
		void __iomem *base = evio->bar + offset;               \
		iowrite##size(ioread##size(base) | value, base);       \
	}

DEFINE_EPF_VIRTIO_CFG_SET(8)
DEFINE_EPF_VIRTIO_CFG_SET(16)
DEFINE_EPF_VIRTIO_CFG_SET(32)

#define DEFINE_EPF_VIRTIO_CFG_CLEAR(size)                              \
	static inline void epf_virtio_cfg_clear##size(                 \
		struct epf_virtio *evio, size_t offset, u##size value) \
	{                                                              \
		void __iomem *base = evio->bar + offset;               \
		iowrite##size(ioread##size(base) & ~value, base);      \
	}

DEFINE_EPF_VIRTIO_CFG_CLEAR(8)
DEFINE_EPF_VIRTIO_CFG_CLEAR(16)
DEFINE_EPF_VIRTIO_CFG_CLEAR(32)

static inline void epf_virtio_cfg_memcpy_toio(struct epf_virtio *evio,
					      size_t offset, void *buf,
					      size_t len)
{
	void __iomem *base = evio->bar + offset;

	memcpy_toio(base, buf, len);
}

int epf_virtio_init(struct epf_virtio *evio, struct pci_epf_header *hdr,
		    size_t bar_size);
void epf_virtio_final(struct epf_virtio *evio);
int epf_virtio_launch_bgtask(struct epf_virtio *evio);
void epf_virtio_terminate_bgtask(struct epf_virtio *evio);
int epf_virtio_reset(struct epf_virtio *evio);

int epf_virtio_getdesc(struct epf_virtio *evio, int index,
		       struct vringh_kiov *riov, struct vringh_kiov *wiov,
		       u16 *head);
void epf_virtio_abandon(struct epf_virtio *evio, int index, int num);
void epf_virtio_iov_complete(struct epf_virtio *evio, int index, u16 head,
			     size_t total_len);

int epf_virtio_memcpy_kiov2kiov(struct epf_virtio *evio,
				struct vringh_kiov *siov,
				struct vringh_kiov *diov,
				enum dma_transfer_direction dir);

#endif /* __PCI_EPF_VIRTIO_H__ */
