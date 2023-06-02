#ifndef _UAPI_LINUX_VIRTIO_NET_H
#define _UAPI_LINUX_VIRTIO_NET_H
/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. */
#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>
#include <linux/if_ether.h>

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM	0	/* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM	1	/* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_CTRL_GUEST_OFFLOADS 2 /* Dynamic offload configuration. */
#define VIRTIO_NET_F_MTU	3	/* Initial MTU advice */
#define VIRTIO_NET_F_MAC	5	/* Host has given MAC address. */
#define VIRTIO_NET_F_GUEST_TSO4	7	/* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6	8	/* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN	9	/* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO	10	/* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4	11	/* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6	12	/* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN	13	/* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO	14	/* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF	15	/* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS	16	/* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ	17	/* Control channel available */
#define VIRTIO_NET_F_CTRL_RX	18	/* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN	19	/* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA 20	/* Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21	/* Guest can announce device on the
					 * network */
#define VIRTIO_NET_F_MQ	22	/* Device supports Receive Flow
					 * Steering */
#define VIRTIO_NET_F_CTRL_MAC_ADDR 23	/* Set MAC address */
#define VIRTIO_NET_F_ROCE	24	/* Device supports RoCE */
#define VIRTIO_NET_F_NOTF_COAL	53	/* Device supports notifications coalescing */
#define VIRTIO_NET_F_GUEST_USO4	54	/* Guest can handle USOv4 in. */
#define VIRTIO_NET_F_GUEST_USO6	55	/* Guest can handle USOv6 in. */
#define VIRTIO_NET_F_HOST_USO	56	/* Host can handle USO in. */
#define VIRTIO_NET_F_HASH_REPORT  57	/* Supports hash report */
#define VIRTIO_NET_F_GUEST_HDRLEN  59	/* Guest provides the exact hdr_len value. */
#define VIRTIO_NET_F_RSS	  60	/* Supports RSS RX steering */
#define VIRTIO_NET_F_RSC_EXT	  61	/* extended coalescing info */
#define VIRTIO_NET_F_STANDBY	  62	/* Act as standby for another device
					 * with the same MAC.
					 */
#define VIRTIO_NET_F_SPEED_DUPLEX 63	/* Device set linkspeed and duplex */

#ifndef VIRTIO_NET_NO_LEGACY
#define VIRTIO_NET_F_GSO	6	/* Host handles pkts w/ any GSO type */
#endif /* VIRTIO_NET_NO_LEGACY */

#define VIRTIO_NET_S_LINK_UP	1	/* Link is up */
#define VIRTIO_NET_S_ANNOUNCE	2	/* Announcement is needed */

/* supported/enabled hash types */
#define VIRTIO_NET_RSS_HASH_TYPE_IPv4          (1 << 0)
#define VIRTIO_NET_RSS_HASH_TYPE_TCPv4         (1 << 1)
#define VIRTIO_NET_RSS_HASH_TYPE_UDPv4         (1 << 2)
#define VIRTIO_NET_RSS_HASH_TYPE_IPv6          (1 << 3)
#define VIRTIO_NET_RSS_HASH_TYPE_TCPv6         (1 << 4)
#define VIRTIO_NET_RSS_HASH_TYPE_UDPv6         (1 << 5)
#define VIRTIO_NET_RSS_HASH_TYPE_IP_EX         (1 << 6)
#define VIRTIO_NET_RSS_HASH_TYPE_TCP_EX        (1 << 7)
#define VIRTIO_NET_RSS_HASH_TYPE_UDP_EX        (1 << 8)

struct virtio_net_config {
	/* The config defining mac address (if VIRTIO_NET_F_MAC) */
	__u8 mac[ETH_ALEN];
	/* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
	__virtio16 status;
	/* Maximum number of each of transmit and receive queues;
	 * see VIRTIO_NET_F_MQ and VIRTIO_NET_CTRL_MQ.
	 * Legal values are between 1 and 0x8000
	 */
	__virtio16 max_virtqueue_pairs;
	/* Default maximum transmit unit advice */
	__virtio16 mtu;
	/*
	 * speed, in units of 1Mb. All values 0 to INT_MAX are legal.
	 * Any other value stands for unknown.
	 */
	__le32 speed;
	/*
	 * 0x00 - half duplex
	 * 0x01 - full duplex
	 * Any other value stands for unknown.
	 */
	__u8 duplex;
	/* maximum size of RSS key */
	__u8 rss_max_key_size;
	/* maximum number of indirection table entries */
	__le16 rss_max_indirection_table_length;
	/* bitmask of supported VIRTIO_NET_RSS_HASH_ types */
	__le32 supported_hash_types;
	/* Maximum number of queue pairs for RDMA usage */
	__le32 max_rdma_qps;
	/* Maximum number of completion queues for RDMA usage */
	__le32 max_rdma_cqs;
} __attribute__((packed));

/*
 * This header comes first in the scatter-gather list.  If you don't
 * specify GSO or CSUM features, you can simply ignore the header.
 *
 * This is bitwise-equivalent to the legacy struct virtio_net_hdr_mrg_rxbuf,
 * only flattened.
 */
struct virtio_net_hdr_v1 {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM	1	/* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID	2	/* Csum is valid */
#define VIRTIO_NET_HDR_F_RSC_INFO	4	/* rsc info in csum_ fields */
	__u8 flags;
#define VIRTIO_NET_HDR_GSO_NONE		0	/* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4	1	/* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP		3	/* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6	4	/* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_UDP_L4	5	/* GSO frame, IPv4& IPv6 UDP (USO) */
#define VIRTIO_NET_HDR_GSO_ECN		0x80	/* TCP has ECN set */
	__u8 gso_type;
	__virtio16 hdr_len;	/* Ethernet + IP + tcp/udp hdrs */
	__virtio16 gso_size;	/* Bytes to append to hdr_len per frame */
	union {
		struct {
			__virtio16 csum_start;
			__virtio16 csum_offset;
		};
		/* Checksum calculation */
		struct {
			/* Position to start checksumming from */
			__virtio16 start;
			/* Offset after that to place checksum */
			__virtio16 offset;
		} csum;
		/* Receive Segment Coalescing */
		struct {
			/* Number of coalesced segments */
			__le16 segments;
			/* Number of duplicated acks */
			__le16 dup_acks;
		} rsc;
	};
	__virtio16 num_buffers;	/* Number of merged rx buffers */
};

struct virtio_net_hdr_v1_hash {
	struct virtio_net_hdr_v1 hdr;
	__le32 hash_value;
#define VIRTIO_NET_HASH_REPORT_NONE            0
#define VIRTIO_NET_HASH_REPORT_IPv4            1
#define VIRTIO_NET_HASH_REPORT_TCPv4           2
#define VIRTIO_NET_HASH_REPORT_UDPv4           3
#define VIRTIO_NET_HASH_REPORT_IPv6            4
#define VIRTIO_NET_HASH_REPORT_TCPv6           5
#define VIRTIO_NET_HASH_REPORT_UDPv6           6
#define VIRTIO_NET_HASH_REPORT_IPv6_EX         7
#define VIRTIO_NET_HASH_REPORT_TCPv6_EX        8
#define VIRTIO_NET_HASH_REPORT_UDPv6_EX        9
	__le16 hash_report;
	__le16 padding;
};

#ifndef VIRTIO_NET_NO_LEGACY
/* This header comes first in the scatter-gather list.
 * For legacy virtio, if VIRTIO_F_ANY_LAYOUT is not negotiated, it must
 * be the first element of the scatter-gather list.  If you don't
 * specify GSO or CSUM features, you can simply ignore the header. */
struct virtio_net_hdr {
	/* See VIRTIO_NET_HDR_F_* */
	__u8 flags;
	/* See VIRTIO_NET_HDR_GSO_* */
	__u8 gso_type;
	__virtio16 hdr_len;		/* Ethernet + IP + tcp/udp hdrs */
	__virtio16 gso_size;		/* Bytes to append to hdr_len per frame */
	__virtio16 csum_start;	/* Position to start checksumming from */
	__virtio16 csum_offset;	/* Offset after that to place checksum */
};

/* This is the version of the header to use when the MRG_RXBUF
 * feature has been negotiated. */
struct virtio_net_hdr_mrg_rxbuf {
	struct virtio_net_hdr hdr;
	__virtio16 num_buffers;	/* Number of merged rx buffers */
};
#endif /* ...VIRTIO_NET_NO_LEGACY */

/*
 * Control virtqueue data structures
 *
 * The control virtqueue expects a header in the first sg entry
 * and an ack/status response in the last entry.  Data for the
 * command goes in between.
 */
struct virtio_net_ctrl_hdr {
	__u8 class;
	__u8 cmd;
} __attribute__((packed));

typedef __u8 virtio_net_ctrl_ack;

#define VIRTIO_NET_OK     0
#define VIRTIO_NET_ERR    1

/*
 * Control the RX mode, ie. promisucous, allmulti, etc...
 * All commands require an "out" sg entry containing a 1 byte
 * state value, zero = disable, non-zero = enable.  Commands
 * 0 and 1 are supported with the VIRTIO_NET_F_CTRL_RX feature.
 * Commands 2-5 are added with VIRTIO_NET_F_CTRL_RX_EXTRA.
 */
#define VIRTIO_NET_CTRL_RX    0
 #define VIRTIO_NET_CTRL_RX_PROMISC      0
 #define VIRTIO_NET_CTRL_RX_ALLMULTI     1
 #define VIRTIO_NET_CTRL_RX_ALLUNI       2
 #define VIRTIO_NET_CTRL_RX_NOMULTI      3
 #define VIRTIO_NET_CTRL_RX_NOUNI        4
 #define VIRTIO_NET_CTRL_RX_NOBCAST      5

/*
 * Control the MAC
 *
 * The MAC filter table is managed by the hypervisor, the guest should
 * assume the size is infinite.  Filtering should be considered
 * non-perfect, ie. based on hypervisor resources, the guest may
 * received packets from sources not specified in the filter list.
 *
 * In addition to the class/cmd header, the TABLE_SET command requires
 * two out scatterlists.  Each contains a 4 byte count of entries followed
 * by a concatenated byte stream of the ETH_ALEN MAC addresses.  The
 * first sg list contains unicast addresses, the second is for multicast.
 * This functionality is present if the VIRTIO_NET_F_CTRL_RX feature
 * is available.
 *
 * The ADDR_SET command requests one out scatterlist, it contains a
 * 6 bytes MAC address. This functionality is present if the
 * VIRTIO_NET_F_CTRL_MAC_ADDR feature is available.
 */
struct virtio_net_ctrl_mac {
	__virtio32 entries;
	__u8 macs[][ETH_ALEN];
} __attribute__((packed));

#define VIRTIO_NET_CTRL_MAC    1
 #define VIRTIO_NET_CTRL_MAC_TABLE_SET        0
 #define VIRTIO_NET_CTRL_MAC_ADDR_SET         1

/*
 * Control VLAN filtering
 *
 * The VLAN filter table is controlled via a simple ADD/DEL interface.
 * VLAN IDs not added may be filterd by the hypervisor.  Del is the
 * opposite of add.  Both commands expect an out entry containing a 2
 * byte VLAN ID.  VLAN filterting is available with the
 * VIRTIO_NET_F_CTRL_VLAN feature bit.
 */
#define VIRTIO_NET_CTRL_VLAN       2
 #define VIRTIO_NET_CTRL_VLAN_ADD             0
 #define VIRTIO_NET_CTRL_VLAN_DEL             1

/*
 * Control link announce acknowledgement
 *
 * The command VIRTIO_NET_CTRL_ANNOUNCE_ACK is used to indicate that
 * driver has recevied the notification; device would clear the
 * VIRTIO_NET_S_ANNOUNCE bit in the status field after it receives
 * this command.
 */
#define VIRTIO_NET_CTRL_ANNOUNCE       3
 #define VIRTIO_NET_CTRL_ANNOUNCE_ACK         0

/*
 * Control Receive Flow Steering
 */
#define VIRTIO_NET_CTRL_MQ   4
/*
 * The command VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
 * enables Receive Flow Steering, specifying the number of the transmit and
 * receive queues that will be used. After the command is consumed and acked by
 * the device, the device will not steer new packets on receive virtqueues
 * other than specified nor read from transmit virtqueues other than specified.
 * Accordingly, driver should not transmit new packets  on virtqueues other than
 * specified.
 */
struct virtio_net_ctrl_mq {
	__virtio16 virtqueue_pairs;
};

 #define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET        0
 #define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN        1
 #define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX        0x8000

/*
 * The command VIRTIO_NET_CTRL_MQ_RSS_CONFIG has the same effect as
 * VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET does and additionally configures
 * the receive steering to use a hash calculated for incoming packet
 * to decide on receive virtqueue to place the packet. The command
 * also provides parameters to calculate a hash and receive virtqueue.
 */
struct virtio_net_rss_config {
	__le32 hash_types;
	__le16 indirection_table_mask;
	__le16 unclassified_queue;
	__le16 indirection_table[1/* + indirection_table_mask */];
	__le16 max_tx_vq;
	__u8 hash_key_length;
	__u8 hash_key_data[/* hash_key_length */];
};

 #define VIRTIO_NET_CTRL_MQ_RSS_CONFIG          1

/*
 * The command VIRTIO_NET_CTRL_MQ_HASH_CONFIG requests the device
 * to include in the virtio header of the packet the value of the
 * calculated hash and the report type of hash. It also provides
 * parameters for hash calculation. The command requires feature
 * VIRTIO_NET_F_HASH_REPORT to be negotiated to extend the
 * layout of virtio header as defined in virtio_net_hdr_v1_hash.
 */
struct virtio_net_hash_config {
	__le32 hash_types;
	/* for compatibility with virtio_net_rss_config */
	__le16 reserved[4];
	__u8 hash_key_length;
	__u8 hash_key_data[/* hash_key_length */];
};

 #define VIRTIO_NET_CTRL_MQ_HASH_CONFIG         2

/*
 * Control network offloads
 *
 * Reconfigures the network offloads that Guest can handle.
 *
 * Available with the VIRTIO_NET_F_CTRL_GUEST_OFFLOADS feature bit.
 *
 * Command data format matches the feature bit mask exactly.
 *
 * See VIRTIO_NET_F_GUEST_* for the list of offloads
 * that can be enabled/disabled.
 */
#define VIRTIO_NET_CTRL_GUEST_OFFLOADS   5
#define VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET        0

/*
 * Control notifications coalescing.
 *
 * Request the device to change the notifications coalescing parameters.
 *
 * Available with the VIRTIO_NET_F_NOTF_COAL feature bit.
 */
#define VIRTIO_NET_CTRL_NOTF_COAL		6
/*
 * Set the tx-usecs/tx-max-packets parameters.
 */
struct virtio_net_ctrl_coal_tx {
	/* Maximum number of packets to send before a TX notification */
	__le32 tx_max_packets;
	/* Maximum number of usecs to delay a TX notification */
	__le32 tx_usecs;
};

#define VIRTIO_NET_CTRL_NOTF_COAL_TX_SET		0

/*
 * Set the rx-usecs/rx-max-packets parameters.
 */
struct virtio_net_ctrl_coal_rx {
	/* Maximum number of packets to receive before a RX notification */
	__le32 rx_max_packets;
	/* Maximum number of usecs to delay a RX notification */
	__le32 rx_usecs;
};

#define VIRTIO_NET_CTRL_NOTF_COAL_RX_SET		1

#define VIRTIO_NET_CTRL_ROCE    6

struct virtio_rdma_ack_query_device {
#define VIRTIO_IB_DEVICE_RC_RNR_NAK_GEN    (1 << 0)
	/* Capabilities mask */
	__le64 device_cap_flags;
	/* Largest contiguous block that can be registered */
	__le64 max_mr_size;
	/* Supported memory shift sizes */
	__le64 page_size_cap;
	/* Hardware version */
	__le32 hw_ver;
	/* Maximum number of outstanding Work Requests (WR) on Send Queue (SQ) and Receive Queue (RQ) */
	__le32 max_qp_wr;
	/* Maximum number of scatter/gather (s/g) elements per WR for SQ for non RDMA Read operations */
	__le32 max_send_sge;
	/* Maximum number of s/g elements per WR for RQ for non RDMA Read operations */
	__le32 max_recv_sge;
	/* Maximum number of s/g per WR for RDMA Read operations */
	__le32 max_sge_rd;
	/* Maximum size of Completion Queue (CQ) */
	__le32 max_cqe;
	/* Maximum number of Memory Regions (MR) */
	__le32 max_mr;
	/* Maximum number of Protection Domains (PD) */
	__le32 max_pd;
	/* Maximum number of RDMA Read perations that can be outstanding per Queue Pair (QP) */
	__le32 max_qp_rd_atom;
	/* Maximum depth per QP for initiation of RDMA Read operations */
	__le32 max_qp_init_rd_atom;
	/* Maximum number of Address Handles (AH) */
	__le32 max_ah;
	/* Local CA ack delay */
	__u8 local_ca_ack_delay;
	/* Padding */
	__u8 padding[3];
	/* Reserved for future */
	__le32 reserved[14];
};

 #define VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE        0

struct virtio_rdma_ack_query_port {
	/* Length of source Global Identifier (GID) table */
	__le32 gid_tbl_len;
	/* Maximum message size */
	__le32 max_msg_sz;
	/* Reserved for future */
	__le32 reserved[6];
};

 #define VIRTIO_NET_CTRL_ROCE_QUERY_PORT        1

struct virtio_rdma_cmd_create_cq {
	/* Size of CQ */
	__le32 cqe;
	u64 virt;
	u64 phys;
};

struct virtio_rdma_ack_create_cq {
	/* The index of CQ */
	__le32 cqn;
};

 #define VIRTIO_NET_CTRL_ROCE_CREATE_CQ        2

struct virtio_rdma_cmd_destroy_cq {
	/* The index of CQ */
	__le32 cqn;
};

 #define VIRTIO_NET_CTRL_ROCE_DESTROY_CQ        3

struct virtio_rdma_ack_create_pd {
	/* The handle of PD */
	__le32 pdn;
};

 #define VIRTIO_NET_CTRL_ROCE_CREATE_PD        4

struct virtio_rdma_cmd_destroy_pd {
	/* The handle of PD */
	__le32 pdn;
};

 #define VIRTIO_NET_CTRL_ROCE_DESTROY_PD        5

enum virtio_ib_access_flags {
	VIRTIO_IB_ACCESS_LOCAL_WRITE = (1 << 0),
	VIRTIO_IB_ACCESS_REMOTE_WRITE = (1 << 1),
	VIRTIO_IB_ACCESS_REMOTE_READ = (1 << 2),
};

struct virtio_rdma_cmd_get_dma_mr {
	/* The handle of PD which the MR associated with */
	__le32 pdn;
	/* MR's protection attributes, enum virtio_ib_access_flags */
	__le32 access_flags;
};

struct virtio_rdma_ack_get_dma_mr {
	/* The handle of MR */
	__le32 mrn;
	/* MR's local access key */
	__le32 lkey;
	/* MR's remote access key */
	__le32 rkey;
};

 #define VIRTIO_NET_CTRL_ROCE_GET_DMA_MR        6

struct virtio_rdma_cmd_reg_user_mr {
	/* The handle of PD which the MR associated with */
	__le32 pdn;
	/* MR's protection attributes, enum virtio_ib_access_flags */
	__le32 access_flags;
	/* Starting virtual address of MR */
	__le64 virt_addr;
	/* Length of MR */
	__le64 length;
	/* Size of the below page array */
	__le32 npages;
	/* Padding */
	__le32 padding;
	/* Array to store physical address of each page in MR */
	__le64 pages[];
};

struct virtio_rdma_ack_reg_user_mr {
	/* The handle of MR */
	__le32 mrn;
	/* MR's local access key */
	__le32 lkey;
	/* MR's remote access key */
	__le32 rkey;
};

 #define VIRTIO_NET_CTRL_ROCE_REG_USER_MR        7

struct virtio_rdma_cmd_dereg_mr {
	/* The handle of MR */
	__le32 mrn;
};

 #define VIRTIO_NET_CTRL_ROCE_DEREG_MR        8

struct virtio_rdma_qp_cap {
	/* Maximum number of outstanding WRs in SQ */
	__le32 max_send_wr;
	/* Maximum number of outstanding WRs in RQ */
	__le32 max_recv_wr;
	/* Maximum number of s/g elements per WR in SQ */
	__le32 max_send_sge;
	/* Maximum number of s/g elements per WR in RQ */
	__le32 max_recv_sge;
	/* Maximum number of data (bytes) that can be posted inline to SQ */
	__le32 max_inline_data;
	/* Padding */
	__le32 padding;
};

struct virtio_rdma_cmd_create_qp {
	/* The handle of PD which the QP associated with */
	__le32 pdn;
#define VIRTIO_IB_QPT_SMI    0
#define VIRTIO_IB_QPT_GSI    1
#define VIRTIO_IB_QPT_RC     2
#define VIRTIO_IB_QPT_UC     3
#define VIRTIO_IB_QPT_UD     4
	/* QP's type */
	__u8 qp_type;
	/* If set, each WR submitted to the SQ generates a completion entry */
	__u8 sq_sig_all;
	/* Padding */
	__u8 padding[2];
	/* The index of CQ which the SQ associated with */
	__le32 send_cqn;
	/* The index of CQ which the RQ associated with */
	__le32 recv_cqn;
	/* QP's capabilities */
	struct virtio_rdma_qp_cap cap;
	/* Reserved for future */
	__le32 reserved[4];
};

struct virtio_rdma_ack_create_qp {
	/* The index of QP */
	__le32 qpn;
};

 #define VIRTIO_NET_CTRL_ROCE_CREATE_QP        9

struct virtio_rdma_global_route {
	/* Destination GID or MGID */
	__u8 dgid[16];
	/* Flow label */
	__le32 flow_label;
	/* Source GID index */
	__u8 sgid_index;
	/* Hop limit */
	__u8 hop_limit;
	/* Traffic class */
	__u8 traffic_class;
	/* padding */
	__u8 padding;
};

struct virtio_rdma_ah_attr {
	/* Global Routing Header (GRH) attributes */
	struct virtio_rdma_global_route grh;
	/* RoCE address handle attribute */
	__u8 dmac[6];
	/* Reserved for future */
	__u8 reserved[10];
};

enum virtio_ib_qp_attr_mask {
	VIRTIO_IB_QP_STATE = (1 << 0),
	VIRTIO_IB_QP_CUR_STATE = (1 << 1),
	VIRTIO_IB_QP_ACCESS_FLAGS = (1 << 2),
	VIRTIO_IB_QP_QKEY = (1 << 3),
	VIRTIO_IB_QP_AV = (1 << 4),
	VIRTIO_IB_QP_PATH_MTU = (1 << 5),
	VIRTIO_IB_QP_TIMEOUT = (1 << 6),
	VIRTIO_IB_QP_RETRY_CNT = (1 << 7),
	VIRTIO_IB_QP_RNR_RETRY = (1 << 8),
	VIRTIO_IB_QP_RQ_PSN = (1 << 9),
	VIRTIO_IB_QP_MAX_QP_RD_ATOMIC = (1 << 10),
	VIRTIO_IB_QP_MIN_RNR_TIMER = (1 << 11),
	VIRTIO_IB_QP_SQ_PSN = (1 << 12),
	VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC = (1 << 13),
	VIRTIO_IB_QP_CAP = (1 << 14),
	VIRTIO_IB_QP_DEST_QPN = (1 << 15),
	VIRTIO_IB_QP_RATE_LIMIT = (1 << 16),
};

enum virtio_ib_qp_state {
	VIRTIO_IB_QPS_RESET,
	VIRTIO_IB_QPS_INIT,
	VIRTIO_IB_QPS_RTR,
	VIRTIO_IB_QPS_RTS,
	VIRTIO_IB_QPS_SQD,
	VIRTIO_IB_QPS_SQE,
	VIRTIO_IB_QPS_ERR
};

enum virtio_ib_mtu {
	VIRTIO_IB_MTU_256  = 1,
	VIRTIO_IB_MTU_512  = 2,
	VIRTIO_IB_MTU_1024 = 3,
	VIRTIO_IB_MTU_2048 = 4,
	VIRTIO_IB_MTU_4096 = 5
};

struct virtio_rdma_cmd_modify_qp {
	/* The index of QP */
	__le32 qpn;
	/* The mask of attributes need to be modified, enum virtio_ib_qp_attr_mask */
	__le32 attr_mask;
	/* Move the QP to this state, enum virtio_ib_qp_state */
	__u8 qp_state;
	/* Current QP state, enum virtio_ib_qp_state */
	__u8 cur_qp_state;
	/* Path MTU (valid only for RC/UC QPs), enum virtio_ib_mtu */
	__u8 path_mtu;
	/* Number of outstanding RDMA Read operations on destination QP (valid only for RC QPs) */
	__u8 max_rd_atomic;
	/* Number of responder resources for handling incoming RDMA reads operations (valid only for RC QPs) */
	__u8 max_dest_rd_atomic;
	/* Minimum RNR (Receiver Not Ready) NAK timer (valid only for RC QPs) */
	__u8 min_rnr_timer;
	/* Local ack timeout (valid only for RC QPs) */
	__u8 timeout;
	/* Retry count (valid only for RC QPs) */
	__u8 retry_cnt;
	/* RNR retry (valid only for RC QPs) */
	__u8 rnr_retry;
	/* Padding */
	__u8 padding[7];
	/* Q_Key for the QP (valid only for UD QPs) */
	__le32 qkey;
	/* PSN for RQ (valid only for RC/UC QPs) */
	__le32 rq_psn;
	/* PSN for SQ */
	__le32 sq_psn;
	/* Destination QP number (valid only for RC/UC QPs) */
	__le32 dest_qp_num;
	/* Mask of enabled remote access operations (valid only for RC/UC QPs), enum virtio_ib_access_flags */
	__le32 qp_access_flags;
	/* Rate limit in kbps for packet pacing */
	__le32 rate_limit;
	/* QP capabilities */
	struct virtio_rdma_qp_cap cap;
	/* Address Vector (valid only for RC/UC QPs) */
	struct virtio_rdma_ah_attr ah_attr;
	/* Reserved for future */
	__le32 reserved[4];
};

 #define VIRTIO_NET_CTRL_ROCE_MODIFY_QP        10

struct virtio_rdma_cmd_query_qp {
	/* The index of QP */
	__le32 qpn;
	/* The mask of attributes need to be queried, enum virtio_ib_qp_attr_mask */
	__le32 attr_mask;
};

struct virtio_rdma_ack_query_qp {
	/* Move the QP to this state, enum virtio_ib_qp_state */
	__u8 qp_state;
	/* Path MTU (valid only for RC/UC QPs), enum virtio_ib_mtu */
	__u8 path_mtu;
	/* Is the SQ draining */
	__u8 sq_draining;
	/* Number of outstanding RDMA read operations on the destination QP (valid only for RC QPs) */
	__u8 max_rd_atomic;
	/* Number of responder resources for handling incoming RDMA read operations (valid only for RC QPs) */
	__u8 max_dest_rd_atomic;
	/* Minimum RNR NAK timer (valid only for RC QPs) */
	__u8 min_rnr_timer;
	/* Local ack timeout (valid only for RC QPs) */
	__u8 timeout;
	/* Retry count (valid only for RC QPs) */
	__u8 retry_cnt;
	/* RNR retry (valid only for RC QPs) */
	__u8 rnr_retry;
	/* Padding */
	__u8 padding[7];
	/* Q_Key for the QP (valid only for UD QPs) */
	__le32 qkey;
	/* PSN for RQ (valid only for RC/UC QPs) */
	__le32 rq_psn;
	/* PSN for SQ */
	__le32 sq_psn;
	/* Destination QP number (valid only for RC/UC QPs) */
	__le32 dest_qp_num;
	/* Mask of enabled remote access operations (valid only for RC/UC QPs), enum virtio_ib_access_flags */
	__le32 qp_access_flags;
	/* Rate limit in kbps for packet pacing */
	__le32 rate_limit;
	/* QP capabilities */
	struct virtio_rdma_qp_cap cap;
	/* Address Vector (valid only for RC/UC QPs) */
	struct virtio_rdma_ah_attr ah_attr;
	/* Reserved for future */
	__le32 reserved[4];
};

 #define VIRTIO_NET_CTRL_ROCE_QUERY_QP        11

struct virtio_rdma_cmd_destroy_qp {
	/* The index of QP */
	__le32 qpn;
};

 #define VIRTIO_NET_CTRL_ROCE_DESTROY_QP        12

struct virtio_rdma_cmd_create_ah {
	/* The handle of PD which the AH associated with */
	__le32 pdn;
	/* Padding */
	__le32 padding;
	/* Address vector */
	struct virtio_rdma_ah_attr ah_attr;
};

struct virtio_rdma_ack_create_ah {
	/* The address handle */
	__le32 ah;
};

 #define VIRTIO_NET_CTRL_ROCE_CREATE_AH        13

struct virtio_rdma_cmd_destroy_ah {
	/* The handle of PD which the AH associated with */
	__le32 pdn;
	/* The address handle */
	__le32 ah;
};

 #define VIRTIO_NET_CTRL_ROCE_DESTROY_AH        14

struct virtio_rdma_cmd_add_gid {
	/* The index of GID */
	__le16 index;
	/* Padding */
	__le16 padding[3];
	/* GID to be added */
	__u8 gid[16];
};

 #define VIRTIO_NET_CTRL_ROCE_ADD_GID        15

struct virtio_rdma_cmd_del_gid {
	/* The index of GID */
	__le16 index;
};

 #define VIRTIO_NET_CTRL_ROCE_DEL_GID        16

struct virtio_rdma_cmd_req_notify {
	/* The index of CQ */
	__le32 cqn;
#define VIRTIO_IB_CQ_SOLICITED    (1 << 0)
#define VIRTIO_IB_CQ_NEXT_COMP    (1 << 1)
	/* Notify flags */
	__le32 flags;
};

 #define VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ        17

#endif /* _UAPI_LINUX_VIRTIO_NET_H */
