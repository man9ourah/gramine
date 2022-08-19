/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#ifndef PERF_XDP_COMMON_H
#define PERF_XDP_COMMON_H

#include <xdp/xsk.h>

#define XDP_FRAME_SIZE          XSK_UMEM__DEFAULT_FRAME_SIZE
#define XDP_NUM_FRAMES          XSK_RING_PROD__DEFAULT_NUM_DESCS * 2
#define XDP_BUFFER_SIZE         XDP_NUM_FRAMES* XDP_FRAME_SIZE
#define XDP_FLAGS               XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE
#define XDP_UMEM_RESERVED_FRAME UINT64_MAX

// see this comment for why we set the fill ring at this amount:
// https://github.com/torvalds/linux/blob/8ab2afa23bd197df47819a87f0265c0ac95c5b6a/samples/bpf/xdpsock_user.c#L954
#define XDP_FILL_RING_SIZE XSK_RING_PROD__DEFAULT_NUM_DESCS * 2

struct xdp_socket_info {
    struct xsk_socket* xsk;
    uint32_t ifindex;
    uint32_t prog_id;

    struct xsk_ring_prod tx_ring;
    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons rx_ring;
    struct xsk_ring_cons compl_ring;

    struct xdp_stats {
        uint32_t tx_pkts;
        uint32_t compl_pkts;
        uint32_t rx_pkts;
    } xdp_stats;

    struct xsk_umem* umem;
    uint64_t umem_frames_map[XDP_NUM_FRAMES];
    uint64_t umem_frames_free_num;
    void* umem_buffer;
};

extern struct xdp_socket_info g_xdp_socket_info;

void xdp_cleanup(void);
void xdp_umem_free_frame(uint64_t frame);
uint64_t xdp_umem_allocate_frame(void);
uint32_t xdp_reclaim_complete_queue(void);
uint32_t xdp_foreach_rcv_pkt(int (*rcv_pkt_cb)(uint64_t, uint32_t));
uint32_t xdp_foreach_snd_pkt(size_t tx_batch_size, uint32_t (*snd_pkt_cb)(uint8_t*));
void xdp_populate_fill_ring(uint32_t fr_size);
void xdp_init_socket(void);
#endif
