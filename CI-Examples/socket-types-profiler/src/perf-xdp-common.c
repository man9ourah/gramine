/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-xdp-common.h"

#include <err.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "perf-common.h"

struct xdp_socket_info g_xdp_socket_info;

/**
 * @brief clean up xdp
 */
void xdp_cleanup(void) { /*{{{*/
    if (munmap(g_xdp_socket_info.umem_buffer, XDP_BUFFER_SIZE))
        errx(EXIT_FAILURE, "ERROR on munmap");
    xsk_socket__delete(g_xdp_socket_info.xsk);
    if (xsk_umem__delete(g_xdp_socket_info.umem))
        errx(EXIT_FAILURE, "ERROR on deleting umem");

    if (!arg_xdp_ctrl_proc_path) {
        uint32_t curr_prog_id = 0;
        if (bpf_get_link_xdp_id(g_xdp_socket_info.ifindex, &curr_prog_id, XDP_FLAGS))
            warn("WARN could not get current bpf program id");

        if (g_xdp_socket_info.prog_id == curr_prog_id)
            bpf_set_link_xdp_fd(g_xdp_socket_info.ifindex, -1, XDP_FLAGS);
        else if (!curr_prog_id)
            warnx("WARN couldn't find a prog id on a given interface\n");
        else
            warnx("WARN program on interface changed, not removing\n");
    }
} /*}}}*/

/**
 * @brief initialize the umem frame allocator
 */
static void xdp_umem_init_alloc(void) { /*{{{*/
    for (int i = 0; i < XDP_NUM_FRAMES; i++)
        g_xdp_socket_info.umem_frames_map[i] = i * XDP_FRAME_SIZE;

    g_xdp_socket_info.umem_frames_free_num = XDP_NUM_FRAMES;
} /*}}}*/

/**
 * @brief given an open connection on ctrl_sock_fd, it will receive the xsk map fd
 * and write it to *xsk_map_fd
 *
 * @param ctrl_sock_fd
 * @param xsk_map_fd
 * @return zero on success
 */
static int recv_xsks_map_fd_from_ctrl_node(int ctrl_sock_fd, int* xsk_map_fd) {/*{{{*/
    char cms[CMSG_SPACE(sizeof(int))];
    struct cmsghdr* cmsg;
    struct msghdr msg;
    struct iovec iov;
    int value;
    int len;

    iov.iov_base = &value;
    iov.iov_len  = sizeof(int);
    msg.msg_name       = 0;
    msg.msg_namelen    = 0;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_flags      = 0;
    msg.msg_control    = (void*)cms;
    msg.msg_controllen = sizeof(cms);

    len = recvmsg(ctrl_sock_fd, &msg, 0);
    if (len <= 0)
        err(EXIT_FAILURE, "ERROR on receiving bpf map fd from control process\n" );

    cmsg = CMSG_FIRSTHDR(&msg);
    *xsk_map_fd = *(int*)CMSG_DATA(cmsg);
    return 0;
}/*}}}*/

/**
 * @brief opens a connections to control process at arg_xdp_ctrl_proc_path
 * and writes the *xsks_map_fd
 *
 * @param xsks_map_fd
 * @return zero on success
 */
static int recv_xsks_map_fd(int* xsks_map_fd) {/*{{{*/
    struct sockaddr_un server;
    int sock;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        err(EXIT_FAILURE, "ERROR on opening socket to control process");

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, arg_xdp_ctrl_proc_path);

    if (connect(sock, (struct sockaddr*)&server, sizeof(struct sockaddr_un)) < 0)
        err(EXIT_FAILURE, "ERROR on connecting to control process socket at %s", arg_xdp_ctrl_proc_path);

    recv_xsks_map_fd_from_ctrl_node(sock, xsks_map_fd);
    return 0;
}/*}}}*/

/**
 * @brief free the given umem frame
 *
 * @param frame to free
 */
void xdp_umem_free_frame(uint64_t frame) { /*{{{*/
    if(g_xdp_socket_info.umem_frames_free_num >= XDP_NUM_FRAMES)
        errx(EXIT_FAILURE, "ERROR umem frame double-free");

    if(g_xdp_socket_info.umem_frames_map[g_xdp_socket_info.umem_frames_free_num] != XDP_UMEM_RESERVED_FRAME)
        errx(EXIT_FAILURE, "ERROR freeing a non-allocated frame");

    g_xdp_socket_info.umem_frames_map[g_xdp_socket_info.umem_frames_free_num] = frame;
    g_xdp_socket_info.umem_frames_free_num++;
} /*}}}*/

/**
 * @brief allocates a new umem frame
 *
 * @return frame addr
 */
uint64_t xdp_umem_allocate_frame(void) { /*{{{*/
    if (g_xdp_socket_info.umem_frames_free_num == 0)
        errx(EXIT_FAILURE, "ERROR no more free UMEM frames to allocate");

    g_xdp_socket_info.umem_frames_free_num--;
    uint64_t frame = g_xdp_socket_info.umem_frames_map[g_xdp_socket_info.umem_frames_free_num];
    if(frame == XDP_UMEM_RESERVED_FRAME)
        errx(EXIT_FAILURE, "ERROR allocating an already allocated frame!!");

    g_xdp_socket_info.umem_frames_map[g_xdp_socket_info.umem_frames_free_num] = XDP_UMEM_RESERVED_FRAME;
    return frame;
} /*}}}*/

/**
 * @brief check any frames reclaimable in complete queue from the kernel
 */
uint32_t xdp_reclaim_complete_queue(void) { /*{{{*/
    uint32_t completed = 0;

    // there are still packets which the kernel have not complete sending
    if (g_xdp_socket_info.xdp_stats.compl_pkts < g_xdp_socket_info.xdp_stats.tx_pkts) {
        uint32_t ret, idx_cr;

        // tell kernel to send, if we need to
        if (xsk_ring_prod__needs_wakeup(&(g_xdp_socket_info.tx_ring))) {
            ret = sendto(xsk_socket__fd(g_xdp_socket_info.xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

            if (!(ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY ||
                  errno == ENETDOWN))
                err(EXIT_FAILURE, "ERORR on xdp sendto");
        }

        completed = xsk_ring_cons__peek(&(g_xdp_socket_info.compl_ring),
                                        g_xdp_socket_info.compl_ring.size, &idx_cr);

        if (completed > 0) {
            for (uint32_t i = 0; i < completed; i++)
                xdp_umem_free_frame(
                    *xsk_ring_cons__comp_addr(&(g_xdp_socket_info.compl_ring), idx_cr++));

            xsk_ring_cons__release(&(g_xdp_socket_info.compl_ring), completed);
        }

        g_xdp_socket_info.xdp_stats.compl_pkts += completed;
    }

    return completed;
} /*}}}*/

/**
 * @brief calls rcv_pkt_cb for every packet received
 *
 * @param rcv_pkt_cb function to callback, should return 0 if umem frame should not be freed
 * @return number of packets received
 */
uint32_t xdp_foreach_rcv_pkt(int (*rcv_pkt_cb)(uint64_t, uint32_t)) { /*{{{*/
    uint32_t rcvd = 0, idx_rx = 0;

    // how many packets were received
    rcvd = xsk_ring_cons__peek(&(g_xdp_socket_info.rx_ring), arg_xdp_rx_batch_size, &idx_rx);
    if (rcvd > 0) {
        // for each received frame
        for (uint32_t i = 0; i < rcvd; i++) {
            // get umem addr and len, and advance rx index
            const struct xdp_desc* rx_desc =
                xsk_ring_cons__rx_desc(&(g_xdp_socket_info.rx_ring), idx_rx++);
            uint64_t addr = rx_desc->addr;
            uint32_t len  = rx_desc->len;

            // pass the buffer and the len to callback,
            // and see if we can free the frame or not
            if (rcv_pkt_cb(addr, len))
                xdp_umem_free_frame(addr);
        }

        // release all received in rx qu
        xsk_ring_cons__release(&(g_xdp_socket_info.rx_ring), rcvd);
    }

    g_xdp_socket_info.xdp_stats.rx_pkts += rcvd;
    return rcvd;
} /*}}}*/

/**
 * @brief calls snd_pkt_cb for every available spot for sending
 *
 * @param tx_batch_size how many packets to send
 * @param snd_pkt_cb function to callback, should return the len of the packet
 * @return number of packets sent
 */
uint32_t xdp_foreach_snd_pkt(size_t tx_batch_size, uint32_t (*snd_pkt_cb)(uint8_t*)) { /*{{{*/
    unsigned int idx_tx;

    if (xsk_ring_prod__reserve(&(g_xdp_socket_info.tx_ring), tx_batch_size, &idx_tx) !=
        tx_batch_size) {
        // there is no space in tx queue, see if we need to signal to kernel to send
        xdp_reclaim_complete_queue();
        return 0;
    }

    for (size_t i = 0; i < tx_batch_size; i++) {
        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&(g_xdp_socket_info.tx_ring), idx_tx++);
        tx_desc->addr            = xdp_umem_allocate_frame();
        uint8_t* pkt             = xsk_umem__get_data(g_xdp_socket_info.umem_buffer, tx_desc->addr);
        // write the packet to the frame
        tx_desc->len = snd_pkt_cb(pkt);
    }

    xsk_ring_prod__submit(&(g_xdp_socket_info.tx_ring), tx_batch_size);
    g_xdp_socket_info.xdp_stats.tx_pkts += tx_batch_size;
    return tx_batch_size;
} /*}}}*/

/**
 * @brief populate the fill ring with the given size of umem frames
 *
 * @param fr_size
 */
void xdp_populate_fill_ring(uint32_t fr_size) { /*{{{*/
    uint32_t ret, idx_fr;

    // claim frames from fill queue
    do {
        ret = xsk_ring_prod__reserve(&(g_xdp_socket_info.fill_ring), fr_size, &idx_fr);
        if (ret < 0)
            errx(EXIT_FAILURE, "ERROR on reserving fill queue");
    } while (ret != fr_size);

    for (uint32_t i = 0; i < fr_size; i++)
        *xsk_ring_prod__fill_addr(&(g_xdp_socket_info.fill_ring), idx_fr++) =
            xdp_umem_allocate_frame();

    // submit to kernel
    xsk_ring_prod__submit(&(g_xdp_socket_info.fill_ring), fr_size);
} /*}}}*/

/**
 * @brief create and prepares a xdp_socket_info struct
 *
 * @param socket_info
 */
void xdp_init_socket(void) { /*{{{*/
    // umem configuration
    struct xsk_umem_config umem_cfg = {
        .fill_size      = XDP_FILL_RING_SIZE,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = XDP_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags          = 0
    };

    // socket configuration
    struct xsk_socket_config xsk_cfg = {
        .rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = (arg_xdp_ctrl_proc_path) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0,
        .xdp_flags    = XDP_FLAGS,
        .bind_flags   = (arg_xdp_zero_copy) ? XDP_ZEROCOPY : XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    // reset struct's mem
    memset(&g_xdp_socket_info, 0, sizeof(struct xdp_socket_info));

    // verify and get the interface index
    g_xdp_socket_info.ifindex = if_nametoindex(arg_xdp_if);
    if (g_xdp_socket_info.ifindex == 0)
        err(EXIT_FAILURE, "ERROR could not find interface");

    // lock infinite memory, if configured
    if(arg_xdp_rlimit_memlock){
      struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
      if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        err(EXIT_FAILURE, "ERROR could not lock memory");
    }

    // allocate page-size-aligned umem buffer
    g_xdp_socket_info.umem_buffer = mmap(NULL, XDP_BUFFER_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_xdp_socket_info.umem_buffer == MAP_FAILED)
        err(EXIT_FAILURE, "ERROR allocating packets buffer");

    // create the umem
    if (xsk_umem__create(&(g_xdp_socket_info.umem), g_xdp_socket_info.umem_buffer, XDP_BUFFER_SIZE,
                         &(g_xdp_socket_info.fill_ring), &(g_xdp_socket_info.compl_ring),
                         &umem_cfg) != 0)
        err(EXIT_FAILURE, "ERROR on creating UMEM");

    // create the socket
    if (xsk_socket__create(&(g_xdp_socket_info.xsk), arg_xdp_if, arg_xdp_if_queue,
                           g_xdp_socket_info.umem, &(g_xdp_socket_info.rx_ring),
                           &(g_xdp_socket_info.tx_ring), &xsk_cfg) != 0)
        err(EXIT_FAILURE, "ERROR on creating XDP socket");

    if (arg_xdp_ctrl_proc_path){
          int xsks_map_fd;
          int ret = recv_xsks_map_fd(&xsks_map_fd);
          if (ret)
              err(EXIT_FAILURE, "ERROR on receiving xsks_map_fd");

          ret = xsk_socket__update_xskmap(g_xdp_socket_info.xsk, xsks_map_fd);
          if (ret)
              err(EXIT_FAILURE, "ERROR on updating xsks map");
    }else{
        // make sure bpf program is loaded, and get its id
        if (bpf_get_link_xdp_id(g_xdp_socket_info.ifindex, &g_xdp_socket_info.prog_id, XDP_FLAGS))
            warn("WARN bpf prog was not loaded");
    }

    // init the frame alloc
    xdp_umem_init_alloc();

    printf("[*] XDP socket initialization DONE.\n");
    fflush(stdout);
} /*}}}*/
