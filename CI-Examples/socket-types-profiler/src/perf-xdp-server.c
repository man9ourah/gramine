/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-xdp-server.h"

#include <arpa/inet.h>
#include <err.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <signal.h>
#include <stdlib.h>

#include "perf-common.h"
#include "perf-server.h"
#include "perf-xdp-common.h"

/**
 * @brief handles the signals
 *
 * @param sig the signal number passed to generic signal handler
 */
static void xdp_server_cleanup(int sig) { /*{{{*/
    xdp_cleanup();
    server_handle_signal_report(sig);
} /*}}}*/

/**
 * @brief prepare received packets for echo back
 *
 * @param pkt
 * @param len
 * @param data_len the actual user data len will be written here
 * @return 1 to echo back, 0 to drop
 */
static int xdp_server_reverse_pkt(uint8_t* pkt, uint32_t len, uint32_t* data_len) { /*{{{*/
    struct ethhdr* eth_hdr = (struct ethhdr*)pkt;
    struct iphdr* ip_hdr   = (struct iphdr*)(eth_hdr + 1);
    struct udphdr* udp_hdr = (struct udphdr*)(ip_hdr + 1);

    // check the validity of packet
    if (ntohs(eth_hdr->h_proto) != ETH_P_IP ||
        len < (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)) ||
        ip_hdr->protocol != IPPROTO_UDP ||
        memcmp(eth_hdr->h_dest, arg_xdp_server_mac, sizeof(eth_hdr->h_dest)) != 0 ||
        ip_hdr->daddr != inet_addr(arg_inet_xdp_server_ip) ||
        udp_hdr->dest != htons(arg_inet_xdp_server_portnum)) {
        return 0;
    }

    // reverse eth
    uint8_t tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth_hdr->h_dest, ETH_ALEN);
    memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
    memcpy(eth_hdr->h_source, tmp_mac, ETH_ALEN);

    // reverse ip
    struct in_addr tmp_ip;
    memcpy(&tmp_ip, &ip_hdr->saddr, sizeof(tmp_ip));
    memcpy(&ip_hdr->saddr, &ip_hdr->daddr, sizeof(tmp_ip));
    memcpy(&ip_hdr->daddr, &tmp_ip, sizeof(tmp_ip));

    // reverse udp
    __be16 tmp_prtnum;
    tmp_prtnum      = udp_hdr->dest;
    udp_hdr->dest   = udp_hdr->source;
    udp_hdr->source = tmp_prtnum;

    // set to a special value, the client will check for this
    // zero so that is also work with INET sockets
    udp_hdr->check = 0;

    g_server_stat.bytes_rcvd += htons(udp_hdr->len) - sizeof(struct udphdr);
    *data_len = (udp_hdr->len) - sizeof(struct udphdr);

    return 1;
} /*}}}*/

/**
 * @brief function to call back when a packet is received
 *
 * @param addr
 * @param len
 * @return whether umem frames should be freed: 1 free, 0 keep
 */
static int xdp_server_rcv_pkt_cb(uint64_t addr, uint32_t len) { /*{{{*/
    uint32_t idx_tx = 0, data_len = 0;

    g_server_stat.pkt_rcvd++;

    // get ptr to pkt
    uint8_t* rcvd_pkt = xsk_umem__get_data(g_xdp_socket_info.umem_buffer, addr);

    if (xdp_server_reverse_pkt(rcvd_pkt, len, &data_len)) {
        if (xsk_ring_prod__reserve(&(g_xdp_socket_info.tx_ring), 1, &idx_tx) != 1) {
            // is there a space in the tx qu?
            // we are not sending this packet,
            // give the umem frame back to allocator
            return 1;
        }

        // point it to the prepared buffer and submit for transmission
        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&(g_xdp_socket_info.tx_ring), idx_tx);
        tx_desc->addr            = addr;
        tx_desc->len             = len;

        g_server_stat.pkt_sent++;
        g_server_stat.bytes_sent += data_len;
        return 0;
    }

    // we are not sending this packet, put the umem frame back to allocator
    return 1;
} /*}}}*/

/**
 * @brief ensures the needed arguments are provided
 */
static void xdp_server_ensure_args(){/*{{{*/
    if ( arg_iteration_timeout == 0 ||
        arg_inet_xdp_server_ip == NULL ||
        arg_inet_xdp_server_portnum == 0 ||
        arg_xdp_server_mac == NULL ||
        arg_xdp_if == NULL){

        errx(EXIT_FAILURE, "ERROR invalid xdp server arguments");
    }
}/*}}}*/

/**
 * @brief entry for xdp server code
 */
void xdp_server_echo(void) { /*{{{*/
    // we need to clean up after xdp
    signal(SIGINT, xdp_server_cleanup);
    signal(SIGTERM, xdp_server_cleanup);
    signal(SIGABRT, xdp_server_cleanup);

    xdp_server_ensure_args();

    // creates the xdp socket
    xdp_init_socket();

    // fill the fill ring with all umem frames
    xdp_populate_fill_ring(XDP_FILL_RING_SIZE);

    while (1) {
        // make note; so that we know how many pkts was echoed back
        uint32_t tx_temp = g_server_stat.pkt_sent;

        // receive and echo back pkts
        xdp_foreach_rcv_pkt(xdp_server_rcv_pkt_cb);

        tx_temp = g_server_stat.pkt_sent - tx_temp;
        if (tx_temp > 0) {
            // there are packets that were resent back, tell kernel to send
            xsk_ring_prod__submit(&(g_xdp_socket_info.tx_ring), tx_temp);
            g_xdp_socket_info.xdp_stats.tx_pkts += tx_temp;
        }

        // now we check the complete queue
        xdp_reclaim_complete_queue();

        if (g_xdp_socket_info.umem_frames_free_num > 0) {
            // we have free umem frames! give them to fill queue

            uint32_t stock_frames = xsk_prod_nb_free(&(g_xdp_socket_info.fill_ring),
                                                     g_xdp_socket_info.umem_frames_free_num);

            // making sure fill queue have available spots left
            uint32_t min_avail = (stock_frames < g_xdp_socket_info.umem_frames_free_num)
                                     ? stock_frames
                                     : g_xdp_socket_info.umem_frames_free_num;

            xdp_populate_fill_ring(min_avail);
        }
    }
} /*}}}*/
