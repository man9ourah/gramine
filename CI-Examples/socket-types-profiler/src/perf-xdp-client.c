/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-xdp-client.h"

#include <arpa/inet.h>
#include <err.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <signal.h>
#include <stdlib.h>

#include "perf-client.h"
#include "perf-common.h"
#include "perf-xdp-common.h"

// useful constants
#define ETH_FRAME_CHECK_SQ_SIZE 4
#define UDP_PKT_DATA_SIZE       arg_message_size
#define UDP_PKT_SIZE            (UDP_PKT_DATA_SIZE + sizeof(struct udphdr))
#define IP_PKT_SIZE             (UDP_PKT_SIZE + sizeof(struct iphdr))
#define PKT_SIZE                (IP_PKT_SIZE + sizeof(struct ethhdr) + ETH_FRAME_CHECK_SQ_SIZE)

// current iteration number
size_t g_cur_iter = 0;

// we use this to move on from lost pkts
struct timespec g_timeout_timer = {.tv_sec = 0, .tv_nsec = 0};
uint8_t g_timeout_started       = 0;

/**
 * @brief those functions taken from the kernel source tree handles the checksum gen
 */
/* Checksum functions{{{*/
static inline __sum16 csum_fold(__wsum csum) {
    uint32_t sum = (uint32_t)csum;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__sum16)~sum;
}

static inline uint32_t from64to32(uint64_t x) {
    /* add up 32-bit and 32-bit for 32+c bit */
    x = (x & 0xffffffff) + (x >> 32);
    /* add up carry.. */
    x = (x & 0xffffffff) + (x >> 32);
    return (uint32_t)x;
}

static __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len, __u8 proto,
                                 __wsum sum) {
    unsigned long long s = (uint32_t)sum;

    s += (uint32_t)saddr;
    s += (uint32_t)daddr;
#ifdef __BIG_ENDIAN__
    s += proto + len;
#else
    s += (proto + len) << 8;
#endif
    return (__wsum)from64to32(s);
}

static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len, __u8 proto,
                                        __wsum sum) {
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline uint16_t udp_csum(uint32_t saddr, uint32_t daddr, uint32_t len, uint8_t proto,
                                uint16_t* udp_pkt) {
    uint32_t csum = 0;
    uint32_t cnt  = 0;

    /* udp hdr and data */
    for (; cnt < len; cnt += 2) csum += udp_pkt[cnt >> 1];

    return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

static inline unsigned short from32to16(unsigned int x) {
    /* add up 16-bit and 16-bit for 16+c bit */
    x = (x & 0xffff) + (x >> 16);
    /* add up carry.. */
    x = (x & 0xffff) + (x >> 16);
    return x;
}

static unsigned int do_csum(const unsigned char* buff, int len) {
    unsigned int result = 0;
    int odd;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd) {
#ifdef __LITTLE_ENDIAN
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    if (len >= 2) {
        if (2 & (unsigned long)buff) {
            result += *(unsigned short*)buff;
            len -= 2;
            buff += 2;
        }
        if (len >= 4) {
            const unsigned char* end = buff + ((unsigned int)len & ~3);
            unsigned int carry       = 0;

            do {
                unsigned int w = *(unsigned int*)buff;

                buff += 4;
                result += carry;
                result += w;
                carry = (w > result);
            } while (buff < end);
            result += carry;
            result = (result & 0xffff) + (result >> 16);
        }
        if (len & 2) {
            result += *(unsigned short*)buff;
            buff += 2;
        }
    }
    if (len & 1)
#ifdef __LITTLE_ENDIAN
        result += *buff;
#else
        result += (*buff << 8);
#endif
    result = from32to16(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
    return result;
}

static __sum16 ip_fast_csum(const void* iph, unsigned int ihl)
{
    return (__sum16)~do_csum(iph, ihl * 4);
}
/*}}}*/

/**
 * @brief handles the signals
 *
 * @param _sig the signal number (not used)
 */
static void cli_handle_signal(int _sig) { /*{{{*/
    client_log_iteration_stat(g_cur_iter);
    xdp_cleanup();
    exit(0);
} /*}}}*/

/**
 * @brief given a buffer, it will fill it with proper eth(ip(udp(data))) for it
 * to be sent from client to server
 *
 * @param pkt_buffer pointer to buffer with at least XDP_FRAME_SIZE
 * @return length of the packet
 */
static uint32_t prepare_client_pkt(uint8_t* pkt_buffer) { /*{{{*/
    struct ethhdr* eth_hdr = (struct ethhdr*)pkt_buffer;
    struct iphdr* ip_hdr   = (struct iphdr*)(eth_hdr + 1);
    struct udphdr* udp_hdr = (struct udphdr*)(ip_hdr + 1);
    uint8_t* udp_data      = (uint8_t*)(udp_hdr + 1);

    if(PKT_SIZE > XDP_FRAME_SIZE)
        err(EXIT_FAILURE, "data size is bigger than xdp frame size");

    /* ethernet header */
    memcpy(eth_hdr->h_dest, arg_xdp_server_mac, ETH_ALEN);
    memcpy(eth_hdr->h_source, arg_xdp_client_mac, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_IP);

    /* IP header */
    ip_hdr->version  = IPVERSION;
    ip_hdr->ihl      = 0x5; /* 20 byte header */
    ip_hdr->tos      = 0x0;
    ip_hdr->tot_len  = htons(IP_PKT_SIZE);
    ip_hdr->id       = 0;
    ip_hdr->frag_off = 0;
    ip_hdr->ttl      = IPDEFTTL;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->saddr    = inet_addr(arg_xdp_client_ip);
    ip_hdr->daddr    = inet_addr(arg_inet_xdp_server_ip);

    /* IP header checksum */
    ip_hdr->check = 0;
    ip_hdr->check = ip_fast_csum((const void*)ip_hdr, ip_hdr->ihl);

    /* UDP header */
    udp_hdr->source = htons(arg_xdp_client_portnum);
    udp_hdr->dest   = htons(arg_inet_xdp_server_portnum);
    udp_hdr->len    = htons(UDP_PKT_SIZE);

    /* UDP data */
    memset32_htonl(udp_data, arg_pkt_fill_pattern, arg_message_size);

    /* UDP header checksum */
    udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE, IPPROTO_UDP, (uint16_t*)udp_hdr);

    g_client_stat[g_cur_iter].bytes_sent += arg_message_size;
    return PKT_SIZE;
} /*}}}*/

/**
 * @brief simply check some fields in the packet
 *
 * @param pkt
 * @param len
 */
static void process_pkt(uint8_t* pkt, unsigned int len) { /*{{{*/
    struct ethhdr* eth_hdr = (struct ethhdr*)pkt;
    struct iphdr* ip_hdr   = (struct iphdr*)(eth_hdr + 1);
    struct udphdr* udp_hdr = (struct udphdr*)(ip_hdr + 1);

    // check the protocols
    if (ntohs(eth_hdr->h_proto) != ETH_P_IP ||
        len < (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr)) ||
        ip_hdr->protocol != IPPROTO_UDP)
        return;

    // check the destinations
    if (memcmp(eth_hdr->h_dest, arg_xdp_client_mac, sizeof(eth_hdr->h_dest)) != 0 ||
        ip_hdr->daddr != inet_addr(arg_xdp_client_ip) ||
        udp_hdr->dest != htons(arg_xdp_client_portnum))
        return;

    g_client_stat[g_cur_iter].bytes_rcvd += htons(udp_hdr->len) - sizeof(struct udphdr);
} /*}}}*/

/**
 * @brief called-back when a packet is received
 *
 * @param addr
 * @param len
 * @return always return 1: give frame back to allocator
 */
static int rcv_pkt_cb(uint64_t addr, uint32_t len) { /*{{{*/
    g_client_stat[g_cur_iter].pkt_rcvd++;
    uint8_t* pkt = xsk_umem__get_data(g_xdp_socket_info.umem_buffer, addr);
    process_pkt(pkt, len);
    // give back to allocator
    return 1;
} /*}}}*/

/**
 * @brief checks if we have timed out on this iteration
 *
 * @return 1 if timed out, 0 otherwise
 */
static int check_timeout(void) { /*{{{*/
    if (!g_timeout_started)
        return 0;

    if (g_timeout_timer.tv_sec == 0 && g_timeout_timer.tv_nsec == 0) {
        client_log_time(&g_timeout_timer);
        return 0;

    } else {
        // we already finished transmitting packets, we should timeout if we
        // have not received a packet in a while
        struct timespec bkeep_ctime;
        client_log_time(&bkeep_ctime);
        uint64_t iteration_time_delta_us = (bkeep_ctime.tv_sec - g_timeout_timer.tv_sec) * 1000000;
        iteration_time_delta_us += (bkeep_ctime.tv_nsec - g_timeout_timer.tv_nsec) / 1000;
        return iteration_time_delta_us > arg_iteration_timeout;
    }
} /*}}}*/

/**
 * @brief main client loop for sending and receiving batch_size pkts
 */
static void echo_loop_xdp(void) { /*{{{*/
    while (g_xdp_socket_info.xdp_stats.compl_pkts < arg_client_batch_size ||
           g_xdp_socket_info.xdp_stats.rx_pkts < arg_client_batch_size) {

        // tx: do we need to send more packets?
        if (g_xdp_socket_info.xdp_stats.compl_pkts < arg_client_batch_size) {
            if (g_xdp_socket_info.xdp_stats.tx_pkts < arg_client_batch_size) {
                int tx_batch_size = arg_xdp_tx_batch_size;
                if(g_xdp_socket_info.xdp_stats.tx_pkts + arg_xdp_tx_batch_size > arg_client_batch_size)
                    tx_batch_size = arg_client_batch_size - g_xdp_socket_info.xdp_stats.tx_pkts;

                uint32_t snt_pkts = xdp_foreach_snd_pkt(tx_batch_size, prepare_client_pkt);
                g_client_stat[g_cur_iter].pkt_sent += snt_pkts;
            }

            xdp_reclaim_complete_queue();
        } else {
            // we finished sending all packets. we start the timeout now for
            // receiving packets.
            g_timeout_started = 1;
        }

        // rx: do we need to receive more pkts?
        if (g_xdp_socket_info.xdp_stats.rx_pkts < arg_client_batch_size) {
            uint32_t rcvd = xdp_foreach_rcv_pkt(rcv_pkt_cb);
            if (rcvd > 0) {
                // we received packets, reset timeout timer
                g_timeout_timer.tv_sec  = 0;
                g_timeout_timer.tv_nsec = 0;
                // circle back rcvd frames into fill queue
                xdp_populate_fill_ring(rcvd);
            } else {
                // we have not received anyting, did we timeout?
                if (check_timeout()) {
                    warnx("iteration timeout, breaking!");
                    g_client_stat[g_cur_iter].timedout = 1;
                    break;
                }
            }
        }

    }  // while loop
} /*}}}*/

/**
 * @brief ensures the needed arguments are provided
 */
static void xdp_client_ensure_args(){/*{{{*/
    if (arg_message_size == 0 ||
        arg_client_batch_size == 0 ||
        arg_iteration_timeout == 0 ||
        arg_inet_xdp_server_ip == NULL ||
        arg_inet_xdp_server_portnum == 0 ||
        arg_xdp_server_mac == NULL ||
        arg_xdp_client_ip  == NULL ||
        arg_xdp_client_portnum == 0 ||
        arg_xdp_client_mac == NULL ||
        arg_xdp_if == NULL){

        errx(EXIT_FAILURE, "ERROR invalid xdp client arguments");
    }
}/*}}}*/

/**
 * @brief entry point for AF_XDP echo client
 */
void xdp_client_echo(void) { /*{{{*/
    // we need to unlink for easy reiterations
    signal(SIGINT, cli_handle_signal);
    signal(SIGTERM, cli_handle_signal);
    signal(SIGABRT, cli_handle_signal);

    xdp_client_ensure_args();

    // creates the xdp socket
    xdp_init_socket();

    // put half of the umem frames in the fill ring
    xdp_populate_fill_ring(XDP_CLIENT_FQ_UMEM);

    for (g_cur_iter = 0; g_cur_iter < arg_iteration_count; g_cur_iter++) {
        printf("[*] Iteration#%lu:\n", g_cur_iter + 1);

        client_log_time(&g_client_stat[g_cur_iter].starttime);
        echo_loop_xdp();
        client_log_time(&g_client_stat[g_cur_iter].stoptime);

        client_log_iteration_stat(g_cur_iter);

        // reset xdp stats
        g_xdp_socket_info.xdp_stats.rx_pkts    = 0;
        g_xdp_socket_info.xdp_stats.tx_pkts    = 0;
        g_xdp_socket_info.xdp_stats.compl_pkts = 0;

        // reset timeout timer
        g_timeout_timer.tv_sec  = 0;
        g_timeout_timer.tv_nsec = 0;
        g_timeout_started       = 0;

        printf("**********\n");
    }

    client_report_stats();
    xdp_cleanup();
} /*}}}*/
