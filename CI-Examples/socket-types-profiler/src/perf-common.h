/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#ifndef PERF_COMMON_H
#define PERF_COMMON_H

#include <stddef.h>
#include <net/ethernet.h>

extern int arg_socket_type;
extern size_t arg_client_batch_size;
extern size_t arg_message_size;
extern size_t arg_iteration_count;
extern size_t arg_iteration_timeout;
extern size_t arg_pkt_fill_pattern;
extern const char* arg_unix_server_path;
extern const char* arg_unix_client_path;
extern const char* arg_inet_xdp_server_ip;
extern size_t arg_inet_xdp_server_portnum;
extern const char* arg_xdp_client_ip;
extern size_t arg_xdp_client_portnum;
extern const char* arg_xdp_if;
extern size_t arg_xdp_zero_copy;
extern size_t arg_xdp_rlimit_memlock;
extern size_t arg_xdp_rx_batch_size;
extern size_t arg_xdp_tx_batch_size;
extern size_t arg_xdp_if_queue;
extern struct ether_addr* arg_xdp_server_mac;
extern struct ether_addr* arg_xdp_client_mac;
extern const char* arg_xdp_ctrl_proc_path;

void usage(const char* prog_name);
void dbg_hex_dump(void* pkt, size_t length);
void memset32_htonl(void* dest, uint32_t val, uint32_t size);
void parse_command_line(int argc, char** argv);
#endif
