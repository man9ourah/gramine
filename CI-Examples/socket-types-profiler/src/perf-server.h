/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#ifndef PERF_SERVER_H
#define PERF_SERVER_H

#include <stdint.h>

struct server_stat {
    uint64_t bytes_sent;
    uint64_t bytes_rcvd;
    uint64_t pkt_sent;
    uint64_t pkt_rcvd;
};

extern struct server_stat g_server_stat;

void server_handle_signal_report(int _sig);
#endif
