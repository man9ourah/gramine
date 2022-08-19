/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#ifndef PERF_CLIENT_H
#define PERF_CLIENT_H

#include <stdint.h>
#include <time.h>

struct client_iteration_stat {
    // the following is calculated in log_iteration_stat
    uint64_t msg_thrgpt;
    uint64_t mbps_thrgpt;
    uint64_t latency;

    // the following has to be incremented/set by user of this struct
    struct timespec starttime;
    struct timespec stoptime;
    uint64_t bytes_sent;
    uint64_t bytes_rcvd;
    uint64_t pkt_sent;
    uint64_t pkt_rcvd;
    uint8_t timedout;
};

extern struct client_iteration_stat* g_client_stat;
extern size_t arg_client_batch_size;

void client_log_iteration_stat(size_t iteration);
void client_report_stats(void);
void client_log_time(struct timespec* tspc);
#endif
