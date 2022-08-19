/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-client.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include "perf-common.h"
#include "perf-inet-client.h"
#include "perf-unix-client.h"
#include "perf-xdp-client.h"

// an array for each iteration stat
struct client_iteration_stat* g_client_stat;

/**
 * @brief report single iteration stats and aggregate for total
 *
 * @param iteration iteration to log
 */
void client_log_iteration_stat(size_t iteration) { /*{{{*/
    struct client_iteration_stat* current_stat = &g_client_stat[iteration];

    struct timespec* starttime = &current_stat->starttime;
    struct timespec* stoptime  = &current_stat->stoptime;
    uint64_t time_delta_us     = (stoptime->tv_sec - starttime->tv_sec) * 1000000 +
                             (stoptime->tv_nsec - starttime->tv_nsec) / 1000;
    uint64_t time_delta_ns = time_delta_us * 1000;

    if (current_stat->pkt_rcvd > 0) {
        // cap the pkt received to pkt sent. sometimes it carries over from previous
        // iteration which we already timed out on
        current_stat->pkt_rcvd = (current_stat->pkt_rcvd > current_stat->pkt_sent)
                                     ? current_stat->pkt_sent
                                     : current_stat->pkt_rcvd;

        current_stat->bytes_rcvd = (current_stat->bytes_rcvd > current_stat->bytes_sent)
                                       ? current_stat->bytes_sent
                                       : current_stat->bytes_rcvd;

        // we use rcvd pkt number, not sent; this account for packets dropped
        current_stat->latency = time_delta_ns / (current_stat->pkt_rcvd * 2);

        // we mulitply by two since delta is a two way time measurment
        current_stat->msg_thrgpt = (current_stat->pkt_rcvd * 2 * 1000000 / time_delta_us);
        current_stat->mbps_thrgpt =
            ((current_stat->bytes_rcvd * 2 * 8 * 1000000) / time_delta_us) / 1000000;

        printf("%-54s %ld ns\n", "[*] Single-Iteration average latency:", current_stat->latency);
        printf("%-54s %ld Mbps\n", "[*] Single-Iteration average bits throughput:", current_stat->mbps_thrgpt);
        printf("%-54s %ld pkt/s\n", "[*] Single-Iteration average msg throughput:", current_stat->msg_thrgpt);
    }

    uint64_t pkts_dropped  = current_stat->pkt_sent - current_stat->pkt_rcvd;
    uint64_t pkts_droppedP = (pkts_dropped / current_stat->pkt_sent) * 100;

    printf("%-54s %ld pkts\n", "[*] Single-Iteration pkt sent:", current_stat->pkt_sent);
    printf("%-54s %ld bytes\n", "[*] Single-Iteration bytes sent:", current_stat->bytes_sent);
    printf("%-54s %ld pkts\n", "[*] Single-Iteration pkt rcvd:", current_stat->pkt_rcvd);
    printf("%-54s %ld bytes\n", "[*] Single-Iteration bytes rcvd:", current_stat->bytes_rcvd);
    printf("%-54s %ld (%%%ld) bytes\n", "[*] Single-Iteration pkts dropped:", pkts_dropped,
           pkts_droppedP);
} /*}}}*/

/**
 * @brief report starts accross iterations
 */
void client_report_stats(void) { /*{{{*/
    uint64_t total_latency         = 0;
    uint64_t total_msg_thrgpt      = 0;
    uint64_t total_byte_thrgpt     = 0;
    uint64_t total_bytes_sent      = 0;
    uint64_t total_bytes_rcvd      = 0;
    uint64_t total_pkt_sent        = 0;
    uint64_t total_pkt_rcvd        = 0;
    uint64_t overall_msg_thrgpt    = 0;
    uint64_t overall_byte_thrgpt   = 0;
    uint64_t avg_latency           = 0;
    uint64_t overall_pkts_dropped  = 0;
    uint64_t overall_pkts_droppedP = 0;

    size_t timedout_iterations     = 0;
    for (size_t i = 0; i < arg_iteration_count; i++) {
        total_pkt_sent      += g_client_stat[i].pkt_sent;
        total_bytes_sent    += g_client_stat[i].bytes_sent;
        total_pkt_rcvd      += g_client_stat[i].pkt_rcvd;
        total_bytes_rcvd    += g_client_stat[i].bytes_rcvd;
        total_latency       += g_client_stat[i].latency;
        total_msg_thrgpt    += g_client_stat[i].msg_thrgpt;
        total_byte_thrgpt   += g_client_stat[i].mbps_thrgpt;
        timedout_iterations += g_client_stat[i].timedout;
    }

    overall_msg_thrgpt    = total_msg_thrgpt / arg_iteration_count;
    overall_byte_thrgpt   = total_byte_thrgpt / arg_iteration_count;
    avg_latency           = total_latency / arg_iteration_count;
    overall_pkts_dropped  = total_pkt_sent - total_pkt_rcvd;
    overall_pkts_droppedP = overall_pkts_dropped * 100 / total_pkt_sent;

    printf("******************************\n");
    printf("Test ended.\n");

    const char* fmt_str = "[*] %4d %-45s %ld %s\n";
    printf(fmt_str, arg_iteration_count, "Iterations average msg throughput:", overall_msg_thrgpt, "pkt/s");
    printf(fmt_str, arg_iteration_count, "Iterations average byte throughput:", overall_byte_thrgpt, "Mbps");
    printf(fmt_str, arg_iteration_count, "Iterations average latency:", avg_latency, "ns");
    printf(fmt_str, arg_iteration_count, "Iterations total pkt sent:", total_pkt_sent, "packets");
    printf(fmt_str, arg_iteration_count, "Iterations total bytes sent:", total_bytes_sent, "bytes");
    printf(fmt_str, arg_iteration_count, "Iterations total pkt received:", total_pkt_rcvd, "packets");
    printf(fmt_str, arg_iteration_count, "Iterations total bytes received:", total_bytes_rcvd, "bytes");
    printf(fmt_str, arg_iteration_count, "Iterations number of timedout iterations:", timedout_iterations, "iterations");
    printf(fmt_str, arg_iteration_count, "Iterations total of packets dropped:", overall_pkts_dropped, "packets");
    printf(fmt_str, arg_iteration_count, "Iterations % of packets dropped:", overall_pkts_droppedP, "%");
} /*}}}*/

/**
 * @brief logs a timetamp to tspc
 *
 * @param tspc where timetamp is saved
 */
void client_log_time(struct timespec* tspc) { /*{{{*/
    if (clock_gettime(CLOCK_MONOTONIC, tspc) == -1)
        err(EXIT_FAILURE, "clock_gettime");
} /*}}}*/

/**
 * @brief prints usage and exit
 *
 * @param prog_name
 */
void usage(const char *prog_name){/*{{{*/
    const char* usage_fmt_str = " Usage: %s [OPTIONS] SOCKET_TYPE\n"
        " Required options:\n"
        " SOCKET_TYPE                  Socket type to test [unix|inet|xdp].\n"
        "\n"

        " Options:\n"
        " Experiment options:\n"
        " -c n                         Number of iterations [Default = 10].\n"
        " -b n                         Number of packets sent in one iteration [Default = 100].\n"
        " -s n                         Size of packets data (bytes) [Default = 1024].\n"
        " -o n                         Timeout for a single iteration in microseconds [Default = 100].\n"
        " -d n                         data fill pattern [Default = 0x41414141].\n"
        "\n"

        " Unix sockets required options:\n"
        " -U path                      Unix server path.\n"
        " -u path                      Unix client path.\n"
        "\n"

        " INET sockets required options:\n"
        " -I ip                        Server IP address [format: 111.222.333.444].\n"
        " -P n                         Server port number.\n"
        "\n"

        " XDP sockets required options:\n"
        " -I ip                        Server IP address [format: 111.222.333.444].\n"
        " -P n                         Server port number.\n"
        " -M mac                       Server MAC address [format: aa:bb:cc:dd:ee:ff].\n"
        " -i ip                        Client IP address [format: 111.222.333.444].\n"
        " -p n                         Client port number.\n"
        " -m mac                       Client MAC address [format: aa:bb:cc:dd:ee:ff].\n"
        " -f name                      Ethernet interface name.\n"
        " -q n                         Interface queue ID.\n"
        "\n"

        " XDP sockets optional options:\n"
        " -z                           Use zero copy mode and avoid waking-up the kernel (need NIC support)[Default: false].\n"
        " -l                           Set rlimit for memory locking to infinite [Default: false].\n"
        " -r n                         RX batch size - in number of packets [Default: 64].\n"
        " -t n                         TX batch size - in number of packets [Default: 64].\n"
        " -x ctrl_process_unix_path    Dont setup bpf xdp program and connect to a control process to receive the bpf map fd [Default: Not set].\n"
        "\n";

    fprintf(stderr, usage_fmt_str, prog_name);
    exit(EXIT_FAILURE);
}/*}}}*/

int main(int argc, char** argv) { /*{{{*/
    parse_command_line(argc, argv);
    g_client_stat = malloc(sizeof(struct client_iteration_stat) * arg_iteration_count);

    switch (arg_socket_type) {
        case AF_UNIX:
            unix_client_echo();
            break;
        case AF_INET:
            inet_client_echo();
            break;
        case AF_XDP:
            xdp_client_echo();
            break;
        default:
            errx(EXIT_FAILURE, "Required arg: socket type was not provided. Aborting.");
    }
    return 0;
} /*}}}*/
