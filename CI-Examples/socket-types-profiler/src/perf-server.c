/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-server.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "perf-common.h"
#include "perf-inet-server.h"
#include "perf-unix-server.h"
#include "perf-xdp-server.h"

struct server_stat g_server_stat;

/**
 * @brief reports the server status before exiting due to interrupt
 *
 * @param _sig the signal number (not used)
 */
void server_handle_signal_report(int _sig) { /*{{{*/
    printf("******************************\n");
    printf("Server interrupted\n");
    printf("[*] Total pkt sent:\t\t%ld pkts\n", g_server_stat.pkt_sent);
    printf("[*] Total bytes sent:\t\t%ld bytes\n", g_server_stat.bytes_sent);
    printf("[*] Total pkt rcvd:\t\t%ld pkts\n", g_server_stat.pkt_rcvd);
    printf("[*] Total bytes rcvd:\t\t%ld bytes\n", g_server_stat.bytes_rcvd);
    exit(0);
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
        " -s n                         Size of packets data (bytes) [Default = 1024].\n"
        "\n"

        " Unix sockets required options:\n"
        " -U path                      Unix server path.\n"
        "\n"

        " INET sockets required options:\n"
        " -I ip                        Server IP address [format: 111.222.333.444].\n"
        " -P n                         Server port number.\n"
        "\n"

        " XDP sockets required options:\n"
        " -I ip                        Server IP address [format: 111.222.333.444].\n"
        " -P n                         Server port number.\n"
        " -M mac                       Server MAC address [format: aa:bb:cc:dd:ee:ff].\n"
        " -f name                      Ethernet interface name.\n"
        " -q n                         Interface queue ID.\n"
        "\n"

        " XDP sockets optional options:\n"
        " -z                           Use zero copy mode and avoid waking-up the kernel (need NIC support)[Default: false].\n"
        " -l                           Set rlimit for memory locking to infinite [Default: false].\n"
        " -r n                         RX batch size - in number of packets [Default: 64].\n"
        " -x ctrl_process_unix_path    Dont setup bpf xdp program and connect to a control process to receive the bpf map fd [Default: Not set].\n"
        "\n";

    fprintf(stderr, usage_fmt_str, prog_name);
    exit(EXIT_FAILURE);
}/*}}}*/

int main(int argc, char** argv) { /*{{{*/
    parse_command_line(argc, argv);

    switch (arg_socket_type) {
        case AF_UNIX:
            unix_server_echo();
            break;
        case AF_INET:
            inet_server_echo();
            break;
        case AF_XDP:
            xdp_server_echo();
            break;
        default:
            errx(EXIT_FAILURE, "Required arg: socket type was not provided. Aborting.");
    }
    return 0;
} /*}}}*/
