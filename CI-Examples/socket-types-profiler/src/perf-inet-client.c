/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-inet-client.h"

#include <arpa/inet.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include "perf-client.h"
#include "perf-common.h"

/**
 * @brief sends batch_count to echo server and reads them back
 *
 * @param iteration the current iteration number
 * @param socketfd socket
 * @param server_addr server address
 * @param server_addr_len server address len
 */
static void inet_client_snd_rcv_batch(int iteration, int socketfd, struct sockaddr* server_addr, /*{{{*/
                                      socklen_t server_addr_len) {
    char buf[arg_message_size];
    memset32_htonl(buf, arg_pkt_fill_pattern, arg_message_size);

    for (size_t i = 0; i < arg_client_batch_size; i++) {
        ssize_t bytes_sent = sendto(socketfd, buf, arg_message_size, 0, server_addr, server_addr_len);
        if (bytes_sent < 0) {
            warn("WARN send error, breaking!");
            g_client_stat[iteration].timedout = 1;
            break;
        }
        g_client_stat[iteration].bytes_sent += bytes_sent;
        g_client_stat[iteration].pkt_sent++;
    }

    for (size_t i = 0; i < arg_client_batch_size; i++) {
        ssize_t bytes_rcvd = recvfrom(socketfd, buf, arg_message_size, 0, NULL, NULL);
        if (bytes_rcvd < 0) {
            warn("WARN iteration timeout, breaking!");
            g_client_stat[iteration].timedout = 1;
            break;
        }
        g_client_stat[iteration].bytes_rcvd += bytes_rcvd;
        g_client_stat[iteration].pkt_rcvd++;
    }
} /*}}}*/

/**
 * @brief creates a client socket based for AF_INET
 *
 * @return socketfd
 */
static int inet_client_create_socket(void) { /*{{{*/
    int socketfd;

    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
        err(EXIT_FAILURE, "ERROR opening socket");

    struct timeval msg_timeout = {.tv_sec = 0, .tv_usec = arg_iteration_timeout};
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &msg_timeout, sizeof(struct timeval)))
        err(EXIT_FAILURE, "ERROR on setting timeout");

    return socketfd;
}
/*}}}*/

/**
 * @brief allocates and prepares the server sockaddr struct for AF_INET
 *
 * @param server_addr where allocated address for server_addr will be written
 * @return returns the size of the addr len based on the type
 */
static socklen_t inet_client_get_server_addr(struct sockaddr** server_addr) { /*{{{*/
    socklen_t server_addr_len;
    struct sockaddr_in* server_addr_in;

    server_addr_in = calloc(1, sizeof(struct sockaddr_in));
    if (server_addr_in == NULL)
        err(EXIT_FAILURE, "ERROR allocating memory");

    server_addr_in->sin_family      = AF_INET;
    server_addr_in->sin_addr.s_addr = inet_addr(arg_inet_xdp_server_ip);
    server_addr_in->sin_port        = htons(arg_inet_xdp_server_portnum);

    *server_addr    = (struct sockaddr*)server_addr_in;
    server_addr_len = sizeof(struct sockaddr_in);

    return server_addr_len;
} /*}}}*/

/**
 * @brief ensures the needed arguments are provided
 */
static void inet_client_ensure_args(){/*{{{*/
    if (arg_message_size == 0 ||
        arg_client_batch_size == 0 ||
        arg_inet_xdp_server_ip == NULL ||
        arg_inet_xdp_server_portnum == 0 ||
        arg_iteration_timeout == 0){

        errx(EXIT_FAILURE, "ERROR invalid inet client arguments");
    }
}/*}}}*/

/**
 * @brief AF_INET echo client
 */
void inet_client_echo(void) { /*{{{*/
    int socketfd;
    struct sockaddr* server_addr;
    socklen_t server_addr_len;

    inet_client_ensure_args();

    server_addr_len = inet_client_get_server_addr(&server_addr);
    socketfd        = inet_client_create_socket();

    for (size_t i = 0; i < arg_iteration_count; i++) {
        printf("[*] Iteration#%zu:\n", i + 1);

        client_log_time(&g_client_stat[i].starttime);
        inet_client_snd_rcv_batch(i, socketfd, server_addr, server_addr_len);
        client_log_time(&g_client_stat[i].stoptime);
        client_log_iteration_stat(i);

        printf("**********\n");
    }

    close(socketfd);
    free(server_addr);
    client_report_stats();
} /*}}}*/
