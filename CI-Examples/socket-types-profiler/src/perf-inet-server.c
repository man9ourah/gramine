/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-inet-server.h"

#include <arpa/inet.h>
#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>

#include "perf-common.h"
#include "perf-server.h"

/**
 * @brief allocates and prepares the client sockaddr struct AF_INET
 *
 * @param client_addr where pointer to client_addr will be written
 * @return len of sockaddr
 */
static socklen_t inet_server_prep_client_addr(struct sockaddr** client_addr) { /*{{{*/
    socklen_t client_addr_len;
    struct sockaddr_in* client_addr_in;

    client_addr_in = calloc(1, sizeof(struct sockaddr_in));
    if (client_addr_in == NULL)
        err(EXIT_FAILURE, "ERROR allocating memory");

    client_addr_in->sin_family = AF_INET;
    *client_addr    = (struct sockaddr*)client_addr_in;
    client_addr_len = sizeof(struct sockaddr_in);
    return client_addr_len;
} /*}}}*/

/**
 * @brief Creates and initialize a server on AF_INET socket
 *
 * @return socket fd
 */
static int inet_server_init_socket(void) { /*{{{*/
    int socketfd;
    int optval;
    struct sockaddr_in serveraddr;

    // create the socket
    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
        err(EXIT_FAILURE, "ERROR opening socket");

    // make it reusable
    optval = 1;
    setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));

    // server's ip & port
    memset((char*)&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family      = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(arg_inet_xdp_server_ip);
    serveraddr.sin_port        = htons(arg_inet_xdp_server_portnum);

    // bind
    if (bind(socketfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
        err(EXIT_FAILURE, "ERROR on binding");

    return socketfd;
} /*}}}*/

/**
 * @brief ensures the needed arguments are provided
 */
static void inet_server_ensure_args(){/*{{{*/
    if (arg_message_size == 0 ||
        arg_inet_xdp_server_ip == NULL ||
        arg_inet_xdp_server_portnum == 0){

        errx(EXIT_FAILURE, "ERROR invalid inet server arguments");
    }
}/*}}}*/

/**
 * @brief AF_INET echo server
 */
void inet_server_echo(void) { /*{{{*/
    int socketfd, n;
    socklen_t cli_addr_len;
    char buf[arg_message_size];
    struct sockaddr* cli_addr;

    inet_server_ensure_args();

    // report status before exiting
    signal(SIGINT, server_handle_signal_report);
    signal(SIGTERM, server_handle_signal_report);
    signal(SIGABRT, server_handle_signal_report);

    socketfd     = inet_server_init_socket();
    cli_addr_len = inet_server_prep_client_addr(&cli_addr);

    while (1) {
        n = recvfrom(socketfd, buf, arg_message_size, 0, cli_addr, &cli_addr_len);
        if (n < 0)
            err(EXIT_FAILURE, "ERROR on reading from socket");

        g_server_stat.pkt_rcvd++;
        g_server_stat.bytes_rcvd += n;

        n = sendto(socketfd, buf, n, 0, cli_addr, cli_addr_len);
        if (n < 0)
            err(EXIT_FAILURE, "ERROR on writing to socket");

        g_server_stat.pkt_sent++;
        g_server_stat.bytes_sent += n;
    }
    // unreachable
} /*}}}*/
