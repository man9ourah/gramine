/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-unix-server.h"

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "perf-common.h"
#include "perf-server.h"

/**
 * @brief handle signals and unlink the unix socket before exiting
 *
 * @param sig passed to generic server signal handler
 */
static void unix_server_unlink(int sig) { /*{{{*/
    unlink(arg_unix_server_path);
    server_handle_signal_report(sig);
} /*}}}*/

/**
 * @brief allocates and prepares the client sockaddr struct AF_UNIX
 *
 * @param client_addr where pointer to client_addr will be written
 * @return len of sockaddr
 */
static socklen_t unix_server_prep_client_addr(struct sockaddr** client_addr) { /*{{{*/
    socklen_t client_addr_len;
    struct sockaddr_un* client_addr_un;

    client_addr_un = calloc(1, sizeof(struct sockaddr_un));
    if (client_addr_un == NULL)
        err(EXIT_FAILURE, "ERROR allocating memory");

    client_addr_un->sun_family = AF_UNIX;
    *client_addr    = (struct sockaddr*)client_addr_un;
    client_addr_len = sizeof(struct sockaddr_un);
    return client_addr_len;
} /*}}}*/

/**
 * @brief Creates and initialize a server AF_UNIX socket
 *
 * @return socket fd
 */
static int unix_server_init_socket(void) { /*{{{*/
    int socketfd;
    struct sockaddr_un server_addr;

    // create socket
    socketfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socketfd < 0)
        err(EXIT_FAILURE, "ERROR opening socket");

    // server's path
    memset((char*)&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    size_t unix_server_path_len = strnlen(arg_unix_server_path, sizeof(server_addr.sun_path));
    if (unix_server_path_len == sizeof(server_addr.sun_path))
        errx(EXIT_FAILURE, "ERROR the provided unix server path is too long!");
    strncpy(server_addr.sun_path, arg_unix_server_path, unix_server_path_len);

    // bind
    if (bind(socketfd, (struct sockaddr*)&server_addr, SUN_LEN(&server_addr)) < 0)
        err(EXIT_FAILURE, "ERROR on binding");

    // listen
    if (listen(socketfd, UNIX_SERVER_BACKLOG) < 0)
        err(EXIT_FAILURE, "ERROR on listening");

    return socketfd;
} /*}}}*/

/**
 * @brief ensures the needed arguments are provided
 */
static void unix_server_ensure_args(){/*{{{*/
    if (arg_unix_server_path == NULL || arg_message_size == 0) {
        errx(EXIT_FAILURE, "ERROR invalid unix server arguments");
    }
}/*}}}*/

/**
 * @brief AF_UNIX echo server
 */
void unix_server_echo(void) { /*{{{*/
    int server_socket, client_socket, n;
    socklen_t client_addr_len;
    char buf[arg_message_size];
    struct sockaddr* client_addr;

    // we need to unlink for easy reiterations
    signal(SIGINT, unix_server_unlink);
    signal(SIGTERM, unix_server_unlink);
    signal(SIGABRT, unix_server_unlink);

    unix_server_ensure_args();

    server_socket   = unix_server_init_socket();
    client_addr_len = unix_server_prep_client_addr(&client_addr);

    while (1) {
        client_socket = accept(server_socket, client_addr, &client_addr_len);
        if (client_socket < 0)
            err(EXIT_FAILURE, "ERROR on accept connection");

        while (1) {
            n = recv(client_socket, buf, arg_message_size, 0);
            if (n < 0)
                err(EXIT_FAILURE, "ERROR on reading from socket");

            if (n == 0)
                break;

            g_server_stat.pkt_rcvd++;
            g_server_stat.bytes_rcvd += n;

            n = send(client_socket, buf, n, 0);
            if (n < 0)
                err(EXIT_FAILURE, "ERROR on writing to socket");

            g_server_stat.pkt_sent++;
            g_server_stat.bytes_sent += n;
        }
    }

    // unreachable
} /*}}}*/
