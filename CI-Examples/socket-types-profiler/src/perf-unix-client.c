/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-unix-client.h"

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "perf-client.h"
#include "perf-common.h"

/**
 * @brief handle signals and unlink the unix socket before exiting
 *
 * @param _sig not used
 */
static void unix_client_unlink(int _sig) { /*{{{*/
    unlink(arg_unix_client_path);
    exit(EXIT_SUCCESS);
} /*}}}*/

/**
 * @brief sends batch_count to echo server and reads them back
 *
 * @param iteration the current iteration number
 * @param socketfd socket
 * @param server_addr server address
 * @param server_addr_len server address len
 */
static void unix_client_snd_rcv_batch(int iteration, int socketfd) { /*{{{*/
    char buf[arg_message_size];
    memset32_htonl(buf, arg_pkt_fill_pattern, arg_message_size);

    for (size_t i = 0; i < arg_client_batch_size; i++) {
        ssize_t bytes_sent = send(socketfd, buf, arg_message_size, 0);
        if (bytes_sent < 0) {
            warn("[!] send error, breaking!");
            g_client_stat[iteration].timedout = 1;
            break;
        }
        g_client_stat[iteration].bytes_sent += bytes_sent;
        g_client_stat[iteration].pkt_sent++;
    }

    for (size_t i = 0; i < arg_client_batch_size; i++) {
        ssize_t bytes_rcvd = recv(socketfd, buf, arg_message_size, 0);
        if (bytes_rcvd < 0) {
            warn("[!] Iteration timeout, breaking!");
            g_client_stat[iteration].timedout = 1;
            break;
        }
        g_client_stat[iteration].bytes_rcvd += bytes_rcvd;
        g_client_stat[iteration].pkt_rcvd++;
    }
} /*}}}*/

/**
 * @brief creates a client socket for AF_UNIX
 *
 * @return socketfd
 */
static int unix_client_create_socket(void) { /*{{{*/
    int socketfd;
    struct sockaddr_un client_addr;
    size_t unix_client_path_len;

    socketfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socketfd < 0)
        err(EXIT_FAILURE, "ERROR opening socket");

    memset(&client_addr, 0, sizeof(struct sockaddr_un));
    client_addr.sun_family = AF_UNIX;

    unix_client_path_len = strnlen(arg_unix_client_path, sizeof(client_addr.sun_path));
    if (unix_client_path_len == sizeof(client_addr.sun_path))
        errx(EXIT_FAILURE, "ERROR the provided unix client path is too long!");
    strncpy(client_addr.sun_path, arg_unix_client_path, unix_client_path_len);

    if (bind(socketfd, (struct sockaddr*)&client_addr, SUN_LEN(&client_addr)) < 0)
        err(EXIT_FAILURE, "ERROR on binding");

    return socketfd;
}
/*}}}*/

/**
 * @brief allocates and prepares the server sockaddr struct for AF_UNIX
 *
 * @param server_addr where pointer to server_addr will be written
 * @return returns the size of the addr len
 */
static socklen_t unix_client_get_server_addr(struct sockaddr** server_addr) { /*{{{*/
    socklen_t server_addr_len;
    struct sockaddr_un* server_addr_un;
    size_t unix_server_path_len;

    server_addr_un = calloc(1, sizeof(struct sockaddr_un));
    if (server_addr_un == NULL)
        err(EXIT_FAILURE, "ERROR allocating memory");

    server_addr_un->sun_family = AF_UNIX;

    unix_server_path_len = strnlen(arg_unix_server_path, sizeof(server_addr_un->sun_path));
    if (unix_server_path_len == sizeof(server_addr_un->sun_path))
        errx(EXIT_FAILURE, "ERROR the provided unix server path is too long!");
    strncpy(server_addr_un->sun_path, arg_unix_server_path, unix_server_path_len);

    *server_addr    = (struct sockaddr*)server_addr_un;
    server_addr_len = SUN_LEN(server_addr_un);

    return server_addr_len;
} /*}}}*/

/**
 * @brief ensures the needed arguments are provided
 */
static void unix_client_ensure_args(){/*{{{*/
    if (arg_unix_server_path == NULL ||
        arg_unix_client_path == NULL ||
        arg_client_batch_size == 0 ||
        arg_iteration_count == 0 ||
        arg_message_size == 0) {

        errx(EXIT_FAILURE, "ERROR invalid unix client arguments");
    }
}/*}}}*/

/**
 * @brief AF_UNIX echo client
 */
void unix_client_echo(void) { /*{{{*/
    int socketfd;
    struct sockaddr* server_addr;
    socklen_t server_addr_len;

    unix_client_ensure_args();

    // we need to unlink for easy reiterations
    signal(SIGINT, unix_client_unlink);
    signal(SIGTERM, unix_client_unlink);
    signal(SIGABRT, unix_client_unlink);

    server_addr_len = unix_client_get_server_addr(&server_addr);
    socketfd        = unix_client_create_socket();

    if (connect(socketfd, server_addr, server_addr_len) < 0)
        err(EXIT_FAILURE, "ERROR on connecting");

    for (size_t i = 0; i < arg_iteration_count; i++) {
        printf("[*] Iteration#%zu:\n", i + 1);

        client_log_time(&g_client_stat[i].starttime);
        unix_client_snd_rcv_batch(i, socketfd);
        client_log_time(&g_client_stat[i].stoptime);

        client_log_iteration_stat(i);

        printf("**********\n");
    }

    close(socketfd);
    unlink(arg_unix_client_path);
    free(server_addr);

    client_report_stats();
}
