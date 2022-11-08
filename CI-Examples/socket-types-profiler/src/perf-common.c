/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include "perf-common.h"

#include <err.h>
#include <getopt.h>
#include <libgen.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// args for all socket types
int arg_socket_type       = AF_UNSPEC;
size_t arg_client_batch_size = 100;
size_t arg_message_size      = 1024;
size_t arg_iteration_count   = 10;
size_t arg_iteration_timeout = 100;
size_t arg_pkt_fill_pattern  = 0x41414141;

// args for unix socket type
const char* arg_unix_server_path = NULL;
const char* arg_unix_client_path = NULL;

// args for inet & xdp socket type
const char* arg_inet_xdp_server_ip = NULL;
size_t arg_inet_xdp_server_portnum = 0;

// args for xdp socket types
struct ether_addr* arg_xdp_server_mac = NULL;
const char* arg_xdp_client_ip         = NULL;
size_t arg_xdp_client_portnum         = 0;
struct ether_addr* arg_xdp_client_mac = NULL;
const char* arg_xdp_if                = NULL;
size_t arg_xdp_if_queue               = 0;
size_t arg_xdp_rlimit_memlock         = 0;
size_t arg_xdp_zero_copy              = 0;
size_t arg_xdp_rx_batch_size          = 64;
size_t arg_xdp_tx_batch_size          = 64;
const char* arg_xdp_ctrl_proc_path    = NULL;

/**
 * @brief hex dumps a pkt, just for debugging
 *
 * @param pkt
 * @param length
 */
void dbg_hex_dump(void* pkt, size_t length) { /*{{{*/
    const uint8_t* address = (uint8_t*)pkt;
    const uint8_t* line    = address;
    size_t line_size       = 32;
    uint8_t c;
    int i = 0;

    printf("length = %zu\n", length);
    while (length-- > 0) {
        printf("%02X ", *address++);
        if (!(++i % line_size) || (length == 0 && i % line_size)) {
            if (length == 0) {
                while (i++ % line_size) printf("__ ");
            }
            printf(" | "); /* right close */
            while (line < address) {
                c = *line++;
                printf("%c", (c < 33 || c == 255) ? 0x2E : c);
            }
            printf("\n");
        }
    }
    printf("\n");
} /*}}}*/

/**
 * @brief fills dest with size of repeated val
 *
 * @param dest
 * @param val
 * @param size
 */
void memset32_htonl(void* dest, uint32_t val, uint32_t size) { /*{{{*/
    uint32_t* ptr = (uint32_t*)dest;
    uint32_t i;

    val = htonl(val);

    for (i = 0; i < (size & (~0x3)); i += 4) ptr[i >> 2] = val;

    for (; i < size; i++) ((char*)dest)[i] = ((char*)&val)[i & 3];
} /*}}}*/

/**
 * @brief parses command line args and set global vars
 *
 * @param argc
 * @param argv
 */
void parse_command_line(int argc, char** argv) { /*{{{*/
    int opt;
    while ((opt = getopt(argc, argv, "c:b:s:o:d:U:u:I:P:M:i:p:m:f:q:lzr:t:x:")) != -1) {
        switch (opt) {
            case 'c':
                arg_iteration_count = atoi(optarg);
                break;
            case 'b':
                arg_client_batch_size = atoi(optarg);
                break;
            case 's':
                arg_message_size = atoi(optarg);
                break;
            case 'o':
                arg_iteration_timeout = atoi(optarg);
                break;
            case 'd':
                arg_pkt_fill_pattern = strtol(optarg, NULL, 16);
                break;
            case 'U':
                arg_unix_server_path = optarg;
                break;
            case 'u':
                arg_unix_client_path = optarg;
                break;
            case 'I':
                arg_inet_xdp_server_ip = optarg;
                break;
            case 'P':
                arg_inet_xdp_server_portnum = atoi(optarg);
                break;
            case 'M':
                arg_xdp_server_mac = calloc(1, sizeof(struct ether_addr));
                if(!arg_xdp_server_mac)
                    errx(EXIT_FAILURE, "ERROR could not allocate memory for arg_xdp_server_mac");

                if (!ether_aton_r(optarg, arg_xdp_server_mac)) {
                    errx(EXIT_FAILURE, "ERROR invalid server mac");
                }
                break;
            case 'i':
                arg_xdp_client_ip = optarg;
                break;
            case 'p':
                arg_xdp_client_portnum = atoi(optarg);
                break;
            case 'm':
                arg_xdp_client_mac = calloc(1, sizeof(struct ether_addr));
                if(!arg_xdp_client_mac)
                    errx(EXIT_FAILURE, "ERROR could not allocate memory for arg_xdp_client_mac");

                if (!ether_aton_r(optarg, arg_xdp_client_mac)) {
                    errx(EXIT_FAILURE, "ERROR invalid server mac");
                }
                break;
            case 'f':
                arg_xdp_if = optarg;
                break;
            case 'q':
                arg_xdp_if_queue = atoi(optarg);
                break;
            case 'l':
                arg_xdp_rlimit_memlock = 1;
                break;
            case 'z':
                arg_xdp_zero_copy = 1;
                break;
            case 'r':
                arg_xdp_rx_batch_size = atoi(optarg);
                break;
            case 't':
                arg_xdp_tx_batch_size = atoi(optarg);
                break;
            case 'x':
                arg_xdp_ctrl_proc_path = optarg;
                break;
            default:
                usage(basename(argv[0]));
        }
    }

    const char* arg_socket_type_str = argv[optind];
    if (arg_socket_type_str == NULL) {
        printf("[!] SOCKET_TYPE is required.\n\n");
        usage(basename(argv[0]));
    }

    if (!strcmp(arg_socket_type_str, "inet")) {
        arg_socket_type = AF_INET;
    } else if (!strcmp(arg_socket_type_str, "unix")) {
        arg_socket_type = AF_UNIX;
    } else if (!strcmp(arg_socket_type_str, "xdp")) {
        arg_socket_type = AF_XDP;
    } else {
        printf("[!] Unknown socket type: %s\n", arg_socket_type_str);
        usage(basename(argv[0]));
    }
} /*}}}*/
