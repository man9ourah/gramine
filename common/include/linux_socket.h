/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#ifndef GRAMINE_LINUX_SOCKET_H
#define GRAMINE_LINUX_SOCKET_H

#include "linux/if_xdp.h"
#include <asm/fcntl.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <stddef.h>

#define SOCKADDR_MAX_SIZE 128

struct sockaddr_storage {
    union {
        unsigned short ss_family;
        char _size[SOCKADDR_MAX_SIZE];
        void* _align;
    };
};

struct iovec {
    void* iov_base;
    size_t iov_len;
};

struct msghdr {
    void* msg_name;
    int msg_namelen;
    struct iovec* msg_iov;
    size_t msg_iovlen;
    void* msg_control;
    size_t msg_controllen;
    unsigned int msg_flags;
};

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
};

#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif

#define CMSG_DATA(cmsg)         ((unsigned char*)((struct cmsghdr*)(cmsg) + 1))
#define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr(mhdr, cmsg)
#define CMSG_FIRSTHDR(mhdr)                                   \
    ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr) \
         ? (struct cmsghdr*)(mhdr)->msg_control               \
         : (struct cmsghdr*)0)
#define CMSG_ALIGN(len) ALIGN_UP(len, sizeof(size_t))
#define CMSG_SPACE(len) (CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_LEN(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))

#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define AF_NETLINK 16
#define AF_PACKET 17
#define AF_XDP 44

#define SOCK_TYPE_MASK 0xf
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3

#define SOCK_CLOEXEC O_CLOEXEC
#define SOCK_NONBLOCK O_NONBLOCK

/* Flags. */
#define MSG_OOB 0x01
#define MSG_PEEK 0x02
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000

/* Option levels. */
#define SOL_SOCKET 1
#define SOL_TCP 6
#define SOL_XDP 283

/* Socket options. */
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define SO_LINGER 13
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_ACCEPTCONN 30
#define SO_PROTOCOL 38
#define SO_DOMAIN 39

/* TCP options. */
#define TCP_NODELAY 1
#define TCP_CORK 3

struct linger {
    int l_onoff;
    int l_linger;
};

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

// socket io cmd for ioctl if_name -> if_index
#define SIOCGIFINDEX    0x8933      /* name -> if_index mapping */
// max len of interface name
#define IF_NAMESIZE    16

// following struct is defined at #include <linux/if.h>
struct ifreq {
    union
    {
        char    ifrn_name[IF_NAMESIZE];        /* if name, e.g. "en0" */
    } ifr_ifrn;

    union {
        // the "linux" definition of this union has much more members. However, including them as
        // is forces us to include definitions of many structs that we will never use.
        // since union members always have the same start address.. I chose to ignore the rest
        // members......
        int ifru_ivalue;
    } ifr_ifru;
};
#define ifr_name    ifr_ifrn.ifrn_name  /* interface name   */
#define ifr_ifindex ifr_ifru.ifru_ivalue    /* interface index  */

#endif /* GRAMINE_LINUX_SOCKET_H */
