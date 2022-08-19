/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#ifndef PERF_XDP_CLIENT_H
#define PERF_XDP_CLIENT_H

#define XDP_CLIENT_FQ_UMEM XDP_NUM_FRAMES / 2

void xdp_client_echo(void);
#endif
