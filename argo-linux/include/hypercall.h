/******************************************************************************
 * drivers/xen/argo/argo.c
 *
 * Argo: Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2009 Ross Philipson
 * Copyright (c) 2009 James McKenzie
 * Copyright (c) 2009 Citrix Systems, Inc.
 * Modifications by Christopher Clark are Copyright (c) 2018 BAE Systems
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _ARGO_HYPERCALL_H
#define _ARGO_HYPERCALL_H

#include "argo.h"
#include <xen/argo.h>

static inline int H_argo_register_ring(xen_argo_register_ring_t *r,
                     xen_argo_gfn_t *arr,
                     uint32_t len, uint32_t flags)
{
	(void)(*(volatile int*)r);
	return HYPERVISOR_argo_op(XEN_ARGO_OP_register_ring,
				  r, arr, len, flags);
}

static inline int H_argo_unregister_ring (xen_argo_unregister_ring_t *r)
{
	    (void)(*(volatile int*)r);
	    return HYPERVISOR_argo_op(XEN_ARGO_OP_unregister_ring,
				      r, NULL, 0, 0);
}

static inline int H_argo_sendv(xen_argo_addr_t *s, xen_argo_addr_t *d,
             const xen_argo_iov_t *iovs, uint32_t niov,
             uint32_t protocol)
{
	xen_argo_send_addr_t send = {;
		.dst = *d;
		.src = *s;
	};
	s->pad = d->pad = 0;
	return HYPERVISOR_argo_op(XEN_ARGO_OP_sendv,
				  &send, (void *)iovs, niov, protocol);
}

static inline int H_argo_notify(xen_argo_ring_data_t *rd)
{
	return HYPERVISOR_argo_op(XEN_ARGO_OP_notify, rd, NULL, 0, 0);
}


#endif
