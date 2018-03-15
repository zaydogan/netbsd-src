/*	$NetBSD$	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2009-2012,2016-2017 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: head/sys/dev/hyperv/include/hyperv.h 326255 2017-11-27 14:52:40Z pfg $
 */

#ifndef _HYPERVVAR_H_
#define _HYPERVVAR_H_

#if defined(_KERNEL)

#include <sys/bus.h>
#include <sys/timex.h>

#define HYPERV_TIMER_NS_FACTOR	100ULL
#define HYPERV_TIMER_FREQ	(NANOSECOND / HYPERV_TIMER_NS_FACTOR)

#endif	/* _KERNEL */

/*
 * Hyper-V Reference TSC
 */
struct hyperv_reftsc {
	volatile uint32_t	tsc_seq;
	volatile uint32_t	tsc_rsvd1;
	volatile uint64_t	tsc_scale;
	volatile int64_t	tsc_ofs;
} __packed __aligned(PAGE_SIZE);
#ifdef __CTASSERT
__CTASSERT(sizeof(struct hyperv_reftsc) == PAGE_SIZE);
#endif

#if defined(_KERNEL)

#define HYPERV_GUID_STRLEN	40

struct hyperv_guid;
struct trapframe;
struct sysctlnode;

int	hyperv_guid2str(const struct hyperv_guid *, char *, size_t);

/*
 * hyperv_tc64 could be NULL, if there were no suitable Hyper-V
 * specific timecounter.
 */
typedef uint64_t (*hyperv_tc64_t)(void);
extern hyperv_tc64_t hyperv_tc64;

extern u_int hyperv_ver_major;
extern u_int hyperv_features;		/* CPUID_HV_MSR_ */
extern u_int hyperv_recommends;

extern const struct sysctlnode *hyperv_sysctl_node;

uint64_t hyperv_hypercall(uint64_t, paddr_t, paddr_t);
uint64_t hyperv_hypercall_post_message(paddr_t);
uint64_t hyperv_hypercall_signal_event(paddr_t);

bool	hyperv_init(void);
bool	hyperv_is_initialized(void);
void	hyperv_intr(struct trapframe *);

typedef void (*hyperv_proc_t)(void *, struct cpu_info *);
void	hyperv_set_event_proc(hyperv_proc_t, void *);
void	hyperv_set_message_proc(hyperv_proc_t, void *);

/*
 * Hyper-V bus_dma utilities.
 */
struct hyperv_dma {
	bus_dmamap_t		map;
	bus_dma_segment_t	*segs;
	void			*addr;
	int			nsegs;
};

static __inline bus_addr_t
hyperv_dma_get_paddr(struct hyperv_dma *dma)
{
	return dma->map->dm_segs[0].ds_addr;
}

void *hyperv_dma_alloc(bus_dma_tag_t, struct hyperv_dma *, bus_size_t,
    bus_size_t, bus_size_t, int);
void hyperv_dma_free(bus_dma_tag_t, struct hyperv_dma *);

/*
 * Vector used for Hyper-V Interrupts.
 */
extern void Xintr_hyperv_upcall(void);
extern void Xresume_hyperv_upcall(void);
extern void Xrecurse_hyperv_upcall(void);

#endif	/* _KERNEL */

#endif	/* _HYPERVVAR_H_ */
