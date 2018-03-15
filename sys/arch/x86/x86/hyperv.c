/*	$NetBSD$	*/

/*-
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
 */

/**
 * Implements low-level interactions with Hyper-V/Azuree
 */
#include <sys/cdefs.h>
#ifdef __KERNEL_RCSID
__KERNEL_RCSID(0, "$NetBSD$");
#endif
#ifdef __FBSDID
__FBSDID("$FreeBSD: head/sys/dev/hyperv/vmbus/hyperv.c 331757 2018-03-30 02:25:12Z emaste $");
#endif

#ifdef _KERNEL_OPT
#include "lapic.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/bus.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/pmf.h>
#include <sys/sysctl.h>
#include <sys/timetc.h>

#include <uvm/uvm_extern.h>

#include <machine/cpufunc.h>
#include <machine/cputypes.h>
#include <machine/cpuvar.h>
#include <machine/cpu_counter.h>

#include <x86/x86/hypervreg.h>
#include <x86/x86/hypervvar.h>

struct hyperv_softc {
	device_t		sc_dev;

	struct sysctllog	*sc_log;
};

struct hyperv_hypercall_ctx {
	void		*hc_addr;
	paddr_t		hc_paddr;
};

static struct hyperv_hypercall_ctx hyperv_hypercall_ctx;

static u_int	hyperv_get_timecount(struct timecounter *);

u_int hyperv_ver_major;

u_int hyperv_features;
u_int hyperv_recommends;

static u_int hyperv_pm_features;
static u_int hyperv_features3;

const struct sysctlnode *hyperv_sysctl_node;

static char hyperv_version_str[64];
static char hyperv_features_str[256];
static char hyperv_pm_features_str[256];
static char hyperv_features3_str[256];

hyperv_tc64_t hyperv_tc64;

static struct timecounter hyperv_timecounter = {
	.tc_get_timecount = hyperv_get_timecount,
	.tc_counter_mask = 0xffffffff,
	.tc_frequency = HYPERV_TIMER_FREQ,
	.tc_name = "Hyper-V",
	.tc_quality = 2000,
};

static void	hyperv_proc_dummy(void *, struct cpu_info *);

static struct hyperv_proc {
	hyperv_proc_t	func;
	void		*arg;
} hyperv_event_proc = {
	.func = hyperv_proc_dummy,
}, hyperv_message_proc = {
	.func = hyperv_proc_dummy,
};

static int	hyperv_match(device_t, cfdata_t, void *);
static void	hyperv_attach(device_t, device_t, void *);
static int	hyperv_detach(device_t, int);

CFATTACH_DECL_NEW(hyperv, sizeof(struct hyperv_softc),
    hyperv_match, hyperv_attach, hyperv_detach, NULL);

static void	hyperv_hypercall_memfree(void);
static bool	hyperv_init_hypercall(void);
static int	hyperv_sysctl_setup_root(struct hyperv_softc *);

static u_int
hyperv_get_timecount(struct timecounter *tc)
{

	return (u_int)rdmsr(MSR_HV_TIME_REF_COUNT);
}

static uint64_t
hyperv_tc64_rdmsr(void)
{

	return rdmsr(MSR_HV_TIME_REF_COUNT);
}

#ifdef __amd64__
/*
 * Reference TSC
 */
struct hyperv_ref_tsc {
	struct hyperv_reftsc	*tsc_ref;
	paddr_t			tsc_paddr;
};

static struct hyperv_ref_tsc hyperv_ref_tsc;

static struct timecounter hyperv_tsc_timecounter = {
	.tc_get_timecount = NULL,	/* based on CPU vendor. */
	.tc_counter_mask = 0xffffffff,
	.tc_frequency = HYPERV_TIMER_FREQ,
	.tc_name = "Hyper-V-TSC",
	.tc_quality = 3000,
};

static __inline u_int
atomic_load_acq_int(volatile u_int *p)
{
	u_int r = *p;
	__insn_barrier();
	return r;
}

#define HYPERV_TSC_TIMECOUNT(fence)					\
static uint64_t								\
hyperv_tc64_tsc_##fence(void)						\
{									\
	struct hyperv_reftsc *tsc_ref = hyperv_ref_tsc.tsc_ref;		\
	uint32_t seq;							\
									\
	while ((seq = atomic_load_acq_int(&tsc_ref->tsc_seq)) != 0) {	\
		uint64_t disc, ret, tsc;				\
		uint64_t scale = tsc_ref->tsc_scale;			\
		int64_t ofs = tsc_ref->tsc_ofs;				\
									\
		x86_##fence();						\
		tsc = cpu_counter();					\
									\
		/* ret = ((tsc * scale) >> 64) + ofs */			\
		__asm__ __volatile__ ("mulq %3" :			\
		    "=d" (ret), "=a" (disc) :				\
		    "a" (tsc), "r" (scale));				\
		ret += ofs;						\
									\
		__insn_barrier();					\
		if (tsc_ref->tsc_seq == seq)				\
			return ret;					\
									\
		/* Sequence changed; re-sync. */			\
	}								\
	/* Fallback to the generic timecounter, i.e. rdmsr. */		\
	return rdmsr(MSR_HV_TIME_REF_COUNT);				\
}									\
									\
static u_int								\
hyperv_tsc_timecount_##fence(struct timecounter *tc __unused)		\
{									\
									\
	return hyperv_tc64_tsc_##fence();				\
}

HYPERV_TSC_TIMECOUNT(lfence);
HYPERV_TSC_TIMECOUNT(mfence);

static bool
hyperv_tsc_tcinit(void)
{
	hyperv_tc64_t tc64 = NULL;
	uint64_t orig_msr, msr;

	if ((hyperv_features &
	     (CPUID_HV_MSR_TIME_REFCNT | CPUID_HV_MSR_REFERENCE_TSC)) !=
	    (CPUID_HV_MSR_TIME_REFCNT | CPUID_HV_MSR_REFERENCE_TSC) ||
	    (cpu_feature[0] & CPUID_SSE2) == 0)	/* SSE2 for mfence/lfence */
		return false;

	switch (cpu_vendor) {
	case CPUVENDOR_AMD:
		hyperv_tsc_timecounter.tc_get_timecount =
		    hyperv_tsc_timecount_mfence;
		tc64 = hyperv_tc64_tsc_mfence;
		break;

	case CPUVENDOR_INTEL:
		hyperv_tsc_timecounter.tc_get_timecount =
		    hyperv_tsc_timecount_lfence;
		tc64 = hyperv_tc64_tsc_lfence;
		break;

	default:
		/* Unsupport CPU vendors. */
		return false;
	}

	hyperv_ref_tsc.tsc_ref = (void *)uvm_km_alloc(kernel_map,
	    PAGE_SIZE, PAGE_SIZE, UVM_KMF_WIRED | UVM_KMF_ZERO);
	if (hyperv_ref_tsc.tsc_ref == NULL) {
		aprint_error("Hyper-V: reference TSC page allocation failed\n");
		return false;
	}

	if (!pmap_extract(pmap_kernel(), (vaddr_t)hyperv_ref_tsc.tsc_ref,
	    &hyperv_ref_tsc.tsc_paddr)) {
		aprint_error("Hyper-V: reference TSC page setup failed\n");
		uvm_km_free(kernel_map, (vaddr_t)hyperv_ref_tsc.tsc_ref,
		    PAGE_SIZE, UVM_KMF_WIRED);
		hyperv_ref_tsc.tsc_ref = NULL;
		return false;
	}

	orig_msr = rdmsr(MSR_HV_REFERENCE_TSC);
	msr = MSR_HV_REFTSC_ENABLE | (orig_msr & MSR_HV_REFTSC_RSVD_MASK) |
	    (atop(hyperv_ref_tsc.tsc_paddr) << MSR_HV_REFTSC_PGSHIFT);
	wrmsr(MSR_HV_REFERENCE_TSC, msr);

	/* Install 64 bits timecounter method for other modules to use. */
	hyperv_tc64 = tc64;

	/* Register "enlightened" timecounter. */
	tc_init(&hyperv_tsc_timecounter);

	return true;
}
#endif

static void
delay_tc(unsigned int n)
{
	struct timecounter *tc;
	uint64_t end, now;
	u_int last, u;

	tc = timecounter;
	if (tc->tc_quality <= 0) {
		x86_delay(n);
		return;
	}

	now = 0;
	end = tc->tc_frequency * n / 1000000;
	last = tc->tc_get_timecount(tc) & tc->tc_counter_mask;
	do {
		x86_pause();
		u = tc->tc_get_timecount(tc) & tc->tc_counter_mask;
		if (u < last)
			now += tc->tc_counter_mask - last + u + 1;
		else
			now += u - last;
		last = u;
	} while (now < end);
}

static __inline uint64_t
hyperv_hypercall_md(volatile void *hc_addr, uint64_t in_val, uint64_t in_paddr,
    uint64_t out_paddr)
{
	uint64_t status;

#ifdef __amd64__
	__asm__ __volatile__ ("mov %0, %%r8" : : "r" (out_paddr): "r8");
	__asm__ __volatile__ ("call *%3" : "=a" (status) : "c" (in_val),
	    "d" (in_paddr), "m" (hc_addr));
#else
	uint32_t in_val_hi = in_val >> 32;
	uint32_t in_val_lo = in_val & 0xFFFFFFFF;
	uint32_t status_hi, status_lo;
	uint32_t in_paddr_hi = in_paddr >> 32;
	uint32_t in_paddr_lo = in_paddr & 0xFFFFFFFF;
	uint32_t out_paddr_hi = out_paddr >> 32;
	uint32_t out_paddr_lo = out_paddr & 0xFFFFFFFF;

	__asm__ __volatile__ ("call *%8" : "=d" (status_hi), "=a" (status_lo) :
	    "d" (in_val_hi), "a" (in_val_lo),
	    "b" (in_paddr_hi), "c" (in_paddr_lo),
	    "D" (out_paddr_hi), "S" (out_paddr_lo),
	    "m" (hc_addr));
	status = status_lo | ((uint64_t)status_hi << 32);
#endif

	return status;
}

__inline uint64_t
hyperv_hypercall(uint64_t control, paddr_t in_paddr, paddr_t out_paddr)
{

	if (hyperv_hypercall_ctx.hc_addr == NULL)
		return ~HYPERCALL_STATUS_SUCCESS;

	return hyperv_hypercall_md(hyperv_hypercall_ctx.hc_addr, control,
	    in_paddr, out_paddr);
}

uint64_t
hyperv_hypercall_post_message(paddr_t msg)
{

	return hyperv_hypercall(HYPERCALL_POST_MESSAGE, msg, 0);
}

uint64_t
hyperv_hypercall_signal_event(paddr_t monprm)
{

	return hyperv_hypercall(HYPERCALL_SIGNAL_EVENT, monprm, 0);
}

int
hyperv_guid2str(const struct hyperv_guid *guid, char *buf, size_t sz)
{
	const uint8_t *d = guid->hv_guid;

	return snprintf(buf, sz, "%02x%02x%02x%02x-"
	    "%02x%02x-%02x%02x-%02x%02x-"
	    "%02x%02x%02x%02x%02x%02x",
	    d[3], d[2], d[1], d[0],
	    d[5], d[4], d[7], d[6], d[8], d[9],
	    d[10], d[11], d[12], d[13], d[14], d[15]);
}

static bool
hyperv_identify(void)
{
	char buf[256];
	u_int regs[4];
	u_int maxleaf;

	if (vm_guest != VM_GUEST_HV)
		return false;

	x86_cpuid(CPUID_LEAF_HV_MAXLEAF, regs);
	maxleaf = regs[0];
	if (maxleaf < CPUID_LEAF_HV_LIMITS)
		return false;

	x86_cpuid(CPUID_LEAF_HV_INTERFACE, regs);
	if (regs[0] != CPUID_HV_IFACE_HYPERV)
		return false;

	x86_cpuid(CPUID_LEAF_HV_FEATURES, regs);
	if (!(regs[0] & CPUID_HV_MSR_HYPERCALL)) {
		/*
		 * Hyper-V w/o Hypercall is impossible; someone
		 * is faking Hyper-V.
		 */
		return false;
	}

	hyperv_features = regs[0];
	hyperv_pm_features = regs[2];
	hyperv_features3 = regs[3];

	x86_cpuid(CPUID_LEAF_HV_IDENTITY, regs);
	hyperv_ver_major = regs[1] >> 16;
	snprintf(hyperv_version_str, sizeof(hyperv_version_str),
	    "%d.%d.%d [SP%d]",
	    hyperv_ver_major, regs[1] & 0xffff, regs[0], regs[2]);
	aprint_verbose("Hyper-V Version: %s\n", hyperv_version_str);

	snprintb(hyperv_features_str, sizeof(hyperv_features_str),
	    "\020"
	    "\001VPRUNTIME"	/* MSR_HV_VP_RUNTIME */
	    "\002TMREFCNT"	/* MSR_HV_TIME_REF_COUNT */
	    "\003SYNIC"		/* MSRs for SynIC */
	    "\004SYNTM"		/* MSRs for SynTimer */
	    "\005APIC"		/* MSR_HV_{EOI,ICR,TPR} */
	    "\006HYPERCALL"	/* MSR_HV_{GUEST_OS_ID,HYPERCALL} */
	    "\007VPINDEX"	/* MSR_HV_VP_INDEX */
	    "\010RESET"		/* MSR_HV_RESET */
	    "\011STATS"		/* MSR_HV_STATS_ */
	    "\012REFTSC"	/* MSR_HV_REFERENCE_TSC */
	    "\013IDLE"		/* MSR_HV_GUEST_IDLE */
	    "\014TMFREQ"	/* MSR_HV_{TSC,APIC}_FREQUENCY */
	    "\015DEBUG",	/* MSR_HV_SYNTH_DEBUG_ */
	    hyperv_features);
	aprint_verbose("  Features=%s\n", hyperv_features_str);
	snprintb(buf, sizeof(buf),
	    "\020"
	    "\005C3HPET",	/* HPET is required for C3 state */
	    (hyperv_pm_features & ~CPUPM_HV_CSTATE_MASK));
	snprintf(hyperv_pm_features_str, sizeof(hyperv_pm_features_str),
	    "%s [C%u]", buf, CPUPM_HV_CSTATE(hyperv_pm_features));
	aprint_verbose("  PM Features=%s\n", hyperv_pm_features_str);
	snprintb(hyperv_features3_str, sizeof(hyperv_features3_str),
	    "\020"
	    "\001MWAIT"		/* MWAIT */
	    "\002DEBUG"		/* guest debug support */
	    "\003PERFMON"	/* performance monitor */
	    "\004PCPUDPE"	/* physical CPU dynamic partition event */
	    "\005XMMHC"		/* hypercall input through XMM regs */
	    "\006IDLE"		/* guest idle support */
	    "\007SLEEP"		/* hypervisor sleep support */
	    "\010NUMA"		/* NUMA distance query support */
	    "\011TMFREQ"	/* timer frequency query (TSC, LAPIC) */
	    "\012SYNCMC"	/* inject synthetic machine checks */
	    "\013CRASH"		/* MSRs for guest crash */
	    "\014DEBUGMSR"	/* MSRs for guest debug */
	    "\015NPIEP"		/* NPIEP */
	    "\016HVDIS",	/* disabling hypervisor */
	    hyperv_features3);
	aprint_verbose("  Features3=%s\n", hyperv_features3_str);

	x86_cpuid(CPUID_LEAF_HV_RECOMMENDS, regs);
	hyperv_recommends = regs[0];
	aprint_verbose("  Recommends: %08x %08x\n", regs[0], regs[1]);

	x86_cpuid(CPUID_LEAF_HV_LIMITS, regs);
	aprint_verbose("  Limits: Vcpu:%d Lcpu:%d Int:%d\n",
	    regs[0], regs[1], regs[2]);

	if (maxleaf >= CPUID_LEAF_HV_HWFEATURES) {
		x86_cpuid(CPUID_LEAF_HV_HWFEATURES, regs);
		aprint_verbose("  HW Features: %08x, AMD: %08x\n",
		    regs[0], regs[3]);
	}

	return true;
}

bool
hyperv_init(void)
{

	if (!hyperv_identify()) {
		/* Not Hyper-V; reset guest id to the generic one. */
		if (vm_guest == VM_GUEST_HV)
			vm_guest = VM_GUEST_VM;
		return false;
	}

	/* Set guest id */
	wrmsr(MSR_HV_GUEST_OS_ID, MSR_HV_GUESTID_OSTYPE_NETBSD |
	    (uint64_t)__NetBSD_Version__ << MSR_HV_GUESTID_VERSION_SHIFT);

	if (hyperv_features & CPUID_HV_MSR_TIME_REFCNT) {
		/* Register Hyper-V timecounter */
		tc_init(&hyperv_timecounter);

		/*
		 * Install 64 bits timecounter method for other modules to use.
		 */
		hyperv_tc64 = hyperv_tc64_rdmsr;
#ifdef __amd64__
		hyperv_tsc_tcinit();
#endif

		/* delay with timecounter */
		x86_delay = delay_func = delay_tc;
	}

#if NLAPIC > 0
	if ((hyperv_features & CPUID_HV_MSR_TIME_FREQ) &&
	    (hyperv_features3 & CPUID3_HV_TIME_FREQ)) {
		extern uint32_t lapic_per_second;

		lapic_per_second = rdmsr(MSR_HV_APIC_FREQUENCY);
	}
#endif

	return hyperv_init_hypercall();
}

bool
hyperv_is_initialized(void)
{
	uint64_t msr;

	if (vm_guest != VM_GUEST_HV)
		return false;
	if (rdmsr_safe(MSR_HV_HYPERCALL, &msr) == EFAULT)
		return false;
	return (msr & MSR_HV_HYPERCALL_ENABLE) ? true : false;
}

static int
hyperv_match(device_t parent, cfdata_t cf, void *aux)
{
	struct cpufeature_attach_args *cfaa = aux;
	struct cpu_info *ci = cfaa->ci;

	if (strcmp(cfaa->name, "vm") != 0)
		return 0;
	if ((ci->ci_flags & (CPUF_BSP|CPUF_SP|CPUF_PRIMARY)) == 0)
		return 0;
	if (vm_guest != VM_GUEST_HV)
		return 0;

	return 1;
}

static void
hyperv_attach(device_t parent, device_t self, void *aux)
{
	struct hyperv_softc *sc = device_private(self);

	sc->sc_dev = self;

	aprint_naive("\n");
	aprint_normal(": Hyper-V\n");

	if (!hyperv_is_initialized()) {
		if (rdmsr(MSR_HV_GUEST_OS_ID) == 0) {
			if (!hyperv_init()) {
				aprint_error_dev(self, "initialize failed\n");
				return;
			}
		}
		hyperv_init_hypercall();
	}

	(void) pmf_device_register(self, NULL, NULL);

	(void) hyperv_sysctl_setup_root(sc);
}

static int
hyperv_detach(device_t self, int flags)
{
	struct hyperv_softc *sc = device_private(self);
	uint64_t hc;

	/* Disable Hypercall */
	hc = rdmsr(MSR_HV_HYPERCALL);
	wrmsr(MSR_HV_HYPERCALL, hc & MSR_HV_HYPERCALL_RSVD_MASK);
	hyperv_hypercall_memfree();

	if (hyperv_features & CPUID_HV_MSR_TIME_REFCNT)
		tc_detach(&hyperv_timecounter);

	wrmsr(MSR_HV_GUEST_OS_ID, 0);

	pmf_device_deregister(self);

	if (sc->sc_log != NULL) {
		sysctl_teardown(&sc->sc_log);
		sc->sc_log = NULL;
	}

	return 0;
}

void
hyperv_intr(struct trapframe *frame)
{
	struct cpu_info *ci = curcpu();

	ci->ci_isources[LIR_HYPERV]->is_evcnt.ev_count++;

	(*hyperv_event_proc.func)(hyperv_event_proc.arg, ci);
	(*hyperv_message_proc.func)(hyperv_message_proc.arg, ci);
}

static void
hyperv_proc_dummy(void *arg __unused, struct cpu_info *ci __unused)
{
}

void
hyperv_set_event_proc(void (*func)(void *, struct cpu_info *), void *arg)
{

	hyperv_event_proc.func = func;
	hyperv_event_proc.arg = arg;
}

void
hyperv_set_message_proc(void (*func)(void *, struct cpu_info *), void *arg)
{

	hyperv_message_proc.func = func;
	hyperv_message_proc.arg = arg;
}

static void
hyperv_hypercall_memfree(void)
{

	if (hyperv_hypercall_ctx.hc_addr != NULL) {
		uvm_km_free(kernel_map, (vaddr_t)hyperv_hypercall_ctx.hc_addr,
		    PAGE_SIZE, UVM_KMF_WIRED);
		hyperv_hypercall_ctx.hc_addr = NULL;
	}
}

static bool
hyperv_init_hypercall(void)
{
	uint64_t hc, hc_orig;

	hyperv_hypercall_ctx.hc_addr = (void *)uvm_km_alloc(kernel_map,
	    PAGE_SIZE, PAGE_SIZE,
	    UVM_KMF_WIRED | UVM_KMF_EXEC | (cold ? UVM_KMF_NOWAIT : 0));
	if (hyperv_hypercall_ctx.hc_addr == NULL) {
		aprint_error("Hyper-V: Hypercall page allocation failed\n");
		return false;
	}

	memset(hyperv_hypercall_ctx.hc_addr, 0xcc, PAGE_SIZE);
	wbinvd();
	x86_flush();

	/* The hypercall page must be both readable and executable */
	uvm_km_protect(kernel_map, (vaddr_t)hyperv_hypercall_ctx.hc_addr,
	    PAGE_SIZE, VM_PROT_READ | VM_PROT_EXECUTE);

	if (!pmap_extract(pmap_kernel(), (vaddr_t)hyperv_hypercall_ctx.hc_addr,
	    &hyperv_hypercall_ctx.hc_paddr)) {
		aprint_error("Hyper-V: Hypercall page setup failed\n");
		hyperv_hypercall_memfree();
		/* Can't perform any Hyper-V specific actions */
		vm_guest = VM_GUEST_VM;
		return false;
	}

	/* Get the 'reserved' bits, which requires preservation. */
	hc_orig = rdmsr(MSR_HV_HYPERCALL);

	/*
	 * Setup the Hypercall page.
	 *
	 * NOTE: 'reserved' bits MUST be preserved.
	 */
	hc = (atop(hyperv_hypercall_ctx.hc_paddr) << MSR_HV_HYPERCALL_PGSHIFT) |
	    (hc_orig & MSR_HV_HYPERCALL_RSVD_MASK) |
	    MSR_HV_HYPERCALL_ENABLE;
	wrmsr(MSR_HV_HYPERCALL, hc);

	/*
	 * Confirm that Hypercall page did get setup.
	 */
	hc = rdmsr(MSR_HV_HYPERCALL);
	if (!(hc & MSR_HV_HYPERCALL_ENABLE)) {
		aprint_error("Hyper-V: Hypercall setup failed\n");
		hyperv_hypercall_memfree();
		/* Can't perform any Hyper-V specific actions */
		vm_guest = VM_GUEST_VM;
		return false;
	}

	return true;
}

/*
 * Hyper-V bus_dma utilities.
 */
void *
hyperv_dma_alloc(bus_dma_tag_t dmat, struct hyperv_dma *dma, bus_size_t size,
    bus_size_t alignment, bus_size_t boundary, int nsegs)
{
	const int kmemflags = cold ? KM_NOSLEEP : KM_SLEEP;
	const int dmaflags = cold ? BUS_DMA_NOWAIT : BUS_DMA_WAITOK;
	int rseg, error;

	KASSERT(dma != NULL);
	KASSERT(dma->segs == NULL);
	KASSERT(nsegs > 0);

	dma->segs = kmem_zalloc(sizeof(*dma->segs) * nsegs, kmemflags);
	if (dma->segs == NULL)
		return NULL;

	dma->nsegs = nsegs;

	error = bus_dmamem_alloc(dmat, size, alignment, boundary, dma->segs,
	    nsegs, &rseg, dmaflags);
	if (error) {
		aprint_error("%s: bus_dmamem_alloc failed: error=%d\n",
		    __func__, error);
		goto fail1;
	}
	error = bus_dmamem_map(dmat, dma->segs, rseg, size, &dma->addr,
	    dmaflags);
	if (error) {
		aprint_error("%s: bus_dmamem_map failed: error=%d\n",
		    __func__, error);
		goto fail2;
	}
	error = bus_dmamap_create(dmat, size, rseg, size, boundary, dmaflags,
	    &dma->map);
	if (error) {
		aprint_error("%s: bus_dmamap_create failed: error=%d\n",
		    __func__, error);
		goto fail3;
	}
	error = bus_dmamap_load(dmat, dma->map, dma->addr, size, NULL,
	    BUS_DMA_READ | BUS_DMA_WRITE | dmaflags);
	if (error) {
		aprint_error("%s: bus_dmamap_load failed: error=%d\n",
		    __func__, error);
		goto fail4;
	}

	return dma->addr;

fail4:	bus_dmamap_destroy(dmat, dma->map);
fail3:	bus_dmamem_unmap(dmat, dma->addr, size);
	dma->addr = NULL;
fail2:	bus_dmamem_free(dmat, dma->segs, rseg);
fail1:	kmem_free(dma->segs, sizeof(*dma->segs) * nsegs);
	dma->segs = NULL;
	dma->nsegs = 0;
	return NULL;
}

void
hyperv_dma_free(bus_dma_tag_t dmat, struct hyperv_dma *dma)
{
	bus_size_t size = dma->map->dm_mapsize;
	int rsegs = dma->map->dm_nsegs;

	bus_dmamap_unload(dmat, dma->map);
	bus_dmamap_destroy(dmat, dma->map);
	bus_dmamem_unmap(dmat, dma->addr, size);
	dma->addr = NULL;
	bus_dmamem_free(dmat, dma->segs, rsegs);
	kmem_free(dma->segs, sizeof(*dma->segs) * dma->nsegs);
	dma->segs = NULL;
	dma->nsegs = 0;
}

static int
hyperv_sysctl_setup(struct hyperv_softc *sc,
    const struct sysctlnode *hyperv_node)
{
	int error;

	error = sysctl_createv(&sc->sc_log, 0, &hyperv_node, NULL,
	    CTLFLAG_READONLY, CTLTYPE_STRING, "version", NULL,
	    NULL, 0, hyperv_version_str,
	    0, CTL_CREATE, CTL_EOL);
	if (error)
		return error;

	error = sysctl_createv(&sc->sc_log, 0, &hyperv_node, NULL,
	    CTLFLAG_READONLY, CTLTYPE_STRING, "features", NULL,
	    NULL, 0, hyperv_features_str,
	    0, CTL_CREATE, CTL_EOL);
	if (error)
		return error;

	error = sysctl_createv(&sc->sc_log, 0, &hyperv_node, NULL,
	    CTLFLAG_READONLY, CTLTYPE_STRING, "pm_features", NULL,
	    NULL, 0, hyperv_pm_features_str,
	    0, CTL_CREATE, CTL_EOL);
	if (error)
		return error;

	error = sysctl_createv(&sc->sc_log, 0, &hyperv_node, NULL,
	    CTLFLAG_READONLY, CTLTYPE_STRING, "features3", NULL,
	    NULL, 0, hyperv_features3_str,
	    0, CTL_CREATE, CTL_EOL);
	if (error)
		return error;

	return 0;
}

static int
hyperv_sysctl_setup_root(struct hyperv_softc *sc)
{
	const struct sysctlnode *machdep_node, *hyperv_node;
	int error;

	error = sysctl_createv(&sc->sc_log, 0, NULL, &machdep_node,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE, "machdep", NULL,
	    NULL, 0, NULL, 0, CTL_MACHDEP, CTL_EOL);
	if (error)
		goto fail;

	error = sysctl_createv(&sc->sc_log, 0, &machdep_node, &hyperv_node,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE, device_xname(sc->sc_dev), NULL,
	    NULL, 0, NULL, 0, CTL_CREATE, CTL_EOL);
	if (error)
		goto fail;

	error = hyperv_sysctl_setup(sc, hyperv_node);
	if (error)
		goto fail;

	hyperv_sysctl_node = hyperv_node;

	return 0;

fail:
	sysctl_teardown(&sc->sc_log);
	sc->sc_log = NULL;
	return error;
}

MODULE(MODULE_CLASS_DRIVER, hyperv, NULL);

#ifdef _MODULE
#include "ioconf.c"
#endif

static int
hyperv_modcmd(modcmd_t cmd, void *aux)
{
	int rv = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
#ifdef _MODULE
		rv = config_init_component(cfdriver_ioconf_hyperv,
		    cfattach_ioconf_hyperv, cfdata_ioconf_hyperv);
#endif
		hyperv_init();
		break;

	case MODULE_CMD_FINI:
#ifdef _MODULE
		rv = config_fini_component(cfdriver_ioconf_hyperv,
		    cfattach_ioconf_hyperv, cfdata_ioconf_hyperv);
#endif
		break;

	default:
		rv = ENOTTY;
		break;
	}

	return rv;
}
