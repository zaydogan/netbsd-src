/* $NetBSD: psci_fdt.c,v 1.17 2018/09/09 21:16:05 jmcneill Exp $ */

/*-
 * Copyright (c) 2017 Jared McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_multiprocessor.h"

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: psci_fdt.c,v 1.17 2018/09/09 21:16:05 jmcneill Exp $");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/atomic.h>

#include <dev/fdt/fdtvar.h>

#include <arm/locore.h>
#include <arm/armreg.h>
#include <arm/cpufunc.h>

#include <arm/arm/psci.h>
#include <arm/fdt/psci_fdt.h>

static int	psci_fdt_match(device_t, cfdata_t, void *);
static void	psci_fdt_attach(device_t, device_t, void *);

static int	psci_fdt_init(const int);

static const char * const compatible[] = {
	"arm,psci",
	"arm,psci-0.2",
	"arm,psci-1.0",
	NULL
};

CFATTACH_DECL_NEW(psci_fdt, 0, psci_fdt_match, psci_fdt_attach, NULL, NULL);

static void
psci_fdt_power_reset(device_t dev)
{
	delay(500000);
	psci_system_reset();
}

static void
psci_fdt_power_poweroff(device_t dev)
{
	delay(500000);
	psci_system_off();
}

static const struct fdtbus_power_controller_func psci_power_funcs = {
	.reset = psci_fdt_power_reset,
	.poweroff = psci_fdt_power_poweroff,
};

static int
psci_fdt_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_match_compatible(faa->faa_phandle, compatible);
}

static void
psci_fdt_attach(device_t parent, device_t self, void *aux)
{
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;

	psci_fdt_init(phandle);

	const uint32_t ver = psci_version();
	const u_int ver_maj = __SHIFTOUT(ver, PSCI_VERSION_MAJOR);
	const u_int ver_min = __SHIFTOUT(ver, PSCI_VERSION_MINOR);

	aprint_naive("\n");
	aprint_normal(": PSCI %u.%u\n", ver_maj, ver_min);

	fdtbus_register_power_controller(self, phandle,
	    &psci_power_funcs);
}

static int
psci_fdt_init(const int phandle)
{
	const char *method, *psciver;
	uint32_t val;

	method = fdtbus_get_string(phandle, "method");
	psciver = fdtbus_get_string(phandle, "compatible");
	if (method == NULL || psciver == NULL) {
		aprint_error("PSCI: missing required property on /psci\n");
		return EINVAL;
	}

	if (strcmp(method, "smc") == 0)
		psci_init(psci_call_smc);
	else if (strcmp(method, "hvc") == 0)
		psci_init(psci_call_hvc);
	else {
		aprint_error("PSCI: unsupported method '%s'\n", method);
		return EINVAL;
	}

	/*
	 * If the first compatible string is "arm,psci" then we
	 * are dealing with PSCI 0.1
	 */
	if (strcmp(psciver, "arm,psci") == 0) {
		psci_clearfunc();
		if (of_getprop_uint32(phandle, "cpu_on", &val) == 0)
			psci_setfunc(PSCI_FUNC_CPU_ON, val);
	}

	return 0;
}

static int
psci_fdt_preinit(void)
{
	const int phandle = OF_finddevice("/psci");
	if (phandle == -1) {
		aprint_error("PSCI: no /psci node found\n");
		return ENODEV;
	}

	return psci_fdt_init(phandle);
}

#ifdef MULTIPROCESSOR

static register_t
psci_fdt_mpstart_pa(void)
{
#ifdef __aarch64__
	extern void aarch64_mpstart(void);
	return (register_t)aarch64_kern_vtophys((vaddr_t)aarch64_mpstart);
#else
	extern void cortex_mpstart(void);
	return (register_t)cortex_mpstart;
#endif
}
#endif

static bool
psci_fdt_cpu_okay(const int child)
{
	const char *s;

	s = fdtbus_get_string(child, "device_type");
	if (!s || strcmp(s, "cpu") != 0)
		return false;

	s = fdtbus_get_string(child, "status");
	if (s) {
		if (strcmp(s, "okay") == 0)
			return false;
		if (strcmp(s, "disabled") == 0)
			return of_hasprop(child, "enable-method");
		return false;
	} else {
		return true;
	}
}

void
psci_fdt_bootstrap(void)
{
#ifdef MULTIPROCESSOR
	uint64_t mpidr, bp_mpidr;
	u_int cpuindex;
	int child;
	const char *devtype;

	const int cpus = OF_finddevice("/cpus");
	if (cpus == -1) {
		aprint_error("PSCI: no /cpus node found\n");
		arm_cpu_max = 1;
		return;
	}

	/* Count CPUs */
	arm_cpu_max = 0;
	for (child = OF_child(cpus); child; child = OF_peer(child))
		if (fdtbus_status_okay(child) && ((devtype =
		    fdtbus_get_string(child, "device_type")) != NULL) &&
		    (strcmp(devtype, "cpu") == 0))
			arm_cpu_max++;

	if (psci_fdt_preinit() != 0)
		return;

	/* MPIDR affinity levels of boot processor. */
	bp_mpidr = cpu_mpidr_aff_read();

	/* Boot APs */
	cpuindex = 1;
	for (child = OF_child(cpus); child; child = OF_peer(child)) {
		if (!psci_fdt_cpu_okay(child))
			continue;
		if (fdtbus_get_reg64(child, 0, &mpidr, NULL) != 0)
			continue;
		if (mpidr == bp_mpidr)
			continue; 	/* BP already started */

#ifdef __aarch64__
		/* argument for mpstart() */
		arm_cpu_hatch_arg = cpuindex;
		cpu_dcache_wb_range((vaddr_t)&arm_cpu_hatch_arg,
		    sizeof(arm_cpu_hatch_arg));
#endif

		int ret = psci_cpu_on(mpidr, psci_fdt_mpstart_pa(), 0);
		if (ret != PSCI_SUCCESS)
			continue;

		/* Wait for APs to start */
		for (u_int i = 0x4000000; i > 0; i--) {
			membar_consumer();
			if (arm_cpu_hatched & __BIT(cpuindex))
				break;
		}

		cpuindex++;
	}
#endif
}

void
psci_fdt_reset(void)
{
	if (psci_fdt_preinit() != 0) {
		aprint_error("PSCI: reset failed\n");
		return;
	}

	psci_system_reset();
}
