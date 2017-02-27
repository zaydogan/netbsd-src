/*	$NetBSD: efi.c,v 1.15 2018/05/19 17:18:57 jakllsch Exp $	*/

/*-
 * Copyright (c) 2016 The NetBSD Foundation, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: efi.c,v 1.15 2018/05/19 17:18:57 jakllsch Exp $");

#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/uuid.h>
#include <sys/conf.h>

#include <uvm/uvm.h>

#include <machine/bootinfo.h>
#include <machine/pmap.h>

#include <x86/efi.h>
#include <sys/efiio.h>

#include <dev/mm.h>
#include <dev/pci/pcivar.h> /* for pci_mapreg_map_enable_decode */

const struct uuid EFI_UUID_ACPI20 = EFI_TABLE_ACPI20;
const struct uuid EFI_UUID_ACPI10 = EFI_TABLE_ACPI10;
const struct uuid EFI_UUID_SMBIOS = EFI_TABLE_SMBIOS;
const struct uuid EFI_UUID_SMBIOS3 = EFI_TABLE_SMBIOS3;

static vaddr_t 	efi_getva(paddr_t);
static void 	efi_relva(vaddr_t);
struct efi_cfgtbl *efi_getcfgtblhead(void);
struct efi_rt	*efi_getrt(void);
#ifdef __x86_64__
paddr_t		efi_make_tmp_pgtbl(void);
void		efi_free_tmp_pgtbl(void);
pt_entry_t	*efi_get_pte_tmp_pgtbl(paddr_t, vaddr_t);
bool		efi_set_virtual_address_map(struct efi_rt *);
#endif
void 		efi_aprintcfgtbl(void);
void 		efi_aprintuuid(const struct uuid *);
bool 		efi_uuideq(const struct uuid *, const struct uuid *);

static bool efi_is32x64 = false;
static struct efi_systbl *efi_systbl_va = NULL;
static struct efi_cfgtbl *efi_cfgtblhead_va = NULL;
static struct efi_rt *efi_rt_va = NULL;
static struct efi_e820memmap {
	struct btinfo_memmap bim;
	struct bi_memmap_entry entry[VM_PHYSSEG_MAX - 1];
} efi_e820memmap;

void efiattach(int);
void
efiattach(int n)
{
	/* nothing */
}

/*
 * Map a physical address (PA) to a newly allocated virtual address (VA).
 * The VA must be freed using efi_relva().
 */
static vaddr_t
efi_getva(paddr_t pa)
{
	vaddr_t va;

#ifdef __HAVE_MM_MD_DIRECT_MAPPED_PHYS
	mm_md_direct_mapped_phys(pa, &va);
#else
	/* XXX This code path is not tested. */
	va = uvm_km_alloc(kernel_map, PAGE_SIZE, 0,
	    UVM_KMF_VAONLY | UVM_KMF_WAITVA);
	if (va == 0) {
		aprint_debug("efi: unable to allocate va\n");
		return 0;
	}
	pmap_kenter_pa(va, pa, VM_PROT_READ, 0);
	pmap_update(pmap_kernel());
#endif
	return va;
}

/*
 * Free a virtual address (VA) allocated using efi_getva().
 */
static void
efi_relva(vaddr_t va)
{
#ifdef __HAVE_MM_MD_DIRECT_MAPPED_PHYS
	/* XXX Should we free the va? */
#else
	/* XXX This code path is not tested. */
	uvm_km_free(kernel_map, va, PAGE_SIZE, UVM_KMF_VAONLY);
#endif
}

/*
 * Test if 2 UUIDs matches.
 */
bool
efi_uuideq(const struct uuid * a, const struct uuid * b)
{
	return !memcmp(a, b, sizeof(struct uuid));
}

/*
 * Print an UUID in a human-readable manner.
 */
void
efi_aprintuuid(const struct uuid * uuid)
{
	int i;

	aprint_debug(" %08" PRIx32 "", uuid->time_low);
	aprint_debug("-%04" PRIx16 "", uuid->time_mid);
	aprint_debug("-%04" PRIx16 "", uuid->time_hi_and_version);
	aprint_debug("-%02" PRIx8 "", uuid->clock_seq_hi_and_reserved);
	aprint_debug("-%02" PRIx8 "", uuid->clock_seq_low);
	aprint_debug("-");
	for (i = 0; i < _UUID_NODE_LEN; i++) {
		aprint_debug("%02" PRIx8 "", uuid->node[i]);
	}
	/* If known, also print the human-readable name */
	if (efi_uuideq(uuid, &EFI_UUID_ACPI20)) {
		aprint_debug(" ACPI 2.0");
	} else if (efi_uuideq(uuid, &EFI_UUID_ACPI10)) {
		aprint_debug(" ACPI 1.0");
	} else if (efi_uuideq(uuid, &EFI_UUID_SMBIOS)) {
		aprint_debug(" SMBIOS");
	} else if (efi_uuideq(uuid, &EFI_UUID_SMBIOS3)) {
		aprint_debug(" SMBIOS3");
	}
}

/*
 * Return the VA of the cfgtbl. Must be freed using efi_relva().
 */
struct efi_cfgtbl *
efi_getcfgtblhead(void)
{
	paddr_t	pa;
	vaddr_t	va;

	if (efi_cfgtblhead_va != NULL)
		return efi_cfgtblhead_va;

	if (efi_is32x64) {
#if defined(__x86_64__)
		struct efi_systbl32 *systbl32 = (void *) efi_systbl_va;
		pa = systbl32->st_cfgtbl;
#elif defined(__i386__)
		struct efi_systbl64 *systbl64 = (void *) efi_systbl_va;
		if (systbl64->st_cfgtbl & 0xffffffff00000000ULL)
			return NULL;
		pa = (paddr_t) systbl64->st_cfgtbl;
#endif
	} else
		pa = (paddr_t)(u_long) efi_systbl_va->st_cfgtbl;
	aprint_debug("efi: cfgtbl at pa %" PRIxPADDR "\n", pa);
	va = efi_getva(pa);
	aprint_debug("efi: cfgtbl mapped at va %" PRIxVADDR "\n", va);
	efi_cfgtblhead_va = (struct efi_cfgtbl *) va;
	efi_aprintcfgtbl();

	return efi_cfgtblhead_va;
}

/*
 * Print the config tables.
 */
void
efi_aprintcfgtbl(void)
{
	struct efi_cfgtbl *ct;
	unsigned long count;

	if (efi_is32x64) {
#if defined(__x86_64__)
		struct efi_systbl32 *systbl32 = (void *) efi_systbl_va;
		struct efi_cfgtbl32 *ct32 = (void *) efi_cfgtblhead_va;

		count = systbl32->st_entries;
		aprint_debug("efi: %lu cfgtbl entries:\n", count);
		for (; count; count--, ct32++) {
			aprint_debug("efi: %08" PRIx32, ct32->ct_data);
			efi_aprintuuid(&ct32->ct_uuid);
			aprint_debug("\n");
		}
#elif defined(__i386__)
		struct efi_systbl64 *systbl64 = (void *) efi_systbl_va;
		struct efi_cfgtbl64 *ct64 = (void *) efi_cfgtblhead_va;
		uint64_t count64 = systbl64->st_entries;

		aprint_debug("efi: %" PRIu64 " cfgtbl entries:\n", count64);
		for (; count64; count64--, ct64++) {
			aprint_debug("efi: %016" PRIx64, ct64->ct_data);
			efi_aprintuuid(&ct64->ct_uuid);
			aprint_debug("\n");
		}
#endif
		return;
	}

	ct = efi_cfgtblhead_va;
	count = efi_systbl_va->st_entries;
	aprint_debug("efi: %lu cfgtbl entries:\n", count);
	for (; count; count--, ct++) {
		aprint_debug("efi: %p", ct->ct_data);
		efi_aprintuuid(&ct->ct_uuid);
		aprint_debug("\n");
	}
}

/*
 * Return the VA of the config table with the given UUID if found.
 * The VA must be freed using efi_relva().
 */
void *
efi_getcfgtbl(const struct uuid * uuid)
{
	paddr_t pa;
	vaddr_t va;

	pa = efi_getcfgtblpa(uuid);
	if (pa == 0)
		return NULL;
	va = efi_getva(pa);
	return (void *) va;
}

/*
 * Return the PA of the first config table.
 */
paddr_t
efi_getcfgtblpa(const struct uuid * uuid)
{
	struct efi_cfgtbl *ct;
	unsigned long count;

	if (efi_is32x64) {
#if defined(__x86_64__)
		struct efi_systbl32 *systbl32 = (void *) efi_systbl_va;
		struct efi_cfgtbl32 *ct32 = (void *) efi_cfgtblhead_va;

		count = systbl32->st_entries;
		for (; count; count--, ct32++)
			if (efi_uuideq(&ct32->ct_uuid, uuid))
				return ct32->ct_data;
#elif defined(__i386__)
		struct efi_systbl64 *systbl64 = (void *) efi_systbl_va;
		struct efi_cfgtbl64 *ct64 = (void *) efi_cfgtblhead_va;
		uint64_t count64 = systbl64->st_entries;

		for (; count64; count64--, ct64++)
			if (efi_uuideq(&ct64->ct_uuid, uuid))
				if (!(ct64->ct_data & 0xffffffff00000000ULL))
					return ct64->ct_data;
#endif
		return 0;	/* Not found. */
	}

	ct = efi_cfgtblhead_va;
	count = efi_systbl_va->st_entries;
	for (; count; count--, ct++)
		if (efi_uuideq(&ct->ct_uuid, uuid))
			return (paddr_t)(u_long) ct->ct_data;

	return 0;	/* Not found. */
}

/* Return the PA of the EFI System Table. */
paddr_t
efi_getsystblpa(void)
{
	struct btinfo_efi *bi;
	paddr_t	pa;

	bi = lookup_bootinfo(BTINFO_EFI);
	if (bi == NULL) {
		/* Unable to locate the EFI System Table. */
		return 0;
	}
	if (sizeof(vaddr_t) == 4 &&
	    (bi->systblpa & 0xffffffff00000000ULL)) {
		/* Unable to access EFI System Table. */
		return 0;
	}
	if (bi->common.len > 16 && (bi->flags & BI_EFI_32BIT)) {
		/* boot from 32bit UEFI */
#if defined(__x86_64__)
		efi_is32x64 = true;
#endif
	} else {
		/* boot from 64bit UEFI */
#if defined(__i386__)
		efi_is32x64 = true;
#endif
	}
	pa = (paddr_t) bi->systblpa;
	return pa;
}

/*
 * Return a pointer to the EFI System Table. The pointer must be freed using
 * efi_relva().
 */
struct efi_systbl *
efi_getsystbl(void)
{
	paddr_t pa;
	vaddr_t va;
	struct efi_systbl *systbl;

	if (efi_systbl_va)
		return efi_systbl_va;

	pa = efi_getsystblpa();
	if (pa == 0)
		return NULL;

	aprint_normal("efi: systbl at pa %" PRIxPADDR "\n", pa);
	va = efi_getva(pa);
	aprint_debug("efi: systbl mapped at va %" PRIxVADDR "\n", va);

	if (efi_is32x64) {
#if defined(__x86_64__)
		struct efi_systbl32 *systbl32 = (struct efi_systbl32 *) va;

		/* XXX Check the signature and the CRC32 */
		aprint_debug("efi: signature %" PRIx64 " revision %" PRIx32
		    " crc32 %" PRIx32 "\n", systbl32->st_hdr.th_sig,
		    systbl32->st_hdr.th_rev, systbl32->st_hdr.th_crc32);
		aprint_debug("efi: firmware revision %" PRIx32 "\n",
		    systbl32->st_fwrev);
		/*
		 * XXX Also print fwvendor, which is an UCS-2 string (use
		 * some UTF-16 routine?)
		 */
		aprint_debug("efi: runtime services at pa 0x%08" PRIx32 "\n",
		    systbl32->st_rt);
		aprint_debug("efi: boot services at pa 0x%08" PRIx32 "\n",
		    systbl32->st_bs);

		efi_systbl_va = (struct efi_systbl *) systbl32;
#elif defined(__i386__)
		struct efi_systbl64 *systbl64 = (struct efi_systbl64 *) va;

		/* XXX Check the signature and the CRC32 */
		aprint_debug("efi: signature %" PRIx64 " revision %" PRIx32
		    " crc32 %" PRIx32 "\n", systbl64->st_hdr.th_sig,
		    systbl64->st_hdr.th_rev, systbl64->st_hdr.th_crc32);
		aprint_debug("efi: firmware revision %" PRIx32 "\n",
		    systbl64->st_fwrev);
		/*
		 * XXX Also print fwvendor, which is an UCS-2 string (use
		 * some UTF-16 routine?)
		 */
		aprint_debug("efi: runtime services at pa 0x%016" PRIx64 "\n",
		    systbl64->st_rt);
		aprint_debug("efi: boot services at pa 0x%016" PRIx64 "\n",
		    systbl64->st_bs);

		efi_systbl_va = (struct efi_systbl *) systbl64;
#endif
		return efi_systbl_va;
	}

	systbl = (struct efi_systbl *) va;
	/* XXX Check the signature and the CRC32 */
	aprint_debug("efi: signature %" PRIx64 " revision %" PRIx32
	    " crc32 %" PRIx32 "\n", systbl->st_hdr.th_sig,
	    systbl->st_hdr.th_rev, systbl->st_hdr.th_crc32);
	aprint_debug("efi: firmware revision %" PRIx32 "\n", systbl->st_fwrev);
	/*
	 * XXX Also print fwvendor, which is an UCS-2 string (use
	 * some UTF-16 routine?)
	 */
	aprint_debug("efi: runtime services at pa %p\n", systbl->st_rt);
	aprint_debug("efi: boot services at pa %p\n", systbl->st_bs);

	efi_systbl_va = systbl;
	return efi_systbl_va;
}

/*
 * Return a pointer to the EFI Runtime Service.
 */
struct efi_rt *
efi_getrt(void)
{
#ifdef __x86_64__
	vaddr_t va;
#endif

	if (efi_rt_va != NULL)
		return efi_rt_va;

#ifdef __x86_64__
	if (efi_is32x64)	/* XXX */
		return NULL;

	va = efi_getva((paddr_t)efi_getsystbl()->st_rt);
	if (va == 0)
		return NULL;

	if (!efi_set_virtual_address_map((void *)va)) {
		efi_relva(va);
		return NULL;
	}

	efi_rt_va = (void *)va;
#endif
	return efi_rt_va;
}

#ifdef __x86_64__
#if PTP_LEVELS > 4
#error "Unsupported number of page table mappings"
#endif

struct pglist efi_pgtbl_list;
struct pglist efi_pgtbl_free;
bool efi_do_set_virtual_address_map;

static int
alloc_pgfree(void)
{
	const int allocpg = 256;

	return uvm_pglistalloc(allocpg * PAGE_SIZE, 0, ptoa(physmem), 0, 0,
	    &efi_pgtbl_free, allocpg, 0);
}

/**
 * from x86/x86/pmap.c:pmap_init_tmp_pgtbl()
 */
paddr_t
efi_make_tmp_pgtbl(void)
{
	extern const vaddr_t ptp_masks[];
	extern const int ptp_shifts[];
	pd_entry_t *tmp_pml, *kernel_pml;
	paddr_t pgpa, endpa;
	vaddr_t pgva;
	int i, error, pgsz;

	/* map PA=VA 0-4GB */
	pgsz = 0;
	pgsz += 1;	/* PML4 (256TiB) */
	pgsz += 1;	/* PDP (512GiB) */
	pgsz += 4;	/* PD (1GiB) */
	endpa = ptoa(physmem);
	if (endpa > 4ULL * 1024 * 1024 * 1024)
		endpa = 4ULL * 1024 * 1024 * 1024;
	error = uvm_pglistalloc(pgsz * PAGE_SIZE, 0, endpa - pgsz * PAGE_SIZE,
	    0, 0, &efi_pgtbl_list, 1, 0);
	if (error) {
		aprint_error("efi: uvm_pglistalloc failed\n");
		return 0;
	}

	const struct vm_page * const pg = TAILQ_FIRST(&efi_pgtbl_list);
	KASSERT(pg != NULL);
	pgpa = VM_PAGE_TO_PHYS(pg);

	pgva = PMAP_DIRECT_MAP(pgpa);

	/* Copy PML4 */
	kernel_pml = pmap_kernel()->pm_pdir;
	tmp_pml = (void *)pgva;
	memcpy(tmp_pml, kernel_pml, PAGE_SIZE);

	/* Zero levels 2-3 */
	for (i = 1; i < pgsz; i++) {
		tmp_pml = (void *)(pgva + i * PAGE_SIZE);
		memset(tmp_pml, 0, PAGE_SIZE);
	}

	/* PDP at PML4 */
	tmp_pml = (void *)pgva;
	tmp_pml[pl_i(pgpa, 4)] = ((pgpa + PAGE_SIZE) & PG_FRAME) | PG_RW | PG_V;

	/* PD at PDP */
	tmp_pml = (void *)(pgva + PAGE_SIZE);
	for (i = 2; i < pgsz; i++) {
		tmp_pml[pl_i(pgpa, 3)] =
		    ((pgpa + i * PAGE_SIZE) & PG_FRAME) | PG_RW | PG_V;
	}

	error = alloc_pgfree();
	if (error) {
		aprint_error("efi: couldn't allocate page table page\n");
		uvm_pglistfree(&efi_pgtbl_list);
		return 0;
	}

	return pgpa;
}

void
efi_free_tmp_pgtbl(void)
{

	uvm_pglistfree(&efi_pgtbl_list);
	uvm_pglistfree(&efi_pgtbl_free);
}

static struct vm_page *
get_page_from_free_list(void)
{
	struct vm_page *pg;
	int error;

	pg = TAILQ_FIRST(&efi_pgtbl_free);
	if (pg == NULL) {
		error = alloc_pgfree();
		if (error)
			panic("efi: couldn't allocate page table page\n");
		pg = TAILQ_FIRST(&efi_pgtbl_free);
	}
	KASSERT(pg != NULL);
	TAILQ_REMOVE(&efi_pgtbl_free, pg, pageq.queue);
	TAILQ_INSERT_TAIL(&efi_pgtbl_list, pg, pageq.queue);
	memset((void *)PMAP_DIRECT_MAP(VM_PAGE_TO_PHYS(pg)), 0, PAGE_SIZE);
	return pg;
}

pt_entry_t *
efi_get_pte_tmp_pgtbl(paddr_t pgtbl_pa, vaddr_t va)
{
	pd_entry_t *pml4e, *pdpe, *pde;
	pt_entry_t *pte;
	struct vm_page *pg;
	paddr_t pa;

	pml4e = (void *)PMAP_DIRECT_MAP(pgtbl_pa);
	pml4e = &pml4e[pl4_pi(va)];
	if (*pml4e == 0) {
		pg = get_page_from_free_list();
		pa = VM_PAGE_TO_PHYS(pg);
		*pml4e = pa | PG_RW | PG_V;
	} else
		pa = *pml4e & ~PAGE_MASK;

	pdpe = (void *)PMAP_DIRECT_MAP(pa);
	pdpe = &pdpe[pl3_pi(va)];
	if (*pdpe == 0) {
		pg = get_page_from_free_list();
		pa = VM_PAGE_TO_PHYS(pg);
		*pdpe = pa | PG_RW | PG_V;
	} else
		pa = *pdpe & ~PAGE_MASK;

	pde = (void *)PMAP_DIRECT_MAP(pa);
	pde = &pde[pl2_pi(va)];
	if (*pde == 0) {
		pg = get_page_from_free_list();
		pa = VM_PAGE_TO_PHYS(pg);
		*pde = pa | PG_RW | PG_V;
	} else
		pa = *pde & ~PAGE_MASK;

	pte = (void *)PMAP_DIRECT_MAP(pa);
	pte = &pte[pl1_pi(va)];
	KASSERT(*pte == 0);

	return pte;
}

bool
efi_set_virtual_address_map(struct efi_rt *rt)
{
	efi_status status;
	struct btinfo_efimemmap *efimm;
	struct efi_md *md;
	paddr_t pa;
	vaddr_t va;
	u_long descsz, allocsz;
	u_long orig_cr3, tmp_cr3;
	pt_entry_t *pte;
	int i, flags;

	if (efi_do_set_virtual_address_map)
		return false;

	efi_do_set_virtual_address_map = true;

	efimm = lookup_bootinfo(BTINFO_EFIMEMMAP);
	KASSERT(efimm != NULL);

	descsz = efimm->size;
	allocsz = efimm->size * efimm->num;
	for (i = 0, md = (struct efi_md *)efimm->memmap;
	     i < efimm->num;
	     i++, md = efi_next_descriptor(md, descsz)) {
		if (!(md->md_attr & EFI_MD_ATTR_RT))
			continue;

		if (md->md_virt != 0) {
			aprint_verbose(
			    "efi: EFI Runtime entry %d is mapped\n", i);
			goto fail;
		}
		if ((md->md_phys & EFI_PAGE_MASK) != 0) {
			aprint_verbose(
			    "efi: EFI Runtime entry %d is not aligned\n", i);
			goto fail;
		}

		va = uvm_km_alloc(kernel_map, md->md_pages * EFI_PAGE_SIZE,
		    0, UVM_KMF_VAONLY);
		if (va == 0) {
			aprint_error("efi: couldn't allocate entry %d va\n", i);
			goto fail;
		}
		md->md_virt = va;

		flags = 0;
		if ((md->md_attr & EFI_MD_ATTR_WB))
			flags |= PMAP_WRITE_BACK;
		else if ((md->md_attr & EFI_MD_ATTR_WT))
			;
		else if ((md->md_attr & EFI_MD_ATTR_WC))
			flags |= PMAP_WRITE_COMBINE;
		else if ((md->md_attr & EFI_MD_ATTR_WP))
			;
		else if ((md->md_attr & EFI_MD_ATTR_UC))
			flags |= PMAP_NOCACHE;
		else {
			aprint_verbose("efi: EFI Runtime entry %d mapping "
			    "attributes unsupported\n", i);
			flags |= PMAP_NOCACHE;
		}

		for (pa = (paddr_t)md->md_phys;
		    pa < (paddr_t)md->md_phys + md->md_pages * EFI_PAGE_SIZE;
		    pa += PAGE_SIZE, va += PAGE_SIZE)
			pmap_kenter_pa(va, pa, VM_PROT_DEFAULT, flags);
	}
	pmap_update(pmap_kernel());

	/* make VA=PA page table */
	tmp_cr3 = efi_make_tmp_pgtbl();
	if (tmp_cr3 == 0)
		goto fail;

	for (i = 0, md = (struct efi_md *)efimm->memmap;
	     i < efimm->num;
	     i++, md = efi_next_descriptor(md, descsz)) {
		if (!(md->md_attr & EFI_MD_ATTR_RT))
			continue;

		flags = 0;
		if ((md->md_attr & EFI_MD_ATTR_WB))
			;
		else if ((md->md_attr & EFI_MD_ATTR_WT))
			flags |= PG_WT;
		else if ((md->md_attr & EFI_MD_ATTR_WC))
			;
		else if ((md->md_attr & EFI_MD_ATTR_WP))
			;
		else if ((md->md_attr & EFI_MD_ATTR_UC))
			flags |= PG_N;
		else
			flags |= PG_N;

		for (pa = (paddr_t)md->md_phys;
		    pa < (paddr_t)md->md_phys + md->md_pages * EFI_PAGE_SIZE;
		    pa += PAGE_SIZE) {
			/* VA=PA */
			pte = efi_get_pte_tmp_pgtbl(tmp_cr3, (vaddr_t)pa);
			*pte = pa | PG_RW | PG_V | flags;
		}
	}

	x86_disable_intr();
	orig_cr3 = rcr3();
	wbinvd();
	x86_flush();
	lcr3(tmp_cr3);
	tlbflushg();

	status = rt->rt_setvirtual(allocsz, descsz, efimm->version,
	    (struct efi_md *)efimm->memmap);

	lcr3(orig_cr3);
	tlbflushg();
	x86_enable_intr();

	efi_free_tmp_pgtbl();

	if (status != 0) {
		aprint_error("efi: SetVirtualAddressMap failed: %lx(%d)\n",
		    status, efi_status_to_errno(status));
		goto fail;
	}

	return true;

fail:
	while (--i >= 0) {
		md = (void *)((uint8_t *)md - descsz);
		if (!(md->md_attr & EFI_MD_ATTR_RT))
			continue;
		va = (vaddr_t)md->md_virt;
		pmap_kremove(va, md->md_pages * EFI_PAGE_SIZE);
		uvm_km_free(kernel_map, va, md->md_pages * EFI_PAGE_SIZE,
		    UVM_KMF_VAONLY);
		md->md_virt = 0;
	}
	pmap_update(pmap_kernel());
	return false;
}
#endif

/*
 * EFI is available if we are able to locate the EFI System Table.
 */
void
efi_init(void)
{

	if (efi_getsystbl() == NULL) {
		aprint_debug("efi: missing or invalid systbl\n");
		bootmethod_efi = false;
		return;
	}
	if (efi_getcfgtblhead() == NULL) {
		aprint_debug("efi: missing or invalid cfgtbl\n");
		efi_relva((vaddr_t) efi_systbl_va);
		bootmethod_efi = false;
		return;
	}
	if (efi_getrt() == NULL)
		aprint_debug("efi: missing or invalid runtime service\n");
	bootmethod_efi = true;
	pci_mapreg_map_enable_decode = true; /* PR port-amd64/53286 */
}

bool
efi_probe(void)
{

	return bootmethod_efi;
}

int
efi_getbiosmemtype(uint32_t type, uint64_t attr)
{

	switch (type) {
	case EFI_MD_TYPE_CODE:
	case EFI_MD_TYPE_DATA:
	case EFI_MD_TYPE_BS_CODE:
	case EFI_MD_TYPE_BS_DATA:
	case EFI_MD_TYPE_FREE:
		return (attr & EFI_MD_ATTR_WB) ? BIM_Memory : BIM_Reserved;

	case EFI_MD_TYPE_RECLAIM:
		return BIM_ACPI;

	case EFI_MD_TYPE_FIRMWARE:
		return BIM_NVS;

	case EFI_MD_TYPE_PERSISTENT:
		return BIM_PMEM;

	case EFI_MD_TYPE_NULL:
	case EFI_MD_TYPE_RT_CODE:
	case EFI_MD_TYPE_RT_DATA:
	case EFI_MD_TYPE_BAD:
	case EFI_MD_TYPE_IOMEM:
	case EFI_MD_TYPE_IOPORT:
	case EFI_MD_TYPE_PALCODE:
	default:
		return BIM_Reserved;
	}
}

const char *
efi_getmemtype_str(uint32_t type)
{
	static const char *efimemtypes[] = {
		"Reserved",
		"LoaderCode",
		"LoaderData",
		"BootServicesCode",
		"BootServicesData",
		"RuntimeServicesCode",
		"RuntimeServicesData",
		"ConventionalMemory",
		"UnusableMemory",
		"ACPIReclaimMemory",
		"ACPIMemoryNVS",
		"MemoryMappedIO",
		"MemoryMappedIOPortSpace",
		"PalCode",
		"PersistentMemory",
	};

	if (type < __arraycount(efimemtypes))
		return efimemtypes[type];
	return "unknown";
}

struct btinfo_memmap *
efi_get_e820memmap(void)
{
	struct btinfo_efimemmap *efimm;
	struct bi_memmap_entry *entry;
	struct efi_md *md;
	uint64_t addr, size;
	uint64_t start_addr = 0;        /* XXX gcc -Os: maybe-uninitialized */
	uint64_t end_addr = 0;          /* XXX gcc -Os: maybe-uninitialized */
	uint32_t i;
	int n, type, seg_type = -1;

	if (efi_e820memmap.bim.common.type == BTINFO_MEMMAP)
		return &efi_e820memmap.bim;

	efimm = lookup_bootinfo(BTINFO_EFIMEMMAP);
	if (efimm == NULL)
		return NULL;

	for (n = 0, i = 0; i < efimm->num; i++) {
		md = (struct efi_md *)(efimm->memmap + efimm->size * i);
		addr = md->md_phys;
		size = md->md_pages * EFI_PAGE_SIZE;
		type = efi_getbiosmemtype(md->md_type, md->md_attr);

#ifdef DEBUG_MEMLOAD
		printf("MEMMAP: p0x%016" PRIx64 "-0x%016" PRIx64
		    ", v0x%016" PRIx64 "-0x%016" PRIx64
		    ", size=0x%016" PRIx64 ", attr=0x%016" PRIx64
		    ", type=%d(%s)\n",
		    addr, addr + size - 1,
		    md->md_virt, md->md_virt + size - 1,
		    size, md->md_attr, md->md_type,
		    efi_getmemtype_str(md->md_type));
#endif

		if (seg_type == -1) {
			/* first entry */
		} else if (seg_type == type && end_addr == addr) {
			/* continuous region */
			end_addr = addr + size;
			continue;
		} else {
			entry = &efi_e820memmap.bim.entry[n];
			entry->addr = start_addr;
			entry->size = end_addr - start_addr;
			entry->type = seg_type;
			if (++n == VM_PHYSSEG_MAX)
				break;
		}

		start_addr = addr;
		end_addr = addr + size;
		seg_type = type;
	}
	if (i > 0 && n < VM_PHYSSEG_MAX) {
		entry = &efi_e820memmap.bim.entry[n];
		entry->addr = start_addr;
		entry->size = end_addr - start_addr;
		entry->type = seg_type;
		++n;
	} else if (n == VM_PHYSSEG_MAX) {
		printf("WARNING: too many memory segments"
		    "(increase VM_PHYSSEG_MAX)\n");
	}

	efi_e820memmap.bim.num = n;
	efi_e820memmap.bim.common.len =
	    (intptr_t)&efi_e820memmap.bim.entry[n] - (intptr_t)&efi_e820memmap;
	efi_e820memmap.bim.common.type = BTINFO_MEMMAP;
	return &efi_e820memmap.bim;
}

/*
 * ioctl
 */

dev_type_open(efiopen);
dev_type_close(eficlose);
dev_type_ioctl(efiioctl);

const struct cdevsw efi_cdevsw = {
	.d_open = efiopen,
	.d_close = eficlose,
	.d_read = noread,
	.d_write = nowrite,
	.d_ioctl = efiioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = nommap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER,
};

int
efiopen(dev_t dev, int flag, int mode, struct lwp *l)
{

	if (minor(dev) != 0)
		return ENXIO;

	if (!efi_probe())
		return ENXIO;

	return 0;
}

int
eficlose(dev_t dev, int flag, int mode, struct lwp *l)
{

	return 0;
}

int
efiioctl(dev_t dev, u_long cmd, void *data, int flag, struct lwp *l)
{
	int error;

	switch (cmd) {
	case EFIIOC_VAR_GET:
	case EFIIOC_VAR_NEXT:
	case EFIIOC_VAR_SET:
	default:
		error = ENOTTY;
		break;
	}

	return error;
}
