/*     $NetBSD: efi.h,v 1.8 2017/10/22 00:59:28 maya Exp $   */

/*-
 * Copyright (c) 2004 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _X86_EFI_H_
#define _X86_EFI_H_

/*
 * XXX: from gcc 6.2 manual:
 * Note, the ms_abi attribute for Microsoft Windows 64-bit targets
 * currently requires the -maccumulate-outgoing-args option.
 */
#define	EFIABI_ATTR	__attribute__((ms_abi))

extern const struct uuid EFI_UUID_ACPI20;
extern const struct uuid EFI_UUID_ACPI10;
extern const struct uuid EFI_UUID_SMBIOS;
extern const struct uuid EFI_UUID_SMBIOS3;

extern bool bootmethod_efi;

#if defined(__amd64__)
struct efi_cfgtbl32 {
	struct uuid		ct_uuid;
	uint32_t		ct_data;	/* void * */
};

struct efi_systbl32 {
	struct efi_tblhdr	st_hdr;

	uint32_t		st_fwvendor;
	uint32_t		st_fwrev;
	uint32_t		st_cin;		/* = 0 */
	uint32_t		st_cinif;	/* = 0 */
	uint32_t		st_cout;	/* = 0 */
	uint32_t		st_coutif;	/* = 0 */
	uint32_t		st_cerr;	/* = 0 */
	uint32_t		st_cerrif;	/* = 0 */
	uint32_t		st_rt;		/* struct efi_rt32 * */
	uint32_t		st_bs;		/* = 0 */
	uint32_t		st_entries;
	uint32_t		st_cfgtbl;	/* struct efi_cfgtbl32 * */
};
#elif defined(__i386__)
struct efi_cfgtbl64 {
	struct uuid		ct_uuid;
	uint64_t		ct_data;	/* void * */
};

struct efi_systbl64 {
	struct efi_tblhdr	st_hdr;

	uint64_t		st_fwvendor;
	uint32_t		st_fwrev;
	uint32_t		__pad;
	uint64_t		st_cin;		/* = 0 */
	uint64_t		st_cinif;	/* = 0 */
	uint64_t		st_cout;	/* = 0 */
	uint64_t		st_coutif;	/* = 0 */
	uint64_t		st_cerr;	/* = 0 */
	uint64_t		st_cerrif;	/* = 0 */
	uint64_t		st_rt;		/* struct efi_rt64 * */
	uint64_t		st_bs;		/* = 0 */
	uint64_t		st_entries;
	uint64_t		st_cfgtbl;	/* struct efi_cfgtbl64 * */
};
#endif

void               efi_init(void);
bool               efi_probe(void);
paddr_t            efi_getsystblpa(void);
struct efi_systbl *efi_getsystbl(void);
paddr_t            efi_getcfgtblpa(const struct uuid *);
void              *efi_getcfgtbl(const struct uuid *);
int                efi_getbiosmemtype(uint32_t, uint64_t);
const char        *efi_getmemtype_str(uint32_t);
struct btinfo_memmap;
struct btinfo_memmap *efi_get_e820memmap(void);

#endif /* _X86_EFI_H_ */
