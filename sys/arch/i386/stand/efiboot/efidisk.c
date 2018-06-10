/*	$NetBSD: efidisk.c,v 1.6 2018/04/11 10:32:09 nonaka Exp $	*/

/*
 * Copyright (c) 1996
 *	Matthias Drochner.  All rights reserved.
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*-
 * Copyright (c) 2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Bang Jun-Young.
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

/*
 * Copyright (c) 1996
 * 	Matthias Drochner.  All rights reserved.
 * Copyright (c) 1996
 * 	Perry E. Metzger.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgements:
 *	This product includes software developed for the NetBSD Project
 *	by Matthias Drochner.
 *	This product includes software developed for the NetBSD Project
 *	by Perry E. Metzger.
 * 4. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

/*-
 * Copyright (c) 2016 Kimihiro Nonaka <nonaka@netbsd.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define FSTYPENAMES	/* for sys/disklabel.h */

#include "efiboot.h"

#include <sys/disklabel.h>

#include "devopen.h"
#include "efidisk.h"

struct efidisk_ll {
	int             dev;		/* BIOS device number */
	int		type;		/* device type; see below */
	int             sec, head, cyl;	/* geometry */
	int		chs_sectors;	/* # of sectors addressable by CHS */
	int		secsize;	/* bytes per sector */
};

#define EFIDISK_TYPE_FD	0
#define EFIDISK_TYPE_HD	1
#define EFIDISK_TYPE_CD	2

/*
 * Version 1.x drive parameters from int13 extensions
 * - should be supported by every BIOS that supports the extensions.
 * Version 3.x parameters allow the drives to be matched properly
 * - but are much less likely to be supported.
 */

struct biosdisk_extinfo {
	uint16_t	size;		/* size of buffer, set on call */
	uint16_t	flags;		/* flags, see below */
	uint32_t	cyl;		/* # of physical cylinders */
	uint32_t	head;		/* # of physical heads */
	uint32_t	sec;		/* # of physical sectors per track */
	uint64_t	totsec;		/* total number of sectors */
	uint16_t	sbytes;		/* # of bytes per sector */
} __packed;

#define EXTINFO_DMA_TRANS	0x0001	/* transparent DMA boundary errors */
#define EXTINFO_GEOM_VALID	0x0002	/* geometry in c/h/s in struct valid */
#define EXTINFO_REMOVABLE	0x0004	/* removable device */
#define EXTINFO_WRITEVERF	0x0008	/* supports write with verify */
#define EXTINFO_CHANGELINE	0x0010	/* changeline support */
#define EXTINFO_LOCKABLE	0x0020	/* device is lockable */
#define EXTINFO_MAXGEOM		0x0040	/* geometry set to max; no media */

#ifndef BIOSDISK_DEFAULT_SECSIZE
#define BIOSDISK_DEFAULT_SECSIZE	512
#endif

int set_geometry(struct efidisk_ll *);
int readsects(struct efidisk_ll *, daddr_t, int, char *, int);

static struct efidiskinfo_lh efi_disklist;
static int nefidisks;

void
efi_disk_probe(void)
{
	EFI_STATUS status;
	UINTN i, nhandles;
	EFI_HANDLE *handles;
	EFI_BLOCK_IO *bio;
	EFI_BLOCK_IO_MEDIA *media;
	EFI_DEVICE_PATH *dp;
	struct efidiskinfo *edi;
	int dev, depth = -1;

	TAILQ_INIT(&efi_disklist);

	status = LibLocateHandle(ByProtocol, &BlockIoProtocol, NULL,
	    &nhandles, &handles);
	if (EFI_ERROR(status))
		panic("LocateHandle(BlockIoProtocol): %" PRIxMAX,
		    (uintmax_t)status);

	if (efi_bootdp != NULL)
		depth = efi_device_path_depth(efi_bootdp, MEDIA_DEVICE_PATH);

	/*
	 * U-Boot incorrectly represents devices with a single
	 * MEDIA_DEVICE_PATH component.  In that case include that
	 * component into the matching, otherwise we'll blindly select
	 * the first device.
	 */
	if (depth == 0)
		depth = 1;

	for (i = 0; i < nhandles; i++) {
		status = uefi_call_wrapper(BS->HandleProtocol, 3, handles[i],
		    &BlockIoProtocol, (void **)&bio);
		if (EFI_ERROR(status))
			panic("HandleProtocol(BlockIoProtocol): %" PRIxMAX,
			    (uintmax_t)status);

		media = bio->Media;
		if (media->LogicalPartition || !media->MediaPresent)
			continue;

		edi = alloc(sizeof(struct efidiskinfo));
		memset(edi, 0, sizeof(*edi));
		edi->type = BIOSDISK_TYPE_HD;
		edi->bio = bio;
		edi->media_id = media->MediaId;

		if (efi_bootdp != NULL && depth > 0) {
			status = uefi_call_wrapper(BS->HandleProtocol, 3,
			    handles[i], &DevicePathProtocol, (void **)&dp);
			if (EFI_ERROR(status))
				goto next;
			if (efi_device_path_ncmp(efi_bootdp, dp, depth) == 0) {
				edi->bootdev = true;
				TAILQ_INSERT_HEAD(&efi_disklist, edi,
				    list);
				continue;
			}
		}
next:
		TAILQ_INSERT_TAIL(&efi_disklist, edi, list);
	}

	FreePool(handles);

	if (efi_bootdp_type == BOOT_DEVICE_TYPE_CD) {
		edi = TAILQ_FIRST(&efi_disklist);
		if (edi != NULL && edi->bootdev) {
			edi->type = BIOSDISK_TYPE_CD;
			TAILQ_REMOVE(&efi_disklist, edi, list);
			TAILQ_INSERT_TAIL(&efi_disklist, edi, list);
		}
	}

	dev = 0x80;
	TAILQ_FOREACH(edi, &efi_disklist, list) {
		edi->dev = dev++;
		if (edi->type == BIOSDISK_TYPE_HD)
			nefidisks++;
		if (edi->bootdev)
			boot_biosdev = edi->dev;
	}
}

void
efi_disk_show(void)
{
	const struct efidiskinfo *edi;
	EFI_BLOCK_IO_MEDIA *media;
	struct biosdisk_partition *part;
	uint64_t size;
	int i, nparts;
	bool first;

	TAILQ_FOREACH(edi, &efi_disklist, list) {
		media = edi->bio->Media;
		first = true;
		printf("disk ");
		switch (edi->type) {
		case BIOSDISK_TYPE_CD:
			printf("cd0");
			printf(" mediaId %u", media->MediaId);
			if (edi->media_id != media->MediaId)
				printf("(%u)", edi->media_id);
			printf("\n");
			printf("  cd0a\n");
			break;
		case BIOSDISK_TYPE_HD:
			printf("hd%d", edi->dev & 0x7f);
			printf(" mediaId %u", media->MediaId);
			if (edi->media_id != media->MediaId)
				printf("(%u)", edi->media_id);
			printf(" size ");
			size = (media->LastBlock + 1) * media->BlockSize;
			if (size >= (10ULL * 1024 * 1024 * 1024))
				printf("%"PRIu64" GB", size / (1024 * 1024 * 1024));
			else
				printf("%"PRIu64" MB", size / (1024 * 1024));
			printf("\n");
			break;
		}
		if (edi->type != BIOSDISK_TYPE_HD)
			continue;

		if (biosdisk_readpartition(edi->dev, &part, &nparts))
			continue;

		for (i = 0; i < nparts; i++) {
			if (part[i].size == 0)
				continue;
			if (part[i].fstype == FS_UNUSED)
				continue;
			if (first) {
				printf(" ");
				first = false;
			}
			printf(" hd%d%c(", edi->dev & 0x7f, i + 'a');
			if (part[i].guid != NULL)
				printf("%s", part[i].guid->name);
			else if (part[i].fstype < FSMAXTYPES)
				printf("%s", fstypenames[part[i].fstype]);
			else
				printf("%d", part[i].fstype);
			printf(")");
		}
		if (!first)
			printf("\n");
		dealloc(part, sizeof(*part) * nparts);
	}
}

const struct efidiskinfo *
efidisk_getinfo(int dev)
{
	const struct efidiskinfo *edi;

	TAILQ_FOREACH(edi, &efi_disklist, list) {
		if (dev == edi->dev)
			return edi;
	}
	return NULL;
}

/*
 * Return the number of hard disk drives.
 */
int
get_harddrives(void)
{
	return nefidisks;
}

int
efidisk_get_efi_system_partition(int dev, int *partition)
{
	extern const struct uuid GET_efi;
	const struct efidiskinfo *edi;
	struct biosdisk_partition *part;
	int i, nparts;

	edi = efidisk_getinfo(dev);
	if (edi == NULL)
		return ENXIO;

	if (edi->type != BIOSDISK_TYPE_HD)
		return ENOTSUP;

	if (biosdisk_readpartition(edi->dev, &part, &nparts))
		return EIO;

	for (i = 0; i < nparts; i++) {
		if (part[i].size == 0)
			continue;
		if (part[i].fstype == FS_UNUSED)
			continue;
		if (guid_is_equal(part[i].guid->guid, &GET_efi))
			break;
	}
	dealloc(part, sizeof(*part) * nparts);
	if (i == nparts)
		return ENOENT;

	*partition = i;
	return 0;
}

/*
 * shared by bootsector startup (bootsectmain) and biosdisk.c
 * needs lowlevel parts from bios_disk.S
 */

static int do_read(struct biosdisk_ll *, daddr_t, int, char *);

#ifndef BIOSDISK_RETRIES
#define BIOSDISK_RETRIES 5
#endif

int
set_geometry(struct biosdisk_ll *d, struct biosdisk_extinfo *ed)
{
	const struct efidiskinfo *edi;
	EFI_BLOCK_IO_MEDIA *media;

	edi = efidisk_getinfo(d->dev);
	if (edi == NULL)
		return 1;

	media = edi->bio->Media;

	d->secsize = media->BlockSize;
	d->type = edi->type;

	if (ed != NULL) {
		ed->totsec = media->LastBlock + 1;
		ed->sbytes = media->BlockSize;
		ed->flags = 0;
		if (media->RemovableMedia)
			ed->flags |= EXTINFO_REMOVABLE;
	}

	return 0;
}

static char *diskbufp;		/* allocated from heap */
static const void *diskbuf_user;

/*
 * Global shared "diskbuf" is used as read ahead buffer.
 * This MAY have to not cross a 64k boundary.
 * In practise it is allocated out of the heap early on...
 * NB a statically allocated diskbuf is not guaranteed to not
 * cross a 64k boundary.
 */
static char *
alloc_diskbuf(const void *user)
{
	diskbuf_user = user;
	if (diskbufp == NULL)
		diskbufp = alloc(DISKBUFSIZE);
	return diskbufp;
}

/*
 * Global shared "diskbuf" is used as read ahead buffer.  For reading from
 * floppies, the bootstrap has to be loaded on a 64K boundary to ensure that
 * this buffer doesn't cross a 64K DMA boundary.
 */
static int      ra_dev;
static daddr_t  ra_end;
static daddr_t  ra_first;

static int
do_read(struct biosdisk_ll *d, daddr_t dblk, int num, char *buf)
{
	EFI_STATUS status;
	const struct efidiskinfo *edi;

	edi = efidisk_getinfo(d->dev);
	if (edi == NULL)
		return -1;

	status = uefi_call_wrapper(edi->bio->ReadBlocks, 5, edi->bio,
	    edi->media_id, dblk, num * d->secsize, buf);
	if (EFI_ERROR(status))
		return -1;
	return num;
}

/*
 * NB if 'cold' is set below not all of the program is loaded, so
 * mustn't use data segment, bss, call library functions or do read-ahead.
 */
int
readsects(struct biosdisk_ll *d, daddr_t dblk, int num, char *buf, int cold)
{
	while (num) {
		int nsec;

		/* check for usable data in read-ahead buffer */
		if (cold || diskbuf_user != &ra_dev || d->dev != ra_dev
		    || dblk < ra_first || dblk >= ra_end) {

			/* no, read from disk */
			char *trbuf;
			int maxsecs;
			int retries = BIOSDISK_RETRIES;

			if (cold) {
				/* transfer directly to buffer */
				trbuf = buf;
				maxsecs = num;
			} else {
				/* fill read-ahead buffer */
				trbuf = alloc_diskbuf(0); /* no data yet */
				maxsecs = DISKBUFSIZE / d->secsize;
			}

			while ((nsec = do_read(d, dblk, maxsecs, trbuf)) < 0) {
#ifdef DISK_DEBUG
				if (!cold)
					printf("read error dblk %"PRId64"-%"PRId64"\n",
					    dblk, (dblk + maxsecs - 1));
#endif
				if (--retries >= 0)
					continue;
				return -1;	/* XXX cannot output here if
						 * (cold) */
			}
			if (!cold) {
				ra_dev = d->dev;
				ra_first = dblk;
				ra_end = dblk + nsec;
				diskbuf_user = &ra_dev;
			}
		} else		/* can take blocks from end of read-ahead
				 * buffer */
			nsec = ra_end - dblk;

		if (!cold) {
			/* copy data from read-ahead to user buffer */
			if (nsec > num)
				nsec = num;
			memcpy(buf,
			       diskbufp + (dblk - ra_first) * d->secsize,
			       nsec * d->secsize);
		}
		buf += nsec * d->secsize;
		num -= nsec;
		dblk += nsec;
	}

	return 0;
}
