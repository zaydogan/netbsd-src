/*	$NetBSD$	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2018 Alexander Motin <mav@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD$");
#if 0
__FBSDID("$FreeBSD: head/sbin/nvmecontrol/format.c 330846 2018-03-13 15:29:13Z mav $");
#endif
#endif

#include <sys/param.h>

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nvmectl.h"

static void __dead
format_usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "\t%s " FORMAT_USAGE, getprogname());
	exit(1);
}

void
format(int argc, char *argv[])
{
	struct nvm_identify_controller	cd;
	struct nvm_identify_namespace	nsd;
	struct nvme_pt_command		pt;
	char				path[64];
	char				*target;
	uint32_t			nsid;
	int				ch, fd;
	int lbaf = -1, mset = -1, pi = -1, pil = -1, ses = 0;

	if (argc < 2)
		format_usage();

	while ((ch = getopt(argc, argv, "f:m:p:l:EC")) != -1) {
		switch (ch) {
		case 'f':
			lbaf = strtol(optarg, NULL, 0);
			break;
		case 'm':
			mset = strtol(optarg, NULL, 0);
			break;
		case 'p':
			pi = strtol(optarg, NULL, 0);
			break;
		case 'l':
			pil = strtol(optarg, NULL, 0);
			break;
		case 'E':
			if (ses == 2)
				errx(1, "-E and -C are mutually exclusive");
			ses = 1;
			break;
		case 'C':
			if (ses == 1)
				errx(1, "-E and -C are mutually exclusive");
			ses = 2;
			break;
		default:
			format_usage();
		}
	}

	/* Check that a controller or namespace was specified. */
	if (optind >= argc)
		format_usage();
	target = argv[optind];

	/*
	 * Check if the specified device node exists before continuing.
	 * This is a cleaner check for cases where the correct controller
	 * is specified, but an invalid namespace on that controller.
	 */
	open_dev(target, &fd, 1, 1);

	/*
	 * If device node contains "ns", we consider it a namespace,
	 * otherwise, consider it a controller.
	 */
	if (strstr(target, NVME_NS_PREFIX) == NULL) {
		nsid = NVME_GLOBAL_NAMESPACE_TAG;
	} else {
		/*
		 * We send FORMAT commands to the controller, not the namespace,
		 * since it is an admin cmd.  The namespace ID will be specified
		 * in the command itself.  So parse the namespace's device node
		 * string to get the controller substring and namespace ID.
		 */
		close(fd);
		parse_ns_str(target, path, &nsid);
		open_dev(path, &fd, 1, 1);
	}

	/* Check that controller can execute this command. */
	read_controller_data(fd, &cd);
	if (!(cd.oacs & NVME_ID_CTRLR_OACS_FORMAT))
		errx(1, "controller does not support format");
	if (!(cd.fna & NVME_ID_CTRLR_FNA_CRYPTO_ERASE) && ses == 2)
		errx(1, "controller does not support cryptographic erase");

	if (nsid != NVME_GLOBAL_NAMESPACE_TAG) {
		if ((cd.fna & NVME_ID_CTRLR_FNA_FORMAT_ALL) && ses == 0)
			errx(1, "controller does not support per-NS format");
		if ((cd.fna & NVME_ID_CTRLR_FNA_ERASE_ALL) && ses != 0)
			errx(1, "controller does not support per-NS erase");

		/* Try to keep previous namespace parameters. */
		read_namespace_data(fd, nsid, &nsd);
		if (lbaf < 0)
			lbaf = NVME_ID_NS_FLBAS(nsd.flbas);
		if (lbaf > nsd.nlbaf)
			errx(1, "LBA format is out of range");
		if (mset < 0)
			mset = (nsd.flbas & NVME_ID_NS_FLBAS_MD) ? 1 : 0;
		if (pi < 0)
			pi = (nsd.dps & NVME_ID_NS_DPS_MD_START) ? 1 : 0;
		if (pil < 0)
			pil = NVME_ID_NS_DPS_PIT(nsd.dps);
	} else {

		/* We have no previous parameters, so default to zeroes. */
		if (lbaf < 0)
			lbaf = 0;
		if (mset < 0)
			mset = 0;
		if (pi < 0)
			pi = 0;
		if (pil < 0)
			pil = 0;
	}

	memset(&pt, 0, sizeof(pt));
	pt.cmd.opcode = NVM_ADMIN_FORMAT_NVM;
	pt.cmd.nsid = nsid;
	pt.cmd.cdw10 = (ses << 9) + (pil << 8) + (pi << 5) + (mset << 4) + lbaf;

	if (ioctl(fd, NVME_PASSTHROUGH_CMD, &pt) < 0)
		err(1, "format request failed");

	if (nvme_completion_is_error(&pt.cpl))
		errx(1, "format request returned error");

	close(fd);
	exit(0);
}
