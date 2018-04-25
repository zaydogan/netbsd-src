/*	$NetBSD$	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2003 Poul-Henning Kamp
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
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 *
 * $FreeBSD: head/lib/libgeom/libgeom.h 326219 2017-11-26 02:00:33Z pfg $
 */
#ifndef _LIBGEOM_H_
#define _LIBGEOM_H_

#include <sys/cdefs.h>

#include <sys/queue.h>
#include <sys/time.h>

__BEGIN_DECLS

#ifndef DEBUG_LIBGEOM
#define DEBUG_LIBGEOM 0
#endif

struct gclass;
struct ggeom;
struct gconsumer;
struct gprovider;

LIST_HEAD(gconf, gconfig);

struct gident {
	void			*lg_id;
	void			*lg_ptr;
	enum {	ISCLASS,
		ISGEOM,
		ISPROVIDER,
		ISCONSUMER }	lg_what;
};

struct gmesh {
	LIST_HEAD(, gclass)	lg_class;
	struct gident		*lg_ident;
#ifdef __NetBSD__
	size_t			_lg_nident;
	size_t			_lg_aident;
#endif
};

struct gconfig {
	LIST_ENTRY(gconfig)	lg_config;
	char			*lg_name;
	char			*lg_val;
};

struct gclass {
	void			*lg_id;
	char			*lg_name;
	LIST_ENTRY(gclass)	lg_class;
	LIST_HEAD(, ggeom)	lg_geom;
	struct gconf		lg_config;
};

struct ggeom {
	void			*lg_id;
	struct gclass		*lg_class;
	char			*lg_name;
	u_int			lg_rank;
	LIST_ENTRY(ggeom)	lg_geom;
	LIST_HEAD(, gconsumer)	lg_consumer;
	LIST_HEAD(, gprovider)	lg_provider;
	struct gconf		lg_config;
};

struct gconsumer {
	void			*lg_id;
	struct ggeom		*lg_geom;
	LIST_ENTRY(gconsumer)	lg_consumer;
	struct gprovider	*lg_provider;
	LIST_ENTRY(gconsumer)	lg_consumers;
	char			*lg_mode;
	struct gconf		lg_config;
};

struct gprovider {
	void			*lg_id;
	char			*lg_name;
	struct ggeom		*lg_geom;
	LIST_ENTRY(gprovider)	lg_provider;
	LIST_HEAD(, gconsumer)	lg_consumers;
	char			*lg_mode;
	off_t			lg_mediasize;
	u_int			lg_sectorsize;
	off_t			lg_stripeoffset;
	off_t			lg_stripesize;
	struct gconf		lg_config;
};

int geom_gettree(struct gmesh *);
void geom_deletetree(struct gmesh *);

/* geom_util.c */
char *g_device_path(const char *);

__END_DECLS

#endif /* _LIBGEOM_H_ */
