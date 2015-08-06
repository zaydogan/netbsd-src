/*	$NetBSD: keyboard.c,v 1.9 2008/04/28 20:23:09 martin Exp $ */

/*-
 * Copyright (c) 1998, 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Juergen Hannken-Illjes.
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

#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dev/wscons/wsksymdef.h>
#include <dev/wscons/wsconsio.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>

#include "wsconsctl.h"

static int kbtype;
static int keyclick;
static struct wskbd_bell_data bell;
static struct wskbd_bell_data dfbell;
struct wsmux_device_list kbdevs;
static int *kbfd;
static struct wscons_keymap *mapdata;
struct wskbd_map_data *kbmap; /* used in map_parse.y and in util.c */
struct wskbd_map_data *kbmaps;
static struct wskbd_keyrepeat_data repeat;
static struct wskbd_keyrepeat_data dfrepeat;
static struct wskbd_scroll_data scroll;
static int ledstate;
static kbd_t kbdencoding;
static int havescroll = 1;

struct field keyboard_field_tab[] = {
    { "type",			&kbtype,	FMT_KBDTYPE,	FLG_RDONLY },
    { "bell.pitch",		&bell.pitch,	FMT_UINT,	FLG_MODIFY },
    { "bell.period",		&bell.period,	FMT_UINT,	FLG_MODIFY },
    { "bell.volume",		&bell.volume,	FMT_UINT,	FLG_MODIFY },
    { "bell.pitch.default",	&dfbell.pitch,	FMT_UINT,	FLG_MODIFY },
    { "bell.period.default",	&dfbell.period,	FMT_UINT,	FLG_MODIFY },
    { "bell.volume.default",	&dfbell.volume,	FMT_UINT,	FLG_MODIFY },
    { "map",			&kbmap,		FMT_KBMAP,	FLG_MODIFY |
    								FLG_NOAUTO },
    { "repeat.del1",		&repeat.del1,	FMT_UINT,	FLG_MODIFY },
    { "repeat.deln",		&repeat.delN,	FMT_UINT,	FLG_MODIFY },
    { "repeat.del1.default",	&dfrepeat.del1,	FMT_UINT,	FLG_MODIFY },
    { "repeat.deln.default",	&dfrepeat.delN,	FMT_UINT,	FLG_MODIFY },
    { "ledstate",		&ledstate,	FMT_UINT,	0 },
    { "encoding",		&kbdencoding,	FMT_KBDENC,	FLG_MODIFY },
    { "keyclick",		&keyclick,	FMT_UINT,	FLG_MODIFY },
    { "scroll.mode",		&scroll.mode,	FMT_UINT,	FLG_MODIFY },
    { "scroll.modifier",	&scroll.modifier, FMT_UINT,	FLG_MODIFY },
};

int keyboard_field_tab_len = sizeof(keyboard_field_tab) /
	sizeof(keyboard_field_tab[0]);

void
keyboard_get_values(int fd)
{
	char file[PATH_MAX];
	int i;

	if (field_by_value(&kbtype)->flags & FLG_GET)
		if (ioctl(fd, WSKBDIO_GTYPE, &kbtype) < 0)
			err(EXIT_FAILURE, "WSKBDIO_GTYPE");

	bell.which = 0;
	if (field_by_value(&bell.pitch)->flags & FLG_GET)
		bell.which |= WSKBD_BELL_DOPITCH;
	if (field_by_value(&bell.period)->flags & FLG_GET)
		bell.which |= WSKBD_BELL_DOPERIOD;
	if (field_by_value(&bell.volume)->flags & FLG_GET)
		bell.which |= WSKBD_BELL_DOVOLUME;
	if (bell.which != 0 && ioctl(fd, WSKBDIO_GETBELL, &bell) < 0)
		err(EXIT_FAILURE, "WSKBDIO_GETBELL");

	dfbell.which = 0;
	if (field_by_value(&dfbell.pitch)->flags & FLG_GET)
		dfbell.which |= WSKBD_BELL_DOPITCH;
	if (field_by_value(&dfbell.period)->flags & FLG_GET)
		dfbell.which |= WSKBD_BELL_DOPERIOD;
	if (field_by_value(&dfbell.volume)->flags & FLG_GET)
		dfbell.which |= WSKBD_BELL_DOVOLUME;
	if (dfbell.which != 0 &&
	    ioctl(fd, WSKBDIO_GETDEFAULTBELL, &dfbell) < 0)
		err(EXIT_FAILURE, "WSKBDIO_GETDEFAULTBELL");

	if (field_by_value(&kbmap)->flags & FLG_GET) {
		if (ioctl(fd, WSMUXIO_LIST_DEVICES, &kbdevs) < 0) {
			/* wskbd device */
			kbdevs.ndevices = 1;
			kbdevs.devices[0].type = WSMUX_KBD;
			kbdevs.devices[0].idx = -1;	/* XXX */

			kbfd = malloc(sizeof(*kbfd));
			if (kbfd == NULL)
				err(EXIT_FAILURE,
				    "keyboard descriptor allocation failed");
			kbfd[0] = fd;
			kbmaps = malloc(sizeof(*kbmaps));
			if (kbmaps == NULL)
				err(EXIT_FAILURE,
				    "keyboard map allocation failed");
			mapdata = malloc(sizeof(*mapdata) * KS_NUMKEYCODES);
			if (mapdata == NULL)
				err(EXIT_FAILURE,
				    "keyboard map data allocation failed");
			kbmaps[0].maplen = KS_NUMKEYCODES;
			kbmaps[0].map = &mapdata[0 * KS_NUMKEYCODES];
			if (ioctl(kbfd[0], WSKBDIO_GETMAP, &kbmaps[0]) < 0)
				err(EXIT_FAILURE, "WSKBDIO_GETMAP");
		} else {
			/* wsmux device */
			if (kbdevs.ndevices < 1)
				err(EXIT_FAILURE, "No mux devices");
			for (i = 0; i < kbdevs.ndevices; i++) {
				if (kbdevs.devices[i].type != WSMUX_KBD)
					err(EXIT_FAILURE, "Not keyboard device");
			}

			kbfd = malloc(sizeof(*kbfd) * kbdevs.ndevices);
			if (kbfd == NULL)
				err(EXIT_FAILURE,
				    "keyboard descriptor allocation failed");
			kbmaps = malloc(sizeof(*kbmaps) * kbdevs.ndevices);
			if (kbmaps == NULL)
				err(EXIT_FAILURE,
				    "keyboard map allocation failed");
			mapdata = malloc(sizeof(*mapdata) * KS_NUMKEYCODES
			    * kbdevs.ndevices);
			if (mapdata == NULL)
				err(EXIT_FAILURE,
				    "keyboard map data allocation failed");
			for (i = 0; i < kbdevs.ndevices; i++) {
				snprintf(file, sizeof(file), "/dev/wskbd%d",
				    kbdevs.devices[i].idx);
				kbfd[i] = open(file, O_WRONLY);
				if (kbfd[i] < 0)
					kbfd[i] = open(file, O_RDONLY);
				if (kbfd[i] < 0)
					err(EXIT_FAILURE, "%s", file);
				kbmaps[i].maplen = KS_NUMKEYCODES;
				kbmaps[i].map = &mapdata[i * KS_NUMKEYCODES];
				if (ioctl(kbfd[i], WSKBDIO_GETMAP, &kbmaps[i]) < 0)
					err(EXIT_FAILURE, "WSKBDIO_GETMAP");
			}
		}
		kbmap = &kbmaps[0];
	}

	repeat.which = 0;
	if (field_by_value(&repeat.del1)->flags & FLG_GET)
		repeat.which |= WSKBD_KEYREPEAT_DODEL1;
	if (field_by_value(&repeat.delN)->flags & FLG_GET)
		repeat.which |= WSKBD_KEYREPEAT_DODELN;
	if (repeat.which != 0 &&
	    ioctl(fd, WSKBDIO_GETKEYREPEAT, &repeat) < 0)
		err(EXIT_FAILURE, "WSKBDIO_GETKEYREPEAT");

	dfrepeat.which = 0;
	if (field_by_value(&dfrepeat.del1)->flags & FLG_GET)
		dfrepeat.which |= WSKBD_KEYREPEAT_DODEL1;
	if (field_by_value(&dfrepeat.delN)->flags & FLG_GET)
		dfrepeat.which |= WSKBD_KEYREPEAT_DODELN;
	if (dfrepeat.which != 0 &&
	    ioctl(fd, WSKBDIO_GETKEYREPEAT, &dfrepeat) < 0)
		err(EXIT_FAILURE, "WSKBDIO_GETKEYREPEAT");

	if (field_by_value(&ledstate)->flags & FLG_GET)
		if (ioctl(fd, WSKBDIO_GETLEDS, &ledstate) < 0)
			err(EXIT_FAILURE, "WSKBDIO_GETLEDS");

	if (field_by_value(&kbdencoding)->flags & FLG_GET)
		if (ioctl(fd, WSKBDIO_GETENCODING, &kbdencoding) < 0)
			err(EXIT_FAILURE, "WSKBDIO_GETENCODING");

	if (field_by_value(&keyclick)->flags & FLG_GET) {
		ioctl(fd, WSKBDIO_GETKEYCLICK, &keyclick);
		/* Optional; don't complain. */
	}
	
	scroll.which = 0;
	if (field_by_value(&scroll.mode)->flags & FLG_GET)
		scroll.which |= WSKBD_SCROLL_DOMODE;
	if (field_by_value(&scroll.modifier)->flags & FLG_GET)
		scroll.which |= WSKBD_SCROLL_DOMODIFIER;
	if (scroll.which != 0) {
		if (ioctl(fd, WSKBDIO_GETSCROLL, &scroll) == -1) {
			if (errno != ENODEV)
				err(EXIT_FAILURE, "WSKBDIO_GETSCROLL");
			else
				havescroll = 0;
		}
	}
}

void
keyboard_put_values(int fd)
{
	int i;

	bell.which = 0;
	if (field_by_value(&bell.pitch)->flags & FLG_SET)
		bell.which |= WSKBD_BELL_DOPITCH;
	if (field_by_value(&bell.period)->flags & FLG_SET)
		bell.which |= WSKBD_BELL_DOPERIOD;
	if (field_by_value(&bell.volume)->flags & FLG_SET)
		bell.which |= WSKBD_BELL_DOVOLUME;
	if (bell.which != 0 && ioctl(fd, WSKBDIO_SETBELL, &bell) < 0)
		err(EXIT_FAILURE, "WSKBDIO_SETBELL");
	if (bell.which & WSKBD_BELL_DOPITCH)
		pr_field(field_by_value(&bell.pitch), " -> ");
	if (bell.which & WSKBD_BELL_DOPERIOD)
		pr_field(field_by_value(&bell.period), " -> ");
	if (bell.which & WSKBD_BELL_DOVOLUME)
		pr_field(field_by_value(&bell.volume), " -> ");

	dfbell.which = 0;
	if (field_by_value(&dfbell.pitch)->flags & FLG_SET)
		dfbell.which |= WSKBD_BELL_DOPITCH;
	if (field_by_value(&dfbell.period)->flags & FLG_SET)
		dfbell.which |= WSKBD_BELL_DOPERIOD;
	if (field_by_value(&dfbell.volume)->flags & FLG_SET)
		dfbell.which |= WSKBD_BELL_DOVOLUME;
	if (dfbell.which != 0 &&
	    ioctl(fd, WSKBDIO_SETDEFAULTBELL, &dfbell) < 0)
		err(EXIT_FAILURE, "WSKBDIO_SETDEFAULTBELL");
	if (dfbell.which & WSKBD_BELL_DOPITCH)
		pr_field(field_by_value(&dfbell.pitch), " -> ");
	if (dfbell.which & WSKBD_BELL_DOPERIOD)
		pr_field(field_by_value(&dfbell.period), " -> ");
	if (dfbell.which & WSKBD_BELL_DOVOLUME)
		pr_field(field_by_value(&dfbell.volume), " -> ");

	if (field_by_value(&kbmap)->flags & FLG_SET) {
		for (i = 0; i < kbdevs.ndevices; i++) {
			if (ioctl(kbfd[i], WSKBDIO_SETMAP, &kbmaps[i]) < 0)
				err(EXIT_FAILURE, "WSKBDIO_SETMAP");
		}
		kbmap = &kbmaps[0];
		pr_field(field_by_value(&kbmap), " -> ");
	}

	repeat.which = 0;
	if (field_by_value(&repeat.del1)->flags & FLG_SET)
		repeat.which |= WSKBD_KEYREPEAT_DODEL1;
	if (field_by_value(&repeat.delN)->flags & FLG_SET)
		repeat.which |= WSKBD_KEYREPEAT_DODELN;
	if (repeat.which != 0 &&
	    ioctl(fd, WSKBDIO_SETKEYREPEAT, &repeat) < 0)
		err(EXIT_FAILURE, "WSKBDIO_SETKEYREPEAT");
	if (repeat.which & WSKBD_KEYREPEAT_DODEL1)
		pr_field(field_by_value(&repeat.del1), " -> ");
	if (repeat.which & WSKBD_KEYREPEAT_DODELN)
		pr_field(field_by_value(&repeat.delN), " -> ");

	dfrepeat.which = 0;
	if (field_by_value(&dfrepeat.del1)->flags & FLG_SET)
		dfrepeat.which |= WSKBD_KEYREPEAT_DODEL1;
	if (field_by_value(&dfrepeat.delN)->flags & FLG_SET)
		dfrepeat.which |= WSKBD_KEYREPEAT_DODELN;
	if (dfrepeat.which != 0 &&
	    ioctl(fd, WSKBDIO_SETDEFAULTKEYREPEAT, &dfrepeat) < 0)
		err(EXIT_FAILURE, "WSKBDIO_SETDEFAULTKEYREPEAT");
	if (dfrepeat.which &WSKBD_KEYREPEAT_DODEL1)
		pr_field(field_by_value(&dfrepeat.del1), " -> ");
	if (dfrepeat.which & WSKBD_KEYREPEAT_DODELN)
		pr_field(field_by_value(&dfrepeat.delN), " -> ");

	if (field_by_value(&ledstate)->flags & FLG_SET) {
		if (ioctl(fd, WSKBDIO_SETLEDS, &ledstate) < 0)
			err(EXIT_FAILURE, "WSKBDIO_SETLEDS");
		pr_field(field_by_value(&ledstate), " -> ");
	}

	if (field_by_value(&kbdencoding)->flags & FLG_SET) {
		if (ioctl(fd, WSKBDIO_SETENCODING, &kbdencoding) < 0)
			err(EXIT_FAILURE, "WSKBDIO_SETENCODING");
		pr_field(field_by_value(&kbdencoding), " -> ");
	}

	if (field_by_value(&keyclick)->flags & FLG_SET) {
		if (ioctl(fd, WSKBDIO_SETKEYCLICK, &keyclick) < 0)
			err(EXIT_FAILURE, "WSKBDIO_SETKEYCLICK");
		pr_field(field_by_value(&keyclick), " -> ");
	}


	if (havescroll == 0)
		return;

	scroll.which = 0;
	if (field_by_value(&scroll.mode)->flags & FLG_SET)
		scroll.which |= WSKBD_SCROLL_DOMODE;
	if (field_by_value(&scroll.modifier)->flags & FLG_SET)
		scroll.which |= WSKBD_SCROLL_DOMODIFIER;

	if (scroll.which & WSKBD_SCROLL_DOMODE)
		pr_field(field_by_value(&scroll.mode), " -> ");
	if (scroll.which & WSKBD_SCROLL_DOMODIFIER)
		pr_field(field_by_value(&scroll.modifier), " -> ");
	if (scroll.which != 0) {
		if (ioctl(fd, WSKBDIO_SETSCROLL, &scroll) == -1) {
			if (errno != ENODEV)
				err(EXIT_FAILURE, "WSKBDIO_SETSCROLL");
			else {
				warnx("scrolling is not supported by this "
				    "kernel");
				havescroll = 0;
			}
		}
	}
}

