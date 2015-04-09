/*	$NetBSD$	*/

/*
 * Copyright (c) 1983, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD$");
#endif /* not lint */

#include <sys/param.h> 
#include <sys/ioctl.h> 

#include <net/if.h> 
#include <net/if_media.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_netbsd.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <util.h>

#include "env.h"
#include "extern.h"
#include "util.h"

static status_func_t status;
static usage_func_t usage;
static cmdloop_branch_t branch;
static int wlan_mode;

static void wlan_constructor(void) __attribute__((constructor));
static void wlan_status(prop_dictionary_t, prop_dictionary_t);

static int setwlandev(prop_dictionary_t, prop_dictionary_t);
static int setwlanmode(prop_dictionary_t, prop_dictionary_t);

static struct piface wlandev = PIFACE_INITIALIZER(&wlandev, "wlandev",
    setwlandev, "wlandev", &command_root.pb_parser);

static struct pstr parse_wlanmode = PSTR_INITIALIZER(&parse_wlanmode,
    "wlanmode", setwlanmode, "wlanmode", &command_root.pb_parser);

static const struct kwinst wlankw[] = {
	  {.k_word = "wlanmode", .k_nextparser = &parse_wlanmode.ps_parser}
	, {.k_word = "wlandev", .k_nextparser = &wlandev.pif_parser}
};

struct pkw wlan = PKW_INITIALIZER(&wlan, "wlan", NULL, NULL,
    wlankw, __arraycount(wlankw), NULL);

static int
set80211(prop_dictionary_t env, uint16_t type, int16_t val, int16_t len,
    u_int8_t *data)
{
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	ireq.i_type = type;
	ireq.i_val = val;
	ireq.i_len = len;
	ireq.i_data = data;
	if (direct_ioctl(env, SIOCS80211, &ireq) == -1) {
		warn("SIOCS80211");
		return -1;
	}
	return 0;
}

static int
checkifname(prop_dictionary_t env)
{
	const char *ifname;
	size_t i, len;

	if ((ifname = getifname(env)) == NULL)
		return 1;

	len = strlen(ifname);
	if (len < 5)
		return 1;

	if (strncmp(ifname, "wlan", 4))
		return 1;

	for (i = 4; i < len; i++)
		if (!isdigit((unsigned char)ifname[i]))
			return 1;
	return 0;
}

static int
setwlandev(prop_dictionary_t env, prop_dictionary_t oenv)
{
	struct ieee80211_wlan_param_req param;
	const char *wlan_dev;

	if (checkifname(env))
		errx(EXIT_FAILURE, "valid only with wlan(4) interfaces");

	if (!prop_dictionary_get_cstring_nocopy(env, "wlandev", &wlan_dev)) {
		errno = ENOENT;
		return -1;
	}
	strlcpy(param.wp_name, wlan_dev, sizeof(param.wp_name));

	switch (wlan_mode) {
	case 0:
		param.wp_opmode = IEEE80211_M_STA;
		break;

	case IFM_IEEE80211_HOSTAP:
		param.wp_opmode = IEEE80211_M_HOSTAP;
		break;

	default:
		errx(EXIT_FAILURE, "unkown wlanmode (%x)", wlan_mode);
		break;
	}

	if (set80211(env, IEEE80211_IOC_WLAN_PARAM, 0, sizeof(param),
	    (void *)&param) == -1)
		err(EXIT_FAILURE, "IEEE80211_IOC_WLAN_PARAM");
	return 0;
}

static int
setwlanmode(prop_dictionary_t env, prop_dictionary_t oenv)
{
	char mode[8];
	char *invalid;

	if (checkifname(env))
		errx(EXIT_FAILURE, "valid only with wlan(4) interfaces");

	if (getargstr(env, "wlanmode", mode, sizeof(mode)) == -1)
		errx(EXIT_FAILURE, "%s: wlanmode too long", __func__);

	if (strcmp(mode, "sta") == 0)
		wlan_mode = 0;
	else {
		wlan_mode = get_media_options(IFM_IEEE80211, mode, &invalid);
		switch (wlan_mode) {
		case IFM_IEEE80211_HOSTAP:
			break;

		case IFM_IEEE80211_ADHOC:
		case IFM_IEEE80211_MONITOR:
		case IFM_IEEE80211_TURBO:
		case IFM_IEEE80211_IBSS:
		case IFM_IEEE80211_WDS:
		case IFM_IEEE80211_MBSS:
		default:
			errx(EXIT_FAILURE, "invalid value of wlanmode (%s)",
			    mode);
			break;
		}
	}

	return 0;
}

static const char *
wlan_get_opmode_name(int opmode)
{
	static const char *opmode_name[IEEE80211_OPMODE_MAX] = {
		"ibss",		/* IEEE80211_M_IBSS */
		"sta",		/* IEEE80211_M_STA */
		"wds",		/* IEEE80211_M_WDS */
		"ahdemo",	/* IEEE80211_M_AHDEMO */
		"hostap",	/* IEEE80211_M_HOSTAP */
		"monitor",	/* IEEE80211_M_MONITOR */
		"mbss"		/* IEEE80211_M_MBSS */
	};
	if ((size_t)opmode < __arraycount(opmode_name))
		return opmode_name[opmode];
	return "unknown";
}

static void
wlan_status(prop_dictionary_t env, prop_dictionary_t oenv)
{
	struct ieee80211req ireq;
	struct ieee80211_wlan_param_req wp;

	if (checkifname(env))
		return;

	memset(&ireq, 0, sizeof(ireq));
	ireq.i_type = IEEE80211_IOC_WLAN_PARAM;
	ireq.i_len = sizeof(wp);
	ireq.i_data = &wp;
	if (direct_ioctl(env, SIOCG80211, &ireq) == -1)
		;
	else
		printf("\twlandev %s, wlanmode %s\n", wp.wp_name,
		    wlan_get_opmode_name(wp.wp_opmode));
}

static void
wlan_usage(prop_dictionary_t env)
{
	fprintf(stderr, "\t[ [ wlanmode mode ] wlandev iface ]\n");
}

static void
wlan_constructor(void)
{
	cmdloop_branch_init(&branch, &wlan.pk_parser);
	register_cmdloop_branch(&branch);
	status_func_init(&status, wlan_status);
	usage_func_init(&usage, wlan_usage);
	register_status(&status);
	register_usage(&usage);
}
