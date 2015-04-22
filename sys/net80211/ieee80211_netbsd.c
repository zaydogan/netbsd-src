/* $NetBSD$ */
/*-
 * Copyright (c) 2003-2009 Sam Leffler, Errno Consulting
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifdef __FreeBSD__
__FBSDID("$FreeBSD: src/sys/net80211/ieee80211_freebsd.c,v 1.8 2005/08/08 18:46:35 sam Exp $");
#endif
#ifdef __NetBSD__
__KERNEL_RCSID(0, "$NetBSD$");
#endif

/*
 * IEEE 802.11 support (NetBSD-specific code)
 */
#include "opt_inet.h"
#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h> 
#include <sys/cprng.h>   
#include <sys/kauth.h>
#include <sys/mbuf.h>   
#include <sys/module.h>
#include <sys/once.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <net/bpf.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/route.h>
#ifdef notyet	/* XXX FBSD80211 vnet */
#include <net/vnet.h>
#endif

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_input.h>

static int wlan_root_num;
#ifdef IEEE80211_DEBUG
int	ieee80211_debug = 0;
#endif

SYSCTL_SETUP(sysctl_wlan, "sysctl wlan subtree setupdebugging printfs")
{
	const struct sysctlnode *rnode;

	if (sysctl_createv(clog, 0, NULL, NULL,
	    0, CTLTYPE_NODE, "hw",
	    NULL,
	    NULL, 0, NULL, 0,
	    CTL_HW, CTL_EOL) != 0)
		goto bad;

	if (sysctl_createv(clog, 0, NULL, &rnode,
	    0, CTLTYPE_NODE, "wlan",
	    SYSCTL_DESCR("wlan interface"),
	    NULL, 0, NULL, 0,
	    CTL_HW, CTL_CREATE, CTL_EOL) != 0)
		goto bad;
	wlan_root_num = rnode->sysctl_num;

#ifdef IEEE80211_DEBUG
	const struct sysctlnode *cnode;
	if (sysctl_createv(clog, 0, &rnode, &cnode,
	    CTLFLAG_READWRITE, CTLTYPE_INT, "debug",
	    SYSCTL_DESCR("debugging printfs"),
	    NULL, 0, &ieee80211_debug, 0,
	    CTL_CREATE, CTL_EOL) != 0)
		goto out;

 out:
#endif
	return;

 bad:
	aprint_error("could not attach wlan sysctl node\n");
}

static int	wlan_clone_create(struct if_clone *, int);
static int	wlan_clone_destroy(struct ifnet *);

static struct if_clone wlan_cloner =
    IF_CLONE_INITIALIZER("wlan", wlan_clone_create, wlan_clone_destroy);

/* list of all instances */
SLIST_HEAD(ieee80211_list, ieee80211com);
static struct ieee80211_list ieee80211_list =
	SLIST_HEAD_INITIALIZER(ieee80211_list);
static kmutex_t *ieee80211_list_lock;

static const uint8_t zerobssid[IEEE80211_ADDR_LEN];

static int
ieee80211_netbsd_init0(void)
{

	KASSERT(ieee80211_list_lock == NULL);
	ieee80211_list_lock = mutex_obj_alloc(MUTEX_DEFAULT, IPL_NET);

	if_clone_attach(&wlan_cloner);

	return 0;
}

void
ieee80211_netbsd_init(void)
{
	static ONCE_DECL(ieee80211_init_once);

	RUN_ONCE(&ieee80211_init_once, ieee80211_netbsd_init0);
	KASSERT(ieee80211_list_lock != NULL);
}

void
ieee80211_add_instance(struct ieee80211com *ic)
{

	KASSERT(ic->ic_next == NULL);
	mutex_enter(ieee80211_list_lock);
	SLIST_INSERT_HEAD(&ieee80211_list, ic, ic_next);
	mutex_exit(ieee80211_list_lock);
}

void
ieee80211_remove_instance(struct ieee80211com *ic)
{

	KASSERT(ic->ic_next != NULL);
	mutex_enter(ieee80211_list_lock);
	SLIST_REMOVE(&ieee80211_list, ic, ieee80211com, ic_next);
	mutex_exit(ieee80211_list_lock);
}

struct ieee80211com *
ieee80211_find_instance(struct ifnet *ifp)
{
	struct ieee80211com *ic;

	/* XXX not right for multiple instances but works for now */
	mutex_enter(ieee80211_list_lock);
	SLIST_FOREACH(ic, &ieee80211_list, ic_next)
		if (ic->ic_ifp == ifp)
			break;
	mutex_exit(ieee80211_list_lock);
	return ic;
}

static int
wlan_ioctl_set_wlan_param(struct ifnet *ifp,
    struct ieee80211_wlan_param_req *wp)
{
	struct ifnet *parent;
	struct ieee80211com *ic;
	struct ieee80211vap *vap;

	parent = ifunit(wp->wp_name);
	if (parent == NULL)
		return ENXIO;
	ic = ieee80211_find_instance(parent);
	if (ic == NULL)
		return ENXIO;
	if (wp->wp_opmode < IEEE80211_M_IBSS ||
	    wp->wp_opmode > IEEE80211_M_MBSS) {
		if_printf(ifp, "invalid opmode %d\n", wp->wp_opmode);
		return EINVAL;
	}
	if (!(ic->ic_caps & ieee80211_opcap[wp->wp_opmode])) {
		if_printf(ifp, "%s mode not supported\n",
		    ieee80211_opmode_name[wp->wp_opmode]);
		return EOPNOTSUPP;
	}

	vap = (*ic->ic_vap_create)(ic, ifp, wp->wp_opmode, 0, zerobssid,
	    CLLADDR(parent->if_sadl));
	if (vap == NULL)
		return EINVAL;
	return 0;
}

static int
wlan_ioctl(struct ifnet *ifp, u_long cmd, void *data)
{
	struct ieee80211req *req;
	int error;
	int s;

	s = splnet();

	switch (cmd) {
	case SIOCSIFFLAGS:
		error = ifioctl_common(ifp, cmd, data);
		break;

	case SIOCS80211:
		error = kauth_authorize_network(curlwp->l_cred,
		    KAUTH_NETWORK_INTERFACE,
		    KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ifp, (void *)cmd,
		    NULL);
		if (error != 0)
			break;
		req = (struct ieee80211req *)data;
		switch (req->i_type) {
		case IEEE80211_IOC_WLAN_PARAM:
			error = wlan_ioctl_set_wlan_param(ifp, req->i_data);
			break;

		default:
			error = ENOTTY;
			break;
		}
		break;

	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	splx(s);

	return error;
}

static int
wlan_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet *ifp;

	ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL)
		return ENOMEM;

	if_initname(ifp, ifc->ifc_name, unit);
	ifp->if_flags = IFF_SIMPLEX | IFF_BROADCAST | IFF_MULTICAST;
	ifp->if_mtu = IEEE80211_MTU_MAX;
	ifp->if_dlt = DLT_IEEE802;
	ifp->if_init = (void *)nullop;
	ifp->if_start = (void *)nullop;
	ifp->if_stop = (void *)nullop;
	ifp->if_output = (void *)nullop;
	ifp->if_ioctl = wlan_ioctl;

	if_attach(ifp);
	if_alloc_sadl(ifp);

	return 0;
}

static int
wlan_clone_destroy(struct ifnet *ifp)
{

	if_detach(ifp);

	if (ifp->if_softc != NULL) {
		/* XXX implement me! */
	}
	if_free(ifp);

	return 0;
}

void
ieee80211_vap_destroy(struct ieee80211vap *vap)
{

	if_clone_destroy(vap->iv_ifp->if_xname);
}

#ifdef notyet	/* XXX FBSD80211 sysctl */
int
ieee80211_sysctl_msecs_ticks(SYSCTL_HANDLER_ARGS)
{
	int msecs = ticks_to_msecs(*(int *)arg1);
	int error, t;

	error = sysctl_handle_int(oidp, &msecs, 0, req);
	if (error || !req->newptr)
		return error;
	t = msecs_to_ticks(msecs);
	*(int *)arg1 = (t < 1) ? 1 : t;
	return 0;
}

static int
ieee80211_sysctl_inact(SYSCTL_HANDLER_ARGS)
{
	int inact = (*(int *)arg1) * IEEE80211_INACT_WAIT;
	int error;

	error = sysctl_handle_int(oidp, &inact, 0, req);
	if (error || !req->newptr)
		return error;
	*(int *)arg1 = inact / IEEE80211_INACT_WAIT;
	return 0;
}

static int
ieee80211_sysctl_parent(SYSCTL_HANDLER_ARGS)
{
	struct ieee80211com *ic = arg1;
	const char *name = ic->ic_ifp->if_xname;

	return SYSCTL_OUT(req, name, strlen(name));
}

static int
ieee80211_sysctl_radar(SYSCTL_HANDLER_ARGS)
{
	struct ieee80211com *ic = arg1;
	int t = 0, error;

	error = sysctl_handle_int(oidp, &t, 0, req);
	if (error || !req->newptr)
		return error;
	IEEE80211_LOCK(ic);
	ieee80211_dfs_notify_radar(ic, ic->ic_curchan);
	IEEE80211_UNLOCK(ic);
	return 0;
}
#endif

void
ieee80211_sysctl_attach(struct ieee80211com *ic)
{
}

void
ieee80211_sysctl_detach(struct ieee80211com *ic)
{
}

void
ieee80211_sysctl_vattach(struct ieee80211vap *vap)
{
	struct ifnet *ifp = vap->iv_ifp;
	const struct sysctlnode *rnode;

	if (sysctl_createv(&vap->iv_clog, 0, NULL, &rnode,
	    0, CTLTYPE_NODE, ifp->if_xname,
	    SYSCTL_DESCR("wlan interface"),
	    NULL, 0, NULL, 0,
	    CTL_HW, wlan_root_num, CTL_CREATE, CTL_EOL) != 0)
		goto bad;

#ifdef notyet	/* XXX FBSD80211 sysctl */
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"%parent", CTLTYPE_STRING | CTLFLAG_RD, vap->iv_ic, 0,
		ieee80211_sysctl_parent, "A", "parent device");
	SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"driver_caps", CTLFLAG_RW, &vap->iv_caps, 0,
		"driver capabilities");
#endif
#ifdef IEEE80211_DEBUG
	const struct sysctlnode *cnode;
	vap->iv_debug = ieee80211_debug;
	if (sysctl_createv(&vap->iv_clog, 0, &rnode, &cnode,
	    CTLFLAG_READWRITE, CTLTYPE_INT, "debug",
	    SYSCTL_DESCR("control debugging printfs"),
	    NULL, 0, &vap->iv_debug, 0,
	    CTL_CREATE, CTL_EOL) != 0)
		goto out;
#endif
#ifdef notyet	/* XXX FBSD80211 sysctl */
	SYSCTL_ADD_INT(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"bmiss_max", CTLFLAG_RW, &vap->iv_bmiss_max, 0,
		"consecutive beacon misses before scanning");
	/* XXX inherit from tunables */
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"inact_run", CTLTYPE_INT | CTLFLAG_RW, &vap->iv_inact_run, 0,
		ieee80211_sysctl_inact, "I",
		"station inactivity timeout (sec)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"inact_probe", CTLTYPE_INT | CTLFLAG_RW, &vap->iv_inact_probe, 0,
		ieee80211_sysctl_inact, "I",
		"station inactivity probe timeout (sec)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"inact_auth", CTLTYPE_INT | CTLFLAG_RW, &vap->iv_inact_auth, 0,
		ieee80211_sysctl_inact, "I",
		"station authentication timeout (sec)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
		"inact_init", CTLTYPE_INT | CTLFLAG_RW, &vap->iv_inact_init, 0,
		ieee80211_sysctl_inact, "I",
		"station initial state timeout (sec)");
	if (vap->iv_htcaps & IEEE80211_HTC_HT) {
		SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
			"ampdu_mintraffic_bk", CTLFLAG_RW,
			&vap->iv_ampdu_mintraffic[WME_AC_BK], 0,
			"BK traffic tx aggr threshold (pps)");
		SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
			"ampdu_mintraffic_be", CTLFLAG_RW,
			&vap->iv_ampdu_mintraffic[WME_AC_BE], 0,
			"BE traffic tx aggr threshold (pps)");
		SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
			"ampdu_mintraffic_vo", CTLFLAG_RW,
			&vap->iv_ampdu_mintraffic[WME_AC_VO], 0,
			"VO traffic tx aggr threshold (pps)");
		SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
			"ampdu_mintraffic_vi", CTLFLAG_RW,
			&vap->iv_ampdu_mintraffic[WME_AC_VI], 0,
			"VI traffic tx aggr threshold (pps)");
	}
	if (vap->iv_caps & IEEE80211_C_DFS) {
		SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
			"radar", CTLTYPE_INT | CTLFLAG_RW, vap->iv_ic, 0,
			ieee80211_sysctl_radar, "I", "simulate radar event");
	}
#endif
#ifdef IEEE80211_DEBUG
 out:
#endif
	return;

 bad:
	if_printf(ifp, "could not attach %s sysctl node\n", ifp->if_xname);
}

void
ieee80211_sysctl_vdetach(struct ieee80211vap *vap)
{

	if (vap->iv_clog != NULL)
		sysctl_teardown(&vap->iv_clog);
}

int
ieee80211_node_dectestref(struct ieee80211_node *ni)
{
	/* XXX need equivalent of atomic_dec_and_test */
	atomic_add_int(&ni->ni_refcnt, -1);
	return atomic_cas_32(&ni->ni_refcnt, 0, 1) == 1;
}

void
ieee80211_drain_ifq(struct ifqueue *ifq)
{
	struct ieee80211_node *ni;
	struct mbuf *m;

	for (;;) {
		IF_DEQUEUE(ifq, m);
		if (m == NULL)
			break;

		ni = (struct ieee80211_node *)m->m_pkthdr.rcvif;
		IASSERT(ni != NULL, ("frame w/o node"));
		ieee80211_free_node(ni);
		m->m_pkthdr.rcvif = NULL;

		m_freem(m);
	}
}

void
ieee80211_flush_ifq(struct ifqueue *ifq, struct ieee80211vap *vap)
{
	struct ieee80211_node *ni;
	struct mbuf *m, **mprev;

	IFQ_LOCK(ifq);	/* XXX FBSD80211 ifqueue */
	mprev = &ifq->ifq_head;
	while ((m = *mprev) != NULL) {
		ni = (struct ieee80211_node *)m->m_pkthdr.rcvif;
		if (ni != NULL && ni->ni_vap == vap) {
			*mprev = m->m_nextpkt;		/* remove from list */
			ifq->ifq_len--;

			m_freem(m);
			ieee80211_free_node(ni);	/* reclaim ref */
		} else
			mprev = &m->m_nextpkt;
	}
	/* recalculate tail ptr */
	m = ifq->ifq_head;
	for (; m != NULL && m->m_nextpkt != NULL; m = m->m_nextpkt)
		;
	ifq->ifq_tail = m;
	IFQ_UNLOCK(ifq);	/* XXX FBSD80211 ifqueue */
}

void
if_printf(struct ifnet *ifp, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	printf("%s: ", ifp->if_xname);
	vprintf(fmt, ap);

	va_end(ap);
	return;
}

/*
 * As above, for mbufs allocated with m_gethdr/MGETHDR
 * or initialized by M_COPY_PKTHDR.
 */
#define	MC_ALIGN(m, len)						\
do {									\
	(m)->m_data += (MCLBYTES - (len)) &~ (sizeof(long) - 1);	\
} while (/* CONSTCOND */ 0)

/*
 * Allocate and setup a management frame of the specified
 * size.  We return the mbuf and a pointer to the start
 * of the contiguous data area that's been reserved based
 * on the packet length.  The data area is forced to 32-bit
 * alignment and the buffer length to a multiple of 4 bytes.
 * This is done mainly so beacon frames (that require this)
 * can use this interface too.
 */
struct mbuf *
ieee80211_getmgtframe(uint8_t **frm, int headroom, int pktlen)
{
	struct mbuf *m;
	u_int len;

	/*
	 * NB: we know the mbuf routines will align the data area
	 *     so we don't need to do anything special.
	 */
	len = roundup2(headroom + pktlen, 4);
	IASSERT(len <= MCLBYTES, ("802.11 mgt frame too large: %u", len));
	if (len < MINCLSIZE) {
		m = m_gethdr(M_NOWAIT, MT_DATA);
		/*
		 * Align the data in case additional headers are added.
		 * This should only happen when a WEP header is added
		 * which only happens for shared key authentication mgt
		 * frames which all fit in MHLEN.
		 */
		if (m != NULL)
			MH_ALIGN(m, len);
	} else {
		m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
		if (m != NULL)
			MC_ALIGN(m, len);
	}
	if (m != NULL) {
		m->m_data += headroom;
		*frm = m->m_data;
	}
	return m;
}

#ifndef __NO_STRICT_ALIGNMENT
/*
 * Re-align the payload in the mbuf.  This is mainly used (right now)
 * to handle IP header alignment requirements on certain architectures.
 */
struct mbuf *
ieee80211_realign(struct ieee80211vap *vap, struct mbuf *m, size_t align)
{
	int pktlen, space;
	struct mbuf *n;

	pktlen = m->m_pkthdr.len;
	space = pktlen + align;
	if (space < MINCLSIZE)
		n = m_gethdr(M_NOWAIT, MT_DATA);
	else {
		n = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
		    space <= MCLBYTES ?     MCLBYTES :
#if MJUMPAGESIZE != MCLBYTES
		    space <= MJUMPAGESIZE ? MJUMPAGESIZE :
#endif
		    space <= MJUM9BYTES ?   MJUM9BYTES : MJUM16BYTES);
	}
	if (__predict_true(n != NULL)) {
		m_move_pkthdr(n, m);
		n->m_data = (char *)(ALIGN(n->m_data + align) - align);
		m_copydata(m, 0, pktlen, mtod(n, char *));
		n->m_len = pktlen;
	} else {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ANY,
		    mtod(m, const struct ieee80211_frame *), NULL,
		    "%s", "no mbuf to realign");
		vap->iv_stats.is_rx_badalign++;
	}
	m_freem(m);
	return n;
}
#endif /* !__NO_STRICT_ALIGNMENT */

int
ieee80211_add_callback(struct mbuf *m,
	void (*func)(struct ieee80211_node *, void *, int), void *arg)
{
	struct m_tag *mtag;
	struct ieee80211_cb *cb;

	mtag = m_tag_get(NET80211_TAG_CALLBACK,
			sizeof(struct ieee80211_cb), M_NOWAIT);
	if (mtag == NULL)
		return 0;

	cb = (struct ieee80211_cb *)(mtag+1);
	cb->func = func;
	cb->arg = arg;
	m_tag_prepend(m, mtag);
	M_SET_FLAGS(m, M_TXCB);
	return 1;
}

void
ieee80211_process_callback(struct ieee80211_node *ni,
	struct mbuf *m, int status)
{
	struct m_tag *mtag;

	mtag = m_tag_find(m, NET80211_TAG_CALLBACK, NULL);
	if (mtag != NULL) {
		struct ieee80211_cb *cb = (struct ieee80211_cb *)(mtag+1);
		cb->func(ni, cb->arg, status);
	}
}

static int
xmitpkt(struct ifnet *ifp, struct mbuf *m)
{
	ALTQ_DECL(struct altq_pktattr pktattr;)
	int error;

#ifdef ALTQ
	if (ALTQ_IS_ENABLED(&ifp->if_snd)) {
		altq_etherclassify(&ifp->if_snd, m,
		    &pktattr);
	}
#endif
	IFQ_ENQUEUE(&ifp->if_snd, m, &pktattr, error);
	return error;
}

/*
 * Transmit a frame to the parent interface.
 *
 * TODO: if the transmission fails, make sure the parent node is freed
 *   (the callers will first need modifying.)
 */
int
ieee80211_parent_xmitpkt(struct ieee80211com *ic,
	struct mbuf *m)
{
	struct ifnet *parent = ic->ic_ifp;

	/*
	 * Assert the IC TX lock is held - this enforces the
	 * processing -> queuing order is maintained
	 */
	IEEE80211_TX_LOCK_ASSERT(ic);

	return xmitpkt(parent, m);
}

/*
 * Transmit a frame to the VAP interface.
 */
int
ieee80211_vap_xmitpkt(struct ieee80211vap *vap, struct mbuf *m)
{
	struct ifnet *ifp = vap->iv_ifp;

	/*
	 * When transmitting via the VAP, we shouldn't hold
	 * any IC TX lock as the VAP TX path will acquire it.
	 */
	IEEE80211_TX_UNLOCK_ASSERT(vap->iv_ic);

	return xmitpkt(ifp, m);
}

void
get_random_bytes(void *p, size_t n)
{
	uint8_t *dp = p;

	while (n > 0) {
		uint32_t v = cprng_fast32();
		size_t nb = n > sizeof(uint32_t) ? sizeof(uint32_t) : n;
		bcopy(&v, dp, n > sizeof(uint32_t) ? sizeof(uint32_t) : n);
		dp += sizeof(uint32_t), n -= nb;
	}
}

/*
 * Helper function for events that pass just a single mac address.
 */
static void
notify_macaddr(struct ifnet *ifp, int op, const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ieee80211_join_event iev;

#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET(ifp->if_vnet);
#endif
	memset(&iev, 0, sizeof(iev));
	IEEE80211_ADDR_COPY(iev.iev_addr, mac);
	rt_ieee80211msg(ifp, op, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_node_join(struct ieee80211_node *ni, int newassoc)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET_QUIET(ifp->if_vnet);
#endif
	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%snode join",
	    (ni == vap->iv_bss) ? "bss " : "");

	if (ni == vap->iv_bss) {
		notify_macaddr(ifp, newassoc ?
		    RTM_IEEE80211_ASSOC : RTM_IEEE80211_REASSOC, ni->ni_bssid);
		if_link_state_change(ifp, LINK_STATE_UP);
	} else {
		notify_macaddr(ifp, newassoc ?
		    RTM_IEEE80211_JOIN : RTM_IEEE80211_REJOIN, ni->ni_macaddr);
	}
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_node_leave(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET_QUIET(ifp->if_vnet);
#endif
	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%snode leave",
	    (ni == vap->iv_bss) ? "bss " : "");

	if (ni == vap->iv_bss) {
		rt_ieee80211msg(ifp, RTM_IEEE80211_DISASSOC, NULL, 0);
		if_link_state_change(ifp, LINK_STATE_DOWN);
	} else {
		/* fire off wireless event station leaving */
		notify_macaddr(ifp, RTM_IEEE80211_LEAVE, ni->ni_macaddr);
	}
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_scan_done(struct ieee80211vap *vap)
{
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s\n", "notify scan done");

	/* dispatch wireless event indicating scan completed */
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET(ifp->if_vnet);
#endif
	rt_ieee80211msg(ifp, RTM_IEEE80211_SCAN, NULL, 0);
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_replay_failure(struct ieee80211vap *vap,
	const struct ieee80211_frame *wh, const struct ieee80211_key *k,
	u_int64_t rsc, int tid)
{
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_CRYPTO, wh->i_addr2,
	    "%s replay detected tid %d <rsc %ju, csc %ju, keyix %u rxkeyix %u>",
	    k->wk_cipher->ic_name, tid, (intmax_t) rsc,
	    (intmax_t) k->wk_keyrsc[tid],
	    k->wk_keyix, k->wk_rxkeyix);

	if (ifp != NULL) {		/* NB: for cipher test modules */
		struct ieee80211_replay_event iev;

		IEEE80211_ADDR_COPY(iev.iev_dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(iev.iev_src, wh->i_addr2);
		iev.iev_cipher = k->wk_cipher->ic_cipher;
		if (k->wk_rxkeyix != IEEE80211_KEYIX_NONE)
			iev.iev_keyix = k->wk_rxkeyix;
		else
			iev.iev_keyix = k->wk_keyix;
		iev.iev_keyrsc = k->wk_keyrsc[tid];
		iev.iev_rsc = rsc;
#ifdef notyet	/* XXX FBSD80211 vnet */
		CURVNET_SET(ifp->if_vnet);
#endif
		rt_ieee80211msg(ifp, RTM_IEEE80211_REPLAY, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
		CURVNET_RESTORE();
#endif
	}
}

void
ieee80211_notify_michael_failure(struct ieee80211vap *vap,
	const struct ieee80211_frame *wh, u_int keyix)
{
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_CRYPTO, wh->i_addr2,
	    "michael MIC verification failed <keyix %u>", keyix);
	vap->iv_stats.is_rx_tkipmic++;

	if (ifp != NULL) {		/* NB: for cipher test modules */
		struct ieee80211_michael_event iev;

		IEEE80211_ADDR_COPY(iev.iev_dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(iev.iev_src, wh->i_addr2);
		iev.iev_cipher = IEEE80211_CIPHER_TKIP;
		iev.iev_keyix = keyix;
#ifdef notyet	/* XXX FBSD80211 vnet */
		CURVNET_SET(ifp->if_vnet);
#endif
		rt_ieee80211msg(ifp, RTM_IEEE80211_MICHAEL, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
		CURVNET_RESTORE();
#endif
	}
}

void
ieee80211_notify_wds_discover(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	notify_macaddr(ifp, RTM_IEEE80211_WDS, ni->ni_macaddr);
}

void
ieee80211_notify_csa(struct ieee80211com *ic,
	const struct ieee80211_channel *c, int mode, int count)
{
	struct ifnet *ifp = ic->ic_ifp;
	struct ieee80211_csa_event iev;

	memset(&iev, 0, sizeof(iev));
	iev.iev_flags = c->ic_flags;
	iev.iev_freq = c->ic_freq;
	iev.iev_ieee = c->ic_ieee;
	iev.iev_mode = mode;
	iev.iev_count = count;
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET(ifp->if_vnet);
#endif
	rt_ieee80211msg(ifp, RTM_IEEE80211_CSA, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_radar(struct ieee80211com *ic,
	const struct ieee80211_channel *c)
{
	struct ifnet *ifp = ic->ic_ifp;
	struct ieee80211_radar_event iev;

	memset(&iev, 0, sizeof(iev));
	iev.iev_flags = c->ic_flags;
	iev.iev_freq = c->ic_freq;
	iev.iev_ieee = c->ic_ieee;
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET(ifp->if_vnet);
#endif
	rt_ieee80211msg(ifp, RTM_IEEE80211_RADAR, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_cac(struct ieee80211com *ic,
	const struct ieee80211_channel *c, enum ieee80211_notify_cac_event type)
{
	struct ifnet *ifp = ic->ic_ifp;
	struct ieee80211_cac_event iev;

	memset(&iev, 0, sizeof(iev));
	iev.iev_flags = c->ic_flags;
	iev.iev_freq = c->ic_freq;
	iev.iev_ieee = c->ic_ieee;
	iev.iev_type = type;
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET(ifp->if_vnet);
#endif
	rt_ieee80211msg(ifp, RTM_IEEE80211_CAC, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_node_deauth(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%s", "node deauth");

	notify_macaddr(ifp, RTM_IEEE80211_DEAUTH, ni->ni_macaddr);
}

void
ieee80211_notify_node_auth(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%s", "node auth");

	notify_macaddr(ifp, RTM_IEEE80211_AUTH, ni->ni_macaddr);
}

void
ieee80211_notify_country(struct ieee80211vap *vap,
	const uint8_t bssid[IEEE80211_ADDR_LEN], const uint8_t cc[2])
{
	struct ifnet *ifp = vap->iv_ifp;
	struct ieee80211_country_event iev;

	memset(&iev, 0, sizeof(iev));
	IEEE80211_ADDR_COPY(iev.iev_addr, bssid);
	iev.iev_cc[0] = cc[0];
	iev.iev_cc[1] = cc[1];
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET(ifp->if_vnet);
#endif
	rt_ieee80211msg(ifp, RTM_IEEE80211_COUNTRY, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_notify_radio(struct ieee80211com *ic, int state)
{
	struct ifnet *ifp = ic->ic_ifp;
	struct ieee80211_radio_event iev;

	memset(&iev, 0, sizeof(iev));
	iev.iev_state = state;
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_SET(ifp->if_vnet);
#endif
	rt_ieee80211msg(ifp, RTM_IEEE80211_RADIO, &iev, sizeof(iev));
#ifdef notyet	/* XXX FBSD80211 vnet */
	CURVNET_RESTORE();
#endif
}

void
ieee80211_load_module(const char *modname)
{

	if (module_autoload(modname, MODULE_CLASS_MISC))
		aprint_error("load the %s module by hand for now.\n", modname);
}

#ifdef notyet	/* XXX FBSD80211 module */
static eventhandler_tag wlan_bpfevent;
static eventhandler_tag wlan_ifllevent;

static void
bpf_track(void *arg, struct ifnet *ifp, int dlt, int attach)
{
	/* NB: identify vap's by if_init */
	if (dlt == DLT_IEEE802_11_RADIO &&
	    ifp->if_init == ieee80211_init) {
		struct ieee80211vap *vap = ifp->if_softc;
		/*
		 * Track bpf radiotap listener state.  We mark the vap
		 * to indicate if any listener is present and the com
		 * to indicate if any listener exists on any associated
		 * vap.  This flag is used by drivers to prepare radiotap
		 * state only when needed.
		 */
		if (attach) {
			ieee80211_syncflag_ext(vap, IEEE80211_FEXT_BPF);
			if (vap->iv_opmode == IEEE80211_M_MONITOR)
				atomic_add_int(&vap->iv_ic->ic_montaps, 1);
		} else if (!bpf_peers_present(vap->iv_rawbpf)) {
			ieee80211_syncflag_ext(vap, -IEEE80211_FEXT_BPF);
			if (vap->iv_opmode == IEEE80211_M_MONITOR)
				atomic_subtract_int(&vap->iv_ic->ic_montaps, 1);
		}
	}
}

static void
wlan_iflladdr(void *arg __unused, struct ifnet *ifp)
{
	struct ieee80211com *ic = ifp->if_l2com;
	struct ieee80211vap *vap, *next;

	if (ifp->if_type != IFT_IEEE80211 || ic == NULL)
		return;

	IEEE80211_LOCK(ic);
	TAILQ_FOREACH_SAFE(vap, &ic->ic_vaps, iv_next, next) {
		/*
		 * If the MAC address has changed on the parent and it was
		 * copied to the vap on creation then re-sync.
		 */
		if (vap->iv_ic == ic &&
		    (vap->iv_flags_ext & IEEE80211_FEXT_UNIQMAC) == 0) {
			IEEE80211_ADDR_COPY(vap->iv_myaddr, IF_LLADDR(ifp));
			IEEE80211_UNLOCK(ic);
			if_setlladdr(vap->iv_ifp, IF_LLADDR(ifp),
			    IEEE80211_ADDR_LEN);
			IEEE80211_LOCK(ic);
		}
	}
	IEEE80211_UNLOCK(ic);
}

/*
 * Module glue.
 *
 * NB: the module name is "wlan" for compatibility with NetBSD.
 */
static int
wlan_modevent(module_t mod, int type, void *unused)
{
	switch (type) {
	case MOD_LOAD:
		if (bootverbose)
			printf("wlan: <802.11 Link Layer>\n");
		wlan_bpfevent = EVENTHANDLER_REGISTER(bpf_track,
		    bpf_track, 0, EVENTHANDLER_PRI_ANY);
		if (wlan_bpfevent == NULL)
			return ENOMEM;
		wlan_ifllevent = EVENTHANDLER_REGISTER(iflladdr_event,
		    wlan_iflladdr, NULL, EVENTHANDLER_PRI_ANY);
		if (wlan_ifllevent == NULL) {
			EVENTHANDLER_DEREGISTER(bpf_track, wlan_bpfevent);
			return ENOMEM;
		}
		wlan_cloner = if_clone_simple(wlanname, wlan_clone_create,
		    wlan_clone_destroy, 0);
		if_register_com_alloc(IFT_IEEE80211, wlan_alloc, wlan_free);
		return 0;
	case MOD_UNLOAD:
		if_deregister_com_alloc(IFT_IEEE80211);
		if_clone_detach(wlan_cloner);
		EVENTHANDLER_DEREGISTER(bpf_track, wlan_bpfevent);
		EVENTHANDLER_DEREGISTER(iflladdr_event, wlan_ifllevent);
		return 0;
	}
	return EINVAL;
}

static moduledata_t wlan_mod = {
	wlanname,
	wlan_modevent,
	0
};
DECLARE_MODULE(wlan, wlan_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(wlan, 1);
MODULE_DEPEND(wlan, ether, 1, 1, 1);
#ifdef	IEEE80211_ALQ
MODULE_DEPEND(wlan, alq, 1, 1, 1);
#endif	/* IEEE80211_ALQ */
#endif	/* XXX FBSD80211 module */
