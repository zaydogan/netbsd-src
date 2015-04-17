/*	$NetBSD$	*/

/*-
 * Copyright (c) 2000 Doug Rabson
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

#ifndef _NET80211_IEEE80211_TASK_H_
#define _NET80211_IEEE80211_TASK_H_

#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/workqueue.h>

struct ieee80211_task {
	struct work			ta_work;
	STAILQ_ENTRY(ieee80211_task)	ta_link;
	kcondvar_t			ta_cv;
	pri_t				ta_priority;
	int				ta_pending;
	void				(*ta_func)(void *, int);
	void				*ta_context;
};

struct ieee80211_taskqueue;
int	ieee80211_taskqueue_create(struct ieee80211_taskqueue **, const char *,
	    pri_t, int, int);
void	ieee80211_taskqueue_destroy(struct ieee80211_taskqueue *);
int	ieee80211_taskqueue_enqueue(struct ieee80211_taskqueue *,
	    struct ieee80211_task *);
void	ieee80211_taskqueue_drain(struct ieee80211_taskqueue *,
	    struct ieee80211_task *);
void	ieee80211_taskqueue_drain_all(struct ieee80211_taskqueue *);
void	ieee80211_taskqueue_block(struct ieee80211_taskqueue *);
void	ieee80211_taskqueue_unblock(struct ieee80211_taskqueue *);

#define	IEEE80211_TASK_INIT(task, prio, func, context)			\
do {									\
	memset(&(task)->ta_work, 0, sizeof((task)->ta_work));		\
	cv_init(&(task)->ta_cv, "80211tsk");				\
	(task)->ta_priority = (prio);					\
	(task)->ta_pending = 0;						\
	(task)->ta_func = (func);					\
	(task)->ta_context = (context);					\
} while (/*CONSTCOND*/0)

#define	IEEE80211_TQ_MPSAFE	__BIT(0)
#define	IEEE80211_TQ_PERCPU	__BIT(1)

#endif	/* _NET80211_IEEE80211_TASK_H_ */
