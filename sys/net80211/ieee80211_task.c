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

/*
 * embedded FreeBSD taskqueue(9) for net80211
 */

#include <sys/cdefs.h>
#ifdef __NetBSD__
__KERNEL_RCSID(0, "$NetBSD$");
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/condvar.h>
#include <sys/mutex.h>

#include <net/if.h>
#include <net/if_media.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_task.h>

STAILQ_HEAD(ieee80211_taskqhead, ieee80211_task);

struct ieee80211_taskqueue_busy {
	struct ieee80211_task			*tb_running;
	TAILQ_ENTRY(ieee80211_taskqueue_busy)	tb_link;
};
TAILQ_HEAD(ieee80211_taskbusyqhead, ieee80211_taskqueue_busy);

struct ieee80211_taskqueue {
	struct workqueue		*tq_wq;
	kmutex_t			tq_lock;
	kcondvar_t			tq_cv;

	struct ieee80211_taskqhead	tq_queue;
	struct ieee80211_taskbusyqhead	tq_activeq;

	uint32_t			tq_flags;
#define	TQ_BLOCKED		__BIT(0)
#define	TQ_PENDING		__BIT(1)
};

static void
ieee80211_taskqueue_run(struct work *wk, void *arg)
{
	struct ieee80211_taskqueue *tq = arg;
	struct ieee80211_taskqueue_busy tb;
	struct ieee80211_task *task;
	int pending;

	mutex_enter(&tq->tq_lock);

	tb.tb_running = NULL;
	TAILQ_INSERT_TAIL(&tq->tq_activeq, &tb, tb_link);

	while ((task = STAILQ_FIRST(&tq->tq_queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&tq->tq_queue, ta_link);

		tb.tb_running = task;
		pending = task->ta_pending;
		task->ta_pending = 0;
		mutex_exit(&tq->tq_lock);

		(task->ta_func)(task->ta_context, pending);

		mutex_enter(&tq->tq_lock);
		tb.tb_running = NULL;
		cv_broadcast(&task->ta_cv);
	}

	TAILQ_REMOVE(&tq->tq_activeq, &tb, tb_link);
	if (TAILQ_EMPTY(&tq->tq_activeq))
		cv_broadcast(&tq->tq_cv);

	mutex_exit(&tq->tq_lock);
}

int
ieee80211_taskqueue_create(struct ieee80211_taskqueue **tqp, const char *name,
    pri_t pri, int ipl, int flags)
{
	struct ieee80211_taskqueue *tq;
	int wq_flags;
	int error;

	tq = kmem_alloc(sizeof(*tq), KM_SLEEP);
	if (tq == NULL)
		return ENOMEM;

	wq_flags = 0;
	if (ISSET(flags, IEEE80211_TQ_MPSAFE))
		SET(wq_flags, WQ_MPSAFE);
	if (ISSET(flags, IEEE80211_TQ_PERCPU))
		SET(wq_flags, WQ_PERCPU);

	error = workqueue_create(&tq->tq_wq, name, ieee80211_taskqueue_run,
	    tq, pri, ipl, wq_flags);
	if (error) {
		kmem_free(tq, sizeof(*tq));
		return error;
	}

	mutex_init(&tq->tq_lock, MUTEX_DEFAULT, ipl);
	cv_init(&tq->tq_cv, "80211tq");
	STAILQ_INIT(&tq->tq_queue);
	TAILQ_INIT(&tq->tq_activeq);
	tq->tq_flags = 0;

	*tqp = tq;
	return 0;
}

void
ieee80211_taskqueue_destroy(struct ieee80211_taskqueue *tq)
{

	if (tq != NULL) {
		workqueue_destroy(tq->tq_wq);
		mutex_destroy(&tq->tq_lock);
		kmem_free(tq, sizeof(*tq));
	}
}

int
ieee80211_taskqueue_enqueue(struct ieee80211_taskqueue *tq,
    struct ieee80211_task *task)
{
	struct ieee80211_task *ins;
	struct ieee80211_task *prev;

	mutex_enter(&tq->tq_lock);

	if (task->ta_pending > 0) {
		if (task->ta_pending < INT_MAX)
			task->ta_pending++;
		mutex_exit(&tq->tq_lock);
		return 0;
	}

	/*
	 * Optimise the case when all tasks have the same priority.
	 */
	prev = STAILQ_LAST(&tq->tq_queue, ieee80211_task, ta_link);
	if ((prev == NULL) || (prev->ta_priority >= task->ta_priority)) {
		STAILQ_INSERT_TAIL(&tq->tq_queue, task, ta_link);
	} else {
		prev = NULL;
		for (ins = STAILQ_FIRST(&tq->tq_queue);
		     ins != NULL;
		     prev = ins, ins = STAILQ_NEXT(ins, ta_link)) {
			if (ins->ta_priority < task->ta_priority)
				break;
		}
		if (prev != NULL)
			STAILQ_INSERT_AFTER(&tq->tq_queue, prev, task, ta_link);
		else
			STAILQ_INSERT_HEAD(&tq->tq_queue, task, ta_link);
	}

	task->ta_pending = 1;
	if (!ISSET(tq->tq_flags, TQ_BLOCKED)) {
		workqueue_enqueue(tq->tq_wq, &task->ta_work, NULL);
	} else {
		SET(tq->tq_flags, TQ_PENDING);
	}

	mutex_exit(&tq->tq_lock);
	return 0;
}

static int
task_is_running(struct ieee80211_taskqueue *tq, struct ieee80211_task *task)
{
	struct ieee80211_taskqueue_busy *tb;

	KASSERT(mutex_owned(tq->tq_lock));

	TAILQ_FOREACH(tb, &tq->tq_activeq, tb_link) {
		if (tb->tb_running == task)
			return 1;
	}
	return 0;
}

static void
ieee80211_taskqueue_drain_locked(struct ieee80211_taskqueue *tq,
    struct ieee80211_task *task)
{

	KASSERT(mutex_owned(&tq->tq_lock));

	while (task->ta_pending > 0 || task_is_running(tq, task))
		cv_wait(&task->ta_cv, &tq->tq_lock);
}

void
ieee80211_taskqueue_drain(struct ieee80211_taskqueue *tq,
    struct ieee80211_task *task)
{

	mutex_enter(&tq->tq_lock);
	ieee80211_taskqueue_drain_locked(tq, task);
	mutex_exit(&tq->tq_lock);
}

void
ieee80211_taskqueue_drain_all(struct ieee80211_taskqueue *tq)
{
	struct ieee80211_task *task;

	mutex_enter(&tq->tq_lock);
	task = STAILQ_LAST(&tq->tq_queue, ieee80211_task, ta_link);
	if (task != NULL)
		ieee80211_taskqueue_drain_locked(tq, task);
	while (!TAILQ_EMPTY(&tq->tq_activeq))
		cv_wait(&tq->tq_cv, &tq->tq_lock);
	mutex_exit(&tq->tq_lock);
}

void
ieee80211_taskqueue_block(struct ieee80211_taskqueue *tq)
{

	mutex_enter(&tq->tq_lock);
	SET(tq->tq_flags, TQ_BLOCKED);
	mutex_exit(&tq->tq_lock);
}

void
ieee80211_taskqueue_unblock(struct ieee80211_taskqueue *tq)
{
	struct ieee80211_task *task;
	uint32_t oflags = tq->tq_flags;

	mutex_enter(&tq->tq_lock);
	CLR(tq->tq_flags, TQ_BLOCKED);
	if (ISSET(oflags, TQ_PENDING)) {
		CLR(tq->tq_flags, TQ_PENDING);
		if (TAILQ_EMPTY(&tq->tq_activeq)) {
			task = STAILQ_FIRST(&tq->tq_queue);
			if (task != NULL) {
				workqueue_enqueue(tq->tq_wq, &task->ta_work,
				    NULL);
			}
		}
	}
	mutex_exit(&tq->tq_lock);
}
