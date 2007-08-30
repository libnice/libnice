/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Rémi Denis-Courmont
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Rémi Denis-Courmont, Nokia
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "timer.h"

#include <stdlib.h> /* div() */
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>


/**
 * Initial STUN timeout (milliseconds). The spec says it should be 100ms,
 * but that's way too short for most types of wireless Internet access.
 */
#define STUN_INIT_TIMEOUT 600
#define STUN_END_TIMEOUT 4800

#define STUN_RELIABLE_TIMEOUT 7900

/**
 * Clock used throughout the STUN code.
 * STUN requires a monotonic 1kHz clock to operate properly.
 */
static void stun_gettime (struct timespec *restrict now)
{
#if (_POSIX_MONOTONIC_CLOCK - 0) >= 0
	if (clock_gettime (CLOCK_MONOTONIC, now))
#endif
	{	// fallback to wall clock
		struct timeval tv;
		gettimeofday (&tv, NULL);
		now->tv_sec = tv.tv_sec;
		now->tv_nsec = tv.tv_usec * 1000;
	}
}


static inline void add_delay (struct timespec *ts, unsigned delay)
{
	div_t d = div (delay, 1000);
	ts->tv_sec += d.quot;
	ts->tv_nsec += d.rem * 1000000;

	while (ts->tv_nsec > 1000000000)
	{
		ts->tv_nsec -= 1000000000;
		ts->tv_sec++;
	}
}


void stun_timer_start (stun_timer_t *timer)
{
	stun_gettime (&timer->deadline);
	add_delay (&timer->deadline, timer->delay = STUN_INIT_TIMEOUT);
}


void stun_timer_start_reliable (stun_timer_t *timer)
{
	stun_gettime (&timer->deadline);
	add_delay (&timer->deadline, timer->delay = STUN_RELIABLE_TIMEOUT);
}



unsigned stun_timer_remainder (const stun_timer_t *timer)
{
	unsigned delay;
	struct timespec now;

	stun_gettime (&now);
	if (now.tv_sec > timer->deadline.tv_sec)
		return 0;

	delay = timer->deadline.tv_sec - now.tv_sec;
	if ((delay == 0) && (now.tv_nsec >= timer->deadline.tv_nsec))
		return 0;

	delay *= 1000;
	delay += ((signed)(timer->deadline.tv_nsec - now.tv_nsec)) / 1000000;
	return delay;
}


int stun_timer_refresh (stun_timer_t *timer)
{
	unsigned delay = stun_timer_remainder (timer);
	if (delay == 0)
	{
#if STUN_RELIABLE_TIMEOUT < STUN_END_TIMEOUT
/* Reliable timeout MUST be bigger (or equal) to end timeout, so that
 * retransmissions never happen with reliable transports. */
# error Inconsistent STUN timeout values!
#endif
		if (timer->delay >= STUN_END_TIMEOUT)
			return -1;

		add_delay (&timer->deadline, timer->delay *= 2);
	}

	return delay;
}
