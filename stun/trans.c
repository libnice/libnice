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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "stun-msg.h"
#include "trans.h"

/**
 * Initializes a new STUN request transaction
 */
int stun_trans_init (stun_trans_t *restrict tr, int fd,
                     const struct sockaddr *restrict srv, socklen_t srvlen)
{
	if (fd == -1)
	{
		if (srvlen < sizeof (struct sockaddr))
			return EINVAL;

		fd = socket (srv->sa_family, SOCK_DGRAM, 0);
		if (fd == -1)
			return errno;

#ifdef FD_CLOEXEC
		fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
		fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
#endif

		if (connect (fd, srv, srvlen))
		{
			close (fd);
			return errno;
		}

		tr->ownfd = true;
		tr->srvlen = 0;
	}
	else
	{
		if (srvlen > sizeof (tr->srv))
			return ENOBUFS;

		tr->ownfd = false;
		memcpy (&tr->srv, srv, tr->srvlen = srvlen);
	}

	tr->fd = fd;
	return 0;
}


/**
 * Sends a STUN request
 */
static int
stun_trans_send (stun_trans_t *tr)
{
	/* FIXME: support for TCP */
	ssize_t val;
	if (tr->srvlen > 0)
		val = sendto (tr->fd, tr->msg, tr->msglen, 0,
		              (struct sockaddr *)&tr->srv, tr->srvlen);
	else
		val = send (tr->fd, tr->msg, tr->msglen, 0);

	if (val == -1)
		return errno;
	if (val < (ssize_t)tr->msglen)
		return EMSGSIZE;
	return 0;
}


void stun_trans_deinit (stun_trans_t *tr)
{
	int saved = errno;
	if (tr->ownfd)
		close (tr->fd);
#ifndef NDEBUG
	tr->fd = -1;
#endif
	errno = saved;
}


int stun_trans_start (stun_trans_t *tr)
{
	int val = stun_trans_send (tr);
	if (val)
		return val;

	stun_timer_start (&tr->timer);
	DBG ("STUN transaction @%p started (timeout: %ums)\n", tr,
	     stun_trans_timeout (tr));
	return 0;
}


/**
 * This is meant to integrate with I/O pooling loops and event frameworks.
 *
 * @return recommended maximum delay (in milliseconds) to wait for a
 * response.
 */
unsigned stun_trans_timeout (const stun_trans_t *tr)
{
	assert (tr != NULL);
	assert (tr->fd != -1);
	return stun_timer_remainder (&tr->timer);
}


/**
 * This is meant to integrate with I/O polling loops and event frameworks.
 *
 * @return file descriptor used by the STUN Binding discovery context.
 * Always succeeds.
 */
int stun_trans_fd (const stun_trans_t *tr)
{
	assert (tr != NULL);
	assert (tr->fd != -1);
	return tr->fd;
}


int stun_trans_tick (stun_trans_t *tr)
{
	switch (stun_timer_refresh (&tr->timer))
	{
		case -1:
			DBG ("STUN transaction @%p failed: time out.\n", tr);
			return ETIMEDOUT; // fatal error!

		case 0:
			stun_trans_send (tr);
			DBG ("STUN transaction @%p retransmitted (timeout: %ums).\n", tr,
			     stun_trans_timeout (tr));
	}
	return EAGAIN;
}
