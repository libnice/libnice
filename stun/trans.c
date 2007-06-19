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
#include <netinet/in.h>

#include "stun-msg.h"
#include "trans.h"

#define TRANS_OWN_FD   0x1 /* descriptor belongs to us */
#define TRANS_RELIABLE 0x2 /* reliable transport */

int stun_trans_init (stun_trans_t *restrict tr, int fd,
                     const struct sockaddr *restrict srv, socklen_t srvlen)
{
	int sotype;
	socklen_t solen = sizeof (sotype);

	assert (fd != -1);

	if (srvlen > sizeof (tr->sock.dst))
		return ENOBUFS;

	tr->flags = 0;
	tr->msg.offset = 0;
	tr->sock.fd = fd;
	memcpy (&tr->sock.dst, srv, tr->sock.dstlen = srvlen);
	tr->key.length = 0;
	tr->key.value = NULL;

	if (getsockopt (fd, SOL_SOCKET, SO_TYPE, &sotype, &solen))
		return errno;

	switch (sotype)
	{
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			tr->flags |= TRANS_RELIABLE;
	}

	return 0;
}


int stun_trans_create (stun_trans_t *restrict tr, int type, int proto,
                       const struct sockaddr *restrict srv, socklen_t srvlen)
{
	int fd, val;

	if (srvlen < sizeof (struct sockaddr))
		return EINVAL;

	fd = socket (srv->sa_family, type, proto);
	if (fd == -1)
		return errno;

#ifdef FD_CLOEXEC
	fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
	fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
#endif

#ifdef MSG_ERRQUEUE
	if (type == SOCK_DGRAM)
	{
		/* Linux specifics for ICMP errors on non-connected sockets */
		int yes = 1;
		switch (srv->sa_family)
		{
			case AF_INET:
				setsockopt (fd, SOL_IP, IP_RECVERR, &yes, sizeof (yes));
				break;
			case AF_INET6:
				setsockopt (fd, SOL_IPV6, IPV6_RECVERR, &yes, sizeof (yes));
				break;
		}
	}
#endif

	if (connect (fd, srv, srvlen) && (errno != EINPROGRESS))
		val = errno;
	else
		val = stun_trans_init (tr, fd, NULL, 0);

	if (val)
	{
		close (fd);
		return val;
	}

	tr->flags |= TRANS_OWN_FD;
	return 0;
}


void stun_trans_deinit (stun_trans_t *tr)
{
	int saved = errno;
	if (tr->flags & TRANS_OWN_FD)
		close (tr->sock.fd);
	free (tr->key.value);

#ifndef NDEBUG
	tr->sock.fd = -1;
#endif
	errno = saved;
}


#ifndef MSG_DONTWAIT
# define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif


static int stun_trans_send (stun_trans_t *tr);

int stun_trans_start (stun_trans_t *tr)
{
	int val;

	assert (tr->msg.offset == 0);

	val = stun_trans_send (tr);
	if (val)
		return val;

	if (tr->flags & TRANS_RELIABLE)
		stun_timer_start_reliable (&tr->timer);
	else
		stun_timer_start (&tr->timer);

	DBG ("STUN transaction @%p started (timeout: %ums)\n", tr,
	     stun_trans_timeout (tr));
	return 0;
}


static inline int stun_err_dequeue (int fd)
{
#ifdef MSG_ERRQUEUE
	struct msghdr hdr;
	memset (&hdr, 0, sizeof (hdr));
	return recvmsg (fd, &hdr, MSG_ERRQUEUE) == 0;
#else
	return 0;
#endif
}


/**
 * Try to send STUN request/indication
 */
static int
stun_trans_send (stun_trans_t *tr)
{
	const uint8_t *data = tr->msg.buf + tr->msg.offset;
	size_t len = tr->msg.length - tr->msg.offset;
	ssize_t val;
	int errval;

	do
	{
		if (tr->sock.dstlen > 0)
			val = sendto (tr->sock.fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL,
			              (struct sockaddr *)&tr->sock.dst, tr->sock.dstlen);
		else
			val = send (tr->sock.fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);

		if (val >= 0)
		{
			/* Message sent succesfully! */
			tr->msg.offset += val;
			return 0;
		}

		errval = errno;
	}
	while (stun_err_dequeue (tr->sock.fd));

	return errval;
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


int stun_trans_preprocess (stun_trans_t *restrict tr,
                           const void *restrict buf, size_t len)
{
	bool code;

	if (stun_validate (buf, len) <= 0)
		return EAGAIN;

	DBG ("Received %u-bytes STUN message\n",
	     (unsigned)stun_validate (buf, len));
	/* FIXME: some error messages cannot be authenticated!! */

	if (!stun_match_messages (buf, tr->msg.buf, tr->key.value, tr->key.length,
	                          &code))
		return EAGAIN;

	if (code)
		return ECONNREFUSED; // FIXME: better error value

	if (stun_has_unknown (buf))
		return EPROTO;

	return 0;
}


unsigned stun_trans_timeout (const stun_trans_t *tr)
{
	assert (tr != NULL);
	assert (tr->sock.fd != -1);
	return stun_timer_remainder (&tr->timer);
}


int stun_trans_fd (const stun_trans_t *tr)
{
	assert (tr != NULL);
	assert (tr->sock.fd != -1);
	return tr->sock.fd;
}
