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

#include <sys/types.h>
#include <sys/socket.h>

#include "bind.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <fcntl.h>

/**
 * Initial STUN timeout (milliseconds). The spec says it should be 100ms,
 * but that's way too short for most types of wireless Internet access.
 */
#define STUN_INIT_TIMEOUT 600
#define STUN_END_TIMEOUT 4800

/**
 * Performs STUN Binding discovery in blocking mode.
 *
 * @param fd socket to use for binding discovery, or -1 to create one
 * @param srv STUN server socket address
 * @param srvlen STUN server socket address byte length
 * @param addr pointer to a socket address structure to hold the discovered
 * binding (remember this can be either IPv4 or IPv6 regardless of the socket
 * family) [OUT]
 * @param addrlen pointer to the byte length of addr [IN], set to the byte
 * length of the binding socket address on return.
 *
 * @return 0 on success, a standard error value in case of error.
 * In case of error, addr and addrlen are undefined.
 */
int stun_bind_run (int fd,
                   const struct sockaddr *restrict srv, socklen_t srvlen,
                   struct sockaddr *restrict addr, socklen_t *addrlen)
{
	stun_bind_t *ctx;
	int val;

	val = stun_bind_start (&ctx, fd, srv, srvlen);
	if (val)
		return val;

	do
	{
		unsigned delay = stun_bind_timeout (ctx);
		struct pollfd ufd[1];
		memset (ufd, 0, sizeof (ufd));
		ufd[0].fd = stun_bind_fd (ctx),
		ufd[0].events = POLLIN;

		poll (ufd, sizeof (ufd) / sizeof (ufd[0]), delay);
		val = stun_bind_resume (ctx, addr, addrlen);
	}
	while (val == EAGAIN);

	return val;
}

#include "stun-msg.h"

struct stun_bind_s
{
	struct sockaddr_storage srv;
	socklen_t srvlen;

	struct timespec deadline;
	unsigned delay;

	int fd;
	bool ownfd;

	stun_transid_t transid;
};

static int
stun_bind_req (stun_bind_t *ctx)
{
	/* FIXME: support for TCP */
	stun_msg_t msg;
	stun_init (&msg, STUN_REQUEST, STUN_BINDING, ctx->transid);

	size_t len = stun_finish (&msg);
	if (!len)
		return errno;

	ssize_t val = sendto (ctx->fd, &msg, len, 0,
	                      (struct sockaddr *)&ctx->srv, ctx->srvlen);
	if (val == -1)
		return errno;
	if (val < (ssize_t)len)
		return EMSGSIZE;
	return 0;
}


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


/**
 * Sets deadline = now + delay
 */
static void
stun_setto (struct timespec *restrict deadline, unsigned delay)
{
	div_t d = div (delay, 1000);
	stun_gettime (deadline);

	// add delay to current time
	deadline->tv_sec += d.quot;
	deadline->tv_nsec += d.rem * 1000000;
	DBG ("New STUN timeout is %ums\n", delay);
}


/**
 * @return Remaining delay = deadline - now, or 0 if behind schedule.
 */
static unsigned
stun_getto (const struct timespec *restrict deadline)
{
	unsigned delay;
	struct timespec now;

	stun_gettime (&now);
	if (now.tv_sec > deadline->tv_sec)
		return 0;

	delay = deadline->tv_sec - now.tv_sec;
	if ((delay == 0) && (now.tv_nsec >= deadline->tv_nsec))
		return 0;

	delay *= 1000;
	delay += ((signed)(deadline->tv_nsec - now.tv_nsec)) / 1000000;
	DBG ("Current STUN timeout is %ums\n", delay);
	return delay;
}


/**
 * Aborts a running STUN Binding dicovery.
 */
void stun_bind_cancel (stun_bind_t *restrict context)
{
	int val = errno;

	if (context->ownfd)
		close (context->fd);
#ifndef NDEBUG
	context->fd = -1;
#endif
	free (context);

	errno = val;
}



/**
 * Starts STUN Binding discovery in non-blocking mode.
 *
 * @param context pointer to an opaque pointer that will be passed to
 * stun_bind_resume() afterward
 * @param fd socket to use for discovery, or -1 to create one
 * @param srv STUN server socket address
 * @param srvlen STUN server socket address length
 *
 * @return 0 on success, a standard error value otherwise.
 */
int stun_bind_start (stun_bind_t **restrict context, int fd,
                     const struct sockaddr *restrict srv,
                     socklen_t srvlen)
{
	stun_bind_t *ctx = malloc (sizeof (*ctx));
	if (ctx == NULL)
		return errno;
	memset (ctx, 0, sizeof (*ctx));
	*context = ctx;

	if (srvlen > sizeof (ctx->srv))
	{
		stun_bind_cancel (ctx);
		return ENOBUFS;
	}
	memcpy (&ctx->srv, srv, ctx->srvlen = srvlen);

	if (fd == -1)
	{
		if (srvlen < sizeof (struct sockaddr))
		{
			stun_bind_cancel (ctx);
			return EINVAL;
		}

		fd = socket (ctx->srv.ss_family, SOCK_DGRAM, 0);
		if (fd == -1)
		{
			stun_bind_cancel (ctx);
			return errno;
		}

#ifdef FD_CLOEXEC
		fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
		fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
#endif
		ctx->ownfd = true;
	}
	ctx->fd = fd;
	stun_setto (&ctx->deadline, ctx->delay = STUN_INIT_TIMEOUT);
	stun_make_transid (ctx->transid);

	int val = stun_bind_req (ctx);
	if (val)
	{
		stun_bind_cancel (ctx);
		return val;
	}

	return 0;
}

/**
 * Continues STUN Binding discovery in non-blocking mode.
 *
 * @param addr pointer to a socket address structure to hold the discovered
 * binding (remember this can be either IPv4 or IPv6 regardless of the socket
 * family) [OUT]
 * @param addrlen pointer to the byte length of addr [IN], set to the byte
 * length of the binding socket address on return.
 *
 * @return EAGAIN is returned if the discovery has not completed yet. 
   0 is returned on successful completion, another standard error value
 * otherwise. If the return value is not EAGAIN, <context> is freed and must
 * not be re-used.
 *
 * FIXME: document file descriptor closure semantics.
 */
int stun_bind_resume (stun_bind_t *restrict context,
                      struct sockaddr *restrict addr, socklen_t *addrlen)
{
	stun_msg_t buf;
	ssize_t len;
	bool error;

	assert (context != NULL);
	assert (context->fd != -1);

	// FIXME: should we only accept packet from server IP:port ?
	// FIXME: write a function to wrap this?
	len = recv (context->fd, &buf, sizeof (buf), MSG_DONTWAIT);
	if (len < 0)
		goto skip;

	len = stun_validate (&buf, len);
	if (len <= 0)
		goto skip;

	DBG ("Received %u-bytes STUN message\n", (unsigned)len);

	if (!stun_match_answer (&buf, STUN_BINDING, context->transid, &error))
		goto skip;

	if (error)
	{
		stun_bind_cancel (context);
		return ECONNREFUSED; // FIXME: better error value
	}

	if (stun_has_unknown (&buf))
	{
		stun_bind_cancel (context);
		return EPROTO;
	}

	len = stun_find_xor_addr (&buf, STUN_XOR_MAPPED_ADDRESS, addr, addrlen);
	if (len)
	{
		DBG (" No XOR-MAPPED-ADDRESS: %s\n", strerror (len));
		len = stun_find_addr (&buf, STUN_MAPPED_ADDRESS, addr, addrlen);
		if (len)
		{
			DBG (" No MAPPED-ADDRESS: %s\n", strerror (len));
			stun_bind_cancel (context);
			return len;
		}
	}

	DBG (" Mapped address found!\n");
	stun_bind_cancel (context);
	return 0;

skip:
	// FIXME: we call gettimeofday() twice here (minor problem)
	if (!stun_getto (&context->deadline))
	{
		if (context->delay >= STUN_END_TIMEOUT)
		{
			DBG ("Received no valid responses. STUN transaction failed.\n");
			stun_bind_cancel (context);
			return ETIMEDOUT; // fatal error!
		}

		context->delay *= 2;
		DBG ("Retrying with longer timeout... %ums\n", context->delay);
		stun_bind_req (context);
		stun_setto (&context->deadline, context->delay);
	}
	return EAGAIN;
}


/**
 * @return recommended maximum delay (in milliseconds) to wait for a
 * response.
 * This is meant to integrate with I/O pooling loops and event frameworks.
 */
unsigned stun_bind_timeout (const stun_bind_t *restrict context)
{
	assert (context != NULL);
	assert (context->fd != -1);
	return stun_getto (&context->deadline);
}


/**
 * @return file descriptor used by the STUN Binding discovery context.
 * Always succeeds.
 * This is meant to integrate with I/O polling loops and event frameworks.
 */
int stun_bind_fd (const stun_bind_t *restrict context)
{
	assert (context != NULL);
	return context->fd;
}
