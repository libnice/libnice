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
#include "stun-msg.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef HAVE_POLL
# include <sys/poll.h>
#endif
#include <fcntl.h>

/** Blocking mode STUN binding discovery */

int stun_bind_run (int fd,
                   const struct sockaddr *restrict srv, socklen_t srvlen,
                   struct sockaddr *restrict addr, socklen_t *addrlen)
{
#ifdef HAVE_POLL
	stun_bind_t *ctx;
	uint8_t buf[STUN_MAXMSG];
	size_t len = 0;
	ssize_t val;

	val = stun_bind_start (&ctx, fd, srv, srvlen);
	if (val)
		return val;

	do
	{
		struct pollfd ufd[1];
		unsigned delay = stun_bind_timeout (ctx);

		memset (ufd, 0, sizeof (ufd));
		ufd[0].fd = fd = stun_bind_fd (ctx),
		ufd[0].events = POLLIN;

		if (poll (ufd, sizeof (ufd) / sizeof (ufd[0]), delay) <= 0)
		{
			val = stun_bind_elapse (ctx);
			continue;
		}

		val = recv (fd, buf + len, sizeof (buf) - len, MSG_DONTWAIT);
		if (val == -1)
		{
#ifdef MSG_ERRQUEUE
			/* FIXME: do proper ICMP error handling? */
			struct msghdr hdr;
			memset (&hdr, 0, sizeof (hdr));
			recvmsg (fd, &hdr, MSG_ERRQUEUE);
#endif
			val = EAGAIN;
			continue;
		}

		len += val;
		val = stun_bind_process (ctx, buf, len, addr, addrlen);
	}
	while (val == EAGAIN);

	return val;
#else
	(void)fd; (void)srv; (void)srvlen; (void)addr; (void)addrlen;
	return ENOSYS;
#endif
}

/** Non-blocking mode STUN binding discovery */

#include "trans.h"

struct stun_bind_s
{
	stun_trans_t trans;
};


/** Initialization/deinitization */

/**
 * Initializes a STUN Binding discovery context. Does not send anything.
 * This allows customization of the STUN Binding Request.
 *
 * @param context pointer to an opaque pointer that will be passed to
 * stun_bind_resume() afterward
 * @param fd socket to use for discovery, or -1 to create one
 * @param srv STUN server socket address
 * @param srvlen STUN server socket address length
 *
 * @return 0 on success, a standard error value otherwise.
 */
static int
stun_bind_alloc (stun_bind_t **restrict context, int fd,
                 const struct sockaddr *restrict srv, socklen_t srvlen)
{
	int val;

	stun_bind_t *ctx = malloc (sizeof (*ctx));
	if (ctx == NULL)
		return ENOMEM;

	memset (ctx, 0, sizeof (*ctx));
	*context = ctx;

	val = (fd != -1)
		? stun_trans_init (&ctx->trans, fd, srv, srvlen)
		: stun_trans_create (&ctx->trans, SOCK_DGRAM, 0, srv, srvlen);

	if (val)
	{
		free (ctx);
		return val;
	}

	stun_init_request (ctx->trans.msg.buf, STUN_BINDING);
	return 0;
}


void stun_bind_cancel (stun_bind_t *context)
{
	stun_trans_deinit (&context->trans);
	free (context);
}


static int
stun_bind_launch (stun_bind_t *ctx)
{
	int val = stun_trans_start (&ctx->trans);
	if (val)
		stun_bind_cancel (ctx);
	return val;
}


int stun_bind_start (stun_bind_t **restrict context, int fd,
                     const struct sockaddr *restrict srv,
                     socklen_t srvlen)
{
	stun_bind_t *ctx;

	int val = stun_bind_alloc (context, fd, srv, srvlen);
	if (val)
		return val;

	ctx = *context;

	ctx->trans.msg.length = sizeof (ctx->trans.msg.buf);
	val = stun_finish (ctx->trans.msg.buf, &ctx->trans.msg.length);
	if (val)
	{
		stun_bind_cancel (ctx);
		return val;
	}

	return stun_bind_launch (ctx);
}


/** Timer and retransmission handling */

unsigned stun_bind_timeout (const stun_bind_t *context)
{
	assert (context != NULL);
	return stun_trans_timeout (&context->trans);
}


int stun_bind_elapse (stun_bind_t *context)
{
	int val = stun_trans_tick (&context->trans);
	if (val != EAGAIN)
		stun_bind_cancel (context);
	return val;
}


/** Incoming packets handling */

int stun_bind_fd (const stun_bind_t *context)
{
	assert (context != NULL);
	return stun_trans_fd (&context->trans);
}


int stun_bind_process (stun_bind_t *restrict ctx,
                       const void *restrict buf, size_t len,
                       struct sockaddr *restrict addr, socklen_t *addrlen)
{
	int val, code;

	assert (ctx != NULL);

	val = stun_trans_preprocess (&ctx->trans, &code, buf, len);
	switch (val)
	{
		case EAGAIN:
			return EAGAIN;
		case 0:
			break;
		default:
			if (code == STUN_ROLE_CONFLICT)
				val = ECONNRESET;
			stun_bind_cancel (ctx);
			return val;
	}

	val = stun_find_xor_addr (buf, STUN_XOR_MAPPED_ADDRESS, addr, addrlen);
	if (val)
	{
		DBG (" No XOR-MAPPED-ADDRESS: %s\n", strerror (val));
		val = stun_find_addr (buf, STUN_MAPPED_ADDRESS, addr, addrlen);
		if (val)
		{
			DBG (" No MAPPED-ADDRESS: %s\n", strerror (val));
			stun_bind_cancel (ctx);
			return val;
		}
	}

	DBG (" Mapped address found!\n");
	stun_bind_cancel (ctx);
	return 0;
}


/** ICE keep-alives (Binding discovery indication!) */

int
stun_bind_keepalive (int fd, const struct sockaddr *restrict srv,
                     socklen_t srvlen)
{
	uint8_t buf[28];
	size_t len = sizeof (buf);
	int val;

	stun_init_indication (buf, STUN_BINDING);
	val = stun_finish (buf, &len);
	assert (val == 0);

	/* NOTE: hopefully, this is only needed for non-stream sockets */
	if (stun_sendto (fd, buf, len, srv, srvlen) == -1)
		return errno;
	return 0;
}


/** Connectivity checks */
#include "stun-ice.h"

int
stun_conncheck_start (stun_bind_t **restrict context, int fd,
                      const struct sockaddr *restrict srv, socklen_t srvlen,
                      const char *username, const char *password,
                      bool cand_use, bool controlling, uint32_t priority,
                      uint64_t tie)
{
	int val;
	stun_bind_t *ctx;

	assert (username != NULL);
	assert (password != NULL);

	val = stun_bind_alloc (&ctx, fd, srv, srvlen);
	if (val)
		return val;

	ctx->trans.key.length = strlen (password);
	ctx->trans.key.value = malloc (ctx->trans.key.length);
	if (ctx->trans.key.value == NULL)
	{
		val = ENOMEM;
		goto error;
	}

	*context = ctx;
	memcpy (ctx->trans.key.value, password, ctx->trans.key.length);

	if (cand_use)
	{
		val = stun_append_flag (ctx->trans.msg.buf,
		                        sizeof (ctx->trans.msg.buf),
		                        STUN_USE_CANDIDATE);
		if (val)
			goto error;
	}

	val = stun_append32 (ctx->trans.msg.buf, sizeof (ctx->trans.msg.buf),
	                     STUN_PRIORITY, priority);
	if (val)
		goto error;

	val = stun_append64 (ctx->trans.msg.buf, sizeof (ctx->trans.msg.buf),
	                     controlling ? STUN_ICE_CONTROLLING
	                                 : STUN_ICE_CONTROLLED, tie);
	if (val)
		goto error;

	ctx->trans.msg.length = sizeof (ctx->trans.msg.buf);
	val = stun_finish_short (ctx->trans.msg.buf, &ctx->trans.msg.length,
	                         username, password, NULL, 0);
	if (val)
		goto error;

	return stun_bind_launch (ctx);

error:
	stun_bind_cancel (*context);
	return val;
}
