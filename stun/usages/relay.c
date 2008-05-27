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
#include "relay.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <errno.h>
#include "stun-msg.h"
#include "trans.h"


struct turn_s
{
	stun_trans_t trans;
};


/**
 * @file relay.c
 * @brief STUN relay usage (TURN) implementation
 */

turn_t *turn_socket (int fd, int family, turn_proto_t proto,
                     const struct sockaddr *restrict srv, socklen_t srvlen)
{
	turn_t *ctx;
	int val;

	if (family != AF_INET)
	{
		errno = EAFNOSUPPORT;
		return NULL;
	}

	if (proto != TURN_PROTO_UDP)
	{
		errno = EPROTONOSUPPORT;
		return NULL;
	}

	ctx = malloc (sizeof (*ctx));
	if (ctx == NULL)
		return NULL;

	memset (ctx, 0, sizeof (*ctx));

	val = (fd != -1)
		? stun_trans_init (&ctx->trans, fd, srv, srvlen)
		: stun_trans_create (&ctx->trans, SOCK_DGRAM, 0, srv, srvlen);
	if (val)
	{
		free (ctx);
		errno = val;
		return NULL;
	}

	stun_init_request (ctx->trans.msg.buf, STUN_ALLOCATE);
	return ctx;
}


int turn_connect (turn_t *restrict ctx, const struct sockaddr *restrict dst,
                  socklen_t len)
{
	assert (ctx != NULL);
	(void)ctx; (void)dst; (void)len;

	errno = ENOSYS;
	return -1;
}


ssize_t turn_sendto (turn_t *restrict ctx, const void *data, size_t datalen,
                     int flags, const struct sockaddr *restrict dst,
                     socklen_t dstlen)
{
	assert (ctx != NULL);
	(void)ctx; (void)data; (void)datalen; (void)flags; (void)dst; (void)dstlen;
	errno = ENOSYS;
	return -1;
}


ssize_t turn_send (turn_t *restrict ctx, const void *data, size_t len,
                   int flags)
{
	assert (ctx != NULL);
	(void)ctx; (void)data; (void)len; (void)flags;
	errno = ENOSYS;
	return -1;
}


ssize_t turn_recvfrom (turn_t *restrict ctx, void *data, size_t len, int flags,
                       const struct sockaddr *restrict src, socklen_t *srclen)
{
	assert (ctx != NULL);
	(void)ctx; (void)data; (void)len; (void)flags; (void)src; (void)srclen;
	errno = ENOSYS;
	return -1;
}


ssize_t turn_recv (turn_t *restrict ctx, void *data, size_t len, int flags)
{
	assert (ctx != NULL);
	(void)ctx; (void)data; (void)len; (void)flags;
	errno = ENOSYS;
	return -1;
}


int turn_getsockname (turn_t *restrict ctx,
                      const struct sockaddr *restrict name, socklen_t *len)
{
	assert (ctx != NULL);
	(void)ctx; (void)name; (void)len;
	errno = ENOSYS;
	return -1;
}


int turn_getpeername (turn_t *restrict ctx,
                      const struct sockaddr *restrict name, socklen_t *len)
{
	assert (ctx != NULL);
	(void)ctx; (void)name; (void)len;
	errno = ENOSYS;
	return -1;
}


int turn_close (turn_t *restrict ctx)
{
	assert (ctx != NULL);
	stun_trans_deinit (&ctx->trans);
	free (ctx);
	return 0;
}
