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
#include "stun/bind.h"
#include "stun/stun-msg.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#undef NDEBUG /* ensure assertions are built-in */
#include <assert.h>


static int listen_dgram (void)
{
	struct addrinfo hints, *res;
	int val = -1;

	memset (&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_DGRAM;

	if (getaddrinfo (NULL, "0", &hints, &res))
		return -1;

	for (const struct addrinfo *ptr = res; ptr != NULL; ptr = ptr->ai_next)
	{
		int fd = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (fd == -1)
			continue;

		if (bind (fd, ptr->ai_addr, ptr->ai_addrlen))
		{
			close (fd);
			continue;
		}

		val = fd;
		break;
	}

	freeaddrinfo (res);
	return val;
}


/** Incorrect socket family test */
static void bad_family (void)
{
	struct sockaddr addr, dummy;
	int val;

	memset (&addr, 0, sizeof (addr));
	addr.sa_family = AF_UNSPEC;
#ifdef HAVE_SA_LEN
	addr.sa_len = sizeof (addr);
#endif

	val = stun_bind_run (-1, &addr, sizeof (addr),
	                     &dummy, &(socklen_t){ sizeof (dummy) });
	assert (val != 0);
}


/** Too small socket address test */
static void small_srv_addr (void)
{
	struct sockaddr addr, dummy;
	int val;

	memset (&addr, 0, sizeof (addr));
	addr.sa_family = AF_INET;
#ifdef HAVE_SA_LEN
	addr.sa_len = sizeof (addr);
#endif

	val = stun_bind_run (-1, &addr, 1,
	                     &dummy, &(socklen_t){ sizeof (dummy) });
	assert (val == EINVAL);
}


/** Too big socket address test */
static void big_srv_addr (void)
{
	uint8_t buf[sizeof (struct sockaddr_storage) + 16];
	struct sockaddr dummy;
	int fd, val;

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	assert (fd != -1);

	memset (buf, 0, sizeof (buf));
	val = stun_bind_run (fd, (struct sockaddr *)buf, sizeof (buf),
	                     &dummy, &(socklen_t){ sizeof (dummy) });
	assert (val == ENOBUFS);
	close (fd);
}


/** Timeout test */
static void timeout (void)
{
	struct sockaddr_storage srv;
	struct sockaddr dummy;
	socklen_t srvlen = sizeof (srv);
	int val;

	/* Allocate a local UDP port, so we are 100% sure nobody responds there */
	int servfd = listen_dgram ();
	assert (servfd != -1);

	val = getsockname (servfd, (struct sockaddr *)&srv, &srvlen);
	assert (val == 0);

	val = stun_bind_run (-1, (struct sockaddr *)&srv, srvlen,
	                     &dummy, &(socklen_t){ sizeof (dummy) });
	assert (val == ETIMEDOUT);

	close (servfd);
}


/** Malformed responses test */
static void bad_responses (void)
{
	stun_bind_t *ctx;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof (addr);
	ssize_t val;
	uint8_t buf[1000];

	/* Allocate a local UDP port */
	int servfd = listen_dgram ();
	assert (servfd != -1);

	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	val = stun_bind_start (&ctx, -1, (struct sockaddr *)&addr, addrlen);
	assert (val == 0);

	/* Send to/receive from our client instance only */
	val = getsockname (stun_bind_fd (ctx),
	                   (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	val = connect (servfd, (struct sockaddr *)&addr, addrlen);
	assert (val == 0);

	/* Send crap response */
	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);
	val = stun_bind_process (ctx, "foobar", 6,
	                         (struct sockaddr *)&addr, &addrlen);
	assert (val == EAGAIN);

	/* Send non-matching message (request instead of response) */
	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);
	val = recv (servfd, buf, 1000, MSG_DONTWAIT);
	assert (val >= 0);

	val = stun_bind_process (ctx, buf, val,
	                         (struct sockaddr *)&addr, &addrlen);
	assert (val == EAGAIN);

	stun_bind_cancel (ctx);
	close (servfd);
}


/** Various responses test */
static void responses (void)
{
	stun_bind_t *ctx;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof (addr);
	ssize_t val;
	size_t len;
	int servfd, fd;
	stun_msg_t buf;

	/* Allocate a local UDP port for server */
	servfd = listen_dgram ();
	assert (servfd != -1);

	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	/* Allocate a client socket and connect to server */
	fd = socket (addr.ss_family, SOCK_DGRAM, 0);
	assert (fd != -1);

	val = connect (fd, (struct sockaddr *)&addr, addrlen);
	assert (val == 0);
	
	/* Send to/receive from our client instance only */
	val = getsockname (fd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	val = connect (servfd, (struct sockaddr *)&addr, addrlen);
	assert (val == 0);

	/* Send error response */
	val = stun_bind_start (&ctx, fd, NULL, 0);
	assert (val == 0);

	val = recv (servfd, buf, 1000, MSG_DONTWAIT);
	assert (val >= 0);

	stun_init_error (buf, sizeof (buf), buf, STUN_GLOBAL_FAILURE);
	len = sizeof (buf);
	val = stun_finish (buf, &len);
	assert (val == 0);

	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);
	val = stun_bind_process (ctx, buf, len,
	                         (struct sockaddr *)&addr, &addrlen);
	assert (val == ECONNREFUSED);

	/* Send response with an unknown attribute */
	val = stun_bind_start (&ctx, fd, NULL, 0);
	assert (val == 0);

	val = recv (servfd, buf, 1000, MSG_DONTWAIT);
	assert (val >= 0);

	stun_init_response (buf, buf);
	val = stun_append_string (buf, sizeof (buf), 0x6000,
	                          "This is an unknown attribute!");
	assert (val == 0);
	len = sizeof (buf);
	val = stun_finish (buf, &len);
	assert (val == 0);

	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	val = stun_bind_process (ctx, buf, len,
	                         (struct sockaddr *)&addr, &addrlen);
	assert (val == EPROTO);

	/* Send response with a no mapped address at all */
	val = stun_bind_start (&ctx, fd, NULL, 0);
	assert (val == 0);

	val = recv (servfd, buf, 1000, MSG_DONTWAIT);
	assert (val >= 0);

	stun_init_response (buf, buf);
	len = sizeof (buf);
	val = stun_finish (buf, &len);
	assert (val == 0);

	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	val = stun_bind_process (ctx, buf, len,
	                         (struct sockaddr *)&addr, &addrlen);
	assert (val == ENOENT);

	/* Send old-style response */
	val = stun_bind_start (&ctx, fd, NULL, 0);
	assert (val == 0);

	val = recv (servfd, buf, 1000, MSG_DONTWAIT);
	assert (val >= 0);

	stun_init_response (buf, buf);
	val = stun_append_addr (buf, sizeof (buf), STUN_MAPPED_ADDRESS,
	                        (struct sockaddr *)&addr, addrlen);
	assert (val == 0);
	len = sizeof (buf);
	val = stun_finish (buf, &len);
	assert (val == 0);

	val = getsockname (servfd, (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	val = stun_bind_process (ctx, buf, len,
	                         (struct sockaddr *)&addr, &addrlen);
	assert (val == 0);

	/* End */
	close (servfd);

	val = close (fd);
	assert (val == 0);
}


static void test (void (*func) (void), const char *name)
{
	alarm (10);

	printf ("%s test... ", name);
	func ();
	puts ("OK");
}


int main (void)
{
	test (bad_family, "Bad socket family");
	test (small_srv_addr, "Too small server address");
	test (big_srv_addr, "Too big server address");
	test (timeout, "Binding discovery timeout");
	test (bad_responses, "Bad responses");
	test (responses, "Error responses");
	return 0;
}
