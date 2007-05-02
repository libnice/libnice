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

//#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <assert.h>

#define ERR( str, exp ) \
	if (exp) { perror (str); exit (1); }
#define ERRVAL( str, exp ) \
	ERR ((str), ((errno = (exp)) != 0))

static void printaddr (const struct sockaddr *addr, socklen_t addrlen)
{
	char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];

	int val = getnameinfo (addr, addrlen, hostbuf, sizeof (hostbuf),
	                       servbuf, sizeof (servbuf),
	                       NI_NUMERICHOST | NI_NUMERICSERV);
	if (val)
		puts (gai_strerror (val));
	else
		printf ("%s port %s\n", hostbuf, servbuf);
}



static int test (int family, const char *hostname)
{
	struct addrinfo hints, *res;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;

	int val = getaddrinfo (hostname, "3478", &hints, &res);
	if (val)
	{
		fprintf (stderr, "%s: %s\n", hostname, gai_strerror (val));
		return -1;
	}

	for (struct addrinfo *ptr = res; ptr != NULL; ptr = ptr->ai_next)
	{
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof (addr);
		stun_bind_t *ctx;

		printf ("STUN server: ");
		printaddr (ptr->ai_addr, ptr->ai_addrlen);

		printf ("Auto discovery: ");
		ERRVAL ("Test 1",
			stun_bind_run (-1, ptr->ai_addr, ptr->ai_addrlen,
			               (struct sockaddr *)&addr, &addrlen));
		printaddr ((struct sockaddr *)&addr, addrlen);
	
		int fd = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		printf ("UDP discovery : ");
		ERR ("socket", fd == -1);
	
		addrlen = sizeof (addr);
		ERRVAL ("Test 2",
			stun_bind_run (fd, ptr->ai_addr, ptr->ai_addrlen,
			               (struct sockaddr *)&addr, &addrlen));
		printaddr ((struct sockaddr *)&addr, addrlen);

		// Cancellation test
		ERRVAL ("Test 3", stun_bind_start (&ctx, -1,
		                                   ptr->ai_addr, ptr->ai_addrlen));
		stun_bind_cancel (ctx);
		close (fd);
	}

	freeaddrinfo (res);
	return 0;
}


static char bigaddr[1024];

int main (int argc, char *argv[])
{
	const char *server = NULL;
	int family = AF_UNSPEC;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp (argv[i], "--ipv4") == 0)
			family = AF_INET;
		else
		if (strcmp (argv[i], "--ipv6") == 0)
			family = AF_INET6;
		else
			server = argv[i];
	}

	alarm (60); // force failure in case of deadlock

	errno = EINVAL;
	ERR ("Error case 1", !stun_bind_run (-1, NULL, 0, NULL, NULL));

	assert (sizeof (bigaddr) > sizeof (struct sockaddr_storage));
	memset (bigaddr, 0, sizeof (bigaddr));
	ERR ("Error case 2",
	     !stun_bind_start (&(stun_bind_t *){ NULL }, -1,
	                       (struct sockaddr *)bigaddr, sizeof (bigaddr)));

	if (test (family, server))
		return 1;

	return 0;
}
