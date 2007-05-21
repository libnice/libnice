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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#ifndef SOL_IP
# define SOL_IP IPPROTO_IP
# define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef IPV6_RECVPKTINFO
# define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

static
int listen_socket (int fam, int type, int proto, uint16_t port)
{
	int yes = 1;
	int fd = socket (fam, type, proto);
	if (fd == -1)
	{
		perror ("Error opening IP port");
		return -1;
	}
	if (fd < 3)
		goto error;

	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof (int));

	struct sockaddr_storage addr;
	memset (&addr, 0, sizeof (addr));
	addr.ss_family = fam;
#ifdef HAVE_SA_LEN
	addr.ss_len = sizeof (addr);
#endif

	switch (fam)
	{
		case AF_INET:
			((struct sockaddr_in *)&addr)->sin_port = port;
			break;

		case AF_INET6:
#ifdef IPV6_V6ONLY
			if (setsockopt (fd, SOL_IPV6, IPV6_V6ONLY, &yes, sizeof (yes)))
				goto error;
#endif
			((struct sockaddr_in6 *)&addr)->sin6_port = port;
			break;
	}

	if (bind (fd, (struct sockaddr *)&addr, sizeof (addr)))
	{
		perror ("Error opening IP port");
		goto error;
	}

	if ((type == SOCK_DGRAM) || (type == SOCK_RAW))
	{
		switch (fam)
		{
			case AF_INET:
				setsockopt (fd, SOL_IP, IP_PKTINFO, &yes, sizeof (yes));
				break;

			case AF_INET6:
				setsockopt (fd, SOL_IPV6, IPV6_RECVPKTINFO, &yes,
				            sizeof (yes));
				break;
		}
	}
	else
	{
		if (listen (fd, INT_MAX))
		{
			perror ("Error opening IP port");
			goto error;
		}
	}

	return fd;

error:
	close (fd);
	return -1;
}


#include "stun-msg.h" // FIXME: remove
#include "bind.h"

static int dgram_process (int sock)
{
	struct sockaddr_storage addr;
	stun_msg_t buf;
	char ctlbuf[CMSG_SPACE (sizeof (struct in6_pktinfo))];
	struct iovec iov = { buf, sizeof (buf) };
	struct msghdr mh;

	memset (&mh, 0, sizeof (mh));
	mh.msg_name = (struct sockaddr *)&addr;
	mh.msg_namelen = sizeof (addr);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = ctlbuf;
	mh.msg_controllen = sizeof (ctlbuf);

	ssize_t len = recvmsg (sock, &mh, 0);
	if (len < 0)
	{
		DBG ("Receive error: %s\n", strerror (errno));
		return errno;
	}

	if (mh.msg_flags & MSG_TRUNC)
	{
		DBG ("Truncated datagram ignored.\n");
		return EMSGSIZE;
	}

	if (stun_validate (buf, len) <= 0)
		return EINVAL;

	len = stun_bind_reply (buf, &iov.iov_len, buf,
	                       mh.msg_name, mh.msg_namelen, false);
	if (iov.iov_len == 0)
		return len;

	len = sendmsg (sock, &mh, 0);
	if (len == -1)
		return errno;
	if ((size_t)len < iov.iov_len)
		return EMSGSIZE;
	return 0;
}


static int run (int family, int protocol)
{
	int sock = listen_socket (family, SOCK_DGRAM, protocol,
	                          htons (IPPORT_STUN));
	if (sock == -1)
		return -1;

	for (;;)
	{
		int val = dgram_process (sock);
		if (val)
			DBG ("stund: %s\n", strerror (val));
	}
}


/* Pretty useless dummy signal handler...
 * But calling exit() is needed for gcov to work properly. */
static void exit_handler (int signum)
{
	(void)signum;
	exit (0);
}


int main (int argc, char *argv[])
{
	int family = AF_INET;

	for (;;)
	{
		int c = getopt (argc, argv, "46");
		if (c == EOF)
			break;

		switch (c)
		{
			case '4':
				family = AF_INET;
				break;

			case '6':
				family = AF_INET6;
				break;
		}
	}

	signal (SIGINT, exit_handler);
	signal (SIGTERM, exit_handler);
	return -run (family, IPPROTO_UDP);
}
