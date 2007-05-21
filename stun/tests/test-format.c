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

#include "stun/stun-msg.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>


static void fatal (const char *msg, ...)
{
	va_list ap;
	va_start (ap, msg);
	vfprintf (stderr, msg, ap);
	va_end (ap);
	fputc ('\n', stderr);
	exit (1);
}


static void
dynamic_check (const uint8_t *msg, size_t len)
{
	size_t len2 = stun_validate (msg, len);
	if ((len != len2) || (len2 & 3))
		fatal ("Invalid message (%u, %u)\n",
		       (unsigned)len, (unsigned)len2);
	if (!stun_demux (msg))
		fatal ("Invalid message multiplexing");

	printf ("Built message of %u bytes\n", (unsigned)len);
}


static size_t
finish_check (uint8_t *msg)
{
	stun_msg_t mshort;
	size_t len = sizeof (stun_msg_t);
	memcpy (mshort, msg, sizeof (mshort));

	if (stun_finish (msg, &len))
		fatal ("Cannot finish message");
	dynamic_check (msg, len);

	len = sizeof (mshort);
	if (stun_verify_password (mshort, "toto") != ENOENT)
		fatal ("Missing HMAC test failed");
	if (stun_finish_short (mshort, &len, "ABCDE", "admin", "ABC", 3))
		fatal ("Cannot finish message with short-term creds");
	dynamic_check (mshort, len);
	if (stun_verify_password (mshort, "admin") != 0)
		fatal ("Valid HMAC test failed");

	return len;
}


static void
check_af (const char *name, int family, socklen_t addrlen)
{
	struct sockaddr_storage addr;
	stun_msg_t msg;

	assert (addrlen <= sizeof (addr));

	memset (&addr, 0, sizeof (addr));
	stun_init_request (msg, STUN_BINDING);

	if (stun_append_addr (msg, sizeof (msg), STUN_MAPPED_ADDRESS,
	                      (struct sockaddr *)&addr, addrlen) != EAFNOSUPPORT)
		fatal ("Unknown address family test failed");
	if (stun_append_xor_addr (msg, sizeof (msg), STUN_XOR_MAPPED_ADDRESS,
	                      (struct sockaddr *)&addr, addrlen) != EAFNOSUPPORT)
		fatal ("Unknown address family xor test failed");

	addr.ss_family = family;
	if (stun_append_addr (msg, sizeof (msg), STUN_MAPPED_ADDRESS,
	                      (struct sockaddr *)&addr, addrlen - 1) != EINVAL)
		fatal ("Too small %s sockaddr test failed", name);

	if (stun_append_xor_addr (msg, sizeof (msg), STUN_XOR_MAPPED_ADDRESS,
	                      (struct sockaddr *)&addr, addrlen - 1) != EINVAL)
		fatal ("Too small %s sockaddr xor test failed", name);

	if (stun_append_addr (msg, sizeof (msg), STUN_MAPPED_ADDRESS,
	                      (struct sockaddr *)&addr, addrlen))
		fatal ("%s sockaddr test failed", name);

	if (stun_append_xor_addr (msg, sizeof (msg), STUN_XOR_MAPPED_ADDRESS,
	                          (struct sockaddr *)&addr, addrlen))
		fatal ("%s sockaddr xor test failed", name);
}


int main (void)
{
	uint8_t msg[STUN_MAXMSG + 8];
	size_t len;

	/* Request formatting test */
	stun_init_request (msg, STUN_BINDING);
	finish_check (msg);
	if (memcmp (msg, "\x00\x01", 2))
		fatal ("Request formatting test failed");

	/* Response formatting test */
	stun_init_response (msg, msg);
	finish_check (msg);
	if (memcmp (msg, "\x01\x01", 2))
		fatal ("Response formatting test failed");

	/* Error formatting test */
	if (stun_init_error (msg, sizeof (msg), msg, 400))
		fatal ("Error initialization test failed");
	finish_check (msg);
	if (memcmp (msg, "\x01\x11", 2))
		fatal ("Error formatting test failed");

	/* Unknown error formatting test */
	if (stun_init_error (msg, sizeof (msg), msg, 666))
		fatal ("Unknown error initialization test failed");
	finish_check (msg);
	if (memcmp (msg, "\x01\x11", 2))
		fatal ("Unknown error formatting test failed");

	/* Overflow tests */
	stun_init_request (msg, STUN_BINDING);
	for (unsigned i = 0;
	     stun_append_flag (msg, sizeof (msg), 0xffff) != ENOBUFS;
	     i++)
	{
		if ((i << 2) > 0xffff)
			fatal ("Overflow protection test failed");
	}

	if (stun_append32 (msg, sizeof (msg), 0xffff, 0x12345678) != ENOBUFS)
		fatal ("Double-word overflow test failed");
	if (stun_append64 (msg, sizeof (msg), 0xffff,
	                   0x123456789abcdef0) != ENOBUFS)
		fatal ("Quad-word overflow test failed");
	if (stun_append_string (msg, sizeof (msg), 0xffff, "foobar") != ENOBUFS)
		fatal ("String overflow test failed");

	struct sockaddr addr;
	memset (&addr, 0, sizeof (addr));
	addr.sa_family = AF_INET;
#ifdef HAVE_SA_LEN
	addr.sa_len = sizeof (addr);
#endif
	if (stun_append_xor_addr (msg, sizeof (msg), 0xffff, &addr,
	                          sizeof (addr)) != ENOBUFS)
		fatal ("Address overflow test failed");
	len = sizeof (msg);
	if (stun_finish (msg, &len) != ENOBUFS)
		fatal ("Fingerprint overflow test failed");
	len = sizeof (msg);
	if (stun_finish_short (msg, &len, NULL, "secret", NULL, 0) != ENOBUFS)
		fatal ("Message integrity overflow test failed");
	len = sizeof (msg);
	if (stun_finish_short (msg, &len, "login", "secret", NULL, 0) != ENOBUFS)
		fatal ("Username overflow test failed");
	len = sizeof (msg);
	if (stun_finish_short (msg, &len, NULL, "secret", "foobar", 6) != ENOBUFS)
		fatal ("Nonce overflow test failed");

	/* Address attributes tests */
	check_af ("IPv4", AF_INET, sizeof (struct sockaddr_in));
#ifdef AF_INET6
	check_af ("IPv6", AF_INET6, sizeof (struct sockaddr_in6));
#endif

	return 0;
}
