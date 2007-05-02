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

#include "stun-msg.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>


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
dynamic_check (const stun_msg_t *msg, size_t len)
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
finish_check (stun_msg_t *msg)
{
	stun_msg_t mshort;
	memcpy (&mshort, msg, sizeof (mshort));

	size_t len = stun_finish (msg);
	if (len == 0)
		fatal ("Cannot finish message");
	dynamic_check (msg, len);
	if (stun_verify_password (&mshort, "toto") != ENOENT)
		fatal ("Missing HMAC test failed");

	size_t slen = stun_finish_short (&mshort, "ABCDE", "admin", "ABC", 3);
	if (slen == 0)
		fatal ("Cannot finish message with short-term creds");
	dynamic_check (&mshort, slen);
	if (stun_verify_password (&mshort, "admin") != 0)
		fatal ("Valid HMAC test failed");

	return len;
}


int main (void)
{
	stun_msg_t msg;
	stun_transid_t id;
	stun_make_transid (id);

	/* Request formatting test */
	stun_init (&msg, STUN_REQUEST, STUN_BINDING, id);
	finish_check (&msg);
	if (memcmp (&msg, "\x00\x01", 2))
		fatal ("Request formatting test failed");

	/* Response formatting test */
	stun_init_response (&msg, &msg);
	finish_check (&msg);
	if (memcmp (&msg, "\x01\x01", 2))
		fatal ("Response formatting test failed");

	return 0;
}
