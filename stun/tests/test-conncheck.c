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
#include "stun/conncheck.h"
#include "stun/stun-msg.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>

#undef NDEBUG /* ensure assertions are built-in */
#include <assert.h>


int main (void)
{
	struct sockaddr_in ip4;
	stun_msg_t req, resp;
	ssize_t val;
	size_t len;
	const uint64_t tie = 0x8000000000000000LL;
	static const char name[] = "admin", pass[] = "secret";
	bool control = false;

	memset (&ip4, 0, sizeof (ip4));
	ip4.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	ip4.sin_len = sizeof (addr);
#endif
	ip4.sin_port = htons (12345);
	ip4.sin_addr.s_addr = htonl (0x7f000001);

	/* Unauthenticated message */
	stun_init_request (req, STUN_BINDING);
	len = sizeof (req);
	val = stun_finish (req, &len);
	assert (val == 0);

	len = sizeof (resp);
	val = stun_conncheck_reply (resp, &len, req, (struct sockaddr *)&ip4,
	                            sizeof (ip4), pass, &control, tie);
	assert (val == EPERM);
	assert (len > 0);
	// FIXME: check error code

	/* No username */
	stun_init_request (req, STUN_BINDING);
	len = sizeof (req);
	val = stun_finish_short (req, &len, NULL, pass, NULL, 0);
	assert (val == 0);

	len = sizeof (resp);
	val = stun_conncheck_reply (resp, &len, req, (struct sockaddr *)&ip4,
	                            sizeof (ip4), pass, &control, tie);
	assert (val == EPERM);
	assert (len > 0);

	/* Good message */
	stun_init_request (req, STUN_BINDING);
	len = sizeof (req);
	val = stun_finish_short (req, &len, name, pass, NULL, 0);
	assert (val == 0);

	len = sizeof (resp);
	val = stun_conncheck_reply (resp, &len, req, (struct sockaddr *)&ip4,
	                            sizeof (ip4), pass, &control, tie);
	assert (val == 0);
	assert (len > 0);

	/* Bad fingerprint */
	val = stun_conncheck_reply (resp, &len, req, (struct sockaddr *)&ip4,
	                            sizeof (ip4), "bad", &control, tie);
	assert (val == EPERM);
	assert (len > 0);

	/* Lost role conflict */
	stun_init_request (req, STUN_BINDING);
	val = stun_append64 (req, sizeof (req), STUN_ICE_CONTROLLING, tie + 1);
	assert (val == 0);
	len = sizeof (req);
	val = stun_finish_short (req, &len, name, pass, NULL, 0);
	assert (val == 0);

	len = sizeof (resp);
	control = true;
	val = stun_conncheck_reply (resp, &len, req, (struct sockaddr *)&ip4,
	                            sizeof (ip4), pass, &control, tie);
	assert (val == EACCES);
	assert (len > 0);
	assert (control == false);

	/* Won role conflict */
	stun_init_request (req, STUN_BINDING);
	val = stun_append64 (req, sizeof (req), STUN_ICE_CONTROLLED, tie - 1);
	assert (val == 0);
	len = sizeof (req);
	val = stun_finish_short (req, &len, name, pass, NULL, 0);
	assert (val == 0);

	len = sizeof (resp);
	control = false;
	val = stun_conncheck_reply (resp, &len, req, (struct sockaddr *)&ip4,
	                            sizeof (ip4), pass, &control, tie);
	assert (val == 0);
	assert (len > 0);
	assert (control == false);

	return 0;
}
