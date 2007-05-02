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
static_check (const uint8_t *msg, unsigned len)
{
	unsigned i = 0;

	do
	{
		size_t vlen = stun_validate (msg, i);
		if ((vlen & 3) || (vlen != ((i >= len) * len)))
			fatal ("%u/%u short message test failed", i, len);
	}
	while (i++ < (len + 4));
}


int main (void)
{
	static const uint8_t simple_resp[] =
		"\x15\x55\x00\x00"
		"\x21\x12\xA4\x42" // cookie
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"
		"\xaa\xbb\xcc\xdd"; //extra garbage
	static const uint8_t old_ind[] =
		"\x14\x55\x00\x00"
		"\xfe\xdc\xba\x98" // NO cookie
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"; //extra garbage
	static const uint8_t fpr_resp[] =
		"\x15\x55\x00\x10"
		"\x21\x12\xA4\x42" // cookie
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"
		"\x00\x06\x00\x04" // dummy USERNAME header
		"\x41\x42\x43\x44"
		"\x80\x21\x00\x04" // FINGERPRINT header
		"\xdc\x8d\xa7\x74" // CRC32
		"\xcc\xdd\xee\xff"; // extra garbage
	static const uint8_t bad1[32] =
		"\x15\x55\x00\x08"
		"\x21\x12\xA4\x42" // cookie
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"
		"\x00\x06\x00\x05" // too big attribute for message
		"\x11\x22\x33\x44"
		"\x55\x66\x77\x88";
	static const uint8_t bad2[24] =
		"\x15\x55\x00\x05" // invalid message length
		"\x21\x12\xA4\x42"
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"
		"\x00\x06\x00\x01";
	static const uint8_t bad3[27] =
		"\x15\x55\x00\x08"
		"\x21\x12\xA4\x42"
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"
		"\x00\x06\x00\x03"
		"\x11\x22\x33"; // missing padding
	static const uint8_t bad_crc[] =
		"\x15\x55\x00\x08"
		"\x21\x12\xA4\x42"
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"
		"\x80\x21\x00\x04" // FINGERPRINT header
		"\x04\x91\xcd\x78"; // CRC32
	static uint8_t bad_crc_offset[] =
		"\x15\x55\x00\x10"
		"\x21\x12\xA4\x42"
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x20\x67\xc4\x09"
		"\x80\x21\x00\x04" // FINGERPRINT header
		"\x00\x00\x00\x00"
		"\x00\x06\x00\x04"
		"\x41\x42\x43\x44";

	static const uint8_t transid[12] =
		"\x76\x54\x32\x10\xfe\xdc\xba\x98\x76\x54\x32\x10";
	static const uint8_t badid[12] =
		"\x76\x54\x32\x10\xfe\xdc\xca\x98\x76\x54\x32\x10";
	bool error;

	if (stun_validate (NULL, 0) != 0)
		fatal ("0 bytes test failed");
	if (stun_validate ("\xf0", 1) >= 0)
		fatal ("1 byte test failed");
	static_check (simple_resp, 20);
	static_check (old_ind, 20);
	static_check (fpr_resp, 36);
	if (stun_demux (simple_resp))
		fatal ("Missing CRC test failed");
	if (stun_demux (old_ind))
		fatal ("Missing cookie test failed");
	if (!stun_demux (fpr_resp))
		fatal ("Good CRC test failed");
	if (stun_demux (bad_crc))
		fatal ("Bad CRC test failed");
	if (stun_demux (bad_crc_offset))
		fatal ("Bad CRC offset test failed");

	if (stun_validate (bad1, sizeof (bad1)) >= 0)
		fatal ("Badness 1 test failed");
	if (stun_validate (bad2, sizeof (bad2)) >= 0)
		fatal ("Badness 2 test failed");
	if (stun_validate (bad3, sizeof (bad3)) != 0)
		fatal ("Badness 3 test failed");

	if (stun_get_class (simple_resp) != 3)
		fatal ("Class test failed");
	if (stun_get_method (simple_resp) != 0x525)
		fatal ("Method test failed");

	if (stun_match_answer (simple_resp, 0x524, transid, &error))
		fatal ("Answer method mismatching test failed");
	if (stun_match_answer (old_ind, 0x525, transid, &error))
		fatal ("Answer class mismatching test failed");
	if (stun_match_answer (simple_resp, 0x525, badid, &error))
		fatal ("Answer transid mismatching test failed");
	if (!stun_match_answer (simple_resp, 0x525, transid, &error))
		fatal ("Answer matching test failed");
	if (!error)
		fatal ("Answer error flag test failed");
	return 0;
}
