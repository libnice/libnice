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
#include <netinet/in.h>

#include "stun/stun-msg.h"
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


static void validate (const uint8_t *msg, unsigned len)
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


/* Tests for generic message validation routines */
static void test_message (void)
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
		"\x80\x28\x00\x04" // FINGERPRINT header
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
		"\x80\x28\x00\x04" // FINGERPRINT header
		"\x04\x91\xcd\x78"; // CRC32
	static uint8_t bad_crc_offset[] =
		"\x15\x55\x00\x10"
		"\x21\x12\xA4\x42"
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x20\x67\xc4\x09"
		"\x80\x28\x00\x04" // FINGERPRINT header
		"\x00\x00\x00\x00"
		"\x00\x06\x00\x04"
		"\x41\x42\x43\x44";

	if (stun_validate (NULL, 0) != 0)
		fatal ("0 bytes test failed");
	if (stun_validate ((uint8_t *)"\xf0", 1) >= 0)
		fatal ("1 byte test failed");
	validate (simple_resp, 20);
	validate (old_ind, 20);
	validate (fpr_resp, 36);
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
}


/* Tests for message attribute parsing */
static void test_attribute (void)
{
	static const uint8_t acme[] =
		"\x15\x55\x00\x64" // <-- update message length if needed!!
		"\x21\x12\xA4\x42" // cookie
		"\x76\x54\x32\x10"
		"\xfe\xdc\xba\x98"
		"\x76\x54\x32\x10"

		/* FF01: empty */
		"\xff\x01\x00\x00"

		/* FF02: address of unknown family, 32-bits */
		"\xff\x02\x00\x04"
		"\x41\x42\x43\x44"

		/* FF03: too short IPv6 address */
		"\xff\x03\x00\x06"
		"\x00\x02\x12\x34"
		"\x20\x01\x0d\xb8"

		/* FF04: valid IPv4 address, 64-bits */
		"\xff\x04\x00\x08"
		"\x00\x01\x12\x34"
		"\xc0\x00\x02\x01"

		/* FF05: too long IPv4 address */
		"\xff\x05\x00\x0A"
		"\x00\x01\x12\x34"
		"\xc0\x00\x02\x01"
		"\x66\x60\x00\x00"

		/* FF06: valid xor'd IPv6 address, 160-bits */
		"\xff\x06\x00\x14"
		"\x00\x02\x12\x34"
		"\x01\x13\xa9\xfa"
		"\xa8\xf9\x8c\xff"
		"\x20\x26\x74\x48"
		"\x8c\x9a\xec\xfd"

		/* MESSAGE-INTEGRITY attribute */
		"\x00\x08\x00\x14"
		"\x20\x10\xee\x8d"
		"\x61\xc9\x3e\x46"
		"\xbe\x41\xad\x5c"
		"\xad\x38\xaa\x4c"
		"\xe8\xf1\xaf\x07"
		;

	union
	{
		struct sockaddr sa;
		struct sockaddr_in6 s6;
	} addr;
	socklen_t addrlen;
	uint32_t dword;
	uint64_t qword;
	char str[5];

	printf ("Attribute test message length: %u\n", sizeof (acme));

	if (stun_validate (acme, sizeof (acme)) <= 0)
		fatal ("Attributes tests message broken");

	if (stun_present (acme, 0xff00))
		fatal ("Absent attribute test failed");
	if (!stun_present (acme, 0xff01))
		fatal ("Present attribute test failed");

	if (stun_find_flag (acme, 0xff00) != ENOENT)
		fatal ("Absent flag test failed");
	if (stun_find_flag (acme, 0xff01) != 0)
		fatal ("Flag test failed");
	if (stun_find_flag (acme, 0xff02) != EINVAL)
		fatal ("Too big flag test failed");

	if (stun_find32 (acme, 0xff00, &dword) != ENOENT)
		fatal ("Absent dword test failed");
	if (stun_find32 (acme, 0xff01, &dword) != EINVAL)
		fatal ("Bad dword test failed");
	if (stun_find32 (acme, 0xff02, &dword) != 0)
		fatal ("Double-word test failed");

	if (stun_find64 (acme, 0xff00, &qword) != ENOENT)
		fatal ("Absent qword test failed");
	if (stun_find64 (acme, 0xff01, &qword) != EINVAL)
		fatal ("Bad qword test failed");
	if (stun_find64 (acme, 0xff04, &qword) !=0)
		fatal ("Quad-word test failed");

	if (stun_find_string (acme, 0xff00, str, sizeof (str)) != -1)
		fatal ("Absent string test failed");
	if ((stun_find_string (acme, 0xff02, str, 1) != 4) || (str[0] != 'A'))
		fatal ("String buffer underflow test failed");
	if ((stun_find_string (acme, 0xff02, str, sizeof (str)) != 4)
	 || strcmp (str, "ABCD"))
		fatal ("String test failed");

	addrlen = sizeof (addr);
	if (stun_find_addr (acme, 0xff01, &addr.sa, &addrlen) != EINVAL)
		fatal ("Too short addres test failed");
	addrlen = sizeof (addr);
	if (stun_find_addr (acme, 0xff02, &addr.sa, &addrlen) != EAFNOSUPPORT)
		fatal ("Unknown address family test failed");
	addrlen = sizeof (addr);
	if (stun_find_addr (acme, 0xff03, &addr.sa, &addrlen) != EINVAL)
		fatal ("Too short IPv6 address test failed");
	addrlen = sizeof (addr);
	if (stun_find_addr (acme, 0xff04, &addr.sa, &addrlen) != 0)
		fatal ("IPv4 address test failed");
	addrlen = sizeof (addr);
	if (stun_find_addr (acme, 0xff05, &addr.sa, &addrlen) != EINVAL)
		fatal ("Too big IPv4 address test failed");
	addrlen = sizeof (addr);
	if (stun_find_xor_addr (acme, 0xff06, &addr.sa, &addrlen)
	 || memcmp (&addr.s6.sin6_addr, "\x20\x01\x0d\xb8""\xde\xad\xbe\xef"
	                                "\xde\xfa\xce\xd0""\xfa\xce\xde\xed", 16))
		fatal ("IPv6 address test failed");

	if (stun_verify_key (acme, "good_guy", 8) != 0)
		fatal ("Good secret HMAC test failed");
	if (stun_verify_key (acme, "bad__guy", 8) != EPERM)
		fatal ("Bad secret HMAC test failed");
}


int main (void)
{
	test_message ();
	test_attribute ();
	return 0;
}
