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

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#ifndef NDEBUG
static inline
int stun_valid (const void *m)
{
	size_t length = 20u + stun_length (m);
	return stun_validate (m, length) == (ssize_t)length;
}
#endif

/**
 * Verifies that a packet is a valid STUN message.
 *
 * @return actual byte length of the message if valid (>0),
 * 0 if it the packet is incomplete or -1 in case of other error.
 */
ssize_t stun_validate (const void *m, size_t len)
{
	const uint8_t *ptr = m;

	DBG ("Validating message @%p (%u bytes):\n", m, (unsigned)len);
	if (len < 1)
	{
		DBG (" No data!\n");
		return 0;
	}

	if (ptr[0] >> 6)
	{
		DBG (" RTP or other non-protocol packet!\n");
		return -1; // RTP or other non-STUN packet
	}

	if (len < 4)
	{
		DBG (" Incomplete STUN message header!\n");
		return 0;
	}

	size_t mlen = 20 + stun_length (ptr);
	if (stun_padding (mlen))
	{
		DBG (" Invalid message length: %u!\n", (unsigned)mlen);
		return -1; // wrong padding
	}

	if (len < mlen)
	{
		DBG (" Incomplete STUN message: %u of %u bytes!\n", len,
		     (unsigned)mlen);
		return 0; // partial message
	}

	ptr += 20;

	/* from then on, we know we have the entire packet in buffer */
	for (const uint8_t *end = ptr + (mlen - 20); end > ptr;)
	{
		ptr += 4;
 		/* thanks to padding check, if (end > ptr) then there is not only one
		 * but at least 4 bytes left */
		assert ((end - ptr) >= 0);

		size_t alen = stun_align (stun_getw (ptr - 2));
		ptr += alen;
		if ((end - ptr) < 0)
		{
			DBG (" No room for STUN attribute: %u instead of %u bytes!\n",
			     (unsigned)(end - (ptr - alen)), (unsigned)alen);
			return -1; // no room for attribute value + padding
		}
	}

	DBG (" Valid message of %u bytes!\n", mlen);
	return mlen;
}


/**
 * Looks for an attribute in a *valid* STUN message.
 * @param msg message buffer
 * @param type STUN attribute type (host byte order)
 * @param palen [OUT] pointer to store the byte length of the attribute
 * @return a pointer to the start of the attribute payload if found,
 * otherwise NULL.
 */
static const void *
stun_find (const void *restrict msg, stun_attr_type_t type,
               uint16_t *restrict palen)
{
	const uint8_t *ptr = msg;
	assert (msg != NULL);
	assert (stun_valid (msg));
	assert (palen != NULL);

	size_t length = stun_length (ptr);
	ptr += 20;

	while (length > 0)
	{
		assert (length >= 4);
		uint16_t atype = stun_getw (ptr);
		unsigned alen = stun_length (ptr);

		length -= 4;
		ptr += 4;

		assert (length >= stun_align (alen));
		if (atype == type)
		{
			assert (alen <= 0xffff);
			*palen = alen;
			return ptr;
		}

		alen = stun_align (alen);
		length -= alen;
		ptr += alen;
	}

	return NULL;
}


#if 0
/**
 * Extracts a 32-bits attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param pval [OUT] where to store the host byte ordered value
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload was not 32-bits.
 */
static int
stun_find32 (const void *restrict msg, stun_attr_type_t type,
                 uint32_t *restrict pval)
{
	uint16_t len;
	const void *ptr = stun_find (msg, type, &len);
	if (ptr == NULL)
		return ENOENT;

	if (len == 4)
	{
		uint32_t val;
		memcpy (&val, ptr, sizeof (val));
		*pval = ntohl (val);
		return 0;
	}
	return EINVAL;
}
#endif


/**
 * Extracts a network address attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param addr [OUT] where to store the socket address
 * @param addrlen [IN/OUT] pointer to the size of the socket address
 * buffer upon entry, set to the length of the extracted socket
 * address upon return,
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload size was wrong or addrlen too small,
 * EAFNOSUPPORT if address family is unknown.
 */
int
stun_find_addr (const void *restrict msg, stun_attr_type_t type,
                struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	uint16_t len;
	const uint8_t *ptr = stun_find (msg, type, &len);
	if (ptr == NULL)
		return ENOENT;

	if (len < 4)
		return EINVAL;

	assert (addrlen != NULL);
	switch (ptr[1])
	{
		case 1:
		{
			struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
			if ((*addrlen < sizeof (*ip4)) || (len != 8))
			{
				*addrlen = sizeof (*ip4);
				return EINVAL;
			}

			memset (ip4, 0, *addrlen);
			ip4->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
			ip4->sin_len =
#endif
			*addrlen = sizeof (*ip4);
			memcpy (&ip4->sin_port, ptr + 2, 2);
			memcpy (&ip4->sin_addr, ptr + 4, 4);
			return 0;
		}

		case 2:
		{
			struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
			if ((*addrlen < sizeof (*ip6)) || (len != 20))
			{
				*addrlen = sizeof (*ip6);
				return EINVAL;
			}

			memset (ip6, 0, *addrlen);
			ip6->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
			ip6->sin6_len =
#endif
			*addrlen = sizeof (*ip6);
			memcpy (&ip6->sin6_port, ptr + 2, 2);
			memcpy (&ip6->sin6_addr, ptr + 4, 16);
			return 0;
		}
	}

	return EAFNOSUPPORT;
}


int stun_xor_address (const void *restrict msg,
                      struct sockaddr *restrict addr, socklen_t addrlen)
{
	switch (addr->sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
			if (addrlen < sizeof (*ip4))
				return EINVAL;

			ip4->sin_port ^= htons (STUN_COOKIE >> 16);
			ip4->sin_addr.s_addr ^= htonl (STUN_COOKIE);
			return 0;
		}

		case AF_INET6:
		{
			struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
			if (addrlen < sizeof (*ip6))
				return EINVAL;

			ip6->sin6_port ^= htons (STUN_COOKIE >> 16);
			for (unsigned i = 0; i < 16; i++)
				ip6->sin6_addr.s6_addr[i] ^= ((uint8_t *)msg)[4 + i];
			return 0;
		}
	}
	return EAFNOSUPPORT;
}


/**
 * Extracts an obfuscated network address attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param addr [OUT] where to store the socket address
 * @param addrlen [IN/OUT] pointer to the size of the socket address
 * buffer upon entry, set to the length of the extracted socket
 * address upon return,
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload size was wrong or addrlen too small,
 * EAFNOSUPPORT if address family is unknown.
 */
int
stun_find_xor_addr (const void *restrict msg, stun_attr_type_t type,
                    struct sockaddr *restrict addr,
                    socklen_t *restrict addrlen)
{
	int val = stun_find_addr (msg, type, addr, addrlen);
	if (val)
		return val;

	return stun_xor_address (msg, addr, *addrlen);
}


static bool check_cookie (const void *msg)
{
	uint32_t value;
	memcpy (&value, ((const uint8_t *)msg) + 4, sizeof (value));
	return value == htonl (STUN_COOKIE);
}


static const uint8_t *stun_end (const void *msg)
{
	return ((const uint8_t *)msg) + 20 + stun_length (msg);
}


/**
 * Checks whether a packet on a mutiplexed STUN/non-STUN channel looks like a
 * STUN message. It is assumed that stun_validate succeeded first (i.e.
 * returned a stricly positive value).
 *
 * @return true if STUN message with cookie and fingerprint, 0 otherwise.
 */
bool stun_demux (const void *msg)
{
	assert (stun_valid (msg));

	DBG ("Demultiplexing STUN message @%p\n", msg);

	/* Checks cookie */
	if (!check_cookie (msg))
	{
		DBG (" No STUN cookie!\n");
		return 0;
	}

	/* Looks for FINGERPRINT */
	uint16_t fprlen;
	const void *fpr = stun_end (msg) - 4;
	if ((fpr != stun_find (msg, STUN_FINGERPRINT, &fprlen)) || (fprlen != 4))
	{
		DBG (" No FINGERPRINT attribute!\n");
		return 0;
	}

	/* Checks FINGERPRINT */
	uint32_t crc32 = htonl (stun_fingerprint (msg));
	if (memcmp (fpr, &crc32, 4))
	{
		DBG (" Incorrect message fingerprint (expected: 0x%08x)!\n",
		     stun_fingerprint (msg));
		return 0;
	}

	DBG (" Valid multiplexed STUN message!\n");
	return 1;
}


/**
 * @param msg valid STUN message
 * @param key HMAC shared secret key pointer
 * @param keylen HMAC shared secret key byte length
 * @return 0 if the message integrity has been successfully verified with the
 * specified key. EPERM if the hash was incorrect. ENOENT if there was no
 * valid MESSAGE-INTEGRITY attribute.
 */
int
stun_verify_key (const void *msg, const void *key, size_t keylen)
{
	uint8_t sha[20];
	uint16_t hlen;

	DBG ("Authenticating STUN message @%p\n", msg);

	const uint8_t *hash = stun_end (msg) - 20;
	if (stun_demux (msg))
		hash -= 8; // room for FINGERPRINT at the end

	if ((stun_find (msg, STUN_MESSAGE_INTEGRITY, &hlen) != hash)
	 || (hlen != 20))
	{
		DBG (" No MESSAGE-INTEGRITY attribute!\n");
		return ENOENT;
	}

	stun_sha1 (msg, sha, key, keylen);
	if (memcmp (sha, hash, sizeof (sha)))
	{
		DBG (" Message HMAC-SHA1 fingerprint mismatch!\n");
		return EPERM;
	}

	DBG (" Message authenticated successfully!\n");
	return 0;
}


int stun_verify_password (const void *msg, const char *pw)
{
	assert (msg != NULL);
	assert (pw != NULL);
	return stun_verify_key (msg, pw, strlen (pw));
}


/**
 * @param msg valid STUN message
 * @param method STUN method number (host byte order)
 * @param id STUN transaction id
 * @param error [OUT] set to true iif the response is an error response
 *
 * @return true if and only if the message is a response or an error response
 * with the STUN cookie and specified method and transaction identifier.
 */
bool
stun_match_answer (const void *msg, stun_method_t method,
                   const stun_transid_t id, bool *restrict error)
{
	assert (stun_valid (msg));
	assert (error != NULL);

	switch (stun_get_class (msg))
	{
		case STUN_REQUEST:
		case STUN_INDICATION:
			return false;

		case STUN_RESPONSE:
			*error = false;
			break;

		case STUN_ERROR:
			*error = true;
			break;
	}

	return (stun_get_method (msg) == method)
	    && check_cookie (msg)
	    && !memcmp (((const uint8_t *)msg) + 8, id, 12);
}


/**
 * Looks for unknown mandatory attributes in a valid STUN message.
 * @param msg valid STUN message
 * @param list [OUT] table pointer to store unknown attributes IDs
 * @param max size of the table in units of uint16_t
 * @return the number of unknown mandatory attributes up to max.
 */
unsigned
stun_find_unknown (const void *restrict msg, uint16_t *restrict list,
                   unsigned max)
{
	const uint8_t *ptr = msg;
	unsigned count = 0;
	uint16_t len = stun_length (ptr);

	assert (stun_valid (msg));
	ptr += 20;

	while ((len > 0) && (count < max))
	{
		uint16_t type = stun_getw (ptr);
		uint16_t alen = stun_length (ptr);
		ptr += 4 + alen;
		len -= 4 + alen;

		if (stun_optional (type))
			continue; /* non-mandatory attribute */
		if ((type >= STUN_MAPPED_ADDRESS)
		 && (type <= STUN_OLD_REFLECTED_FROM))
			continue;
		if ((type >= STUN_REALM) && (type <= STUN_NONCE))
			continue;
		if (type == STUN_XOR_MAPPED_ADDRESS)
			continue;

		DBG (" found unknown attribute: 0x%04x (%u bytes)\n",
		     (unsigned)type, (unsigned)alen);
		list[count++] = type;
	}

	DBG (" %u unknown mandatory attributes\n", count);
	return count;
}
