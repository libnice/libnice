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
#include <pthread.h>

static inline
void stun_set_type (stun_hdr_t *h, stun_class_t c, stun_method_t m)
{
	assert (c < 4);
	assert (m < (1 << 12));

	uint16_t t = ((c << 7) & 0x0100) | ((c << 4) & 0x0010)
	           | ((m << 2) & 0x3e00) | ((m << 1) & 0x00e0) | (m & 0x000f);

	assert (t < (1 << 14));
	h->msg_type = htons (t);
}


void stun_make_transid (stun_transid_t id)
{
	static struct
	{
		pthread_mutex_t lock;
		uint64_t counter;
	} store = { PTHREAD_MUTEX_INITIALIZER, 0 };
	uint64_t counter;

	pthread_mutex_lock (&store.lock);
	counter = store.counter++;
	pthread_mutex_unlock (&store.lock);

	/* FIXME: generate a random key and use HMAC or something... */
	memset (id, 0, 4);
	memcpy (id + 4, &counter, 8);
}


/**
 * Initializes a STUN message structure, with no attributes.
 * @param c STUN message class (host byte order)
 * @param m STUN message method (host byte order)
 * @param id 12-bytes transaction ID
 */
void stun_init (stun_msg_t *msg, stun_class_t c, stun_method_t m,
                const stun_transid_t id)
{
	stun_set_type (&msg->hdr, c, m);
	msg->hdr.msg_len = 0;
	msg->hdr.msg_cookie = htonl (STUN_COOKIE);
	memcpy (msg->hdr.msg_id, id, sizeof (msg->hdr.msg_id));
}


/**
 * Initializes a STUN message structure with no attributes,
 * in response to a given valid STUN request messsage.
 * STUN method and transaction ID are copied from the request message.
 *
 * @param ans [OUT] STUN message buffer
 * @param req STUN message query
 *
 * ans == req is allowed.
 */
void stun_init_response (stun_msg_t *ans, const void *req)
{
	//assert (stun_valid (req));
	assert (stun_get_class (req) == STUN_REQUEST);

	stun_init (ans, STUN_RESPONSE, stun_get_method (req),
	           ((const uint8_t *)req) + 8);
}


/**
 * Reserves room for appending an attribute to an unfinished STUN message.
 * @param type message type (host byte order)
 * @param length attribute payload byte length
 * @return a pointer to an unitialized buffer of <length> bytes to
 * where the attribute payload must be written, or NULL if there is not
 * enough room in the STUN message buffer. Return value is always on a
 * 32-bits boundary.
 */
static void *
stun_append (stun_msg_t *msg, stun_attr_type_t type, size_t length)
{
	uint16_t mlen = ntohs (msg->hdr.msg_len);
	assert (stun_padding (mlen) == 0);

	if (length > 0xffff)
		return NULL;
	if ((((size_t)mlen) + 4 + length) > sizeof (msg->buf))
		return NULL;

	stun_attr_hdr_t *a = (stun_attr_hdr_t *)(msg->buf + mlen);
	a->attr_type = htons (type);
	a->attr_len = htons (length);

	mlen += 4 + length;
	/* Add padding if needed */
	memset (msg->buf + mlen, ' ', stun_padding (length));
	mlen += stun_padding (length);

	msg->hdr.msg_len = htons (mlen);
	return a + 1;
}


#if 0
/**
 * Appends an attribute consisting of a 32-bits value to a STUN message.
 * @param type attribute type (host byte order)
 * @param value payload (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
int
stun_append32 (stun_msg_t *msg, stun_attr_type_t type, uint32_t value)
{
	void *ptr = stun_append (msg, type, sizeof (value));
	if (ptr == NULL)
		return ENOBUFS;

	memcpy (ptr, &(uint32_t){ htonl (value) }, sizeof (value));
	return 0;
}
#endif


/**
 * Appends an attribute from memory.
 * @param type attribute type (host byte order)
 * @param data memory address to copy payload from
 * @param len attribute payload length
 * @return 0 on success, ENOBUFS on error.
 */
static int
stun_append_bytes (stun_msg_t *restrict msg, stun_attr_type_t type,
                   const void *data, size_t len)
{
	void *ptr = stun_append (msg, type, len);
	if (ptr == NULL)
		return ENOBUFS;

	memcpy (ptr, data, len);
	return 0;
}


/**
 * Appends an attribute from a nul-terminated string.
 * @param type attribute type (host byte order)
 * @param str nul-terminated string
 * @return 0 on success, ENOBUFS on error.
 */
static int
stun_append_string (stun_msg_t *restrict msg, stun_attr_type_t type,
                    const char *str)
{
	return stun_append_bytes (msg, type, str, strlen (str));
}


/**
 * Appends an attribute consisting of a network address to a STUN message.
 * @param type attribyte type (host byte order)
 * @param addr socket address to convert into an attribute
 * @param addrlen byte length of socket address
 * @return 0 on success, ENOBUFS if the message buffer overflowed,
 * EAFNOSUPPORT is the socket address family is not supported,
 * EINVAL if the socket address length is too small w.r.t. the address family.
 */
int
stun_append_addr (stun_msg_t *restrict msg, stun_attr_type_t type,
                  const struct sockaddr *restrict addr, socklen_t addrlen)
{
	if (addrlen < sizeof (struct sockaddr))
		return EINVAL;

	const void *pa;
	uint16_t alen, port;
	uint8_t family;

	switch (addr->sa_family)
	{
		case AF_INET:
		{
			const struct sockaddr_in *ip4 = (const struct sockaddr_in *)addr;
			if (addrlen < sizeof (*ip4))
				return EINVAL;

			family = 1;
			port = ip4->sin_port;
			alen = 4;
			pa = &ip4->sin_addr;
			break;
		}

		case AF_INET6:
		{
			const struct sockaddr_in6 *ip6 = (const struct sockaddr_in6 *)addr;
			if (addrlen < sizeof (*ip6))
				return EINVAL;

			family = 2;
			port = ip6->sin6_port;
			alen = 16;
			pa = &ip6->sin6_addr;
			break;
		}

		default:
			return EAFNOSUPPORT;
	}

	uint8_t *ptr = stun_append (msg, type, 4 + alen);
	if (ptr == NULL)
		return ENOBUFS;

	ptr[0] = 0;
	ptr[1] = family;
	memcpy (ptr + 2, &port, 2);
	memcpy (ptr + 4, pa, alen);
	return 0;
}


/**
 * Appends an attribute consisting of a xor'ed network address.
 * @param type attribyte type (host byte order)
 * @param addr socket address to convert into an attribute
 * @param addrlen byte length of socket address
 * @return 0 on success, ENOBUFS if the message buffer overflowed,
 * EAFNOSUPPORT is the socket address family is not supported,
 * EINVAL if the socket address length is too small w.r.t. the address family.
 */
int stun_append_xor_addr (stun_msg_t *restrict msg, stun_attr_type_t type,
                          const struct sockaddr *restrict addr,
                          socklen_t addrlen)
{
	union
	{
		struct sockaddr addr;
		char buf[addrlen];
	} xor;
	int val;

	memcpy (xor.buf, addr, addrlen);
	val = stun_xor_address (msg, &xor.addr, addrlen);
	if (val)
		return val;

	return stun_append_addr (msg, type, &xor.addr, addrlen);
}


static size_t
stun_finish_long (stun_msg_t *restrict msg,
                  const char *realm, const char *username,
                  const void *key, size_t keylen,
                  const void *nonce, size_t noncelen)
{
	void *sha = NULL;

	if (realm != NULL)
	{
		int val = stun_append_string (msg, STUN_REALM, realm);
		if (val)
			return val;
	}

	if (username != NULL)
	{
		int val = stun_append_string (msg, STUN_USERNAME, username);
		if (val)
			return val;
	}

	if (nonce != NULL)
	{
		int val = stun_append_bytes (msg, STUN_NONCE, nonce, noncelen);
		if (val)
			return val;
	}

	if (key != NULL)
	{
		sha = stun_append (msg, STUN_MESSAGE_INTEGRITY, 20);
		if (sha == NULL)
			return ENOBUFS;
	}

	void *crc = stun_append (msg, STUN_FINGERPRINT, 4);
	if (crc == NULL)
		return ENOBUFS;

	if (sha != NULL)
		stun_sha1 (msg, sha, key, keylen);

	uint32_t fpr = htonl (stun_fingerprint (&msg->hdr));
	memcpy (crc, &fpr, sizeof (fpr));
	return sizeof (msg->hdr) + ntohs (msg->hdr.msg_len);
}


/**
 * Finishes a STUN message structure before sending it, and
 * authenticates it with short-term credentials.
 * No further attributes shall be added.
 *
 * @return length of the message in bytes, or 0 on error (and sets errno).
 */
size_t stun_finish_short (stun_msg_t *restrict msg,
                          const char *username, const char *password,
                          const void *nonce, size_t noncelen)
{
	size_t passlen = password ? strlen (password) : 0;
	return stun_finish_long (msg, NULL, username, password, passlen,
	                         nonce, noncelen);
}


/**
 * Finishes a STUN message structure before sending it.
 * No further attributes shall be added.
 *
 * @return length of the message in bytes, or 0 on error (and sets errno).
 */
size_t stun_finish (stun_msg_t *m)
{
	return stun_finish_short (m, NULL, NULL, NULL, 0);
}


