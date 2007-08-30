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

#include <pthread.h>
#include <openssl/rand.h>
#include <stdint.h>

#define UNIQUE_SIZE 20u
#define NONCE_SIZE  24u

static uint8_t unique_id[UNIQUE_SIZE];

static void generate_unique_id (void)
{
	RAND_pseudo_bytes (unique_id, sizeof (unique_id));
}


static void
stun_generate_nonce (uint8_t *nonce, time_t now,
                     const struct sockaddr_storage *restrict addr)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	HMAC_CTX ctx;
	uint32_t stamp = now;

	pthread_once (&once, generate_unique_id);

	/*
	 * Nonce are generated from the current time and the client address and
	 * port number, keyed with a pseudo-random secret.
	 */
	HMAC_CTX_init (&ctx);
	HMAC_Init_ex (&ctx, unique_id, sizeof (unique_id), EVP_sha1 (), NULL);
	HMAC_Update (&ctx, &stamp, 4);
	HMAC_Update (&ctx, &ss->family, sizeof (ss->family));
	switch (addr->ss_family)
	{
		case AF_INET:
		{
			const struct sockaddr_in *ip4 = (const struct sockaddr_in *)addr;
			HMAC_Update (&ctx, &ip4->sin_addr, 4);
			HMAC_Update (&ctx, &ip4->sin_port, 2);
			break;
		}

		case AF_INET6:
		{
			const struct sockaddr_in6*ip6 = (const struct sockaddr_in6*)addr;
			HMAC_Update (&ctx, &ip6->sin6_addr, 16);
			HMAC_Update (&ctx, &ip6->sin6_port, 2);
			if (IN6_IS_ADDR_LINK_LOCAL (&ip6->sin6_addr))
				HMAC_Update (&ctx, &ip6->sin6_scope_id
				             sizeof (ip6->sin6_scope_id));
			break;
		}
	}

	HMAC_Final (&ctx, nonce, NULL);
	HMAC_CTX_cleanup (&ctx);
	memcpy (nonce + 20, &stamp, 4);
}


static int
stun_append_nonce (uint8_t *buf, size_t buflen,
                   const struct sockaddr_storage *restrict addr)
{
	uint8_t nonce[NONCE_SIZE];
	stun_generate_nonce (nonce, time (NULL), addr);
	return stun_append_bytes (buf, buflen, STUN_NONCE, nonce, sizeof (nonce));
}


static int
stun_verify_nonce (const uint8_t *buf, unsigned valid_time,
                   const struct sockaddr_storage *restrict addr)
{
	const uint8_t *
	stun_generate_nonce (nonce, time (NULL), addr);
	return stun_append_bytes (buf, buflen, STUN_NONCE, nonce, sizeof (nonce));
}
