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

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include "stun-msg.h"

#include <string.h>
#include <assert.h>

void stun_sha1 (const uint8_t *msg, uint8_t *sha, const void *key, size_t keylen)
{
	size_t mlen = stun_length (msg);
	assert (mlen >= 32);

	/*
	 * + 20 bytes for STUN header
	 * - 24 bytes for MESSAGE-INTEGRITY attribute
	 * -  8 bytes for FINGERPRINT attribute
	 */
	mlen -= 12;

	HMAC (EVP_sha1 (), key, keylen, msg, mlen, sha, NULL);
}


void stun_make_transid (stun_transid_t id)
{
	/*
	 * transid = (HMAC_SHA1 (secret, counter) >> 64)
	 * This consumes sizeof (secret) bytes of entropy every 2^64 messages.
	 */
	static struct
	{
		pthread_mutex_t lock;
		uint64_t counter;
		uint8_t secret[16];
	} store = { PTHREAD_MUTEX_INITIALIZER, 0, "" };

	union
	{
		uint64_t value;
		uint8_t  bytes[1];
	} counter;
	uint8_t  key[16], sha[20];

	pthread_mutex_lock (&store.lock);

	counter.value = store.counter++;
	if (counter.value == 0)
		RAND_pseudo_bytes (store.secret, sizeof (store.secret));
	memcpy (key, store.secret, sizeof (key));

	pthread_mutex_unlock (&store.lock);

	/* Computes hash out of contentious area */
	HMAC (EVP_sha1 (), key, sizeof (key), counter.bytes, sizeof (counter),
	      sha, NULL);
	memcpy (id, sha, 12);
}
