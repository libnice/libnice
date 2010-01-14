/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
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

#ifndef _STUN_HMAC_H
#define _STUN_HMAC_H

#include "stunmessage.h"

/*
 * Computes the MESSAGE-INTEGRITY hash of a STUN message.
 * @param msg pointer to the STUN message
 * @param len size of the message from header (inclusive) and up to
 *            MESSAGE-INTEGRITY attribute (inclusive)
 * @param sha output buffer for SHA1 hash (20 bytes)
 * @param key HMAC key
 * @param keylen HMAC key bytes length
 *
 * @return fingerprint value in <b>host</b> byte order.
 */
void stun_sha1 (const uint8_t *msg, size_t len, size_t msg_len,
    uint8_t *sha, const void *key, size_t keylen, int padding);

/*
 * SIP H(A1) computation
 */

void stun_hash_creds (const uint8_t *realm, size_t realm_len,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    unsigned char md5[16]);
/*
 * Generates a pseudo-random secure STUN transaction ID.
 */
void stun_make_transid (StunTransactionId id);


#endif /* _STUN_HMAC_H */
