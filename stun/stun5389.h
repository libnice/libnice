/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
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


#ifndef _STUN_5389_H
#define _STUN_5389_H


#ifdef _WIN32
#include "win32_common.h"
#else
# include <stdint.h>
# include <stdbool.h>
#endif
# include <sys/types.h>

#include "stunmessage.h"
/*
 * Computes the FINGERPRINT checksum of a STUN message.
 * @param msg pointer to the STUN message
 * @param len size of the message from header (inclusive) and up to
 *            FINGERPRINT attribute (inclusive)
 *
 * @return fingerprint value in <b>host</b> byte order.
 */
uint32_t stun_fingerprint (const uint8_t *msg, size_t len,
    bool wlm2009_stupid_crc32_typo);

StunMessageReturn stun_message_append_software (StunMessage *msg,
    const char *software);


#endif /* _STUN_5389_H */

