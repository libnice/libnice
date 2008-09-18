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

#ifndef STUN_UTILS_H
# define STUN_UTILS_H 1

/**
 * @file utils.h
 * @brief STUN client generic utility functions
 */

#include "stunmessage.h"

#include <sys/types.h>
#include <sys/socket.h>

# ifdef __cplusplus
extern "C" {
# endif


int sockaddrcmp (const struct sockaddr *a, const struct sockaddr *b);

bool stun_optional (uint16_t t);

size_t stun_padding (size_t l);

size_t stun_align (size_t l);

uint16_t stun_getw (const uint8_t *ptr);

void stun_debug_enable (void);
void stun_debug_disable (void);
void stun_debug (const char *fmt, ...);
void stun_debug_bytes (const void *data, size_t len);

int stun_xor_address (const StunMessage *msg,
    struct sockaddr *restrict addr, socklen_t addrlen,
    uint32_t magic_cookie);

int stun_memcmp (const StunMessage *msg, stun_attr_type_t type,
    const void *data, size_t len);

int stun_strcmp (const StunMessage *msg, stun_attr_type_t type, const char *str);

void *stun_setw (uint8_t *ptr, uint16_t value);

void stun_set_type (uint8_t *h, stun_class_t c, stun_method_t m);

const char *stun_strerror (stun_error_t code);

# ifdef __cplusplus
}
# endif

#endif /* !STUN_UTILS_H */
