/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008-2009 Nokia Corporation. All rights reserved.
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

#ifndef STUN_UTILS_H
# define STUN_UTILS_H 1

/*
 * @file utils.h
 * @brief STUN client generic utility functions
 */

#include "stunmessage.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

# ifdef __cplusplus
extern "C" {
# endif

size_t stun_padding (size_t l);

size_t stun_align (size_t l);

uint16_t stun_getw (const uint8_t *ptr);

void *stun_setw (uint8_t *ptr, uint16_t value);

void stun_set_type (uint8_t *h, StunClass c, StunMethod m);

StunMessageReturn stun_xor_address (const StunMessage *msg,
    struct sockaddr_storage *addr, socklen_t addrlen,
    uint32_t magic_cookie);


# ifdef __cplusplus
}
# endif

#endif /* STUN_UTILS_H */
