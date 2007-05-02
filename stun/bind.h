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

#ifndef STUN_BIND_H
# define STUN_BIND_H 1

typedef struct stun_bind_s stun_bind_t;

# ifdef __cplusplus
extern "C" {
# endif

int stun_bind_run (int fd,
                   const struct sockaddr *restrict srv, socklen_t srvlen,
                   struct sockaddr *restrict addr, socklen_t *addrlen);
int stun_bind_start (stun_bind_t **restrict context, int fd,
                     const struct sockaddr *restrict srv,
                     socklen_t srvlen);
int stun_bind_resume (stun_bind_t *restrict context,
                      struct sockaddr *restrict addr, socklen_t *addrlen);
void stun_bind_cancel (stun_bind_t *restrict context);
int stun_bind_fd (const stun_bind_t *restrict context);
unsigned stun_bind_timeout (const stun_bind_t *restrict context);

# ifdef __cplusplus
}
# endif

#endif
