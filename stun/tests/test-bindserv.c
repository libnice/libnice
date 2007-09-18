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
#include "stun/bind.h"
#include "stun/stun-msg.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>

#undef NDEBUG /* ensure assertions are built-in */
#include <assert.h>


int main (void)
{
  struct sockaddr_in ip4;
  stun_msg_t buf;
  ssize_t val;
  size_t len;
  static const uint8_t req[] =
    "\x00\x01" "\x00\x00"
    "\x00\x01\x02\x03\x04\x05\x06\x07"
    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";

  memset (&ip4, 0, sizeof (ip4));
  ip4.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
  ip4.sin_len = sizeof (addr);
#endif
  ip4.sin_port = htons (12345);
  ip4.sin_addr.s_addr = htonl (0x7f000001);

  /* Same with too small response buffer */
  stun_init_request (buf, STUN_BINDING);
  len = sizeof (buf);
  stun_finish (buf, &len);

  len = 20 + 12 + 4 + stun_align (strlen (PACKAGE_STRING)) + 7;
  val = stun_bind_reply (buf, &len, buf,
                         (struct sockaddr *)&ip4, sizeof (ip4), false);
  assert (val == ENOBUFS);
  assert (len == 0);

  /* Same with too small response buffer */
  stun_init_request (buf, STUN_BINDING);
  stun_append_string (buf, sizeof (buf), 0x666, "Unknown attribute!");
  len = sizeof (buf);
  stun_finish (buf, &len);

  len = 20 + 4 + stun_align (strlen (PACKAGE_STRING)) + 7;
  val = stun_bind_reply (buf, &len, buf,
                         (struct sockaddr *)&ip4, sizeof (ip4), false);
  assert (val == ENOBUFS);
  assert (len == 0);

  return 0;
}
