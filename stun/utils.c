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

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "stun-msg.h"
#include "trans.h"

/** Compares two socket addresses */
int sockaddrcmp (const struct sockaddr *a, const struct sockaddr *b)
{
  int res;

  res = a->sa_family - b->sa_family;
  if (res)
    return res;

  switch (a->sa_family)
  {
    case AF_INET:
    {
      const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
      const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
      res = memcmp (&a4->sin_addr, &b4->sin_addr, 4);
      if (res == 0)
        res = memcmp (&a4->sin_port, &b4->sin_port, 2);
      break;
    }

    case AF_INET6:
    {
      const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
      const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
      res = memcmp (&a6->sin6_addr, &b6->sin6_addr, 16);
      if (res == 0)
        res = a6->sin6_scope_id - b6->sin6_scope_id;
      if (res == 0)
        res = memcmp (&a6->sin6_port, &b6->sin6_port, 2);
      break;
    }
  }

  return res;
}


