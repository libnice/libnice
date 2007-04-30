/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
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
 *   Dafydd Harries, Collabora Ltd.
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

#include <string.h>

#include <arpa/inet.h>

#include <glib.h>

#include "address.h"


NiceAddress *
nice_address_new (void)
{
  return g_slice_new0 (NiceAddress);
}


void
nice_address_set_ipv4 (NiceAddress *addr, guint32 addr_ipv4)
{
  addr->type = NICE_ADDRESS_TYPE_IPV4;
  addr->addr_ipv4 = addr_ipv4;
}


void
nice_address_set_ipv6 (NiceAddress *addr, const gchar *addr_ipv6)
{
  addr->type = NICE_ADDRESS_TYPE_IPV6;
  memcpy (addr->addr_ipv6, addr_ipv6, sizeof (addr->addr_ipv6));
}


/**
 * address_set_ipv4_from_string ()
 *
 * Returns FALSE on error.
 */
gboolean
nice_address_set_ipv4_from_string (NiceAddress *addr, const gchar *str)
{
  struct in_addr iaddr;

  if (inet_aton (str, &iaddr) != 0)
    {
      nice_address_set_ipv4 (addr, ntohl (iaddr.s_addr));
      return TRUE;
    }
  else
    {
      /* invalid address */
      return FALSE;
    }
}


void
nice_address_set_from_sockaddr_in (NiceAddress *addr, struct sockaddr_in *sin)
{
  if (sin->sin_family == AF_INET6)
    {
      addr->type = NICE_ADDRESS_TYPE_IPV6;
      nice_address_set_ipv6 (addr,
          (gchar *) &((struct sockaddr_in6 *) sin)->sin6_addr);
    }
  else
    {
      addr->type = NICE_ADDRESS_TYPE_IPV4;
      nice_address_set_ipv4 (addr, ntohl (sin->sin_addr.s_addr));
    }

  addr->port = ntohs (sin->sin_port);
}


void
nice_address_to_string (NiceAddress *addr, gchar *dst)
{
  struct in_addr iaddr = {0,};
  const gchar *ret = NULL;

  switch (addr->type)
    {
    case NICE_ADDRESS_TYPE_IPV4:
      iaddr.s_addr = htonl (addr->addr_ipv4);
      ret = inet_ntop (AF_INET, &iaddr, dst, INET_ADDRSTRLEN);
      break;
    case NICE_ADDRESS_TYPE_IPV6:
      ret = inet_ntop (AF_INET6, &addr->addr_ipv6, dst, INET6_ADDRSTRLEN);
      break;
    }

  g_assert (ret == dst);
}


gboolean
nice_address_equal (NiceAddress *a, NiceAddress *b)
{
  if (a->type != b->type)
    return FALSE;

  if (a->type == NICE_ADDRESS_TYPE_IPV4)
    return (a->addr_ipv4 == b->addr_ipv4) && (a->port == b->port);

  g_assert_not_reached ();
}


NiceAddress *
nice_address_dup (NiceAddress *a)
{
  NiceAddress *dup = g_slice_new0 (NiceAddress);

  *dup = *a;
  return dup;
}


void
nice_address_free (NiceAddress *addr)
{
  g_slice_free (NiceAddress, addr);
}


/* "private" in the sense of "not routable on the Internet" */
static gboolean
ipv4_address_is_private (guint32 addr)
{
  /* http://tools.ietf.org/html/rfc3330 */
  return (
      /* 10.0.0.0/8 */
      ((addr & 0xff000000) == 0x0a000000) ||
      /* 172.16.0.0/12 */
      ((addr & 0xfff00000) == 0xac100000) ||
      /* 192.168.0.0/16 */
      ((addr & 0xffff0000) == 0xc0a80000) ||
      /* 127.0.0.0/8 */
      ((addr & 0xff000000) == 0x7f000000));
}


gboolean
nice_address_is_private (NiceAddress *a)
{
  if (a->type == NICE_ADDRESS_TYPE_IPV4)
    return ipv4_address_is_private (a->addr_ipv4);

  g_assert_not_reached ();
}

