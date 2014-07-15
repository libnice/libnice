/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
 *   Kai Vehmanen, Nokia
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
# include "config.h"
#else
#define NICEAPI_EXPORT
#endif

#include <string.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "address.h"

#ifdef G_OS_WIN32
#define inet_pton inet_pton_win32
#define inet_ntop inet_ntop_win32

/* Defined in recent versions of mingw:
 * https://github.com/mirror/mingw-w64/commit/0f4899473c4ba2e34fa447b1931a04e38c1f105e
 */
#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a, b) \
  (memcmp ((const void *) (a), (const void *) (b), sizeof (struct in6_addr)) == 0)
#endif


static const char *
inet_ntop_win32 (int af, const void *src, char *dst, socklen_t cnt)
{
  if (af == AF_INET) {
    struct sockaddr_in in;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    memcpy(&in.sin_addr, src, sizeof(struct in_addr));
    getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in),
        dst, cnt, NULL, 0, NI_NUMERICHOST);
    return dst;
  } else if (af == AF_INET6) {
    struct sockaddr_in6 in;
    memset(&in, 0, sizeof(in));
    in.sin6_family = AF_INET6;
    memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
    getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6),
        dst, cnt, NULL, 0, NI_NUMERICHOST);
    return dst;
  }
  return NULL;
}

static int
inet_pton_win32(int af, const char *src, void *dst)
{
  struct addrinfo hints, *res, *ressave;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = af;

  if (getaddrinfo(src, NULL, &hints, &res) != 0) {
    return 0;
  }

  ressave = res;

  while (res)  {
    if( res->ai_addr->sa_family == AF_INET) {
      memcpy(dst, &((struct sockaddr_in *) res->ai_addr)->sin_addr,
          sizeof(struct in_addr));
      res = res->ai_next;
    } else if(res->ai_addr->sa_family == AF_INET6) {
      memcpy(dst, &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr,
          sizeof(struct in_addr6));
      res = res->ai_next;
    }
  }

  freeaddrinfo(ressave);
  return 1;
}

#endif



NICEAPI_EXPORT void
nice_address_init (NiceAddress *addr)
{
  addr->s.addr.sa_family = AF_UNSPEC;
  memset (&addr->s, 0, sizeof(addr->s));
}

NICEAPI_EXPORT NiceAddress *
nice_address_new (void)
{
  NiceAddress *addr = g_slice_new0 (NiceAddress);
  nice_address_init (addr);
  return addr;
}


NICEAPI_EXPORT void
nice_address_set_ipv4 (NiceAddress *addr, guint32 addr_ipv4)
{
  addr->s.ip4.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
  addr->s.ip4.sin_len = sizeof (addr->sa.ip4);
#endif
  addr->s.ip4.sin_addr.s_addr = addr_ipv4 ? htonl (addr_ipv4) : INADDR_ANY;
  addr->s.ip4.sin_port = 0;
}


NICEAPI_EXPORT void
nice_address_set_ipv6 (NiceAddress *addr, const guchar *addr_ipv6)
{
  addr->s.ip6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
  addr->s.ip6.sin6_len = sizeof (addr->sa.ip6);
#endif
  memcpy (addr->s.ip6.sin6_addr.s6_addr, addr_ipv6, 16);
  addr->s.ip6.sin6_port = 0;
  addr->s.ip6.sin6_scope_id = 0;
}


NICEAPI_EXPORT void
nice_address_set_port (NiceAddress *addr, guint port)
{
  g_assert (addr);

  switch (addr->s.addr.sa_family)
    {
    case AF_INET:
      addr->s.ip4.sin_port = htons (port);
      break;
    case AF_INET6:
      addr->s.ip6.sin6_port = htons (port);
      break;
    default:
      g_return_if_reached ();
    }
}


guint
nice_address_get_port (const NiceAddress *addr)
{
  if (!addr)
          return 0;

  switch (addr->s.addr.sa_family)
    {
    case AF_INET:
      return ntohs (addr->s.ip4.sin_port);
    case AF_INET6:
      return ntohs (addr->s.ip6.sin6_port);
    default:
      g_return_val_if_reached (0);
    }
}


NICEAPI_EXPORT gboolean
nice_address_set_from_string (NiceAddress *addr, const gchar *str)
{
  struct addrinfo hints;
  struct addrinfo *res;

  memset (&hints, 0, sizeof (hints));

  /* AI_NUMERICHOST prevents getaddrinfo() from doing DNS resolution. */
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;

  if (getaddrinfo (str, NULL, &hints, &res) != 0)
    return FALSE;  /* invalid address */

  nice_address_set_from_sockaddr (addr, res->ai_addr);

  freeaddrinfo (res);

  return TRUE;
}


NICEAPI_EXPORT void
nice_address_set_from_sockaddr (NiceAddress *addr,
                                const struct sockaddr *sa)
{
  switch (sa->sa_family)
    {
    case AF_INET:
      memcpy(&addr->s.ip4, sa, sizeof (addr->s.ip4));
      break;
    case AF_INET6:
      memcpy(&addr->s.ip6, sa, sizeof (addr->s.ip6));
      break;
    default:
      g_return_if_reached ();
    }
}


NICEAPI_EXPORT void
nice_address_copy_to_sockaddr (const NiceAddress *addr,
                               struct sockaddr *_sa)
{
  union {
    struct sockaddr *addr;
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
  } sa;

  sa.addr = _sa;

  g_assert (_sa);

  switch (addr->s.addr.sa_family)
    {
    case AF_INET:
      memcpy (sa.in, &addr->s.ip4, sizeof (*sa.in));
      break;
    case AF_INET6:
      memcpy (sa.in6, &addr->s.ip6, sizeof (*sa.in6));
      break;
    default:
      g_return_if_reached ();
    }
}

NICEAPI_EXPORT void
nice_address_to_string (const NiceAddress *addr, gchar *dst)
{
  switch (addr->s.addr.sa_family) {
    case AF_INET:
      inet_ntop (AF_INET, &addr->s.ip4.sin_addr, dst, INET_ADDRSTRLEN);
      break;
    case AF_INET6:
      inet_ntop (AF_INET6, &addr->s.ip6.sin6_addr, dst, INET6_ADDRSTRLEN);
      break;
    default:
      g_return_if_reached ();
  }
}


NICEAPI_EXPORT gboolean
nice_address_equal (const NiceAddress *a, const NiceAddress *b)
{
  if (a->s.addr.sa_family != b->s.addr.sa_family)
    return FALSE;

  switch (a->s.addr.sa_family)
    {
    case AF_INET:
      return (a->s.ip4.sin_addr.s_addr == b->s.ip4.sin_addr.s_addr)
          && (a->s.ip4.sin_port == b->s.ip4.sin_port);

    case AF_INET6:
      return IN6_ARE_ADDR_EQUAL (&a->s.ip6.sin6_addr, &b->s.ip6.sin6_addr)
          && (a->s.ip6.sin6_port == b->s.ip6.sin6_port)
          && (a->s.ip6.sin6_scope_id == b->s.ip6.sin6_scope_id);

    default:
      g_return_val_if_reached (FALSE);
    }
}


NICEAPI_EXPORT NiceAddress *
nice_address_dup (const NiceAddress *a)
{
  NiceAddress *dup = g_slice_new0 (NiceAddress);

  *dup = *a;
  return dup;
}


NICEAPI_EXPORT void
nice_address_free (NiceAddress *addr)
{
  g_slice_free (NiceAddress, addr);
}


/* "private" in the sense of "not routable on the Internet" */
static gboolean
ipv4_address_is_private (guint32 addr)
{
  addr = ntohl (addr);

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


static gboolean
ipv6_address_is_private (const guchar *addr)
{
  return (
      /* fe80::/10 */
      ((addr[0] == 0xfe) && ((addr[1] & 0xc0) == 0x80)) ||
      /* fc00::/7 */
      ((addr[0] & 0xfe) == 0xfc) ||
      /* ::1 loopback */
      ((memcmp (addr, "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x01", 16) == 0))); 
}


NICEAPI_EXPORT gboolean
nice_address_is_private (const NiceAddress *a)
{
  switch (a->s.addr.sa_family)
    {
    case AF_INET:
      return ipv4_address_is_private (a->s.ip4.sin_addr.s_addr);
    case AF_INET6:
      return ipv6_address_is_private (a->s.ip6.sin6_addr.s6_addr);
    default:
      g_return_val_if_reached (FALSE);
    }
}


NICEAPI_EXPORT gboolean
nice_address_is_valid (const NiceAddress *a)
{
 switch (a->s.addr.sa_family)
    {
    case AF_INET:
    case AF_INET6:
      return TRUE;
    default:
      return FALSE;
    }
}

NICEAPI_EXPORT int
nice_address_ip_version (const NiceAddress *addr)
{
 switch (addr->s.addr.sa_family)
    {
    case AF_INET:
      return 4;
    case AF_INET6:
      return 6;
    default:
      return 0;
    }
}

NICEAPI_EXPORT gboolean
nice_address_equal_no_port (const NiceAddress *a, const NiceAddress *b)
{
  if (a->s.addr.sa_family != b->s.addr.sa_family)
    return FALSE;

  switch (a->s.addr.sa_family)
    {
    case AF_INET:
      return (a->s.ip4.sin_addr.s_addr == b->s.ip4.sin_addr.s_addr);

    case AF_INET6:
      return IN6_ARE_ADDR_EQUAL (&a->s.ip6.sin6_addr, &b->s.ip6.sin6_addr)
          && (a->s.ip6.sin6_scope_id == b->s.ip6.sin6_scope_id);

    default:
      g_return_val_if_reached (FALSE);
    }
}
