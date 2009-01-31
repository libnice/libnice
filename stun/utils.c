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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "utils.h"

/** Compares two socket addresses
 * @return 0 if the addresses are equal, non-zero otherwise
 */
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



bool stun_optional (uint16_t t)
{
  return (t >> 15) == 1;
}


/**
 * @return complement to the next multiple of 4.
 */
size_t stun_padding (size_t l)
{
  return (4 - (l & 3)) & 3;
}


/**
 * Rounds up an integer to the next multiple of 4.
 */
size_t stun_align (size_t l)
{
  return (l + 3) & ~3;
}


/**
 * Reads a word from a non-aligned buffer.
 * @return host byte order word value.
 */
uint16_t stun_getw (const uint8_t *ptr)
{
  return ((ptr)[0] << 8) | ptr[1];
}



/* /\** */
/*  * @param msg valid STUN message */
/*  * @return true if there is at least one unknown mandatory attribute. */
/*  *\/ */
/* bool stun_has_unknown (const void *msg) */
/* { */
/*   uint16_t dummy; */
/*   return stun_find_unknown (msg, &dummy, 1); */
/* } */

static int debug_enabled = 1;

void stun_debug_enable (void) {
  debug_enabled = 1;
}
void stun_debug_disable (void) {
  debug_enabled = 0;
}

void stun_debug (const char *fmt, ...)
{
  va_list ap;
  if (debug_enabled) {
    va_start (ap, fmt);
    vfprintf (stderr, fmt, ap);
    va_end (ap);
  }
}

void stun_debug_bytes (const void *data, size_t len)
{
  size_t i;

  stun_debug ("0x");
  for (i = 0; i < len; i++)
    stun_debug ("%02x", ((const unsigned char *)data)[i]);
}

StunMessageReturn stun_xor_address (const StunMessage *msg,
    struct sockaddr *addr, socklen_t addrlen,
    uint32_t magic_cookie)
{
  switch (addr->sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
      if ((size_t) addrlen < sizeof (*ip4))
        return STUN_MESSAGE_RETURN_INVALID;

      ip4->sin_port ^= htons (magic_cookie >> 16);
      ip4->sin_addr.s_addr ^= htonl (magic_cookie);
      return STUN_MESSAGE_RETURN_SUCCESS;
    }

    case AF_INET6:
    {
      struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
      unsigned short i;

      if ((size_t) addrlen < sizeof (*ip6))
        return EINVAL;

      ip6->sin6_port ^= htons (magic_cookie >> 16);
      for (i = 0; i < 16; i++)
        ip6->sin6_addr.s6_addr[i] ^= msg->buffer[4 + i];
      return 0;
    }
  }
  return EAFNOSUPPORT;
}

/**
 * Compares the length and content of an attribute.
 *
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param data pointer to value to compare with
 * @param len byte length of the value
 * @return 0 in case of match, ENOENT if attribute was not found,
 * EINVAL if it did not match (different length, or same length but
 * different content)
 */
int stun_memcmp (const StunMessage *msg, stun_attr_type_t type,
                 const void *data, size_t len)
{
  uint16_t alen;
  const void *ptr = stun_message_find (msg, type, &alen);
  if (ptr == NULL)
    return ENOENT;

  if ((len != alen) || memcmp (ptr, data, len))
    return EINVAL;
  return 0;
}


/**
 * Compares the content of an attribute with a string.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param str string to compare with
 * @return 0 in case of match, ENOENT if attribute was not found,
 * EINVAL if it did not match
 */
int stun_strcmp (const StunMessage *msg, stun_attr_type_t type, const char *str)
{
  return stun_memcmp (msg, type, str, strlen (str));
}


void *stun_setw (uint8_t *ptr, uint16_t value)
{
  *ptr++ = value >> 8;
  *ptr++ = value & 0xff;
  return ptr;
}


void stun_set_type (uint8_t *h, stun_class_t c, stun_method_t m)
{
/*   assert (c < 4); */
/*   assert (m < (1 << 12)); */

  h[0] = (c >> 1) | ((m >> 6) & 0x3e);
  h[1] = ((c << 4) & 0x10) | ((m << 1) & 0xe0) | (m & 0x0f);

/*   assert (stun_getw (h) < (1 << 14)); */
/*   assert (stun_get_class (h) == c); */
/*   assert (stun_get_method (h) == m); */
}


/**
 * @param code host-byte order error code
 * @return a static pointer to a nul-terminated error message string.
 */
const char *stun_strerror (stun_error_t code)
{
  static const struct
  {
    stun_error_t code;
    char     phrase[32];
  } tab[] =
  {
    { STUN_ERROR_TRY_ALTERNATE, "Try alternate server" },
    { STUN_ERROR_BAD_REQUEST, "Bad request" },
    { STUN_ERROR_UNAUTHORIZED, "Authorization required" },
    { STUN_ERROR_UNKNOWN_ATTRIBUTE, "Unknown attribute" },
    /*
    { STUN_STALE_CREDENTIALS, "Authentication expired" },
    { STUN_INTEGRITY_CHECK_FAILURE, "Incorrect username/password" },
    { STUN_MISSING_USERNAME, "Username required" },
    { STUN_USE_TLS, "Secure connection required" },
    { STUN_MISSING_REALM, "Authentication domain required" },
    { STUN_MISSING_NONCE, "Authentication token missing" },
    { STUN_UNKNOWN_USERNAME, "Unknown user name" },
    */
    { STUN_ERROR_NO_BINDING, "Session expired" },
    { STUN_ERROR_STALE_NONCE, "Authentication token expired" },
    { STUN_ERROR_ACT_DST_ALREADY, "Changing remote peer forbidden" },
    { STUN_ERROR_UNSUPP_TRANSPORT, "Unknown transport protocol" },
    { STUN_ERROR_INVALID_IP, "Address unavailable" },
    { STUN_ERROR_INVALID_PORT, "Port unavailable" },
    { STUN_ERROR_OP_TCP_ONLY, "Invalid operation" },
    { STUN_ERROR_CONN_ALREADY, "Connection already established" },
    { STUN_ERROR_ALLOC_OVER_QUOTA, "Quota reached" },
    { STUN_ERROR_ROLE_CONFLICT, "Role conflict" },
    { STUN_ERROR_SERVER_ERROR, "Temporary server error" },
    { STUN_ERROR_SERVER_CAPACITY, "Temporary server congestion" },
  };
  const char *str = "Unknown error";
  size_t i;

  for (i = 0; i < (sizeof (tab) / sizeof (tab[0])); i++)
  {
    if (tab[i].code == code)
    {
      str = tab[i].phrase;
      break;
    }
  }

  /* Maximum allowed error message length */
  //  assert (strlen (str) < 128);
  return str;
}
