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

#include "utils.h"

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

uint16_t stun_length (const uint8_t *ptr)
{
  return stun_getw (ptr + 2);
}


/**
 * @return STUN message class in host byte order (value from 0 to 3)
 */
stun_class_t stun_get_class (const uint8_t *msg)
{
  uint16_t t = stun_getw (msg);
  return (stun_class_t)(((t & 0x0100) >> 7) | ((t & 0x0010) >> 4));
}

/**
 * @return STUN message method (value from 0 to 0xfff)
 */
stun_method_t stun_get_method (const uint8_t *msg)
{
  uint16_t t = stun_getw (msg);
  return (stun_method_t)(((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) |
                          (t & 0x000f));
}


/**
 * @return STUN message transaction ID
 */
const uint8_t *stun_id (const uint8_t *msg)
{
  //assert (stun_valid (req));
  return msg + 8;
}

/**
 * Checks if an attribute is present within a STUN message.
 *
 * @param msg valid STUN message
 * @param type STUN attribute type (host byte order)
 *
 * @return whether there is a MESSAGE-INTEGRITY attribute
 */
bool stun_present (const uint8_t *msg, stun_attr_type_t type)
{
  uint16_t dummy;
  return stun_find (msg, type, &dummy) != NULL;
}


/**
 * @param msg valid STUN message
 * @return true if there is at least one unknown mandatory attribute.
 */
bool stun_has_unknown (const void *msg)
{
  uint16_t dummy;
  return stun_find_unknown (msg, &dummy, 1);
}


# ifndef NDEBUG
/**
 * This function is for debugging only, which is why it is only defined under
 * !NDEBUG. It should really only be used in run-time assertions, as it cannot
 * detect all possible errors. stun_validate() should be used instead in real
 * code.
 *
 * @param msg pointer to a potential STUN message
 * @return whether the pointer refers to a valid STUN message
 */
bool stun_valid (const uint8_t *msg)
{
  size_t length = 20u + stun_length (msg);
  return stun_validate (msg, length) == (ssize_t)length;
}
# endif

void stun_debug (const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
}

void stun_debug_bytes (const void *data, size_t len)
{
  size_t i;

  DBG ("0x");
  for (i = 0; i < len; i++)
    DBG ("%02x", ((const unsigned char *)data)[i]);
}
