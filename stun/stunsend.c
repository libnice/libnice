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

#include "stun-msg.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <netinet/in.h>


static inline
void *stun_setw (uint8_t *ptr, uint16_t value)
{
  *ptr++ = value >> 8;
  *ptr++ = value & 0xff;
  return ptr;
}


static inline
void stun_set_type (uint8_t *h, stun_class_t c, stun_method_t m)
{
  assert (c < 4);
  assert (m < (1 << 12));

  h[0] = (c >> 1) | ((m >> 6) & 0x3e);
  h[1] = ((c << 4) & 0x10) | ((m << 1) & 0xe0) | (m & 0x0f);

  assert (stun_getw (h) < (1 << 14));
  assert (stun_get_class (h) == c);
  assert (stun_get_method (h) == m);
}


/**
 * Initializes a STUN message buffer, with no attributes.
 * @param c STUN message class (host byte order)
 * @param m STUN message method (host byte order)
 * @param id 16-bytes transaction ID
 */
static void stun_init (uint8_t *msg, stun_class_t c, stun_method_t m,
                       const stun_transid_t id)
{
  memset (msg, 0, 4);
  stun_set_type (msg, c, m);
  msg += 8;

  if (msg != id)
  {
    uint32_t cookie = htonl (STUN_COOKIE);
    memcpy (msg - 4, &cookie, sizeof (cookie));
    memcpy (msg, id, 12);
  }
}


void stun_init_request (uint8_t *req, stun_method_t m)
{
  stun_transid_t id;

  stun_make_transid (id);
  stun_init (req, STUN_REQUEST, m, id);
}


void stun_init_indication (uint8_t *req, stun_method_t m)
{
  stun_transid_t id;

  stun_make_transid (id);
  stun_init (req, STUN_INDICATION, m, id);
}


/**
 * Reserves room for appending an attribute to an unfinished STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type message type (host byte order)
 * @param length attribute payload byte length
 * @return a pointer to an unitialized buffer of <length> bytes to
 * where the attribute payload must be written, or NULL if there is not
 * enough room in the STUN message buffer. Return value is always on a
 * 32-bits boundary.
 */
void *
stun_append (uint8_t *msg, size_t msize, stun_attr_type_t type, size_t length)
{
  uint8_t *a;
  uint16_t mlen = stun_length (msg);

  assert (stun_valid (msg));
  assert (stun_padding (mlen) == 0);

  if (msize > STUN_MAXMSG)
    msize = STUN_MAXMSG;

  if ((((size_t)mlen) + 24u + length) > msize)
    return NULL;

  assert (length < 0xffff);

  a = msg + 20u + mlen;
  a = stun_setw (a, type);
  /* NOTE: If cookie is not present, we need to force the attribute length
   * to a multiple of 4 for compatibility with old RFC3489 */
  a = stun_setw (a, stun_has_cookie (msg) ? length : stun_align (length));

  mlen += 4 + length;
  /* Add padding if needed */
  memset (a + length, ' ', stun_padding (length));
  mlen += stun_padding (length);

  stun_setw (msg + 2, mlen);
  return a;
}


/**
 * Appends an attribute from memory.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param data memory address to copy payload from
 * @param len attribute payload length
 * @return 0 on success, ENOBUFS on error.
 */
int
stun_append_bytes (uint8_t *restrict msg, size_t msize, stun_attr_type_t type,
                   const void *data, size_t len)
{
  void *ptr = stun_append (msg, msize, type, len);
  if (ptr == NULL)
    return ENOBUFS;

  memcpy (ptr, data, len);
  return 0;
}


int stun_append_flag (uint8_t *msg, size_t msize, stun_attr_type_t type)
{
  return stun_append_bytes (msg, msize, type, NULL, 0);
}


int
stun_append32 (uint8_t *msg, size_t msize, stun_attr_type_t type,
               uint32_t value)
{
  value = htonl (value);
  return stun_append_bytes (msg, msize, type, &value, 4);
}


int stun_append64 (uint8_t *msg, size_t msize, stun_attr_type_t type,
                   uint64_t value)
{
  uint32_t tab[2];
  tab[0] = htonl ((uint32_t)(value >> 32));
  tab[1] = htonl ((uint32_t)value);
  return stun_append_bytes (msg, msize, type, tab, 8);
}


int
stun_append_string (uint8_t *restrict msg, size_t msize,
                    stun_attr_type_t type, const char *str)
{
  return stun_append_bytes (msg, msize, type, str, strlen (str));
}


static int stun_append_server (uint8_t *restrict msg, size_t msize)
{
  static const char server[] = PACKAGE_STRING;
  assert (strlen (server) < 128);

  return stun_append_string (msg, msize, STUN_SERVER, server);
}


void stun_init_response (uint8_t *ans, size_t msize, const uint8_t *req)
{
  assert (stun_valid (req));
  assert (stun_get_class (req) == STUN_REQUEST);
  assert (msize >= 20u);

  stun_init (ans, STUN_RESPONSE, stun_get_method (req), stun_id (req));
  /* For RFC3489 compatibility, we cannot assume the cookie */
  memcpy (ans + 4, req + 4, 4);
  (void)stun_append_server (ans, msize);
}


/**
 * @param code host-byte order error code
 * @return a static pointer to a nul-terminated error message string.
 */
static const char *stun_strerror (stun_error_t code)
{
  static const struct
  {
    stun_error_t code;
    char     phrase[32];
  } tab[] =
  {
    { STUN_TRY_ALTERNATE, "Try alternate server" },
    { STUN_BAD_REQUEST, "Bad request" },
    { STUN_UNAUTHORIZED, "Authorization required" },
    { STUN_UNKNOWN_ATTRIBUTE, "Unknown attribute" },
    /*
    { STUN_STALE_CREDENTIALS, "Authentication expired" },
    { STUN_INTEGRITY_CHECK_FAILURE, "Incorrect username/password" },
    { STUN_MISSING_USERNAME, "Username required" },
    { STUN_USE_TLS, "Secure connection required" },
    { STUN_MISSING_REALM, "Authentication domain required" },
    { STUN_MISSING_NONCE, "Authentication token missing" },
    { STUN_UNKNOWN_USERNAME, "Unknown user name" },
    */
    { STUN_NO_BINDING, "Session expired" },
    { STUN_STALE_NONCE, "Authentication token expired" },
    { STUN_ACT_DST_ALREADY, "Changing remote peer forbidden" },
    { STUN_UNSUPP_TRANSPORT, "Unknown transport protocol" },
    { STUN_INVALID_IP, "Address unavailable" },
    { STUN_INVALID_PORT, "Port unavailable" },
    { STUN_OP_TCP_ONLY, "Invalid operation" },
    { STUN_CONN_ALREADY, "Connection already established" },
    { STUN_ALLOC_OVER_QUOTA, "Quota reached" },
    { STUN_ROLE_CONFLICT, "Role conflict" },
    { STUN_SERVER_ERROR, "Temporary server error" },
    { STUN_SERVER_CAPACITY, "Temporary server congestion" },
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
  assert (strlen (str) < 128);
  return str;
}


/**
 * Appends an ERROR-CODE attribute.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param code STUN host-byte order integer error code
 * @return 0 on success, or ENOBUFS otherwise
 */
static int
stun_append_error (uint8_t *restrict msg, size_t msize, stun_error_t code)
{
  const char *str = stun_strerror (code);
  size_t len = strlen (str);
  div_t d = div (code, 100);

  uint8_t *ptr = stun_append (msg, msize, STUN_ERROR_CODE, 4 + len);
  if (ptr == NULL)
    return ENOBUFS;

  memset (ptr, 0, 2);
  assert (d.quot <= 0x7);
  ptr[2] = d.quot;
  ptr[3] = d.rem;
  memcpy (ptr + 4, str, len);
  return 0;
}


int stun_init_error (uint8_t *ans, size_t msize, const uint8_t *req,
                     stun_error_t err)
{
  assert (stun_valid (req));
  assert (msize >= 20u);
  assert (stun_get_class (req) == STUN_REQUEST);

  stun_init (ans, STUN_ERROR, stun_get_method (req), stun_id (req));
  /* For RFC3489 compatibility, we cannot assume the cookie */
  memcpy (ans + 4, req + 4, 4);
  (void)stun_append_server (ans, msize);
  return stun_append_error (ans, msize, err);
}


int stun_init_error_unknown (uint8_t *ans, size_t msize, const uint8_t *req)
{
  unsigned counter, i;
#ifdef HAVE_C_VARARRAYS
  uint16_t ids[1 + (stun_length (req) / 4)];
#else
  uint16_t ids[256];
#endif

  counter = stun_find_unknown (req, ids, sizeof (ids) / sizeof (ids[0]));
  assert (counter > 0);

  if (stun_init_error (ans, msize, req, STUN_UNKNOWN_ATTRIBUTE))
    return ENOBUFS;

  for (i = 0; i < counter; i++)
    ids[i] = htons (ids[i]);

  /* NOTE: Old RFC3489 compatibility:
   * When counter is odd, duplicate one value for 32-bits padding. */
  if (!stun_has_cookie (req) && (counter & 1))
    ids[counter++] = ids[0];

  return stun_append_bytes (ans, msize, STUN_UNKNOWN_ATTRIBUTES, ids,
                            counter * 2);
}


int
stun_append_addr (uint8_t *restrict msg, size_t msize, stun_attr_type_t type,
                  const struct sockaddr *restrict addr, socklen_t addrlen)
{
  const void *pa;
  uint8_t *ptr;
  uint16_t alen, port;
  uint8_t family;

  if (addrlen < sizeof (struct sockaddr))
    return EINVAL;

  switch (addr->sa_family)
  {
    case AF_INET:
    {
      const struct sockaddr_in *ip4 = (const struct sockaddr_in *)addr;
      assert (addrlen >= sizeof (*ip4));
      family = 1;
      port = ip4->sin_port;
      alen = 4;
      pa = &ip4->sin_addr;
      break;
    }

    case AF_INET6:
    {
      const struct sockaddr_in6 *ip6 = (const struct sockaddr_in6 *)addr;
      if (addrlen < sizeof (*ip6))
        return EINVAL;

      family = 2;
      port = ip6->sin6_port;
      alen = 16;
      pa = &ip6->sin6_addr;
      break;
    }

    default:
      return EAFNOSUPPORT;
  }

  ptr = stun_append (msg, msize, type, 4 + alen);
  if (ptr == NULL)
    return ENOBUFS;

  ptr[0] = 0;
  ptr[1] = family;
  memcpy (ptr + 2, &port, 2);
  memcpy (ptr + 4, pa, alen);
  return 0;
}


int stun_append_xor_addr (uint8_t *restrict msg, size_t msize,
                          stun_attr_type_t type,
                          const struct sockaddr *restrict addr,
                          socklen_t addrlen)
{
  int val;
  /* Must be big enough to hold any supported address: */
  struct sockaddr_storage xor;

  if (addrlen > sizeof (xor))
    addrlen = sizeof (xor);
  memcpy (&xor, addr, addrlen);

  val = stun_xor_address (msg, (struct sockaddr *)&xor, addrlen);
  if (val)
    return val;

  return stun_append_addr (msg, msize, type, (struct sockaddr *)&xor,
                           addrlen);
}


size_t
stun_finish_long (uint8_t *msg, size_t *restrict plen,
                  const char *realm, const char *username, const char *nonce,
                  const void *restrict key, size_t keylen)
{
  size_t len = *plen;
  uint8_t *ptr;
  int val = ENOBUFS;
  uint32_t fpr;

  if (realm != NULL)
  {
    /*if (utf32_strlen (realm) > 127))
      return EINVAL;*/
    val = stun_append_string (msg, len, STUN_REALM, realm);
    if (val)
      return val;
  }

  if (username != NULL)
  {
    if (strlen (username) >= 513)
      return EINVAL;

    val = stun_append_string (msg, len, STUN_USERNAME, username);
    if (val)
      return val;
  }

  if (nonce != NULL)
  {
    /*if (utf32_strlen (nonce) > 127))
      return EINVAL;*/

    val = stun_append_string (msg, len, STUN_NONCE, nonce);
    if (val)
      return val;
  }

  if (key != NULL)
  {
    ptr = stun_append (msg, len, STUN_MESSAGE_INTEGRITY, 20);
    if (ptr == NULL)
      return ENOBUFS;

    stun_sha1 (msg, ptr + 20 - msg, ptr, key, keylen);

    DBG (" Message HMAC-SHA1 fingerprint:"
         "\n  key     : ");
    DBG_bytes (key, keylen);
    DBG ("\n  sent    : ");
    DBG_bytes (ptr, 20);
    DBG ("\n");
  }

  /*
   * NOTE: we always add a FINGERPRINT, even when it's not needed.
   * This is OK, as it is an optional attribute. It also makes my
   * software engineer's life easier.
   */
  ptr = stun_append (msg, len, STUN_FINGERPRINT, 4);
  if (ptr == NULL)
    return ENOBUFS;

  *plen = ptr + 4 -msg;

  fpr = htonl (stun_fingerprint (msg, *plen));
  memcpy (ptr, &fpr, sizeof (fpr));

  return 0;
}


size_t stun_finish_short (uint8_t *msg, size_t *restrict plen,
                          const char *username, const char *restrict password,
                          const char *nonce)
{
  return stun_finish_long (msg, plen, NULL, username, nonce,
                           password, password ? strlen (password) : 0);
}


size_t stun_finish (uint8_t *msg, size_t *restrict plen)
{
  return stun_finish_short (msg, plen, NULL, NULL, NULL);
}
