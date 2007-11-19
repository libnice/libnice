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
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include "stun-msg.h"

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

ssize_t stun_validate (const uint8_t *msg, size_t len)
{
  size_t mlen;

  if (len < 1)
  {
    DBG ("STUN error: No data!\n");
    return 0;
  }

  if (msg[0] >> 6)
  {
    DBG ("STUN error: RTP or other non-protocol packet!\n");
    return -1; // RTP or other non-STUN packet
  }

  if (len < 4)
  {
    DBG ("STUN error: Incomplete STUN message header!\n");
    return 0;
  }

  mlen = 20u + stun_length (msg);
  if (stun_padding (mlen))
  {
    DBG ("STUN error: Invalid message length: %u!\n", (unsigned)mlen);
    return -1; // wrong padding
  }

  if (len < mlen)
  {
    DBG ("STUN error: Incomplete message: %u of %u bytes!\n",
         (unsigned)len, (unsigned)mlen);
    return 0; // partial message
  }

  msg += 20;
  len = mlen - 20;

  /* from then on, we know we have the entire packet in buffer */
  while (len > 0)
  {
    size_t alen = stun_align (stun_length (msg));

     /* thanks to padding check, if (end > msg) then there is not only one
     * but at least 4 bytes left */
    assert (len >= 4);
    len -= 4;

    if (len < alen)
    {
      DBG ("STUN error: %u instead of %u bytes for attribute!\n",
           (unsigned)len, (unsigned)alen);
      return -1; // no room for attribute value + padding
    }

    len -= alen;
    msg += 4 + alen;
  }

  return mlen;
}


const void *
stun_find (const uint8_t *restrict msg, stun_attr_type_t type,
           uint16_t *restrict palen)
{
  size_t length = stun_length (msg);

  assert (stun_valid (msg));
  assert (palen != NULL);

  msg += 20;

  while (length > 0)
  {
    size_t alen = stun_length (msg);
    uint16_t atype = stun_getw (msg);

    assert (length >= 4);

    length -= 4;
    msg += 4;

    assert (length >= stun_align (alen));
    if (atype == type)
    {
      assert (alen <= 0xffff);
      *palen = alen;
      return msg;
    }

    /* Look for and ignore misordered attributes */
    switch (atype)
    {
      case STUN_MESSAGE_INTEGRITY:
        /* Only fingerprint may come after M-I */
        if (type == STUN_FINGERPRINT)
          break;

      case STUN_FINGERPRINT:
        /* Nothing may come after FPR */
        return NULL;
    }

    alen = stun_align (alen);
    length -= alen;
    msg += alen;
  }

  return NULL;
}


int stun_find_flag (const uint8_t *msg, stun_attr_type_t type)
{
  const void *ptr;
  uint16_t len;

  ptr = stun_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;
  return (len == 0) ? 0 : EINVAL;
}


int
stun_find32 (const uint8_t *restrict msg, stun_attr_type_t type,
             uint32_t *restrict pval)
{
  const void *ptr;
  uint16_t len;

  ptr = stun_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;

  if (len == 4)
  {
    uint32_t val;

    memcpy (&val, ptr, sizeof (val));
    *pval = ntohl (val);
    return 0;
  }
  return EINVAL;
}


int stun_find64 (const uint8_t *msg, stun_attr_type_t type, uint64_t *pval)
{
  const void *ptr;
  uint16_t len;

  ptr = stun_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;

  if (len == 8)
  {
    uint32_t tab[2];

    memcpy (tab, ptr, sizeof (tab));
    *pval = ((uint64_t)ntohl (tab[0]) << 32) | ntohl (tab[1]);
    return 0;
  }
  return EINVAL;
}


int stun_find_string (const uint8_t *restrict msg, stun_attr_type_t type,
                      char *buf, size_t buflen)
{
  const unsigned char *ptr;
  uint16_t len;

  ptr = stun_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;

  if (len >= buflen)
    return ENOBUFS;

  memcpy (buf, ptr, len);
  buf[len] = '\0';
  return 0;
}


int
stun_find_addr (const uint8_t *restrict msg, stun_attr_type_t type,
                struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
  const uint8_t *ptr;
  uint16_t len;

  ptr = stun_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;

  if (len < 4)
    return EINVAL;

  assert (addrlen != NULL);
  switch (ptr[1])
  {
    case 1:
    {
      struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
      if ((*addrlen < sizeof (*ip4)) || (len != 8))
      {
        *addrlen = sizeof (*ip4);
        return EINVAL;
      }

      memset (ip4, 0, *addrlen);
      ip4->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
      ip4->sin_len =
#endif
      *addrlen = sizeof (*ip4);
      memcpy (&ip4->sin_port, ptr + 2, 2);
      memcpy (&ip4->sin_addr, ptr + 4, 4);
      return 0;
    }

    case 2:
    {
      struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
      if ((*addrlen < sizeof (*ip6)) || (len != 20))
      {
        *addrlen = sizeof (*ip6);
        return EINVAL;
      }

      memset (ip6, 0, *addrlen);
      ip6->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
      ip6->sin6_len =
#endif
      *addrlen = sizeof (*ip6);
      memcpy (&ip6->sin6_port, ptr + 2, 2);
      memcpy (&ip6->sin6_addr, ptr + 4, 16);
      return 0;
    }
  }

  return EAFNOSUPPORT;
}


int stun_xor_address (const uint8_t *restrict msg,
                      struct sockaddr *restrict addr, socklen_t addrlen)
{
  switch (addr->sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
      if (addrlen < sizeof (*ip4))
        return EINVAL;

      ip4->sin_port ^= htons (STUN_COOKIE >> 16);
      ip4->sin_addr.s_addr ^= htonl (STUN_COOKIE);
      return 0;
    }

    case AF_INET6:
    {
      struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
      unsigned short i;

      if (addrlen < sizeof (*ip6))
        return EINVAL;

      ip6->sin6_port ^= htons (STUN_COOKIE >> 16);
      for (i = 0; i < 16; i++)
        ip6->sin6_addr.s6_addr[i] ^= ((uint8_t *)msg)[4 + i];
      return 0;
    }
  }
  return EAFNOSUPPORT;
}


int
stun_find_xor_addr (const uint8_t *restrict msg, stun_attr_type_t type,
                    struct sockaddr *restrict addr,
                    socklen_t *restrict addrlen)
{
  int val = stun_find_addr (msg, type, addr, addrlen);
  if (val)
    return val;

  return stun_xor_address (msg, addr, *addrlen);
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
int stun_memcmp (const uint8_t *msg, stun_attr_type_t type,
                 const void *data, size_t len)
{
  uint16_t alen;
  const void *ptr = stun_find (msg, type, &alen);
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
int stun_strcmp (const uint8_t *msg, stun_attr_type_t type, const char *str)
{
  return stun_memcmp (msg, type, str, strlen (str));
}


bool stun_has_cookie (const uint8_t *msg)
{
  uint32_t cookie = htonl (STUN_COOKIE);
  return memcmp (msg + 4, &cookie, sizeof (cookie)) == 0;
}


bool stun_demux (const uint8_t *msg)
{
  const uint8_t *fpr;
  uint32_t crc32;
  uint16_t fprlen;

  assert (stun_valid (msg));

  /* Checks cookie */
  if (!stun_has_cookie (msg))
  {
    DBG ("STUN demux error: no cookie!\n");
    return 0;
  }

  /* Looks for FINGERPRINT */
  fpr = stun_find (msg, STUN_FINGERPRINT, &fprlen);
  if ((fpr == NULL) || (fprlen != 4))
  {
    DBG ("STUN demux error: no FINGERPRINT attribute!\n");
    return 0;
  }

  /* Checks FINGERPRINT */
  crc32 = htonl (stun_fingerprint (msg, fpr + 4 - msg));
  if (memcmp (fpr, &crc32, 4))
  {
    DBG ("STUN demux error: bad fingerprint: 0x%08x, expected: 0x%08x!\n",
         (fpr[0] << 24) | (fpr[1] << 16) | (fpr[2] << 8) | fpr[3],
         stun_fingerprint (msg, fpr + 4 - msg));
    return 0;
  }

  DBG ("STUN demux: OK!\n");
  return 1;
}


/**
 * @param msg valid STUN message
 * @param key HMAC shared secret key pointer
 * @param keylen HMAC shared secret key byte length
 * @return 0 if the message integrity has been successfully verified with the
 * specified key. EPERM if the hash was incorrect. ENOENT if there was no
 * valid MESSAGE-INTEGRITY attribute.
 */
int
stun_verify_key (const uint8_t *msg, const void *key, size_t keylen)
{
  const uint8_t *hash;
  uint8_t sha[20];
  uint16_t hlen;

  assert (msg != NULL);
  assert ((keylen == 0) || (key != NULL));

  hash = stun_find (msg, STUN_MESSAGE_INTEGRITY, &hlen);
  if ((hash == NULL) || (hlen != 20))
  {
    DBG ("STUN auth error: no MESSAGE-INTEGRITY attribute!\n");
    return ENOENT;
  }

  stun_sha1 (msg, hash + 20 - msg, sha, key, keylen);
  DBG (" Message HMAC-SHA1 fingerprint:"
       "\n  key     : ");
  DBG_bytes (key, keylen);
  DBG ("\n  expected: ");
  DBG_bytes (sha, sizeof (sha));
  DBG ("\n  received: ");
  DBG_bytes (hash, sizeof (sha));
  DBG ("\n");

  if (memcmp (sha, hash, sizeof (sha)))
  {
    DBG ("STUN auth error: SHA1 fingerprint mismatch!\n");
    return EPERM;
  }

  DBG ("STUN auth: OK!\n");
  return 0;
}


/**
 * @param msg valid STUN message
 * @param pw nul-terminated HMAC shared secret password
 * @return 0 if the message integrity has been successfully verified with the
 * specified key. EPERM if the hash was incorrect. ENOENT if there was no
 * valid MESSAGE-INTEGRITY attribute.
 */
int stun_verify_password (const uint8_t *msg, const char *pw)
{
  return stun_verify_key (msg, pw, strlen (pw));
}

/**
 * @param msg valid STUN message
 * @param pw nul-terminated local username fragment
 * @return 0 if the username in the message is valid and matches
 * the local username fragment, EPERM if the username was incorrect,
 * and ENOENT if there was no USERNAME attribute
 */
int stun_verify_username (const uint8_t *msg, const char *local_ufrag)
{
  const char *username, *n;
  uint16_t username_len;
  assert (msg != NULL);
  username = (const char *)stun_find (msg, STUN_USERNAME, &username_len);
  if (username == NULL)
  {
    DBG ("STUN auth error: no USERNAME attribute!\n");
    return ENOENT;
  }
  n = strchr (username, ':');
  if (n == NULL)
  {
    DBG ("STUN auth error: no colon in USERNAME!\n");
    return EPERM;
  }
  if (strncmp(username, local_ufrag, n - username) != 0)
  {
    DBG ("STUN auth error: local ufrag doesn't match (uname:%s,ufrag:%s,msg:%s)!\n", username,local_ufrag, n);
    return EPERM;
  }
  
  return 0;
}


static
int stun_find_errno (const uint8_t *restrict msg, int *restrict code)
{
  uint16_t alen;
  const uint8_t *ptr = stun_find (msg, STUN_ERROR_CODE, &alen);
  uint8_t class, number;

  if (ptr == NULL)
    return ENOENT;
  if (alen < 4)
    return EINVAL;

  class = ptr[2] & 0x7;
  number = ptr[3];
  if ((class < 3) || (class > 6) || (number > 99))
    return EINVAL;

  *code = (class * 100) + number;
  return 0;
}


/**
 * @param msg valid STUN message
 * @param method STUN method number (host byte order)
 * @param id STUN transaction id
 * @param key HMAC key, or NULL if there is no authentication
 * @param keylen HMAC key byte length, must be 0 if @a key is NULL
 * @param error [OUT] set to -1 if the response is not an error,
 * to the error code ([0..799]) if it is an error response.
 *
 * @return true if and only if the message is a response or an error response
 * with the STUN cookie and specified method and transaction identifier.
 */
static bool
stun_match_answer (const uint8_t *msg, stun_method_t method,
                   const uint8_t *id, const uint8_t *key, size_t keylen,
                   int *restrict error)
{
  assert (stun_valid (msg));
  assert (error != NULL);

  if ((stun_get_method (msg) != method) /* wrong request type */
   || !stun_has_cookie (msg) /* response to old-style request */
   || memcmp (msg + 8, id, 12)) /* wrong transaction ID */
    return false;

  switch (stun_get_class (msg))
  {
    case STUN_REQUEST:
    case STUN_INDICATION:
      return false;

    case STUN_RESPONSE:
      *error = -1;
      break;

    case STUN_ERROR:
      if (stun_find_errno (msg, error) != 0)
        return false; // missing ERROR-CODE: ignore message
      break;
  }

  /* If a shared secret exists, verify the message hash.
   * If there is no shared secret, verify there is no hash at all. */
  if (key != NULL)
  {
    /* FIXME: 401 errors do not have MESSAGE-INTEGRITY, so that we
     * currently ignore them. */
    if (stun_verify_key (msg, key, keylen) != 0)
      return false;
  }
  else
  {
    if (stun_present (msg, STUN_MESSAGE_INTEGRITY))
      return false;
  }

  return true;
}


bool stun_match_messages (const uint8_t *restrict resp,
                          const uint8_t *restrict req,
                          const uint8_t *key, size_t keylen,
                          int *restrict error)
{
  assert (stun_valid (resp));
  assert (stun_valid (req));
  assert ((stun_get_class (req) >> 1) == 0);

  return stun_match_answer (resp, stun_get_method (req),
                            stun_id (req), key, keylen, error);
}


unsigned
stun_find_unknown (const uint8_t *restrict msg, uint16_t *restrict list,
                   unsigned max)
{
  unsigned count = 0;
  uint16_t len = stun_length (msg);

  assert (stun_valid (msg));
  msg += 20;

  while ((len > 0) && (count < max))
  {
    size_t alen = stun_align (stun_length (msg));
    uint16_t atype = stun_getw (msg);

    msg += 4 + alen;
    assert (len >= (4 + alen));
    len -= 4 + alen;

    if (!stun_optional (atype) && stun_is_unknown (atype))
    {
      DBG ("STUN unknown: attribute 0x%04x(%u bytes)\n",
           (unsigned)atype, (unsigned)alen);
      list[count++] = atype;
    }
  }

  DBG ("STUN unknown: %u mandatory attribute(s)!\n", count);
  return count;
}
