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

#include "stunmessage.h"

#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <netinet/in.h>




bool stun_message_init (StunMessage *msg, stun_class_t c, stun_method_t m,
    const stun_transid_t id)
{

  if (msg->buffer_len < STUN_MESSAGE_HEADER_LENGTH)
    return FALSE;

  memset (msg->buffer, 0, 4);
  stun_set_type (msg->buffer, c, m);

  memcpy (msg->buffer + STUN_MESSAGE_TRANS_ID_POS,
      id, STUN_MESSAGE_TRANS_ID_LEN);

  return TRUE;
}

uint16_t stun_message_length (const StunMessage *msg)
{
  return stun_getw (msg->buffer + STUN_MESSAGE_LENGTH_POS) +
      STUN_MESSAGE_HEADER_LENGTH;
}




const void *
stun_message_find (const StunMessage *msg, stun_attr_type_t type,
    uint16_t *restrict palen)
{
  size_t length = stun_message_length (msg);
  size_t offset = 0;


  offset = STUN_MESSAGE_ATTRIBUTES_POS;

  while (offset < length)
  {
    uint16_t atype = stun_getw (msg->buffer + offset);
    size_t alen = stun_getw (msg->buffer + offset + STUN_ATTRIBUTE_TYPE_LEN);


    offset += STUN_ATTRIBUTE_VALUE_POS;

    if (atype == type)
    {
      *palen = alen;
      return msg->buffer + offset;
    }

    /* Look for and ignore misordered attributes */
    switch (atype)
    {
      case STUN_ATTRIBUTE_MESSAGE_INTEGRITY:
        /* Only fingerprint may come after M-I */
        if (type == STUN_ATTRIBUTE_FINGERPRINT)
          break;

      case STUN_ATTRIBUTE_FINGERPRINT:
        /* Nothing may come after FPR */
        return NULL;
    }

    alen = stun_align (alen);
    offset += alen;
  }

  return NULL;
}


int stun_message_find_flag (const StunMessage *msg, stun_attr_type_t type)
{
  const void *ptr;
  uint16_t len;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;
  return (len == 0) ? 0 : EINVAL;
}


int
stun_message_find32 (const StunMessage *msg, stun_attr_type_t type,
    uint32_t *restrict pval)
{
  const void *ptr;
  uint16_t len;

  ptr = stun_message_find (msg, type, &len);
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


int stun_message_find64 (const StunMessage *msg, stun_attr_type_t type,
    uint64_t *pval)
{
  const void *ptr;
  uint16_t len;

  ptr = stun_message_find (msg, type, &len);
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


int stun_message_find_string (const StunMessage *msg, stun_attr_type_t type,
    char *buf, size_t buflen)
{
  const unsigned char *ptr;
  uint16_t len;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;

  if (len >= buflen)
    return ENOBUFS;

  memcpy (buf, ptr, len);
  buf[len] = '\0';
  return 0;
}


int
stun_message_find_addr (const StunMessage *msg, stun_attr_type_t type,
    struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
  const uint8_t *ptr;
  uint16_t len;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return ENOENT;

  if (len < 4)
    return EINVAL;

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

int
stun_message_find_xor_addr (const StunMessage *msg, stun_attr_type_t type,
    struct sockaddr *restrict addr,
    socklen_t *restrict addrlen)
{
  int val = stun_message_find_addr (msg, type, addr, addrlen);
  if (val)
    return val;

  return stun_xor_address (msg, addr, *addrlen);
}

int stun_message_find_error (const StunMessage *msg, int *restrict code)
{
  uint16_t alen;
  const uint8_t *ptr = stun_message_find (msg, STUN_ATTRIBUTE_ERROR_CODE, &alen);
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
stun_message_append (StunMessage *msg, stun_attr_type_t type, size_t length)
{
  uint8_t *a;
  uint16_t mlen = stun_message_length (msg) - STUN_MESSAGE_HEADER_LENGTH;

  if ((((size_t)mlen) + STUN_ATTRIBUTE_HEADER_LENGTH + length) > msg->buffer_len)
    return NULL;


  a = msg->buffer + STUN_MESSAGE_HEADER_LENGTH + mlen;
  a = stun_setw (a, type);
  /* NOTE: If cookie is not present, we need to force the attribute length
   * to a multiple of 4 for compatibility with old RFC3489 */
  a = stun_setw (a, stun_has_cookie (msg) ? length : stun_align (length));

  mlen += 4 + length;
  /* Add padding if needed */
  memset (a + length, ' ', stun_padding (length));
  mlen += stun_padding (length);

  stun_setw (msg->buffer + STUN_MESSAGE_LENGTH_POS, mlen);
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
stun_message_append_bytes (StunMessage *msg, stun_attr_type_t type,
    const void *data, size_t len)
{
  void *ptr = stun_message_append (msg, type, len);
  if (ptr == NULL)
    return ENOBUFS;

  memcpy (ptr, data, len);
  return 0;
}


int stun_message_append_flag (StunMessage *msg, stun_attr_type_t type)
{
  return stun_message_append_bytes (msg, type, NULL, 0);
}


int
stun_message_append32 (StunMessage *msg, stun_attr_type_t type,
    uint32_t value)
{
  value = htonl (value);
  return stun_message_append_bytes (msg, type, &value, 4);
}


int stun_message_append64 (StunMessage *msg, stun_attr_type_t type,
    uint64_t value)
{
  uint32_t tab[2];
  tab[0] = htonl ((uint32_t)(value >> 32));
  tab[1] = htonl ((uint32_t)value);
  return stun_message_append_bytes (msg, type, tab, 8);
}


int
stun_message_append_string (StunMessage * msg, stun_attr_type_t type,
    const char *str)
{
  return stun_message_append_bytes (msg, type, str, strlen (str));
}

int
stun_message_append_addr (StunMessage *msg, stun_attr_type_t type,
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

  ptr = stun_message_append (msg, type, 4 + alen);
  if (ptr == NULL)
    return ENOBUFS;

  ptr[0] = 0;
  ptr[1] = family;
  memcpy (ptr + 2, &port, 2);
  memcpy (ptr + 4, pa, alen);
  return 0;
}


int stun_message_append_xor_addr (StunMessage *msg, stun_attr_type_t type,
    const struct sockaddr *restrict addr, socklen_t addrlen)
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

  return stun_message_append_addr (msg, type, (struct sockaddr *)&xor,
      addrlen);
}



/**
 * Appends an ERROR-CODE attribute.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param code STUN host-byte order integer error code
 * @return 0 on success, or ENOBUFS otherwise
 */
int
stun_message_append_error (StunMessage *msg, stun_error_t code)
{
  const char *str = stun_strerror (code);
  size_t len = strlen (str);
  div_t d = div (code, 100);

  uint8_t *ptr = stun_message_append (msg, STUN_ATTRIBUTE_ERROR_CODE, 4 + len);
  if (ptr == NULL)
    return ENOBUFS;

  memset (ptr, 0, 2);
  ptr[2] = d.quot;
  ptr[3] = d.rem;
  memcpy (ptr + 4, str, len);
  return 0;
}

int stun_message_validate_buffer_length (const uint8_t *msg, size_t length)
{
  size_t mlen;
  size_t len;

  if (length < 1)
  {
    stun_debug ("STUN error: No data!\n");
    return STUN_MESSAGE_BUFFER_INVALID;
  }

  if (msg[0] >> 6)
  {
    stun_debug ("STUN error: RTP or other non-protocol packet!\n");
    return STUN_MESSAGE_BUFFER_INVALID; // RTP or other non-STUN packet
  }

  if (length < 4)
  {
    stun_debug ("STUN error: Incomplete STUN message header!\n");
    return STUN_MESSAGE_BUFFER_INCOMPLETE;
  }

  mlen = stun_getw (msg + STUN_MESSAGE_LENGTH_POS) +
      STUN_MESSAGE_HEADER_LENGTH;

  if (stun_padding (mlen))
  {
    stun_debug ("STUN error: Invalid message length: %u!\n", (unsigned)mlen);
    return STUN_MESSAGE_BUFFER_INVALID; // wrong padding
  }

  if (length < mlen)
  {
    stun_debug ("STUN error: Incomplete message: %u of %u bytes!\n",
        (unsigned)length, (unsigned)mlen);
    return STUN_MESSAGE_BUFFER_INCOMPLETE; // partial message
  }

  msg += 20;
  len = mlen - 20;

  /* from then on, we know we have the entire packet in buffer */
  while (len > 0)
  {
    size_t alen = stun_align (stun_getw (msg + STUN_ATTRIBUTE_TYPE_LEN));

    /* thanks to padding check, if (end > msg) then there is not only one
     * but at least 4 bytes left */
    len -= 4;

    if (len < alen)
    {
      stun_debug ("STUN error: %u instead of %u bytes for attribute!\n",
          (unsigned)len, (unsigned)alen);
      return STUN_MESSAGE_BUFFER_INVALID; // no room for attribute value + padding
    }

    len -= alen;
    msg += 4 + alen;
  }

  return mlen;
}

/**
 * copies STUN message transaction ID
 */
void stun_message_id (const StunMessage *msg, stun_transid_t id)
{
  memcpy (id, msg->buffer + STUN_MESSAGE_TRANS_ID_POS, STUN_MESSAGE_TRANS_ID_LEN);
}

/**
 * @return STUN message method (value from 0 to 0xfff)
 */
stun_method_t stun_message_get_method (const StunMessage *msg)
{
  uint16_t t = stun_getw (msg->buffer);
  return (stun_method_t)(((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) |
                          (t & 0x000f));
}


/**
 * @return STUN message class in host byte order (value from 0 to 3)
 */
stun_class_t stun_message_get_class (const StunMessage *msg)
{
  uint16_t t = stun_getw (msg->buffer);
  return (stun_class_t)(((t & 0x0100) >> 7) | ((t & 0x0010) >> 4));
}

/**
 * Checks if an attribute is present within a STUN message.
 *
 * @param msg valid STUN message
 * @param type STUN attribute type (host byte order)
 *
 * @return whether there is a MESSAGE-INTEGRITY attribute
 */
bool stun_message_has_attribute (const StunMessage *msg, stun_attr_type_t type)
{
  uint16_t dummy;
  return stun_message_find (msg, type, &dummy) != NULL;
}
