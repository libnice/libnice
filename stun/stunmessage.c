/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007-2009 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
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

#include "stunmessage.h"
#include "utils.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif


#include <string.h>
#include <stdlib.h>

bool stun_message_init (StunMessage *msg, StunClass c, StunMethod m,
    const StunTransactionId id)
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
stun_message_find (const StunMessage *msg, StunAttribute type,
    uint16_t *palen)
{
  size_t length = stun_message_length (msg);
  size_t offset = 0;

  /* In MS-TURN, IDs of REALM and NONCE STUN attributes are swapped. */
  if (msg->agent && msg->agent->compatibility == STUN_COMPATIBILITY_OC2007)
  {
    if (type == STUN_ATTRIBUTE_REALM)
      type = STUN_ATTRIBUTE_NONCE;
    else if (type == STUN_ATTRIBUTE_NONCE)
      type = STUN_ATTRIBUTE_REALM;
  }

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

      default:
        /* Nothing misordered. */
        break;
    }

    if (!(msg->agent &&
            (msg->agent->usage_flags & STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES)))
      alen = stun_align (alen);

    offset += alen;
  }

  return NULL;
}


StunMessageReturn
stun_message_find_flag (const StunMessage *msg, StunAttribute type)
{
  const void *ptr;
  uint16_t len = 0;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_FOUND;
  return (len == 0) ? STUN_MESSAGE_RETURN_SUCCESS :
      STUN_MESSAGE_RETURN_INVALID;
}


StunMessageReturn
stun_message_find32 (const StunMessage *msg, StunAttribute type,
    uint32_t *pval)
{
  const void *ptr;
  uint16_t len = 0;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_FOUND;

  if (len == 4)
  {
    uint32_t val;

    memcpy (&val, ptr, sizeof (val));
    *pval = ntohl (val);
    return STUN_MESSAGE_RETURN_SUCCESS;
  }
  return STUN_MESSAGE_RETURN_INVALID;
}


StunMessageReturn
stun_message_find64 (const StunMessage *msg, StunAttribute type,
    uint64_t *pval)
{
  const void *ptr;
  uint16_t len = 0;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_FOUND;

  if (len == 8)
  {
    uint32_t tab[2];

    memcpy (tab, ptr, sizeof (tab));
    *pval = ((uint64_t)ntohl (tab[0]) << 32) | ntohl (tab[1]);
    return STUN_MESSAGE_RETURN_SUCCESS;
  }
  return STUN_MESSAGE_RETURN_INVALID;
}


StunMessageReturn
stun_message_find_string (const StunMessage *msg, StunAttribute type,
    char *buf, size_t buflen)
{
  const unsigned char *ptr;
  uint16_t len = 0;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_FOUND;

  if (len >= buflen)
    return STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE;

  memcpy (buf, ptr, len);
  buf[len] = '\0';
  return STUN_MESSAGE_RETURN_SUCCESS;
}


StunMessageReturn
stun_message_find_addr (const StunMessage *msg, StunAttribute type,
    struct sockaddr_storage *addr, socklen_t *addrlen)
{
  const uint8_t *ptr;
  uint16_t len = 0;

  ptr = stun_message_find (msg, type, &len);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_FOUND;

  if (len < 4)
    return STUN_MESSAGE_RETURN_INVALID;

  switch (ptr[1])
  {
    case 1:
      {
        struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
        if (((size_t) *addrlen < sizeof (*ip4)) || (len != 8))
        {
          *addrlen = sizeof (*ip4);
          return STUN_MESSAGE_RETURN_INVALID;
        }

        memset (ip4, 0, *addrlen);
        ip4->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
        ip4->sin_len =
#endif
            *addrlen = sizeof (*ip4);
        memcpy (&ip4->sin_port, ptr + 2, 2);
        memcpy (&ip4->sin_addr, ptr + 4, 4);
        return STUN_MESSAGE_RETURN_SUCCESS;
      }

    case 2:
      {
        struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
        if (((size_t) *addrlen < sizeof (*ip6)) || (len != 20))
        {
          *addrlen = sizeof (*ip6);
          return STUN_MESSAGE_RETURN_INVALID;
        }

        memset (ip6, 0, *addrlen);
        ip6->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
        ip6->sin6_len =
#endif
            *addrlen = sizeof (*ip6);
        memcpy (&ip6->sin6_port, ptr + 2, 2);
        memcpy (&ip6->sin6_addr, ptr + 4, 16);
        return STUN_MESSAGE_RETURN_SUCCESS;
      }

    default:
      return STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS;
  }
}

StunMessageReturn
stun_message_find_xor_addr (const StunMessage *msg, StunAttribute type,
    struct sockaddr_storage *addr, socklen_t *addrlen)
{
  StunMessageReturn val = stun_message_find_addr (msg, type, addr, addrlen);
  if (val)
    return val;

  return stun_xor_address (msg, addr, *addrlen, STUN_MAGIC_COOKIE);
}

StunMessageReturn
stun_message_find_xor_addr_full (const StunMessage *msg, StunAttribute type,
    struct sockaddr_storage *addr, socklen_t *addrlen, uint32_t magic_cookie)
{
  StunMessageReturn val = stun_message_find_addr (msg, type, addr, addrlen);
  if (val)
    return val;

  return stun_xor_address (msg, addr, *addrlen, magic_cookie);
}

StunMessageReturn
stun_message_find_error (const StunMessage *msg, int *code)
{
  uint16_t alen = 0;
  const uint8_t *ptr = stun_message_find (msg, STUN_ATTRIBUTE_ERROR_CODE, &alen);
  uint8_t class, number;

  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_FOUND;
  if (alen < 4)
    return STUN_MESSAGE_RETURN_INVALID;

  class = ptr[2] & 0x7;
  number = ptr[3];
  if ((class < 3) || (class > 6) || (number > 99))
    return STUN_MESSAGE_RETURN_INVALID;

  *code = (class * 100) + number;
  return STUN_MESSAGE_RETURN_SUCCESS;
}

void *
stun_message_append (StunMessage *msg, StunAttribute type, size_t length)
{
  uint8_t *a;
  uint16_t mlen = stun_message_length (msg);

  /* In MS-TURN, IDs of REALM and NONCE STUN attributes are swapped. */
  if (msg->agent && msg->agent->compatibility == STUN_COMPATIBILITY_OC2007)
  {
    if (type == STUN_ATTRIBUTE_NONCE)
      type = STUN_ATTRIBUTE_REALM;
    else if (type == STUN_ATTRIBUTE_REALM)
      type = STUN_ATTRIBUTE_NONCE;
  }

  if ((size_t)mlen + STUN_ATTRIBUTE_HEADER_LENGTH + length > msg->buffer_len)
    return NULL;


  a = msg->buffer + mlen;
  a = stun_setw (a, type);
  if (msg->agent &&
      (msg->agent->usage_flags & STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES))
  {
    a = stun_setw (a, length);
  } else {
    /* NOTE: If cookie is not present, we need to force the attribute length
     * to a multiple of 4 for compatibility with old RFC3489 */
    a = stun_setw (a, stun_message_has_cookie (msg) ? length : stun_align (length));

    /* Add padding if needed. Avoid a zero-length memset() call. */
    if (stun_padding (length) > 0) {
      memset (a + length, ' ', stun_padding (length));
      mlen += stun_padding (length);
    }
  }

  mlen +=  4 + length;

  stun_setw (msg->buffer + STUN_MESSAGE_LENGTH_POS, mlen - STUN_MESSAGE_HEADER_LENGTH);
  return a;
}


StunMessageReturn
stun_message_append_bytes (StunMessage *msg, StunAttribute type,
    const void *data, size_t len)
{
  void *ptr = stun_message_append (msg, type, len);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE;

  if (len > 0)
    memcpy (ptr, data, len);

  return STUN_MESSAGE_RETURN_SUCCESS;
}


StunMessageReturn
stun_message_append_flag (StunMessage *msg, StunAttribute type)
{
  return stun_message_append_bytes (msg, type, NULL, 0);
}


StunMessageReturn
stun_message_append32 (StunMessage *msg, StunAttribute type,
    uint32_t value)
{
  value = htonl (value);
  return stun_message_append_bytes (msg, type, &value, 4);
}


StunMessageReturn
stun_message_append64 (StunMessage *msg, StunAttribute type,
    uint64_t value)
{
  uint32_t tab[2];
  tab[0] = htonl ((uint32_t)(value >> 32));
  tab[1] = htonl ((uint32_t)value);
  return stun_message_append_bytes (msg, type, tab, 8);
}


StunMessageReturn
stun_message_append_string (StunMessage * msg, StunAttribute type,
    const char *str)
{
  return stun_message_append_bytes (msg, type, str, strlen (str));
}

StunMessageReturn
stun_message_append_addr (StunMessage *msg, StunAttribute type,
    const struct sockaddr *addr, socklen_t addrlen)
{
  const void *pa;
  uint8_t *ptr;
  uint16_t alen, port;
  uint8_t family;

  if ((size_t) addrlen < sizeof (struct sockaddr))
    return STUN_MESSAGE_RETURN_INVALID;

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
        if ((size_t) addrlen < sizeof (*ip6))
          return STUN_MESSAGE_RETURN_INVALID;

        family = 2;
        port = ip6->sin6_port;
        alen = 16;
        pa = &ip6->sin6_addr;
        break;
      }

    default:
      return STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS;
  }

  ptr = stun_message_append (msg, type, 4 + alen);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE;

  ptr[0] = 0;
  ptr[1] = family;
  memcpy (ptr + 2, &port, 2);
  memcpy (ptr + 4, pa, alen);
  return STUN_MESSAGE_RETURN_SUCCESS;
}


StunMessageReturn
stun_message_append_xor_addr (StunMessage *msg, StunAttribute type,
    const struct sockaddr_storage *addr, socklen_t addrlen)
{
  StunMessageReturn val;
  /* Must be big enough to hold any supported address: */
  struct sockaddr_storage tmpaddr;

  if ((size_t) addrlen > sizeof (tmpaddr))
    addrlen = sizeof (tmpaddr);
  memcpy (&tmpaddr, addr, addrlen);

  val = stun_xor_address (msg, &tmpaddr, addrlen,
      STUN_MAGIC_COOKIE);
  if (val)
    return val;

  return stun_message_append_addr (msg, type, (struct sockaddr *) &tmpaddr,
      addrlen);
}

StunMessageReturn
stun_message_append_xor_addr_full (StunMessage *msg, StunAttribute type,
    const struct sockaddr_storage *addr, socklen_t addrlen,
    uint32_t magic_cookie)
{
  StunMessageReturn val;
  /* Must be big enough to hold any supported address: */
  struct sockaddr_storage tmpaddr;

  if ((size_t) addrlen > sizeof (tmpaddr))
    addrlen = sizeof (tmpaddr);
  memcpy (&tmpaddr, addr, addrlen);

  val = stun_xor_address (msg, &tmpaddr, addrlen, magic_cookie);
  if (val)
    return val;

  return stun_message_append_addr (msg, type, (struct sockaddr *) &tmpaddr,
      addrlen);
}



StunMessageReturn
stun_message_append_error (StunMessage *msg, StunError code)
{
  const char *str = stun_strerror (code);
  size_t len = strlen (str);

  uint8_t *ptr = stun_message_append (msg, STUN_ATTRIBUTE_ERROR_CODE, 4 + len);
  if (ptr == NULL)
    return STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE;

  memset (ptr, 0, 2);
  ptr[2] = code / 100;
  ptr[3] = code % 100;
  memcpy (ptr + 4, str, len);
  return STUN_MESSAGE_RETURN_SUCCESS;
}

/* Fast validity check for a potential STUN packet. Examines the type and
 * length, but none of the attributes. Designed to allow vectored I/O on all
 * incoming packets, filtering packets for closer inspection as to whether
 * they’re STUN packets. If they look like they might be, their buffers are
 * compacted to allow a more thorough check. */
ssize_t stun_message_validate_buffer_length_fast (StunInputVector *buffers,
    int n_buffers, size_t total_length, bool has_padding)
{
  size_t mlen;

  if (total_length < 1 || n_buffers == 0 || buffers[0].buffer == NULL)
  {
    stun_debug ("STUN error: No data!");
    return STUN_MESSAGE_BUFFER_INVALID;
  }

  if (buffers[0].buffer[0] >> 6)
  {
    stun_debug ("STUN error: RTP or other non-protocol packet!");
    return STUN_MESSAGE_BUFFER_INVALID; // RTP or other non-STUN packet
  }

  if (total_length < STUN_MESSAGE_LENGTH_POS + STUN_MESSAGE_LENGTH_LEN)
  {
    stun_debug ("STUN error: Incomplete STUN message header!");
    return STUN_MESSAGE_BUFFER_INCOMPLETE;
  }

  if (buffers[0].size >= STUN_MESSAGE_LENGTH_POS + STUN_MESSAGE_LENGTH_LEN) {
    /* Fast path. */
    mlen = stun_getw (buffers[0].buffer + STUN_MESSAGE_LENGTH_POS);
  } else {
    /* Slow path. Tiny buffers abound. */
    size_t skip_remaining = STUN_MESSAGE_LENGTH_POS;
    unsigned int i;

    /* Skip bytes. */
    for (i = 0; (n_buffers >= 0 && i < (unsigned int) n_buffers) ||
             (n_buffers < 0 && buffers[i].buffer != NULL); i++) {
      if (buffers[i].size <= skip_remaining)
        skip_remaining -= buffers[i].size;
      else
        break;
    }

    /* Read bytes. May be split over two buffers. We’ve already checked that
     * @total_length is long enough, so @n_buffers should be too. */
    if (buffers[i].size - skip_remaining > 1) {
      mlen = stun_getw (buffers[i].buffer + skip_remaining);
    } else {
      mlen = (*(buffers[i].buffer + skip_remaining) << 8) |
             (*(buffers[i + 1].buffer));
    }
  }

  mlen += STUN_MESSAGE_HEADER_LENGTH;

  if (has_padding && stun_padding (mlen)) {
    stun_debug ("STUN error: Invalid message length: %u!", (unsigned)mlen);
    return STUN_MESSAGE_BUFFER_INVALID; // wrong padding
  }

  if (total_length < mlen) {
    stun_debug ("STUN error: Incomplete message: %u of %u bytes!",
        (unsigned) total_length, (unsigned) mlen);
    return STUN_MESSAGE_BUFFER_INCOMPLETE; // partial message
  }

  return mlen;
}

int stun_message_validate_buffer_length (const uint8_t *msg, size_t length,
    bool has_padding)
{
  ssize_t fast_retval;
  size_t mlen;
  size_t len;
  StunInputVector input_buffer = { msg, length };

  /* Fast pre-check first. */
  fast_retval = stun_message_validate_buffer_length_fast (&input_buffer, 1,
      length, has_padding);
  if (fast_retval <= 0)
    return fast_retval;

  mlen = fast_retval;

  /* Skip past the header (validated above). */
  msg += 20;
  len = mlen - 20;

  /* from then on, we know we have the entire packet in buffer */
  while (len > 0)
  {
    size_t alen;

    if (len < 4)
    {
      stun_debug ("STUN error: Incomplete STUN attribute header of length "
          "%u bytes!", (unsigned)len);
      return STUN_MESSAGE_BUFFER_INVALID;
    }

    alen = stun_getw (msg + STUN_ATTRIBUTE_TYPE_LEN);
    if (has_padding)
      alen = stun_align (alen);

    /* thanks to padding check, if (end > msg) then there is not only one
     * but at least 4 bytes left */
    len -= 4;

    if (len < alen)
    {
      stun_debug ("STUN error: %u instead of %u bytes for attribute!",
          (unsigned)len, (unsigned)alen);
      return STUN_MESSAGE_BUFFER_INVALID; // no room for attribute value + padding
    }

    len -= alen;
    msg += 4 + alen;
  }

  return mlen;
}

void stun_message_id (const StunMessage *msg, StunTransactionId id)
{
  memcpy (id, msg->buffer + STUN_MESSAGE_TRANS_ID_POS, STUN_MESSAGE_TRANS_ID_LEN);
}

StunMethod stun_message_get_method (const StunMessage *msg)
{
  uint16_t t = stun_getw (msg->buffer);
  /* HACK HACK HACK
     A google/msn data indication is 0x0115 which is contrary to the RFC 5389
     which states that 8th and 12th bits are for the class and that 0x01 is
     for indications...
     So 0x0115 is reported as a "connect error response", while it should be
     a data indication, which message type should actually be 0x0017
     This should fix the issue, and it's considered safe since the "connect"
     method doesn't exist anymore */
  if (t == 0x0115)
    t = 0x0017;
  return (StunMethod)(((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) |
                          (t & 0x000f));
}


StunClass stun_message_get_class (const StunMessage *msg)
{
  uint16_t t = stun_getw (msg->buffer);
  /* HACK HACK HACK
     A google/msn data indication is 0x0115 which is contrary to the RFC 5389
     which states that 8th and 12th bits are for the class and that 0x01 is
     for indications...
     So 0x0115 is reported as a "connect error response", while it should be
     a data indication, which message type should actually be 0x0017
     This should fix the issue, and it's considered safe since the "connect"
     method doesn't exist anymore */
  if (t == 0x0115)
    t = 0x0017;
  return (StunClass)(((t & 0x0100) >> 7) | ((t & 0x0010) >> 4));
}

bool stun_message_has_attribute (const StunMessage *msg, StunAttribute type)
{
  uint16_t dummy;
  return stun_message_find (msg, type, &dummy) != NULL;
}


bool stun_optional (uint16_t t)
{
  return (t >> 15) == 1;
}

const char *stun_strerror (StunError code)
{
  static const struct
  {
    StunError code;
    char     phrase[32];
  } tab[] =
  {
    { STUN_ERROR_TRY_ALTERNATE, "Try alternate server" },
    { STUN_ERROR_BAD_REQUEST, "Bad request" },
    { STUN_ERROR_UNAUTHORIZED, "Unauthorized" },
    { STUN_ERROR_UNKNOWN_ATTRIBUTE, "Unknown Attribute" },
    { STUN_ERROR_ALLOCATION_MISMATCH, "Allocation Mismatch" },
    { STUN_ERROR_STALE_NONCE, "Stale Nonce" },
    { STUN_ERROR_ACT_DST_ALREADY, "Active Destination Already Set" },
    { STUN_ERROR_UNSUPPORTED_FAMILY, "Address Family not Supported" },
    { STUN_ERROR_UNSUPPORTED_TRANSPORT, "Unsupported Transport Protocol" },
    { STUN_ERROR_INVALID_IP, "Invalid IP Address" },
    { STUN_ERROR_INVALID_PORT, "Invalid Port" },
    { STUN_ERROR_OP_TCP_ONLY, "Operation for TCP Only" },
    { STUN_ERROR_CONN_ALREADY, "Connection Already Exists" },
    { STUN_ERROR_ALLOCATION_QUOTA_REACHED, "Allocation Quota Reached" },
    { STUN_ERROR_ROLE_CONFLICT, "Role conflict" },
    { STUN_ERROR_SERVER_ERROR, "Server Error" },
    { STUN_ERROR_SERVER_CAPACITY, "Insufficient Capacity" },
    { STUN_ERROR_INSUFFICIENT_CAPACITY, "Insufficient Capacity" },
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
