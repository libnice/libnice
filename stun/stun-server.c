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
#include <sys/types.h>
#include <sys/socket.h>

#include <glib.h>

#include <stun.h>

const guint port = 3478;

static guint
handle_packet (
  struct sockaddr_in *from,
  guint packet_len,
  guint buf_len,
  gchar *buf)
{
  StunMessage *msg;
  gchar *packed;
  guint length;

  msg = stun_message_unpack (packet_len, buf);

  if (msg == NULL)
    {
      g_debug ("got invalid message");
      return 0;
    }

  if (msg->type != STUN_MESSAGE_BINDING_REQUEST)
    {
      g_debug ("ignoring message which isn't a binding request");
      return 0;
    }

  stun_message_free (msg);
  msg = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE, msg->transaction_id,
      1);
  msg->attributes[0] = stun_attribute_mapped_address_new (
      ntohl (from->sin_addr.s_addr), ntohs (from->sin_port));
  length = stun_message_pack (msg, &packed);
  g_assert (length > 0);

  if (length > buf_len)
    {
      g_debug ("reply message too large to fit in buffer");
      stun_message_free (msg);
      return 0;
    }

  g_memmove (buf, packed, length);
  stun_message_free (msg);
  g_free (packed);
  return length;
}

int
main (void)
{
  guint sock, ret;
  struct sockaddr_in sin;

  sock = socket (AF_INET, SOCK_DGRAM, 0);
  g_assert (sock);

  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  sin.sin_addr.s_addr = INADDR_ANY;

  ret = bind (sock, (struct sockaddr *) &sin, sizeof (sin));
  g_assert (ret == 0);

  for (;;)
    {
      gint recvd;
      gchar buf[1024];
      struct sockaddr_in from;
      guint from_len = sizeof (from);
      guint reply_len;

      recvd = recvfrom (sock, buf, sizeof (buf), 0,
          (struct sockaddr *) &from, &from_len);

      if (recvd < 1)
        continue;

      g_debug ("packet: %s:%d", inet_ntoa (from.sin_addr),
          ntohs (from.sin_port));

      reply_len = handle_packet (&from, recvd, sizeof (buf), buf);

      if (reply_len == 0)
        continue;

      sendto (sock, buf, reply_len, 0, (struct sockaddr *) &from, from_len);
    }
}
