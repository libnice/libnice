/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 * (C) 2008 Nokia Corporation
 *  Contact: Youness Alaoui
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
 *   Rémi Denis-Courmont, Nokia
 *   Kai Vehmanen
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

/*
 * Implementation of UDP socket interface using Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <arpa/inet.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "udp-turn.h"
#include "udp-bsd.h"
#include <stun/stunagent.h>

typedef struct {
  NiceAddress peer;
  uint16_t channel;
} ChannelBinding;

typedef struct {
  StunAgent agent;
  GList *channels;
  ChannelBinding *current_binding;
  NiceUDPSocket *udp_socket;
  NiceAddress server_addr;
  uint8_t *username;
  size_t username_len;
  uint8_t *password;
  size_t password_len;
  NiceUdpTurnSocketCompatibility compatibility;
} turn_priv;


static gboolean
priv_send_channel_bind (turn_priv *priv,  StunMessage *resp,
    uint16_t channel, NiceAddress *peer) {
  uint32_t channel_attr = channel << 16;
  StunMessage msg;
  uint8_t buffer[STUN_MAX_MESSAGE_SIZE];
  size_t stun_len;
  struct sockaddr_storage sa;

  nice_address_copy_to_sockaddr (peer, (struct sockaddr *)&sa);

  if (!stun_agent_init_request (&priv->agent, &msg,
          buffer, sizeof(buffer), STUN_CHANNELBIND))
    return FALSE;

  if (stun_message_append32 (&msg, STUN_ATTRIBUTE_CHANNEL_NUMBER,
          channel_attr) != 0)
    return FALSE;

  if (stun_message_append_xor_addr (&msg, STUN_ATTRIBUTE_PEER_ADDRESS,
          (struct sockaddr *)&sa, sizeof(sa)) != 0)
    return FALSE;

  if (priv->username != NULL && priv->username_len > 0) {
    if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_USERNAME,
            priv->username, priv->username_len) != 0)
      return FALSE;
  }

  if (resp) {
    uint8_t *realm;
    uint8_t *nonce;
    uint16_t len;

    realm = (uint8_t *) stun_message_find (resp, STUN_ATTRIBUTE_REALM, &len);
    if (realm != NULL) {
      if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_REALM, realm, len) != 0)
        return 0;
    }
    nonce = (uint8_t *) stun_message_find (resp, STUN_ATTRIBUTE_NONCE, &len);
    if (nonce != NULL) {
      if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_NONCE, nonce, len) != 0)
        return 0;
    }
  }

  stun_len = stun_agent_finish_message (&priv->agent, &msg,
      priv->password, priv->password_len);

  g_debug ("Sending %d bytes of CHANNEL-BIND", stun_len);
  if (stun_len > 0) {
    nice_udp_socket_send (priv->udp_socket, &priv->server_addr,
        stun_len, (gchar *)buffer);
    return TRUE;
  }

  return FALSE;
}
NICEAPI_EXPORT gboolean
nice_udp_turn_socket_set_peer (NiceUDPSocket *sock, NiceAddress *peer)
{
  turn_priv *priv = (turn_priv *) sock->priv;
  StunMessage msg;
  uint8_t buffer[STUN_MAX_MESSAGE_SIZE];
  size_t stun_len;
  struct sockaddr_storage sa;

  nice_address_copy_to_sockaddr (peer, (struct sockaddr *)&sa);

  if (priv->current_binding)
    return FALSE;

  if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9) {
    uint16_t channel = 0x4000;
    GList *i = priv->channels;
    for (; i; i = i->next) {
      ChannelBinding *b = i->data;
      if (channel == b->channel) {
        i = priv->channels;
        channel++;
        continue;
      }
    }

    if (channel >= 0x4000 && channel < 0xffff) {
      gboolean ret = priv_send_channel_bind (priv, NULL, channel, peer);
      if (ret) {
        priv->current_binding = g_new0 (ChannelBinding, 1);
        priv->current_binding->channel = channel;
        priv->current_binding->peer = *peer;
      }
      return ret;
    }
    return FALSE;
  } else if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_MSN) {
    if (!stun_agent_init_request (&priv->agent, &msg,
            buffer, sizeof(buffer), STUN_OLD_SET_ACTIVE_DST))
      return FALSE;

    if (stun_message_append32 (&msg, STUN_ATTRIBUTE_MAGIC_COOKIE,
            TURN_MAGIC_COOKIE) != 0)
      return FALSE;

    if (priv->username != NULL && priv->username_len > 0) {
      if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_USERNAME,
              priv->username, priv->username_len) != 0)
        return FALSE;
    }

    if (stun_message_append_addr (&msg, STUN_ATTRIBUTE_DESTINATION_ADDRESS,
            (struct sockaddr *)&sa, sizeof(sa)) != 0)
      return FALSE;

    stun_len = stun_agent_finish_message (&priv->agent, &msg,
        priv->password, priv->password_len);

    if (stun_len > 0) {
      priv->current_binding = g_new0 (ChannelBinding, 1);
      priv->current_binding->channel = 0;
      priv->current_binding->peer = *peer;
      nice_udp_socket_send (priv->udp_socket, &priv->server_addr,
          stun_len, (gchar *)buffer);
    }
    return TRUE;
  } else if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    priv->current_binding = g_new0 (ChannelBinding, 1);
    priv->current_binding->channel = 0;
    priv->current_binding->peer = *peer;
    return TRUE;
  } else {
    return FALSE;
  }

  return FALSE;
}


gint
nice_udp_turn_socket_parse_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf,
  NiceAddress *recv_from,
  gchar *recv_buf,
  guint recv_len)
{

  turn_priv *priv = (turn_priv *) sock->priv;
  StunValidationStatus valid;
  StunMessage msg;
  struct sockaddr_storage sa;
  guint from_len = sizeof (sa);

  if (nice_address_equal (&priv->server_addr, recv_from)) {
    valid = stun_agent_validate (&priv->agent, &msg,
        (uint8_t *) recv_buf, (size_t) recv_len, NULL, NULL);

    if (valid == STUN_VALIDATION_SUCCESS) {
      if (priv->compatibility != NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9) {
        uint32_t cookie;
        if (stun_message_find32 (&msg, STUN_ATTRIBUTE_MAGIC_COOKIE, &cookie) != 0)
          goto recv;
        if (cookie != TURN_MAGIC_COOKIE)
          goto recv;
      }

      if (stun_message_get_class (&msg) == STUN_RESPONSE &&
          stun_message_get_method (&msg) == STUN_IND_SEND) {
        return 0;
      } else if (stun_message_get_class (&msg) == STUN_INDICATION &&
          stun_message_get_method (&msg) == STUN_IND_DATA) {
        uint16_t data_len;
        uint8_t *data;
        if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9) {
          if (stun_message_find_xor_addr (&msg, STUN_ATTRIBUTE_REMOTE_ADDRESS,
                  (struct sockaddr *)&sa, &from_len) != 0)
            goto recv;
        } else {
          if (stun_message_find_addr (&msg, STUN_ATTRIBUTE_REMOTE_ADDRESS,
                  (struct sockaddr *)&sa, &from_len) != 0)
            goto recv;
        }

        data = (uint8_t *) stun_message_find (&msg, STUN_ATTRIBUTE_DATA, &data_len);
        if (data == NULL)
          goto recv;

        nice_address_set_from_sockaddr (from, (struct sockaddr *)&sa);

        memmove (buf, data, len > data_len ? data_len : len);
        return len > data_len ? data_len : len;
      } else {
        goto recv;
      }
    }
  }

 recv:
  *from = *recv_from;
  memmove (buf, recv_buf, len > recv_len ? recv_len : len);
  return len > recv_len ? recv_len : len;
}

static gint
socket_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  turn_priv *priv = (turn_priv *) sock->priv;
  uint8_t recv_buf[STUN_MAX_MESSAGE_SIZE];
  gint recv_len;
  NiceAddress recv_from;

  recv_len = nice_udp_socket_recv (priv->udp_socket, &recv_from,
      sizeof(recv_buf), (gchar *) recv_buf);

  return nice_udp_turn_socket_parse_recv (sock, from, len, buf, &recv_from,
      (gchar *) recv_buf, (guint) recv_len);
}

static gboolean
socket_send (
  NiceUDPSocket *sock,
  const NiceAddress *to,
  guint len,
  const gchar *buf)
{
  turn_priv *priv = (turn_priv *) sock->priv;
  StunMessage msg;
  uint8_t buffer[STUN_MAX_MESSAGE_SIZE];
  size_t stun_len;
  struct sockaddr_storage sa;

  nice_address_copy_to_sockaddr (to, (struct sockaddr *)&sa);

  if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9) {
    if (!stun_agent_init_indication (&priv->agent, &msg,
            buffer, sizeof(buffer), STUN_IND_SEND))
      goto send;
    if (stun_message_append_xor_addr (&msg, STUN_ATTRIBUTE_PEER_ADDRESS,
            (struct sockaddr *)&sa, sizeof(sa)) != 0)
      goto send;
  } else {
    if (!stun_agent_init_request (&priv->agent, &msg,
            buffer, sizeof(buffer), STUN_SEND))
      goto send;

    if (stun_message_append32 (&msg, STUN_ATTRIBUTE_MAGIC_COOKIE,
            TURN_MAGIC_COOKIE) != 0)
      goto send;

    if (priv->username != NULL && priv->username_len > 0) {
      if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_USERNAME,
              priv->username, priv->username_len) != 0)
        goto send;
    }

    if (stun_message_append_addr (&msg, STUN_ATTRIBUTE_DESTINATION_ADDRESS,
            (struct sockaddr *)&sa, sizeof(sa)) != 0)
      goto send;
  }


  if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_DATA, buf, len) != 0)
    goto send;

  stun_len = stun_agent_finish_message (&priv->agent, &msg,
      priv->password, priv->password_len);

  if (stun_len > 0) {
    nice_udp_socket_send (priv->udp_socket, &priv->server_addr,
        stun_len, (gchar *)buffer);
    return TRUE;
  }
 send:
  nice_udp_socket_send (priv->udp_socket, to, len, buf);

  return TRUE;
}

static void
socket_close (NiceUDPSocket *sock)
{
  turn_priv *priv = (turn_priv *) sock->priv;
  GList *i = priv->channels;
  for (; i; i = i->next) {
    ChannelBinding *b = i->data;
    g_free (b);
  }
  g_list_free (priv->channels);
  g_free (priv->username);
  g_free (priv->password);
  g_free (priv);
}

/*** NiceUDPSocketFactory ***/

static gboolean
socket_factory_init_socket (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr)
{
  return FALSE;
}

NICEAPI_EXPORT gboolean
nice_udp_turn_create_socket_full (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr,
  NiceUDPSocket *udp_socket,
  NiceAddress *server_addr,
  gchar *username,
  gchar *password,
  NiceUdpTurnSocketCompatibility compatibility,
  gboolean long_term)
{
  turn_priv *priv = g_new0 (turn_priv, 1);

  if (compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_3489BIS,
        long_term ? STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS :
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS);
  } else {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        long_term ? STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS :
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS);
  }

  priv->channels = NULL;
  priv->current_binding = NULL;
  priv->udp_socket = udp_socket;

  if (compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_MSN) {
    priv->username = g_base64_decode (username, &priv->username_len);
    priv->password = g_base64_decode (password, &priv->password_len);
  } else {
    priv->username = (uint8_t *)g_strdup (username);
    priv->username_len = (size_t) strlen (username);
    priv->password = (uint8_t *)g_strdup (password);
    priv->password_len = (size_t) strlen (password);
  }
  priv->server_addr = *server_addr;
  priv->compatibility = compatibility;
  sock->addr = *addr;
  sock->fileno = udp_socket->fileno;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->close = socket_close;
  sock->priv = (void *) priv;
  return TRUE;
}

static void
socket_factory_close (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man)
{
}

NICEAPI_EXPORT void
nice_udp_turn_socket_factory_init (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man)
{

  man->init = socket_factory_init_socket;
  man->close = socket_factory_close;

}

