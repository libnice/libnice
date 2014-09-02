/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation. All rights reserved.
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
 * Implementation of TCP relay socket interface using TCP Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "socks5.h"
#include "agent-priv.h"
#include "socket-priv.h"

#include <string.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef enum {
  SOCKS_STATE_INIT,
  SOCKS_STATE_AUTH,
  SOCKS_STATE_CONNECT,
  SOCKS_STATE_CONNECTED,
  SOCKS_STATE_ERROR
} SocksState;

typedef struct {
  SocksState state;
  NiceSocket *base_socket;
  NiceAddress addr;
  gchar *username;
  gchar *password;
  GQueue send_queue;
} Socks5Priv;


static void socket_close (NiceSocket *sock);
static gint socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages);
static gint socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages);
static gint socket_send_messages_reliable (NiceSocket *sock,
    const NiceAddress *to, const NiceOutputMessage *messages, guint n_messages);
static gboolean socket_is_reliable (NiceSocket *sock);
static gboolean socket_can_send (NiceSocket *sock, NiceAddress *addr);
static void socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data);


NiceSocket *
nice_socks5_socket_new (NiceSocket *base_socket,
    NiceAddress *addr, gchar *username, gchar *password)
{
  Socks5Priv *priv;
  NiceSocket *sock = NULL;

  if (addr) {
    sock = g_slice_new0 (NiceSocket);
    sock->priv = priv = g_slice_new0 (Socks5Priv);

    priv->base_socket = base_socket;
    priv->addr = *addr;
    priv->username = g_strdup (username);
    priv->password = g_strdup (password);

    sock->type = NICE_SOCKET_TYPE_SOCKS5;
    sock->fileno = priv->base_socket->fileno;
    sock->addr = priv->base_socket->addr;
    sock->send_messages = socket_send_messages;
    sock->send_messages_reliable = socket_send_messages_reliable;
    sock->recv_messages = socket_recv_messages;
    sock->is_reliable = socket_is_reliable;
    sock->can_send = socket_can_send;
    sock->set_writable_callback = socket_set_writable_callback;
    sock->close = socket_close;

    /* Send SOCKS5 handshake */
    {
      gchar msg[4];
      gint len = 3;

      msg[0] = 0x05; /* SOCKS version */
      msg[1] = 0x01; /* number of methods supported */
      msg[2] = 0x00; /* no authentication method*/

      g_debug ("user/pass : %s - %s", username, password);
      /* add support for authentication method */
      if (username || password) {
        msg[1] = 0x02; /* number of methods supported */
        msg[3] = 0x02; /* authentication method */
        len++;
      }

      /* We send 'to' NULL because it will always be to an already connected
       * TCP base socket, which ignores the destination */
      nice_socket_send_reliable (priv->base_socket, NULL, len, msg);
      priv->state = SOCKS_STATE_INIT;
    }
  }

  return sock;
}


static void
socket_close (NiceSocket *sock)
{
  Socks5Priv *priv = sock->priv;

  if (priv->base_socket)
    nice_socket_free (priv->base_socket);

  if (priv->username)
    g_free (priv->username);

  if (priv->password)
    g_free (priv->password);

  nice_socket_free_send_queue (&priv->send_queue);

  g_slice_free(Socks5Priv, sock->priv);
  sock->priv = NULL;
}


static gint
socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  Socks5Priv *priv = sock->priv;
  guint i;
  gint ret = -1;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return 0;

  switch (priv->state) {
    case SOCKS_STATE_CONNECTED:
      /* Common case: fast pass-through to the base socket once we’re
       * connected. */
      if (priv->base_socket) {
        ret = nice_socket_recv_messages (priv->base_socket,
            recv_messages, n_recv_messages);
      }

      if (ret <= 0)
        return ret;

      /* After successfully receiving into at least one NiceInputMessage,
       * update the from address in each valid NiceInputMessage. */
      for (i = 0; i < (guint) ret; i++) {
        if (recv_messages[i].from != NULL)
          *recv_messages[i].from = priv->addr;
      }

      return ret;

    case SOCKS_STATE_INIT:
      {
        guint8 data[2];
        GInputVector local_recv_buf = { data, sizeof (data) };
        NiceInputMessage local_recv_message = { &local_recv_buf, 1, NULL, 0 };

        nice_debug ("Socks5 state Init");

        if (priv->base_socket) {
          ret = nice_socket_recv_messages (priv->base_socket,
              &local_recv_message, 1);
        }

        if (ret <= 0) {
          return ret;
        } else if (ret == 1 && local_recv_buf.size == sizeof(data)) {
          if (data[0] == 0x05) {
            if (data[1] == 0x02) {
              gchar msg[515];
              gint len = 0;

              if (priv->username || priv->password) {
                gint ulen = 0;
                gint plen = 0;

                if (priv->username)
                  ulen = strlen (priv->username);
                if (ulen > 255) {
                  nice_debug ("Socks5 username length > 255");
                  goto error;
                }

                if (priv->password)
                  plen  = strlen (priv->password);
                if (plen > 255) {
                  nice_debug ("Socks5 password length > 255");
                  goto error;
                }

                msg[len++] = 0x01; /* auth version */
                msg[len++] = ulen; /* username length */
                if (ulen > 0)
                  memcpy (msg + len, priv->username, ulen); /* Username */
                len += ulen;
                msg[len++] = plen; /* Password length */
                if (plen > 0)
                  memcpy (msg + len, priv->password, plen); /* Password */
                len += plen;

                nice_socket_send_reliable (priv->base_socket, NULL, len, msg);
                priv->state = SOCKS_STATE_AUTH;
              } else {
                /* Authentication required but no auth info available */
                goto error;
              }
            } else if (data[1] == 0x00) {
              goto send_connect;
            } else {
              /* method not supported by socks server */
              goto error;
            }
          } else {
            /* invalid SOCKS server version */
            goto error;
          }
        } else {
          /* read error */
          goto error;
        }
      }
      break;
    case SOCKS_STATE_AUTH:
      {
        guint8 data[2];
        GInputVector local_recv_buf = { data, sizeof (data) };
        NiceInputMessage local_recv_message = { &local_recv_buf, 1, NULL, 0 };

        nice_debug ("Socks5 state auth");
        if (priv->base_socket) {
          ret = nice_socket_recv_messages (priv->base_socket,
              &local_recv_message, 1);
        }

        if (ret <= 0) {
          return ret;
        } else if (ret == 1 && local_recv_buf.size == sizeof(data)) {
          if (data[0] == 0x01 && data[1] == 0x00) {
            /* Authenticated */
            goto send_connect;
          } else {
            /* Authentication failed */
            goto error;
          }
        }
      }
      break;
    case SOCKS_STATE_CONNECT:
      {
        guint8 data[22];
        GInputVector local_recv_buf = { data, sizeof (data) };
        NiceInputMessage local_recv_message = { &local_recv_buf, 1, NULL, 0 };

        nice_debug ("Socks5 state connect");
        if (priv->base_socket) {
          local_recv_buf.size = 4;
          ret = nice_socket_recv_messages (priv->base_socket,
              &local_recv_message, 1);
        }

        if (ret <= 0) {
          return ret;
        } else if (ret == 1 && local_recv_buf.size == 4) {
          if (data[0] == 0x05) {
            switch (data[1]) {
              case 0x00:
                if (data[2] == 0x00) {
                  switch (data[3]) {
                    case 0x01: /* IPV4 bound address */
                      local_recv_buf.size = 6;
                      ret = nice_socket_recv_messages (priv->base_socket,
                          &local_recv_message, 1);
                      if (ret != 1 || local_recv_buf.size != 6) {
                        /* Could not read server bound address */
                        goto error;
                      }
                      break;
                    case 0x04: /* IPV6 bound address */
                      local_recv_buf.size = 18;
                      ret = nice_socket_recv_messages (priv->base_socket,
                          &local_recv_message, 1);
                      if (ret != 1 || local_recv_buf.size != 18) {
                        /* Could not read server bound address */
                        goto error;
                      }
                      break;
                    default:
                      /* Unsupported address type */
                      goto error;
                  }
                  nice_socket_flush_send_queue (priv->base_socket,
                      &priv->send_queue);
                  priv->state = SOCKS_STATE_CONNECTED;
                } else {
                  /* Wrong reserved value */
                  goto error;
                }
                break;
              case 0x01: /* general SOCKS server failure */
              case 0x02: /* connection not allowed by ruleset */
              case 0x03: /* Network unreachable */
              case 0x04: /* Host unreachable */
              case 0x05: /* Connection refused */
              case 0x06: /* TTL expired */
              case 0x07: /* Command not supported */
              case 0x08: /* Address type not supported */
              default: /* Unknown error */
                goto error;
                break;
            }
          } else {
            /* Wrong server version */
            goto error;
          }
        } else {
          /* Invalid data received */
          goto error;
        }
      }
      break;
    case SOCKS_STATE_ERROR:
    default:
      /* Unknown status */
      goto error;
  }

  return 0;

 send_connect:
  {
    gchar msg[22];
    gint len = 0;
    union {
      struct sockaddr_storage storage;
      struct sockaddr addr;
      struct sockaddr_in in;
      struct sockaddr_in6 in6;
    } name;
    nice_address_copy_to_sockaddr(&priv->addr, &name.addr);

    msg[len++] = 0x05; /* SOCKS version */
    msg[len++] = 0x01; /* connect command */
    msg[len++] = 0x00; /* reserved */
    if (name.storage.ss_family == AF_INET) {
      msg[len++] = 0x01; /* IPV4 address type */
      /* Address */
      memcpy (msg + len, &(&name.in)->sin_addr, 4);
      len += 4;
      /* Port */
      memcpy (msg + len, &(&name.in)->sin_port, 2);
      len += 2;
    } else if (name.storage.ss_family == AF_INET6) {
      msg[len++] = 0x04; /* IPV6 address type */
      /* Address */
      memcpy (msg + len, &(&name.in6)->sin6_addr, 16);
      len += 16;
      /* Port */
      memcpy (msg + len, &(&name.in6)->sin6_port, 2);
      len += 2;
    }

    nice_socket_send_reliable (priv->base_socket, NULL, len, msg);
    priv->state = SOCKS_STATE_CONNECT;

    return 0;
  }
 error:
  nice_debug ("Socks5 error");
  if (priv->base_socket)
    nice_socket_free (priv->base_socket);
  priv->base_socket = NULL;
  priv->state = SOCKS_STATE_ERROR;

  return -1;
}

static gint
socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  Socks5Priv *priv = sock->priv;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return -1;

  if (priv->state == SOCKS_STATE_CONNECTED) {
    /* Fast path: pass through to the base socket once connected. */
    if (priv->base_socket == NULL)
      return -1;

    return nice_socket_send_messages (priv->base_socket, to, messages,
        n_messages);
  } else if (priv->state == SOCKS_STATE_ERROR) {
    return -1;
  } else {
    return 0;
  }
}


static gint
socket_send_messages_reliable (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  Socks5Priv *priv = sock->priv;

  if (priv->state == SOCKS_STATE_CONNECTED) {
    /* Fast path: pass through to the base socket once connected. */
    if (priv->base_socket == NULL)
      return -1;

    return nice_socket_send_messages_reliable (priv->base_socket, to, messages,
        n_messages);
  } else if (priv->state == SOCKS_STATE_ERROR) {
    return -1;
  } else {
    nice_socket_queue_send (&priv->send_queue, to, messages, n_messages);
  }
  return n_messages;
}


static gboolean
socket_is_reliable (NiceSocket *sock)
{
  Socks5Priv *priv = sock->priv;

  return nice_socket_is_reliable (priv->base_socket);
}

static gboolean
socket_can_send (NiceSocket *sock, NiceAddress *addr)
{
  Socks5Priv *priv = sock->priv;

  return nice_socket_can_send (priv->base_socket, addr);
}

static void
socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data)
{
  Socks5Priv *priv = sock->priv;

  nice_socket_set_writable_callback (priv->base_socket, callback, user_data);
}
