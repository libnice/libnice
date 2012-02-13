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


struct to_be_sent {
  guint length;
  gchar *buf;
  NiceAddress to;
};


static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gboolean socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);

static void add_to_be_sent (NiceSocket *sock, const NiceAddress *to,
    const gchar *buf, guint len);
static void free_to_be_sent (struct to_be_sent *tbs);


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

    sock->fileno = priv->base_socket->fileno;
    sock->addr = priv->base_socket->addr;
    sock->send = socket_send;
    sock->recv = socket_recv;
    sock->is_reliable = socket_is_reliable;
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
      nice_socket_send (priv->base_socket, NULL, len, msg);
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

  g_queue_foreach (&priv->send_queue, (GFunc) free_to_be_sent, NULL);
  g_queue_clear (&priv->send_queue);

  g_slice_free(Socks5Priv, sock->priv);
}


static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  Socks5Priv *priv = sock->priv;

  if (from)
    *from = priv->addr;

  switch (priv->state) {
    case SOCKS_STATE_CONNECTED:
      if (priv->base_socket)
        return nice_socket_recv (priv->base_socket, NULL, len, buf);
      break;
    case SOCKS_STATE_INIT:
      {
        gchar data[2];
        gint ret  = -1;

        nice_debug ("Socks5 state Init");

        if (priv->base_socket)
          ret = nice_socket_recv (priv->base_socket, NULL, sizeof(data), data);

        if (ret <= 0) {
          return ret;
        } else if(ret == sizeof(data)) {
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

                nice_socket_send (priv->base_socket, NULL, len, msg);
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
        gchar data[2];
        gint ret  = -1;

        nice_debug ("Socks5 state auth");
        if (priv->base_socket)
          ret = nice_socket_recv (priv->base_socket, NULL, sizeof(data), data);

        if (ret <= 0) {
          return ret;
        } else if(ret == sizeof(data)) {
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
        gchar data[22];
        gint ret  = -1;

        nice_debug ("Socks5 state connect");
        if (priv->base_socket)
          ret = nice_socket_recv (priv->base_socket, NULL, 4, data);

        if (ret <= 0) {
          return ret;
        } else if(ret == 4) {
          if (data[0] == 0x05) {
            switch (data[1]) {
              case 0x00:
                if (data[2] == 0x00) {
                  struct to_be_sent *tbs = NULL;
                  switch (data[3]) {
                    case 0x01: /* IPV4 bound address */
                      ret = nice_socket_recv (priv->base_socket, NULL, 6, data);
                      if (ret != 6) {
                        /* Could not read server bound address */
                        goto error;
                      }
                      break;
                    case 0x04: /* IPV6 bound address */
                      ret = nice_socket_recv (priv->base_socket, NULL, 18, data);
                      if (ret != 18) {
                        /* Could not read server bound address */
                        goto error;
                      }
                      break;
                    default:
                      /* Unsupported address type */
                      goto error;
                  }
                  while ((tbs = g_queue_pop_head (&priv->send_queue))) {
                    nice_socket_send (priv->base_socket, &tbs->to,
                        tbs->length, tbs->buf);
                    g_free (tbs->buf);
                    g_slice_free (struct to_be_sent, tbs);
                  }
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
    default:
      /* Unknown status */
      goto error;
  }

  return 0;

 send_connect:
  {
    gchar msg[22];
    gint len = 0;
    struct sockaddr_storage name;
    nice_address_copy_to_sockaddr(&priv->addr, (struct sockaddr *)&name);

    msg[len++] = 0x05; /* SOCKS version */
    msg[len++] = 0x01; /* connect command */
    msg[len++] = 0x00; /* reserved */
    if (name.ss_family == AF_INET) {
      msg[len++] = 0x01; /* IPV4 address type */
      /* Address */
      memcpy (msg + len, &((struct sockaddr_in *) &name)->sin_addr, 4);
      len += 4;
      /* Port */
      memcpy (msg + len, &((struct sockaddr_in *) &name)->sin_port, 2);
      len += 2;
    } else if (name.ss_family == AF_INET6) {
      msg[len++] = 0x04; /* IPV6 address type */
      /* Address */
      memcpy (msg + len, &((struct sockaddr_in6 *) &name)->sin6_addr, 16);
      len += 16;
      /* Port */
      memcpy (msg + len, &((struct sockaddr_in6 *) &name)->sin6_port, 2);
      len += 2;
    }

    nice_socket_send (priv->base_socket, NULL, len, msg);
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

static gboolean
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  Socks5Priv *priv = sock->priv;

  if (priv->state == SOCKS_STATE_CONNECTED) {
    if (priv->base_socket)
      return nice_socket_send (priv->base_socket, to, len, buf);
    else
      return FALSE;
  } else if (priv->state == SOCKS_STATE_ERROR) {
    return FALSE;
  } else {
    add_to_be_sent (sock, to, buf, len);
  }
  return TRUE;
}


static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}


static void
add_to_be_sent (NiceSocket *sock, const NiceAddress *to,
    const gchar *buf, guint len)
{
  Socks5Priv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;

  if (len <= 0)
    return;

  tbs = g_slice_new0 (struct to_be_sent);
  tbs->buf = g_memdup (buf, len);
  tbs->length = len;
  if (to)
    tbs->to = *to;
  g_queue_push_tail (&priv->send_queue, tbs);

}


static void
free_to_be_sent (struct to_be_sent *tbs)
{
  g_free (tbs->buf);
  g_slice_free (struct to_be_sent, tbs);
}
