/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
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
  StunAgent agent;
  int locked;
  NiceUDPSocket udp_socket;
} turn_priv;


static gint
socket_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  turn_priv *priv = (turn_priv *) sock->priv;

  return nice_udp_socket_recv (&priv->udp_socket, from, len, buf);
}

static gboolean
socket_send (
  NiceUDPSocket *sock,
  const NiceAddress *to,
  guint len,
  const gchar *buf)
{
  turn_priv *priv = (turn_priv *) sock->priv;

  nice_udp_socket_send (&priv->udp_socket, to, len, buf);

  return TRUE;
}

static void
socket_close (NiceUDPSocket *sock)
{
  turn_priv *priv = (turn_priv *) sock->priv;
  nice_udp_socket_close (&priv->udp_socket);
  g_free (priv);
}

/*** NiceUDPSocketFactory ***/

static gboolean
socket_factory_init_socket (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr)
{
  NiceUDPSocketFactory *udp_socket_factory = man->priv;
  turn_priv *priv = g_new0 (turn_priv, 1);

  if (nice_udp_socket_factory_make (udp_socket_factory, &priv->udp_socket, addr)
      == FALSE) {
    g_free (priv);
    return FALSE;
  }

  stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_IGNORE_CREDENTIALS);

  sock->fileno = priv->udp_socket.fileno;
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
  NiceUDPSocketFactory *udp_socket_factory = man->priv;
  nice_udp_socket_factory_close (udp_socket_factory);
  g_free (udp_socket_factory);
}

NICEAPI_EXPORT void
nice_udp_turn_socket_factory_init (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man)
{
  NiceUDPSocketFactory *udp_socket_factory = g_new0 (NiceUDPSocketFactory, 1);

  man->init = socket_factory_init_socket;
  man->close = socket_factory_close;
  nice_udp_bsd_socket_factory_init (udp_socket_factory);
  man->priv = (void *) udp_socket_factory;

}

