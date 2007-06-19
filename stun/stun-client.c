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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <glib.h>

#include <stun.h>

static const gchar *server = "stun.fwdnet.net";
static guint port = 3478;

static gboolean
resolve (const gchar *name, struct hostent *ret)
{
  int res;
  int err;
  struct hostent *he;
  gchar buf[1024];

  res = gethostbyname_r (name, ret, buf, sizeof (buf) / sizeof (gchar), &he,
      &err);
  return (res == 0);
}

int
main (int argc, char **argv)
{
  struct hostent he;
  struct sockaddr_in sin;
  struct timeval tv;
  fd_set fds;
  guint sock;
  gchar *packed;
  guint length;
  gchar buffer[256];
  gint ret;
  StunMessage *msg;
  StunAttribute **attr;

  if (argc > 1)
    server = argv[1];

  if (!resolve(server, &he))
    {
      g_debug ("failed to resolve %s\n", server);
      return 1;
    }

  g_assert (he.h_addr_list != NULL);

  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  memcpy (&sin.sin_addr, he.h_addr_list[0], sizeof (struct in_addr));

  sock = socket (AF_INET, SOCK_DGRAM, 0);
  connect (sock, (struct sockaddr *) &sin, sizeof (struct sockaddr));

  msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST, NULL, 0);
  length = stun_message_pack (msg, &packed);

#ifdef DEBUG
  {
    gchar *dump = stun_message_dump (msg);
    g_debug (dump);
    g_free (dump);
  }
#endif

  send (sock, packed, length, 0);
  g_free (packed);
  stun_message_free (msg);

  FD_ZERO (&fds);
  FD_SET (sock, &fds);
  tv.tv_sec = 5;
  tv.tv_usec = 0;

  ret = select (sock + 1, &fds, NULL, NULL, &tv);

  if (ret < 0)
    {
      g_print ("error: %s", g_strerror (errno));
      return 1;
    }
  else if (ret == 0)
    {
      g_print ("timeout\n");
      return 1;
    }

  length = recv (sock, buffer, 256, 0);
  msg = stun_message_unpack (length, buffer);

#ifdef DEBUG
  {
    gchar *dump = stun_message_dump (msg);
    g_debug (dump);
    g_free (dump);
  }
#endif

  for (attr = msg->attributes; *attr; attr++)
    {
      if ((*attr)->type == STUN_ATTRIBUTE_MAPPED_ADDRESS)
        {
          guint32 ip = (*attr)->address.ip;

          g_print ("%d.%d.%d.%d\n",
              (ip & 0xff000000) >> 24,
              (ip & 0x00ff0000) >> 16,
              (ip & 0x0000ff00) >>  8,
              (ip & 0x000000ff));
          break;
        }
    }

  stun_message_free (msg);
  return 0;
}

