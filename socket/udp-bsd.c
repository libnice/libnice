/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
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
 * Implementation of UDP socket interface using Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "udp-bsd.h"

#ifdef G_OS_WIN32
typedef unsigned long ssize_t;
#else
#include <unistd.h>
#endif


static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gboolean socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);

NiceSocket *
nice_udp_bsd_socket_new (NiceAddress *addr)
{
  int sockfd = -1;
  struct sockaddr_storage name;
  socklen_t name_len = sizeof (name);
  NiceSocket *sock = g_slice_new0 (NiceSocket);

  if (!sock) {
    return NULL;
  }

  if (addr != NULL) {
    nice_address_copy_to_sockaddr(addr, (struct sockaddr *)&name);
  } else {
    memset (&name, 0, sizeof (name));
    name.ss_family = AF_UNSPEC;
  }

  if (name.ss_family == AF_UNSPEC || name.ss_family == AF_INET) {
    sockfd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    name.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in);
#endif
  }

  if (sockfd == -1) {
    g_slice_free (NiceSocket, sock);
    return NULL;
  }

#ifdef FD_CLOEXEC
  fcntl (sockfd, F_SETFD, fcntl (sockfd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
  fcntl (sockfd, F_SETFL, fcntl (sockfd, F_GETFL) | O_NONBLOCK);
#endif

  if(bind (sockfd, (struct sockaddr *) &name,
          name.ss_family == AF_INET? sizeof (struct sockaddr_in) :
          sizeof(struct sockaddr_in6)) < 0) {
    g_slice_free (NiceSocket, sock);
#ifdef G_OS_WIN32
    closesocket(sockfd);
#else
    close (sockfd);
#endif
    return NULL;
  }

  name_len = name.ss_family == AF_INET? sizeof (struct sockaddr_in) :
      sizeof(struct sockaddr_in6);
  if (getsockname (sockfd, (struct sockaddr *) &name, &name_len) < 0) {
    g_slice_free (NiceSocket, sock);
#ifdef G_OS_WIN32
    closesocket(sockfd);
#else
    close (sockfd);
#endif
    return NULL;
  }

  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);
  sock->fileno = sockfd;

  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

  return sock;
}

static void
socket_close (NiceSocket *sock)
{
#ifdef G_OS_WIN32
  closesocket(sock->fileno);
#else
  close (sock->fileno);
#endif
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  gint recvd;
  struct sockaddr_storage sa;
  socklen_t from_len = sizeof (sa);

  recvd = recvfrom (sock->fileno, buf, len, 0, (struct sockaddr *) &sa,
      &from_len);

  if (recvd < 0) {
#ifdef G_OS_WIN32
    if (WSAGetLastError () == WSAEWOULDBLOCK)
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK)
#endif
      return 0;
  }

  if (recvd > 0)
    nice_address_set_from_sockaddr (from, (struct sockaddr *)&sa);

  return recvd;
}

static gboolean
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  struct sockaddr_storage sa;
  ssize_t sent;

  nice_address_copy_to_sockaddr (to, (struct sockaddr *)&sa);

  sent = sendto (sock->fileno, buf, len, 0, (struct sockaddr *) &sa,
      sa.ss_family == AF_INET? sizeof (struct sockaddr_in) :
      sizeof(struct sockaddr_in6));

  return sent == (ssize_t)len;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return FALSE;
}

