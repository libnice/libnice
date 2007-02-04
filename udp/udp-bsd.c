
/*
 * Implementation of UDP socket interface using Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */

#include <unistd.h>

#include "udp-bsd.h"

/*** NiceUDPSocket ***/

static gint
socket_recv (
  NiceUDPSocket *sock,
  struct sockaddr_in *from,
  guint len,
  gchar *buf)
{
  gint recvd;
  guint from_len = sizeof (struct sockaddr_in);

  recvd = recvfrom (sock->fileno, buf, len, 0,
      (struct sockaddr *) from, &from_len);

  return recvd;
}

static gboolean
socket_send (
  NiceUDPSocket *sock,
  struct sockaddr_in *to,
  guint len,
  gchar *buf)
{
  sendto (sock->fileno, buf, len, 0, (struct sockaddr *) to,
      sizeof (struct sockaddr_in));
  return TRUE;
}

static void
socket_close (NiceUDPSocket *sock)
{
  close (sock->fileno);
}

/*** NiceUDPSocketFactory ***/

static gboolean
socket_factory_init_socket (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  struct sockaddr_in *sin)
{
  gint sockfd;
  guint name_len = sizeof (struct sockaddr_in);

  sockfd = socket (PF_INET, SOCK_DGRAM, 0);

  if (sock < 0)
    return FALSE;

  if (sin != NULL)
    if (bind (sockfd, (struct sockaddr *) sin, sizeof (*sin)) != 0)
      {
        close (sockfd);
        return FALSE;
      }

  if (getsockname (sockfd, (struct sockaddr *) &(sock->addr), &name_len) != 0)
    {
      close (sockfd);
      return FALSE;
    }

  sock->fileno = sockfd;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->close = socket_close;
  return TRUE;
}

static void
socket_factory_close (NiceUDPSocketFactory *man)
{
}

void
nice_udp_bsd_socket_factory_init (NiceUDPSocketFactory *man)
{
  man->init = socket_factory_init_socket;
  man->close = socket_factory_close;
}

