
/*
 * convenience API for UDP sockets
 *
 * easily:
 *
 *  - create sockets and bind them to an interface
 *  - send and receive packets
 *  - know who packets are received from
 *  - select on a number of sockets
 *
 * also allows faking UDP sockets for testing purposes
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <glib.h>

#include <udp.h>

/*** UDPSocket ***/

static gint
udp_socket_recv (
  struct UDPSocket *sock,
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
udp_socket_send (
  struct UDPSocket *sock,
  struct sockaddr_in *to,
  guint len,
  gchar *buf)
{
  sendto (sock->fileno, buf, len, 0, (struct sockaddr *) to,
      sizeof (struct sockaddr_in));
  return TRUE;
}

static void
udp_socket_close (struct UDPSocket *sock)
{
  close (sock->fileno);
}

/*** UDPSocketManager ***/

/* If sin is not NULL, the new socket will be bound to that IP address/port.
 * If sin->sin_port is 0, a port will be assigned at random. In all cases, the
 * port bound to will be set in sock->port.
 */
static gboolean
udp_socket_manager_init_socket (
  struct UDPSocketManager *man,
  struct UDPSocket *sock,
  struct sockaddr_in *sin)
{
  gint sockfd;
  struct sockaddr_in name;
  guint name_len = sizeof (name);

  sockfd = socket (PF_INET, SOCK_DGRAM, 0);

  if (sock < 0)
    return FALSE;

  if (sin != NULL)
    if (bind (sockfd, (struct sockaddr *) sin, sizeof (*sin)) != 0)
      {
        close (sockfd);
        return FALSE;
      }

  if (getsockname (sockfd, (struct sockaddr *) &name, &name_len) != 0)
    {
      close (sockfd);
      return FALSE;
    }

  sock->fileno = sockfd;
  sock->port = ntohs (name.sin_port);
  sock->send = udp_socket_send;
  sock->recv = udp_socket_recv;
  sock->close = udp_socket_close;
  return TRUE;
}

static void
udp_socket_manager_select (UDPPacketRecvFunc cb)
{
  g_assert_not_reached ();
}

void
udp_socket_manager_init (struct UDPSocketManager *man)
{
  man->init = udp_socket_manager_init_socket;
  man->select = udp_socket_manager_select;
}

void
udp_socket_manager_close (struct UDPSocketManager *man)
{
}

