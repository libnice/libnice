
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

gboolean
nice_udp_socket_factory_make (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr)
{
  return man->init (man, sock, addr);
}

void
nice_udp_socket_factory_close (NiceUDPSocketFactory *man)
{
  man->close (man);
}

guint
nice_udp_socket_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  return sock->recv (sock, from, len, buf);
}

void
nice_udp_socket_send (
  NiceUDPSocket *sock,
  NiceAddress *to,
  guint len,
  gchar *buf)
{
  sock->send (sock, to, len, buf);
}

void
nice_udp_socket_close (NiceUDPSocket *sock)
{
  sock->close (sock);
}

