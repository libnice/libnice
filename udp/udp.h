
#ifndef _UDP_H
#define _UDP_H

#include <arpa/inet.h>

#include <glib.h>

G_BEGIN_DECLS

typedef struct _UDPSocket NiceUDPSocket;

struct _UDPSocket
{
  struct sockaddr_in addr;
  guint fileno;
  gint (*recv) (NiceUDPSocket *sock, struct sockaddr_in *from, guint len,
      gchar *buf);
  gboolean (*send) (NiceUDPSocket *sock, struct sockaddr_in *to, guint len,
      gchar *buf);
  void (*close) (NiceUDPSocket *sock);
  void *priv;
};

typedef gboolean (*NiceUDPRecvFunc) (struct sockaddr_in *from, guint len,
    gchar *buf);

typedef struct _UDPSocketManager NiceUDPSocketFactory;

struct _UDPSocketManager
{
  gboolean (*init) (NiceUDPSocketFactory *man, NiceUDPSocket *sock,
      struct sockaddr_in *sin);
  void (*select) (NiceUDPRecvFunc cb);
  void (*close) (NiceUDPSocketFactory *man);
  void *priv;
};

/**
 * If sin is not NULL, the new socket will be bound to that IP address/port.
 * If sin->sin_port is 0, a port will be assigned at random. In all cases, the
 * address bound to will be set in sock->addr.
 */
gboolean
nice_udp_socket_factory_make (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  struct sockaddr_in *sin);

void
nice_udp_socket_factory_close (NiceUDPSocketFactory *man);

guint
nice_udp_socket_recv (
  NiceUDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf);

void
nice_udp_socket_send (
  NiceUDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf);

void
nice_udp_socket_close (NiceUDPSocket *sock);

G_END_DECLS

#endif /* _UDP_H */

