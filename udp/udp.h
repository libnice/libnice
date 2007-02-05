
#ifndef _UDP_H
#define _UDP_H

#include "address.h"

G_BEGIN_DECLS

typedef struct _NiceUDPSocket NiceUDPSocket;

struct _NiceUDPSocket
{
  NiceAddress addr;
  guint fileno;
  gint (*recv) (NiceUDPSocket *sock, NiceAddress *from, guint len,
      gchar *buf);
  gboolean (*send) (NiceUDPSocket *sock, NiceAddress *to, guint len,
      gchar *buf);
  void (*close) (NiceUDPSocket *sock);
  void *priv;
};

typedef gboolean (*NiceUDPRecvFunc) (NiceAddress *from, guint len,
    gchar *buf);

typedef struct _NiceUDPSocketManager NiceUDPSocketFactory;

struct _NiceUDPSocketManager
{
  gboolean (*init) (NiceUDPSocketFactory *man, NiceUDPSocket *sock,
      NiceAddress *sin);
  void (*close) (NiceUDPSocketFactory *man);
  void *priv;
};

/**
 * If sin is not NULL, the new socket will be bound to that IP address/port.
 * If sin->sin_port is 0, a port will be assigned at random. In all cases, the
 * address bound to will be set in sock->addr.
 */
G_GNUC_WARN_UNUSED_RESULT
gboolean
nice_udp_socket_factory_make (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr);

void
nice_udp_socket_factory_close (NiceUDPSocketFactory *man);

G_GNUC_WARN_UNUSED_RESULT
guint
nice_udp_socket_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf);

void
nice_udp_socket_send (
  NiceUDPSocket *sock,
  NiceAddress *to,
  guint len,
  gchar *buf);

void
nice_udp_socket_close (NiceUDPSocket *sock);

G_END_DECLS

#endif /* _UDP_H */

