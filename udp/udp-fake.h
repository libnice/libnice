
#ifndef _UDP_FAKE_H
#define _UDP_FAKE_H

#include "udp.h"

G_BEGIN_DECLS

void
nice_udp_fake_socket_factory_init (NiceUDPSocketFactory *man);

void
nice_udp_fake_socket_push_recv (
  NiceUDPSocket *man,
  NiceAddress *from,
  guint len,
  const gchar *buf);

guint
nice_udp_fake_socket_pop_send (
  NiceUDPSocket *man,
  NiceAddress *to,
  guint len,
  gchar *buf);

guint
nice_udp_fake_socket_get_peer_fd (
  NiceUDPSocket *sock);

G_END_DECLS

#endif /* _UDP_FAKE_H */

