
#ifndef _UDP_FAKE_H
#define _UDP_FAKE_H

#include "udp.h"

G_BEGIN_DECLS

void
nice_udp_fake_socket_factory_init (NiceUDPSocketFactory *man);

void
nice_udp_fake_socket_push_recv (
  NiceUDPSocket *man,
  struct sockaddr_in *from,
  guint len,
  gchar *buf);

guint
nice_udp_fake_socket_pop_send (
  NiceUDPSocket *man,
  struct sockaddr_in *to,
  guint len,
  gchar *buf);

G_END_DECLS

#endif /* _UDP_FAKE_H */

