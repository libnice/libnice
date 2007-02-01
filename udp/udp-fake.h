
#ifndef _UDP_FAKE_H
#define _UDP_FAKE_H

#include "udp.h"

G_BEGIN_DECLS

void
udp_fake_socket_manager_init (UDPSocketManager *man);

void
udp_fake_socket_push_recv (
  UDPSocket *man,
  struct sockaddr_in *from,
  guint len,
  gchar *buf);

guint
udp_fake_socket_pop_send (
  UDPSocket *man,
  struct sockaddr_in *to,
  guint len,
  gchar *buf);

G_END_DECLS

#endif /* _UDP_FAKE_H */

