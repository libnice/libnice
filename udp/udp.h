
#ifndef _UDP_H
#define _UDP_H

struct UDPSocket
{
  guint fileno;
  guint port;
  gint (*recv) (struct UDPSocket *sock, struct sockaddr_in *from, guint len,
      gchar *buf);
  gboolean (*send) (struct UDPSocket *sock, struct sockaddr_in *to, guint len,
      gchar *buf);
  void (*close) (struct UDPSocket *sock);
};

typedef gboolean (*UDPPacketRecvFunc) (struct sockaddr_in *from, guint len,
    gchar *buf);

struct UDPSocketManager
{
  gboolean (*init) (struct UDPSocketManager *man, struct UDPSocket *sock,
      struct sockaddr_in *sin);
  void (*select) (UDPPacketRecvFunc cb);
  void (*close) (struct UDPSocketManager *man);
};

void
udp_socket_manager_init (struct UDPSocketManager *man);

#endif /* _UDP_H */

