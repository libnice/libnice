
#ifndef _UDP_H
#define _UDP_H

typedef struct _UDPSocket UDPSocket;

struct _UDPSocket
{
  guint fileno;
  guint port;
  gint (*recv) (UDPSocket *sock, struct sockaddr_in *from, guint len,
      gchar *buf);
  gboolean (*send) (UDPSocket *sock, struct sockaddr_in *to, guint len,
      gchar *buf);
  void (*close) (UDPSocket *sock);
};

typedef gboolean (*UDPPacketRecvFunc) (struct sockaddr_in *from, guint len,
    gchar *buf);

typedef struct _UDPSocketManager UDPSocketManager;

struct _UDPSocketManager
{
  gboolean (*init) (UDPSocketManager *man, UDPSocket *sock,
      struct sockaddr_in *sin);
  void (*select) (UDPPacketRecvFunc cb);
  void (*close) (UDPSocketManager *man);
};

void
udp_socket_manager_init (UDPSocketManager *man);

#endif /* _UDP_H */

