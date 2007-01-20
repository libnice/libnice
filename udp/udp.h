
#ifndef _UDP_H
#define _UDP_H

typedef struct _UDPSocket UDPSocket;

struct _UDPSocket
{
  struct sockaddr_in addr;
  guint fileno;
  gint (*recv) (UDPSocket *sock, struct sockaddr_in *from, guint len,
      gchar *buf);
  gboolean (*send) (UDPSocket *sock, struct sockaddr_in *to, guint len,
      gchar *buf);
  void (*close) (UDPSocket *sock);
  void *priv;
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
  void *priv;
};

void
udp_socket_manager_init (UDPSocketManager *man);
gboolean
udp_socket_manager_alloc_socket (
  UDPSocketManager *man,
  UDPSocket *sock,
  struct sockaddr_in *sin);
void
udp_socket_manager_close (UDPSocketManager *man);

guint
udp_socket_recv (
  UDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf);
void
udp_socket_send (
  UDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf);
void
udp_socket_close (UDPSocket *sock);

#endif /* _UDP_H */

