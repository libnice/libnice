
void
udp_fake_socket_manager_init (UDPSocketManager *man);
void
udp_fake_socket_manager_push_recv (
  UDPSocketManager *man,
  struct sockaddr_in *from,
  guint len,
  gchar *buf);
guint
udp_fake_socket_manager_pop_send (
  UDPSocketManager *man,
  struct sockaddr_in *to,
  guint len,
  gchar *buf);

