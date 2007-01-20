
#include <string.h>

#include <arpa/inet.h>
#include <unistd.h>

#include <glib.h>

#include <udp.h>

typedef struct _Packet Packet;

struct _Packet
{
  struct sockaddr_in sin;
  guint len;
  gchar buf[1024];
};

typedef struct _UDPFakeSocketManagerPriv UDPFakeSocketManagerPriv;

struct _UDPFakeSocketManagerPriv
{
  GSList *send_queue;
  guint recv_pipe_in;
  guint recv_pipe_out;
};

static void *
_g_slist_pop (GSList **list)
{
  void *data;
  GSList *head;

  if (*list == NULL)
    return NULL;

  head = *list;
  data = (*list)->data;
  *list = (*list)->next;
  g_slist_free_1 (head);
  return data;
}

static gboolean
fake_send (
  UDPSocket *sock,
  struct sockaddr_in *to,
  guint len,
  gchar *buf)
{
  Packet *packet;
  UDPSocketManager *man;
  UDPFakeSocketManagerPriv *priv;

  packet = g_slice_new0 (Packet);
  packet->len = len;
  packet->sin = *to;
  strncpy (packet->buf, buf, len);

  man = (UDPSocketManager *) sock->priv;
  priv = (UDPFakeSocketManagerPriv *) man->priv;
  priv->send_queue = g_slist_append (priv->send_queue, packet);

  return TRUE;
}

static gint
fake_recv (
  UDPSocket *sock,
  struct sockaddr_in *from,
  guint len,
  gchar *buf)
{
  UDPSocketManager *man;
  UDPFakeSocketManagerPriv *priv;

  man = (UDPSocketManager *) sock->priv;
  priv = (UDPFakeSocketManagerPriv *) man->priv;

  read (priv->recv_pipe_out, from, sizeof (struct sockaddr_in));
  read (priv->recv_pipe_out, &len, sizeof (guint));
  read (priv->recv_pipe_out, buf, len);

  return len;
}

/* XXX: set a port in sin */
static gboolean
fake_socket_init (
  UDPSocketManager *man,
  UDPSocket *sock,
  struct sockaddr_in *sin)
{
  sock->send = fake_send;
  sock->recv = fake_recv;
  sock->priv = man;
  return TRUE;
}

void
udp_fake_socket_manager_push_recv (
  UDPSocketManager *man,
  struct sockaddr_in *from,
  guint len,
  gchar *buf)
{
  UDPFakeSocketManagerPriv *priv;

  priv = (UDPFakeSocketManagerPriv *) man->priv;
  write (priv->recv_pipe_in, from, sizeof (struct sockaddr_in));
  write (priv->recv_pipe_in, &len, sizeof (guint));
  write (priv->recv_pipe_in, buf, len);
}

guint
udp_fake_socket_manager_pop_send (
  UDPSocketManager *man,
  struct sockaddr_in *to,
  guint len,
  gchar *buf)
{
  UDPFakeSocketManagerPriv *priv;
  Packet *packet;

  priv = (UDPFakeSocketManagerPriv *) man->priv;
  packet = (Packet *) _g_slist_pop (&priv->send_queue);

  if (!packet)
    return 0;

  *to = packet->sin;
  return packet->len;
}

static void
fake_socket_manager_close (UDPSocketManager *man)
{
  UDPFakeSocketManagerPriv *priv;

  priv = (UDPFakeSocketManagerPriv *) man->priv;
  close (priv->recv_pipe_out);
  close (priv->recv_pipe_in);
  g_slice_free (UDPFakeSocketManagerPriv, priv);
}

void
udp_fake_socket_manager_init (UDPSocketManager *man)
{
  int fds[2];
  UDPFakeSocketManagerPriv *priv;

  if (pipe (fds) == -1)
    /* XXX: this function should return boolean */
    return;

  priv = g_slice_new0 (UDPFakeSocketManagerPriv);
  priv->recv_pipe_out = fds[0];
  priv->recv_pipe_in = fds[1];

  man->init = fake_socket_init;
  man->select = NULL;
  man->close = fake_socket_manager_close;
  man->priv = priv;
}

