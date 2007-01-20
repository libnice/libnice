
#include <string.h>

#include <arpa/inet.h>

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
  GSList *recv_queue;
  GSList *send_queue;
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
  Packet *packet;
  UDPSocketManager *man;
  UDPFakeSocketManagerPriv *priv;

  man = (UDPSocketManager *) sock->priv;
  priv = (UDPFakeSocketManagerPriv *) man->priv;
  packet = (Packet *) _g_slist_pop (&priv->recv_queue);

  if (packet == NULL)
    {
      g_debug ("recv queue underflow");
      return 0;
    }

  len = packet->len;
  memcpy (buf, packet->buf, len);
  memcpy (from, &(packet->sin), sizeof (*from));
  g_slice_free (Packet, packet);

  return len;
}

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
  Packet *packet;
  UDPFakeSocketManagerPriv *priv;

  packet = g_slice_new0 (Packet);
  packet->len = len;
  packet->sin = *from;
  strncpy (packet->buf, buf, len);

  priv = (UDPFakeSocketManagerPriv *) man->priv;
  priv->recv_queue = g_slist_append (priv->recv_queue, packet);
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
  g_slice_free (UDPFakeSocketManagerPriv, man->priv);
}

void
udp_fake_socket_manager_init (UDPSocketManager *man)
{
  man->init = fake_socket_init;
  man->select = NULL;
  man->close = fake_socket_manager_close;
  man->priv = g_slice_new0 (UDPFakeSocketManagerPriv);
}

