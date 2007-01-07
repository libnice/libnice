
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <glib.h>

#include <stun.h>

const guint port = 3478;

guint
handle_packet (
  struct sockaddr_in *from,
  guint packet_len,
  guint buf_len,
  gchar *buf)
{
  StunMessage *msg;
  gchar *packed;
  guint length;

  msg = stun_message_unpack (packet_len, buf);

  if (msg == NULL)
    {
      g_debug ("got invalid message");
      return 0;
    }

  if (msg->type != STUN_MESSAGE_BINDING_REQUEST)
    {
      g_debug ("ignoring message which isn't a binding request");
      return 0;
    }

  stun_message_free (msg);
  msg = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE);
  msg->attributes = g_malloc0 (2 * sizeof (StunAttribute));
  msg->attributes[0] = stun_attribute_mapped_address_new (
      ntohl (from->sin_addr.s_addr), ntohs (from->sin_port));
  length = stun_message_pack (msg, &packed);
  g_assert (length > 0);

  if (length > buf_len)
    {
      g_debug ("reply message too large to fit in buffer");
      stun_message_free (msg);
      return 0;
    }

  g_memmove (buf, packed, length);
  stun_message_free (msg);
  g_free (packed);
  return length;
}

int
main (void)
{
  guint sock, ret;
  struct sockaddr_in sin;

  sock = socket (AF_INET, SOCK_DGRAM, 0);
  g_assert (sock);

  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  sin.sin_addr.s_addr = INADDR_ANY;

  ret = bind (sock, (struct sockaddr *) &sin, sizeof (sin));
  g_assert (ret == 0);

  for (;;)
    {
      gint recvd;
      gchar buf[1024];
      struct sockaddr_in from;
      guint from_len = sizeof (from);
      guint reply_len;

      recvd = recvfrom (sock, buf, sizeof (buf), 0,
          (struct sockaddr *) &from, &from_len);

      if (recvd < 1)
        continue;

      g_debug ("packet: %s:%d", inet_ntoa (from.sin_addr),
          ntohs (from.sin_port));

      reply_len = handle_packet (&from, recvd, sizeof (buf), buf);

      if (reply_len == 0)
        continue;

      sendto (sock, buf, reply_len, 0, (struct sockaddr *) &from, from_len);
    }
}
