
#include <unistd.h>

#include <glib/gprintf.h>

#include "nice.h"
#include "readline.h"
#include "util.h"
#include "stun.h"

static void
send_stun (NiceUDPSocket *udpsock, struct sockaddr_in sin)
{
  gchar *packed;
  guint packed_len;
  gchar buf[1024];
  StunMessage *msg;

  msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST, NULL, 1);
  msg->attributes[0] = stun_attribute_username_new ("lala");

    {
      gchar *dump;
      dump = stun_message_dump (msg);
      g_print ("%s\n", dump);
      g_free (dump);
    }

  packed_len = stun_message_pack (msg, &packed);
  nice_udp_socket_send (udpsock, &sin, packed_len, packed);
  g_free (packed);
  stun_message_free (msg);

  packed_len = nice_udp_socket_recv (udpsock, &sin, 1024, buf);
  g_assert (packed_len > 0);
  msg = stun_message_unpack (packed_len, buf);
  g_assert (msg);

    {
      gchar *dump;
      dump = stun_message_dump (msg);
      g_print ("%s\n", dump);
      g_free (dump);
    }

  stun_message_free (msg);
}

static void
handle_connection (guint sock)
{
  gchar *line;
  struct sockaddr_in sin;
  NiceUDPSocketFactory man;
  NiceUDPSocket udpsock;
  NiceCandidate *candidate;

  line = readline (sock);

  if (line == NULL)
    return;

  candidate = nice_candidate_from_string (line);

  if (candidate == NULL)
    return;

  g_debug ("got candidate");
  g_free (line);

  nice_udp_bsd_socket_factory_init (&man);

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = 0;

  if (!nice_udp_socket_factory_make (&man, &udpsock, &sin))
    goto OUT;

  // copy remote candidate address into sin
  sin.sin_addr.s_addr = htonl (candidate->addr.addr_ipv4);
  sin.sin_port = htons (candidate->port);

  // agent doesn't proactively do STUN, so we have to do it ourselves for now
  send_stun (&udpsock, sin);

  nice_udp_socket_send (&udpsock, &sin, 6, "\x80hello");
  nice_udp_socket_close (&udpsock);

OUT:
  nice_udp_socket_factory_close (&man);
  nice_candidate_free (candidate);
}

int
main (void)
{
  struct sockaddr_in sin = {0,};
  gint sock;

  sock = socket (AF_INET, SOCK_STREAM, 0);

  if (sock < 0)
    {
      g_print ("failed to create socket\n");
      return 1;
    }

  if (inet_pton (AF_INET, "127.0.0.1", &sin.sin_addr) < 1)
    {
      g_print ("invalid address\n");
      return 1;
    }

  sin.sin_family = AF_INET;
  sin.sin_port = htons (7899);

  if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) != 0)
    {
      g_print ("failed to connect\n");
      return 1;
    }

  handle_connection (sock);
  close (sock);
  return 0;
}

