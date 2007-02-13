
/*
 * This program interoperates with the test-rtp-jingle program from the
 * farsight tests/ directory.
 */

#include <stdlib.h>
#include <string.h>

#include <nice/nice.h>

static void
recv_cb (
    NiceAgent *agent,
    guint stream_id,
    guint candidate_id,
    guint len,
    gchar *buf,
    G_GNUC_UNUSED
    gpointer user_data)
{
  nice_agent_send (agent, stream_id, candidate_id, len, buf);
}

static NiceAgent *
make_agent (NiceUDPSocketFactory *factory)
{
  NiceAgent *agent;
  NiceAddress addr;

  agent = nice_agent_new (factory);

  if (!nice_address_set_ipv4_from_string (&addr, "127.0.0.1"))
    g_assert_not_reached ();

  nice_agent_add_local_address (agent, &addr);
  nice_agent_add_stream (agent, 1);
  return agent;
}

static guint
accept_connection (
  NiceUDPSocketFactory *factory,
  NiceUDPSocket *sock)
{
  NiceAgent *agent;
  NiceAddress recv_addr;
  NiceAddress send_addr;
  guint len;
  gchar buf[1024];
  guint ret = 0;
  GSList *fds = NULL;

  agent = make_agent (factory);

  // accept incoming handshake

  len = nice_udp_socket_recv (sock, &recv_addr, 1, buf);

  if (len != 1)
    {
      ret = 1;
      goto OUT;
    }

  if (buf[0] != '2')
    {
      ret = 2;
      goto OUT;
    }

  g_debug ("got handshake packet");

  // send handshake reply

  send_addr = recv_addr;
  send_addr.port = 1235;
  nice_udp_socket_send (sock, &send_addr, 1, buf);

  // send codec

  strcpy (buf, "1 0 PCMU 0 8000 0");
  nice_udp_socket_send (sock, &send_addr, strlen (buf), buf);
  strcpy (buf, "1 0 LAST 0 0 0");
  nice_udp_socket_send (sock, &send_addr, strlen (buf), buf);

  // send candidate

    {
      NiceCandidate *candidate;

      candidate = nice_agent_get_local_candidates (agent)->data;
      len = g_snprintf (buf, 1024, "0 0 X1 127.0.0.1 %d %s %s",
          candidate->addr.port, candidate->username, candidate->password);
      nice_udp_socket_send (sock, &send_addr, len, buf);
    }

  // IO loop

  fds = g_slist_append (fds, GUINT_TO_POINTER (sock->fileno));

  for (;;)
    {
      gchar **bits;
      NiceAddress addr;

      if (nice_agent_poll_read (agent, fds, recv_cb, NULL) == NULL)
        continue;

      len = nice_udp_socket_recv (sock, &recv_addr, 1024, buf);
      buf[len] = '\0';
      g_debug ("%s", buf);

      if (buf[0] != '0')
        continue;

      bits = g_strsplit (buf, " ", 7);

      if (g_strv_length (bits) != 7)
        {
          g_strfreev (bits);
          return 3;
        }

      if (!nice_address_set_ipv4_from_string (&addr, bits[3]))
        g_assert_not_reached ();

      addr.port = atoi (bits[4]);
      g_debug ("username = %s", bits[5]);
      g_debug ("password = %s", bits[6]);
      nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
          &addr, bits[5], bits[6]);
    }

OUT:
  g_slist_free (fds);
  nice_agent_free (agent);
  return ret;
}

int
main (void)
{
  NiceUDPSocketFactory factory;
  NiceUDPSocket sock;
  NiceAddress addr = {0,};
  guint ret;

  addr.port = 1234;

  nice_udp_bsd_socket_factory_init (&factory);

  if (!nice_udp_socket_factory_make (&factory, &sock, &addr))
    g_assert_not_reached ();

  ret = accept_connection (&factory, &sock);
  nice_udp_socket_close (&sock);
  nice_udp_socket_factory_close (&factory);
  return ret;
}

