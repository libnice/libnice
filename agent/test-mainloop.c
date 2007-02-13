
#include <string.h>

#include <nice/nice.h>

static GMainLoop *loop = NULL;

static void
recv_cb (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf,
  gpointer data)
{
  g_assert (agent != NULL);
  g_assert (stream_id == 1);
  g_assert (component_id == 1);
  g_assert (len == 6);
  g_assert (0 == strncmp (buf,  "\x80hello", len));
  g_assert (42 == GPOINTER_TO_UINT (data));
  g_main_loop_quit (loop);
}

int
main (void)
{
  NiceAgent *agent;
  NiceAddress addr = {0,};
  NiceUDPSocketFactory factory;

  nice_udp_fake_socket_factory_init (&factory);
  agent = nice_agent_new (&factory);
  nice_address_set_ipv4 (&addr, 0x7f000001);
  nice_agent_add_local_address (agent, &addr);
  nice_agent_add_stream (agent, 1);
  // attach to default main context
  nice_agent_main_context_attach (agent, NULL, recv_cb, GUINT_TO_POINTER (42));

    {
      NiceUDPSocket *sock;
      NiceCandidate *candidate;

      candidate = agent->local_candidates->data;
      sock = &candidate->sock;

      nice_udp_fake_socket_push_recv (sock, &addr, 6, "\x80hello");
    }

  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);

  nice_udp_socket_factory_close (&factory);
  nice_agent_free (agent);
  return 0;
}

