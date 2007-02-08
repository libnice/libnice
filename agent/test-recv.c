
#include <string.h>

#include "udp-fake.h"
#include "agent.h"

static gboolean cb_called = FALSE;

void
handle_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf,
  gpointer data)
{
  g_assert (cb_called == FALSE);
  g_assert (stream_id == 1);
  g_assert (component_id == 1);
  g_assert (len == 7);
  g_assert (0 == strncmp (buf, "\x80lalala", 7));
  cb_called = TRUE;
}

int
main (void)
{
  NiceAgent *agent;
  NiceAddress addr = {0,};
  NiceUDPSocketFactory factory;

  nice_udp_fake_socket_factory_init (&factory);

  /* set up agent */
  agent = nice_agent_new (&factory);
  g_assert (nice_address_set_ipv4_from_string (&addr, "192.168.0.1"));
  nice_agent_add_local_address (agent, &addr);
  nice_agent_add_stream (agent, handle_recv, NULL);
  g_assert (agent->local_candidates != NULL);

  /* recieve an RTP packet */

    {
      NiceCandidate *candidate;
      NiceUDPSocket *sock;
      guint len;
      gchar buf[1024];

      candidate = agent->local_candidates->data;
      sock = &(candidate->sock);
      nice_udp_fake_socket_push_recv (sock, &addr, 7, "\x80lalala");
      len = nice_agent_recv (agent, candidate->stream_id,
          candidate->component_id, 1024, buf);
      g_assert (len == 7);
      g_assert (0 == strncmp (buf, "\x80lalala", 7));
    }

  /* clean up */
  nice_agent_free (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

