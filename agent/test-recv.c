
#include <string.h>

#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>
#include <udp-fake.h>

#include <agent.h>

static gboolean cb_called = FALSE;

void
handle_recv (
  Agent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf)
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
  Agent *agent;
  Address addr;
  Candidate *candidate;
  UDPSocketManager mgr;
  UDPSocket *sock;
  struct sockaddr_in from = {0,};

  udp_fake_socket_manager_init (&mgr);

  /* set up agent */
  agent = ice_agent_new (&mgr);
  address_set_ipv4_from_string (&addr, "192.168.0.1");
  ice_agent_add_local_address (agent, &addr);
  ice_agent_add_stream (agent, handle_recv);
  g_assert (agent->local_candidates != NULL);

  /* recieve an RTP packet */
  candidate = (Candidate *) agent->local_candidates->data;
  sock = &(candidate->sock);
  udp_fake_socket_push_recv (sock, &from, 7, "\x80lalala");
  ice_agent_recv (agent, candidate->id);
  g_assert (cb_called == TRUE);

  /* clean up */
  ice_agent_free (agent);
  udp_socket_manager_close (&mgr);

  return 0;
}

