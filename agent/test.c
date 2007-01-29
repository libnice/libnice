
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>
#include <udp-fake.h>

#include <agent.h>

void
handle_recv (
  Agent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf)
{
  g_assert_not_reached ();
}

gint
main (void)
{
  Agent *agent;
  Address addr_local, addr_remote;
  Candidate *candidate;
  UDPSocketManager mgr;

  udp_fake_socket_manager_init (&mgr);

  address_set_ipv4_from_string (&addr_local, "192.168.0.1");
  address_set_ipv4_from_string (&addr_remote, "192.168.0.2");

  agent = ice_agent_new (&mgr);

  g_assert (agent->local_addresses == NULL);
  g_assert (agent->local_candidates == NULL);
  g_assert (ice_agent_pop_event (agent) == NULL);

  /* add one local address */
  ice_agent_add_local_address (agent, &addr_local);

  g_assert (agent->local_addresses != NULL);
  g_assert (g_slist_length (agent->local_addresses) == 1);
  g_assert (address_equal ((Address *) agent->local_addresses->data,
        &addr_local));

  /* no candidates should be generated until we have a stream */
  g_assert (agent->local_candidates == NULL);

  /* add an audio stream */
  ice_agent_add_stream (agent, handle_recv);

  /* adding a stream should cause host candidates to be generated */
  g_assert (agent->local_candidates != NULL);
  g_assert (g_slist_length (agent->local_candidates) == 1);
  candidate = (Candidate *) agent->local_candidates->data;
  g_assert (address_equal (&(candidate->addr), &addr_local));
  g_assert (candidate->id == 1);
  /* fake socket manager uses incremental port numbers starting at 1 */
  g_assert (candidate->port == 1);

  /* add remote candidate */
  ice_agent_add_remote_candidate (agent, CANDIDATE_TYPE_HOST, &addr_remote,
      2345);
  g_assert (agent->remote_candidates != NULL);
  g_assert (g_slist_length (agent->remote_candidates) == 1);
  candidate = (Candidate *) agent->remote_candidates->data;
  g_assert (address_equal (&(candidate->addr), &addr_remote));
  g_assert (candidate->port == 2345);

  /* check there's no unexpected events, and clean up */
  g_assert (ice_agent_pop_event (agent) == NULL);
  ice_agent_free (agent);
  return 0;
}

