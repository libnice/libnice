
#include <glib.h>

#include <agent.h>

gint
main (void)
{
  Agent *agent;
  Address *addr_local, *addr_remote;
  Candidate *candidate;
  Event *event;

  addr_local = address_new_ipv4_from_string ("192.168.0.1");
  addr_remote = address_new_ipv4_from_string ("192.168.0.2");

  agent = ice_agent_new ();

  g_assert (agent->local_addresses == NULL);
  g_assert (agent->local_candidates == NULL);
  g_assert (ice_agent_pop_event (agent) == NULL);

  /* add one local address */
  ice_agent_add_local_address (agent, addr_local);

  g_assert (agent->local_addresses != NULL);
  g_assert (g_slist_length (agent->local_addresses) == 1);
  g_assert (address_equal ((Address *) agent->local_addresses->data,
        addr_local));

  /* no candidates should be generated until we have a stream */
  g_assert (agent->local_candidates == NULL);

  /* add an audio stream */
  ice_agent_add_stream (agent, MEDIA_TYPE_AUDIO);

  /* adding a stream should cause host candidates to be generated */
  g_assert (agent->local_candidates != NULL);
  g_assert (g_slist_length (agent->local_candidates) == 1);
  candidate = (Candidate *) agent->local_candidates->data;
  g_assert (address_equal (candidate->addr, addr_local));
  g_assert (candidate->id == 1);
  g_assert (candidate->port == 0);

  /* there should be a port request for the new candidate */
  event = ice_agent_pop_event (agent);
  g_assert (ice_agent_pop_event (agent) == NULL);
  g_assert (event != NULL);
  g_assert (event->type == EVENT_REQUEST_PORT);
  g_assert (address_equal (event->request_port.addr, addr_local));
  g_assert (event->request_port.candidate_id == 1);
  event_free (event);

  /* assign a port */
  ice_agent_set_candidate_port (agent, 1, 1234);
  g_assert (candidate->port == 1234);

  /* expect event: local candidates ready */
  event = ice_agent_pop_event (agent);
  g_assert (ice_agent_pop_event (agent) == NULL);
  g_assert (event != NULL);
  g_assert (event->type == EVENT_LOCAL_CANDIDATES_READY);
  event_free (event);

  /* add remote candidate */
  ice_agent_add_remote_candidate (agent, CANDIDATE_TYPE_HOST, addr_remote,
      2345);
  g_assert (agent->remote_candidates != NULL);
  g_assert (g_slist_length (agent->remote_candidates) == 1);
  candidate = (Candidate *) agent->remote_candidates->data;
  g_assert (address_equal (candidate->addr, addr_remote));
  g_assert (candidate->port == 2345);

  /* check there's no unexpected events, and clean up */
  g_assert (ice_agent_pop_event (agent) == NULL);
  address_free (addr_local);
  address_free (addr_remote);
  ice_agent_free (agent);
  return 0;
}

