
#include <string.h>

#include "udp-fake.h"
#include "agent.h"

gint
main (void)
{
  NiceAgent *agent;
  NiceAddress addr_local = {0,}, addr_remote = {0,};
  NiceCandidate *candidate;
  NiceUDPSocketFactory factory;
  GSList *candidates;

  g_type_init ();

  nice_udp_fake_socket_factory_init (&factory);

  g_assert (nice_address_set_ipv4_from_string (&addr_local, "192.168.0.1"));
  g_assert (nice_address_set_ipv4_from_string (&addr_remote, "192.168.0.2"));
  addr_remote.port = 2345;

  agent = nice_agent_new (&factory);

  g_assert (agent->local_addresses == NULL);

  /* add one local address */
  nice_agent_add_local_address (agent, &addr_local);

  g_assert (agent->local_addresses != NULL);
  g_assert (g_slist_length (agent->local_addresses) == 1);
  g_assert (nice_address_equal (agent->local_addresses->data, &addr_local));

  /* add a stream */
  nice_agent_add_stream (agent, 1);

  /* adding a stream should cause host candidates to be generated */
  candidates = nice_agent_get_local_candidates (agent, 1, 1);
  g_assert (g_slist_length (candidates) == 1);
  candidate = candidates->data;
  /* fake socket manager uses incremental port numbers starting at 1 */
  addr_local.port = 1;
  g_assert (nice_address_equal (&(candidate->addr), &addr_local));
  g_assert (candidate->id == 1);
  g_slist_free (candidates);

  /* add remote candidate */
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &addr_remote, "username", "password");
  candidates = nice_agent_get_remote_candidates (agent, 1, 1);
  g_assert (candidates != NULL);
  g_assert (g_slist_length (candidates) == 1);
  candidate = candidates->data;
  g_assert (nice_address_equal (&(candidate->addr), &addr_remote));
  g_assert (candidate->stream_id == 1);
  g_assert (candidate->component_id == 1);
  g_assert (candidate->type == NICE_CANDIDATE_TYPE_HOST);
  g_assert (0 == strcmp (candidate->username, "username"));
  g_assert (0 == strcmp (candidate->password, "password"));
  g_slist_free (candidates);

  /* clean up */
  g_object_unref (agent);
  return 0;
}

