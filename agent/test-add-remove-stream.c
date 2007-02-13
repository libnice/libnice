
#include "agent.h"
#include "udp-fake.h"

int
main (void)
{
  NiceAgent *agent;
  NiceAddress addr = {0,};
  NiceUDPSocketFactory factory;

  g_type_init ();

  nice_udp_fake_socket_factory_init (&factory);

  if (!nice_address_set_ipv4_from_string (&addr, "127.0.0.1"))
    g_assert_not_reached ();

  agent = nice_agent_new (&factory);
  nice_agent_add_local_address (agent, &addr);

  g_assert (nice_agent_add_stream (agent, 1) == 1);
  g_assert (nice_agent_add_stream (agent, 1) == 2);
  g_assert (nice_agent_add_stream (agent, 1) == 3);

  g_assert (NULL != agent->streams);
  g_assert (NULL != agent->local_candidates);

  nice_agent_remove_stream (agent, 1);
  nice_agent_remove_stream (agent, 2);
  nice_agent_remove_stream (agent, 3);

  g_assert (NULL == agent->streams);
  /* check no local candidates were left behind when streams were removed*/
  g_assert (NULL == agent->local_candidates);

  nice_agent_free (agent);

  return 0;
}

