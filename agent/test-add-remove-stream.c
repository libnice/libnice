
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

  nice_agent_remove_stream (agent, 1);
  nice_agent_remove_stream (agent, 2);
  nice_agent_remove_stream (agent, 3);

  g_assert (NULL == agent->streams);

  g_object_unref (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

