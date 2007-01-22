
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

#include <agent.h>

int
main (void)
{
  Agent *agent;

  agent = ice_agent_new (NULL);
  g_assert (ice_agent_add_stream (agent, MEDIA_TYPE_AUDIO) == 1);
  g_assert (ice_agent_add_stream (agent, MEDIA_TYPE_AUDIO) == 2);
  g_assert (ice_agent_add_stream (agent, MEDIA_TYPE_AUDIO) == 3);
  ice_agent_free (agent);

  return 0;
}

