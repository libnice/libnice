
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

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

int
main (void)
{
  Agent *agent;

  agent = ice_agent_new (NULL);
  g_assert (ice_agent_add_stream (agent, MEDIA_TYPE_AUDIO, handle_recv) == 1);
  g_assert (ice_agent_add_stream (agent, MEDIA_TYPE_AUDIO, handle_recv) == 2);
  g_assert (ice_agent_add_stream (agent, MEDIA_TYPE_AUDIO, handle_recv) == 3);
  ice_agent_free (agent);

  return 0;
}

