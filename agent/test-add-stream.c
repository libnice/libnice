
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

#include <agent.h>

void
handle_recv (
  NiceAgent *agent,
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
  NiceAgent *agent;

  agent = nice_agent_new (NULL);
  g_assert (nice_agent_add_stream (agent, handle_recv) == 1);
  g_assert (nice_agent_add_stream (agent, handle_recv) == 2);
  g_assert (nice_agent_add_stream (agent, handle_recv) == 3);
  nice_agent_free (agent);

  return 0;
}

