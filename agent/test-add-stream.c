
#include "agent.h"

void
handle_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf,
  gpointer user_data)
{
  g_assert_not_reached ();
}

int
main (void)
{
  NiceAgent *agent;

  agent = nice_agent_new (NULL);
  g_assert (nice_agent_add_stream (agent, handle_recv, NULL) == 1);
  g_assert (nice_agent_add_stream (agent, handle_recv, NULL) == 2);
  g_assert (nice_agent_add_stream (agent, handle_recv, NULL) == 3);
  nice_agent_free (agent);

  return 0;
}

