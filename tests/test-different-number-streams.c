#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "agent.h"

#include <stdlib.h>
#include <string.h>

#define ADD_2_STREAMS TRUE
#define USE_SECOND_STREAM TRUE

static GMainLoop *global_mainloop = NULL;

static guint global_components_ready = 0;
static guint global_components_ready_exit = 0;

static gboolean timer_cb (gpointer pointer)
{
  g_debug ("test-different-number-streams:%s: %p", G_STRFUNC, pointer);

  /* signal status via a global variable */

  /* note: should not be reached, abort */
  g_error ("ERROR: test has got stuck, aborting...");

  return FALSE;
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("%p: gathering done (stream_id: %u)", agent, stream_id);
}

static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  g_debug ("%p: component state changed (stream_id: %u, component_id: %u, state: %s)",
           agent, stream_id, component_id, nice_component_state_to_string (state));

  if (state == NICE_COMPONENT_STATE_READY) {
    global_components_ready++;
  }

  /* signal status via a global variable */
  if (global_components_ready == global_components_ready_exit) {
    g_debug ("Components ready/failed achieved. Stopping mailoop");
    g_main_loop_quit (global_mainloop);
  }
}

static void set_candidates (NiceAgent *from, guint from_stream,
    NiceAgent *to, guint to_stream, guint component)
{
  GSList *cands = NULL, *i;

  cands = nice_agent_get_local_candidates (from, from_stream, component);
  nice_agent_set_remote_candidates (to, to_stream, component, cands);

  for (i = cands; i; i = i->next)
    nice_candidate_free ((NiceCandidate *) i->data);
  g_slist_free (cands);
}

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  g_debug ("%p: recv (stream_id: %u, component_id: %u)", agent, stream_id, component_id);
}

int main (void)
{
  NiceAgent *lagent, *ragent;
  guint timer_id;
  guint ls_id, rs_id_1, rs_id_2;
  gchar *lufrag = NULL, *lpassword = NULL;
  gchar *rufrag1 = NULL, *rpassword1 = NULL, *rufrag2 = NULL, *rpassword2 = NULL;
  NiceAddress addr;


#ifdef G_OS_WIN32
  WSADATA w;

  WSAStartup(0x0202, &w);
#endif

  /* Initialize nice agents */
  nice_address_init (&addr);
  nice_address_set_from_string (&addr, "127.0.0.1");

  global_mainloop = g_main_loop_new (NULL, FALSE);

  /* step: create the agents L and R */
  lagent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_GOOGLE);
  g_debug ("lagent: %p", lagent);

  nice_agent_add_local_address (lagent, &addr);
  nice_agent_set_software (lagent, "test-different-number-streams, Left Agent");
  g_object_set (G_OBJECT (lagent), "ice-tcp", FALSE,  NULL);
  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (lagent), "upnp", FALSE,  NULL);
  g_signal_connect (G_OBJECT (lagent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), NULL);
  g_signal_connect (G_OBJECT (lagent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), NULL);

  ragent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_GOOGLE);
  g_debug ("ragent: %p", ragent);

  nice_agent_add_local_address (ragent, &addr);
  nice_agent_set_software (ragent, "test-different-number-streams, Right Agent");
  g_object_set (G_OBJECT (ragent), "ice-tcp", FALSE,  NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);
  g_object_set (G_OBJECT (ragent), "upnp", FALSE,  NULL);
  g_signal_connect (G_OBJECT (ragent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), NULL);
  g_signal_connect (G_OBJECT (ragent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), NULL);

  /* step: add a timer to catch state changes triggered by signals */
  timer_id = g_timeout_add (30000, timer_cb, NULL);

  ls_id = nice_agent_add_stream (lagent, 2);
  g_assert (ls_id > 0);
  nice_agent_get_local_credentials(lagent, ls_id, &lufrag, &lpassword);

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);

  global_components_ready_exit = 4;

  if (ADD_2_STREAMS) {
    rs_id_1 = nice_agent_add_stream (ragent, 2);
    g_assert (rs_id_1 > 0);
    nice_agent_get_local_credentials(ragent, rs_id_1, &rufrag1, &rpassword1);

    rs_id_2 = nice_agent_add_stream (ragent, 2);
    g_assert (rs_id_2 > 0);
    nice_agent_get_local_credentials(ragent, rs_id_2, &rufrag2, &rpassword2);

    nice_agent_set_remote_credentials (ragent, rs_id_2, lufrag, lpassword);
    nice_agent_set_remote_credentials (lagent, ls_id, rufrag2, rpassword2);

    g_assert (nice_agent_gather_candidates (lagent, ls_id) == TRUE);
    g_assert (nice_agent_gather_candidates (ragent, rs_id_2) == TRUE);
    g_assert (nice_agent_gather_candidates (ragent, rs_id_1) == TRUE);

    if (USE_SECOND_STREAM) {
      set_candidates (ragent, rs_id_2, lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
      set_candidates (ragent, rs_id_2, lagent, ls_id, NICE_COMPONENT_TYPE_RTCP);
      set_candidates (lagent, ls_id, ragent, rs_id_2, NICE_COMPONENT_TYPE_RTP);
      set_candidates (lagent, ls_id, ragent, rs_id_2, NICE_COMPONENT_TYPE_RTCP);
    } else {
      set_candidates (ragent, rs_id_1, lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
      set_candidates (ragent, rs_id_1, lagent, ls_id, NICE_COMPONENT_TYPE_RTCP);
      set_candidates (lagent, ls_id, ragent, rs_id_1, NICE_COMPONENT_TYPE_RTP);
      set_candidates (lagent, ls_id, ragent, rs_id_1, NICE_COMPONENT_TYPE_RTCP);
    }

    /* step: attach to mainloop (needed to register the fds) */
    nice_agent_attach_recv (ragent, rs_id_1, NICE_COMPONENT_TYPE_RTP,
        g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);
    nice_agent_attach_recv (ragent, rs_id_1, NICE_COMPONENT_TYPE_RTCP,
        g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);
    nice_agent_attach_recv (ragent, rs_id_2, NICE_COMPONENT_TYPE_RTP,
        g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);
    nice_agent_attach_recv (ragent, rs_id_2, NICE_COMPONENT_TYPE_RTCP,
        g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);
  } else {
    rs_id_1 = nice_agent_add_stream (ragent, 2);
    g_assert (rs_id_1 > 0);
    nice_agent_get_local_credentials(ragent, rs_id_1, &rufrag1, &rpassword1);

    nice_agent_set_remote_credentials (ragent, rs_id_1, lufrag, lpassword);
    nice_agent_set_remote_credentials (lagent, ls_id, rufrag1, rpassword1);

    g_assert (nice_agent_gather_candidates (lagent, ls_id) == TRUE);
    g_assert (nice_agent_gather_candidates (ragent, rs_id_1) == TRUE);

    /* step: attach to mainloop (needed to register the fds) */
    nice_agent_attach_recv (ragent, rs_id_1, NICE_COMPONENT_TYPE_RTP,
        g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);
    nice_agent_attach_recv (ragent, rs_id_1, NICE_COMPONENT_TYPE_RTCP,
        g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);

    set_candidates (ragent, rs_id_1, lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
    set_candidates (ragent, rs_id_1, lagent, ls_id, NICE_COMPONENT_TYPE_RTCP);
    set_candidates (lagent, ls_id, ragent, rs_id_1, NICE_COMPONENT_TYPE_RTP);
    set_candidates (lagent, ls_id, ragent, rs_id_1, NICE_COMPONENT_TYPE_RTCP);
  }

  /* step: run the mainloop until connectivity checks succeed
  *       (see timer_cb() above) */
  g_main_loop_run (global_mainloop);

  g_free (lufrag);
  g_free (lpassword);
  g_free (rufrag1);
  g_free (rpassword1);
  g_free (rufrag2);
  g_free (rpassword2);
  g_object_unref (lagent);
  g_object_unref (ragent);

  g_main_loop_unref (global_mainloop);
  global_mainloop = NULL;

  g_source_remove (timer_id);

#ifdef G_OS_WIN32
  WSACleanup();
#endif

  return 0;
}
