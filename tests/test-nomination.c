#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gio/gio.h>
#include <gio/gnetworking.h>
#include <agent.h>

static NiceComponentState global_lagent_state[2] = { NICE_COMPONENT_STATE_LAST, NICE_COMPONENT_STATE_LAST };
static NiceComponentState global_ragent_state[2] = { NICE_COMPONENT_STATE_LAST, NICE_COMPONENT_STATE_LAST };
static guint global_components_ready = 0;
static gboolean global_lagent_gathering_done = FALSE;
static gboolean global_ragent_gathering_done = FALSE;
static int global_lagent_cands = 0;
static int global_ragent_cands = 0;

static gboolean timer_cb (gpointer pointer)
{
  g_debug ("test-nomination:%s: %p", G_STRFUNC, pointer);

  /* signal status via a global variable */

  /* note: should not be reached, abort */
  g_error ("ERROR: test has got stuck, aborting...");

  return FALSE;
}

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  g_debug ("test-nomination:%s: %p", G_STRFUNC, user_data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)component_id; (void)buf;

  /*
   * Lets ignore stun packets that got through
   */
  if (len < 8)
    return;
  if (strncmp ("12345678", buf, 8))
    return;

  if (component_id != 1)
    return;
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-nomination:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    global_lagent_gathering_done = TRUE;
  else if (GPOINTER_TO_UINT (data) == 2)
    global_ragent_gathering_done = TRUE;
}


static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  gboolean ready_to_connected = FALSE;
  g_debug ("test-nomination:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1) {
    if (global_lagent_state[component_id - 1] == NICE_COMPONENT_STATE_READY &&
        state == NICE_COMPONENT_STATE_CONNECTED)
      ready_to_connected = TRUE;
    global_lagent_state[component_id - 1] = state;
  } else if (GPOINTER_TO_UINT (data) == 2) {
    if (global_ragent_state[component_id - 1] == NICE_COMPONENT_STATE_READY &&
        state == NICE_COMPONENT_STATE_CONNECTED)
      ready_to_connected = TRUE;
    global_ragent_state[component_id - 1] = state;
  }

  if (state == NICE_COMPONENT_STATE_READY)
    global_components_ready++;
  else if (state == NICE_COMPONENT_STATE_CONNECTED && ready_to_connected)
    global_components_ready--;
  g_assert (state != NICE_COMPONENT_STATE_FAILED);

  g_debug ("test-nomination: checks READY %u.", global_components_ready);
}

static void cb_new_selected_pair(NiceAgent *agent, guint stream_id,
    guint component_id, gchar *lfoundation, gchar* rfoundation, gpointer data)
{
  g_debug ("test-nomination:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    ++global_lagent_cands;
  else if (GPOINTER_TO_UINT (data) == 2)
    ++global_ragent_cands;
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

static void set_credentials (NiceAgent *lagent, guint lstream,
    NiceAgent *ragent, guint rstream)
{
  gchar *ufrag = NULL, *password = NULL;

  nice_agent_get_local_credentials(lagent, lstream, &ufrag, &password);
  nice_agent_set_remote_credentials (ragent, rstream, ufrag, password);
  g_free (ufrag);
  g_free (password);
  nice_agent_get_local_credentials(ragent, rstream, &ufrag, &password);
  nice_agent_set_remote_credentials (lagent, lstream, ufrag, password);
  g_free (ufrag);
  g_free (password);
}

static void
run_test(NiceNominationMode l_nomination_mode,
  NiceNominationMode r_nomination_mode)
{
  NiceAgent *lagent, *ragent;      /* agent's L and R */
  const gchar *localhost;
  NiceAddress localaddr;
  guint ls_id, rs_id;
  gulong timer_id;

  localhost = "127.0.0.1";

  /* step: initialize variables modified by the callbacks */
  global_components_ready = 0;
  global_lagent_gathering_done = FALSE;
  global_ragent_gathering_done = FALSE;
  global_lagent_cands = global_ragent_cands = 0;

  lagent = nice_agent_new_full (NULL,
    NICE_COMPATIBILITY_RFC5245,
    l_nomination_mode == NICE_NOMINATION_MODE_REGULAR ?
    NICE_AGENT_OPTION_REGULAR_NOMINATION : 0);

  ragent = nice_agent_new_full (NULL,
    NICE_COMPATIBILITY_RFC5245,
    r_nomination_mode == NICE_NOMINATION_MODE_REGULAR ?
    NICE_AGENT_OPTION_REGULAR_NOMINATION : 0);

  g_object_set (G_OBJECT (lagent), "ice-tcp", FALSE, NULL);
  g_object_set (G_OBJECT (ragent), "ice-tcp", FALSE, NULL);

  g_object_set (G_OBJECT (lagent), "upnp", FALSE,  NULL);
  g_object_set (G_OBJECT (ragent), "upnp", FALSE,  NULL);
  nice_agent_set_software (lagent, "Test-nomination, Left Agent");
  nice_agent_set_software (ragent, "Test-nomination, Right Agent");

  timer_id = g_timeout_add (30000, timer_cb, NULL);

  if (!nice_address_set_from_string (&localaddr, localhost))
    g_assert_not_reached ();
  nice_agent_add_local_address (lagent, &localaddr);
  nice_agent_add_local_address (ragent, &localaddr);

  g_signal_connect (G_OBJECT (lagent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), GUINT_TO_POINTER(1));
  g_signal_connect (G_OBJECT (ragent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), GUINT_TO_POINTER (2));
  g_signal_connect (G_OBJECT (lagent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), GUINT_TO_POINTER (1));
  g_signal_connect (G_OBJECT (ragent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), GUINT_TO_POINTER (2));
  g_signal_connect (G_OBJECT (lagent), "new-selected-pair",
      G_CALLBACK (cb_new_selected_pair), GUINT_TO_POINTER(1));
  g_signal_connect (G_OBJECT (ragent), "new-selected-pair",
      G_CALLBACK (cb_new_selected_pair), GUINT_TO_POINTER (2));

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  ls_id = nice_agent_add_stream (lagent, 1);
  rs_id = nice_agent_add_stream (ragent, 1);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);

  /* Gather candidates and test nice_agent_set_port_range */
  g_assert (nice_agent_gather_candidates (lagent, ls_id) == TRUE);
  g_assert (nice_agent_gather_candidates (ragent, rs_id) == TRUE);

  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_context_default (), cb_nice_recv, GUINT_TO_POINTER (1));
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_context_default (), cb_nice_recv, GUINT_TO_POINTER (2));

  g_debug ("test-nomination: Added streams, running context until 'candidate-gathering-done'...");
  while (!global_lagent_gathering_done)
    g_main_context_iteration (NULL, TRUE);
  g_assert (global_lagent_gathering_done == TRUE);
  while (!global_ragent_gathering_done)
    g_main_context_iteration (NULL, TRUE);
  g_assert (global_ragent_gathering_done == TRUE);

  set_credentials (lagent, ls_id, ragent, rs_id);

  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTP);

  while (global_lagent_state[0] != NICE_COMPONENT_STATE_READY ||
      global_ragent_state[0] != NICE_COMPONENT_STATE_READY)
    g_main_context_iteration (NULL, TRUE);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  g_source_remove (timer_id);

  g_clear_object(&lagent);
  g_clear_object(&ragent);
}

static void
regular (void)
{
  run_test(NICE_NOMINATION_MODE_REGULAR, NICE_NOMINATION_MODE_REGULAR);
}

static void
aggressive (void)
{
  run_test(NICE_NOMINATION_MODE_AGGRESSIVE, NICE_NOMINATION_MODE_AGGRESSIVE);
}

static void
mixed_ra (void)
{
  run_test(NICE_NOMINATION_MODE_REGULAR, NICE_NOMINATION_MODE_AGGRESSIVE);
}

static void
mixed_ar (void)
{
  run_test(NICE_NOMINATION_MODE_AGGRESSIVE, NICE_NOMINATION_MODE_REGULAR);
}

int
main (int argc, char **argv)
{
  int ret;

  g_networking_init ();

  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/nice/nomination/regular", regular);
  g_test_add_func ("/nice/nomination/aggressive", aggressive);
  g_test_add_func ("/nice/nomination/mixed_ra", mixed_ra);
  g_test_add_func ("/nice/nomination/mixed_ar", mixed_ar);

  ret = g_test_run ();

  return ret;
}
