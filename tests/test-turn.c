#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gio/gio.h>
#include <agent.h>

static NiceComponentState global_lagent_state[2] = { NICE_COMPONENT_STATE_LAST, NICE_COMPONENT_STATE_LAST };
static NiceComponentState global_ragent_state[2] = { NICE_COMPONENT_STATE_LAST, NICE_COMPONENT_STATE_LAST };
static guint global_components_ready = 0;
static gboolean global_lagent_gathering_done = FALSE;
static gboolean global_ragent_gathering_done = FALSE;
static int global_lagent_cands = 0;
static int global_ragent_cands = 0;

#define TURN_USER "toto"
#define TURN_PASS "password"

static gboolean timer_cb (gpointer pointer)
{
  g_debug ("test-turn:%s: %p", G_STRFUNC, pointer);

  /* signal status via a global variable */

  /* note: should not be reached, abort */
  g_error ("ERROR: test has got stuck, aborting...");

  return FALSE;
}

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, user_data);

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

#if 0
  if (GPOINTER_TO_UINT (user_data) == 2) {
    global_ragent_read += len;
  }
#endif
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    global_lagent_gathering_done = TRUE;
  else if (GPOINTER_TO_UINT (data) == 2)
    global_ragent_gathering_done = TRUE;
}


static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  gboolean ready_to_connected = FALSE;
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, data);

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

  g_debug ("test-turn: checks READY %u.", global_components_ready);
}

static void cb_new_selected_pair(NiceAgent *agent, guint stream_id,
    guint component_id, gchar *lfoundation, gchar* rfoundation, gpointer data)
{
  g_debug ("test-turn:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    ++global_lagent_cands;
  else if (GPOINTER_TO_UINT (data) == 2)
    ++global_ragent_cands;
}

static void cb_closed (GObject *src, GAsyncResult *res, gpointer data)
{
  NiceAgent *agent = NICE_AGENT (src);
  g_debug ("test-turn:%s: %p", G_STRFUNC, agent);

  *((gboolean *)data) = TRUE;
}

static void set_candidates (NiceAgent *from, guint from_stream,
    NiceAgent *to, guint to_stream, guint component, gboolean remove_non_relay,
    gboolean force_relay)
{
  GSList *cands = NULL, *i;

  cands = nice_agent_get_local_candidates (from, from_stream, component);
  if (remove_non_relay) {
  restart:
    for (i = cands; i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (force_relay)
        g_assert (cand->type == NICE_CANDIDATE_TYPE_RELAYED);
      if (cand->type != NICE_CANDIDATE_TYPE_RELAYED) {
        cands = g_slist_remove (cands, cand);
        nice_candidate_free (cand);
        goto restart;
      }
    }
  }
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
run_test(guint turn_port, gboolean is_ipv6,
    gboolean ice_udp, gboolean ice_tcp, gboolean force_relay,
    gboolean remove_non_relay,
    NiceRelayType turn_type)
{
  NiceAgent *lagent, *ragent;      /* agent's L and R */
  const gchar *localhost;
  NiceAddress localaddr;
  guint ls_id, rs_id;
  gulong timer_id;
  gboolean lagent_closed = FALSE;
  gboolean ragent_closed = FALSE;

  if (is_ipv6)
    localhost = "::1";
  else
    localhost = "127.0.0.1";

  /* step: initialize variables modified by the callbacks */
  global_components_ready = 0;
  global_lagent_gathering_done = FALSE;
  global_ragent_gathering_done = FALSE;
  global_lagent_cands = global_ragent_cands = 0;

  lagent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);
  ragent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);

  g_object_set (G_OBJECT (lagent), "ice-tcp", ice_tcp, "ice-udp", ice_udp,
      "force-relay", force_relay, NULL);
  g_object_set (G_OBJECT (ragent), "ice-tcp", ice_tcp, "ice-udp", ice_udp,
      "force-relay", force_relay, NULL);

  g_object_set (G_OBJECT (lagent), "upnp", FALSE,  NULL);
  g_object_set (G_OBJECT (ragent), "upnp", FALSE,  NULL);
  nice_agent_set_software (lagent, "Test-turn, Left Agent");
  nice_agent_set_software (ragent, "Test-turn, Right Agent");

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
  nice_agent_set_relay_info(lagent, ls_id, 1,
      localhost, turn_port, TURN_USER, TURN_PASS, turn_type);
  nice_agent_set_relay_info(ragent, rs_id, 1,
      localhost, turn_port, TURN_USER, TURN_PASS, turn_type);

  g_assert (global_lagent_gathering_done == FALSE);
  g_assert (global_ragent_gathering_done == FALSE);
  g_debug ("test-turn: Added streams, running context until 'candidate-gathering-done'...");

  /* Gather candidates and test nice_agent_set_port_range */
  g_assert (nice_agent_gather_candidates (lagent, ls_id) == TRUE);
  g_assert (nice_agent_gather_candidates (ragent, rs_id) == TRUE);

  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_context_default (), cb_nice_recv, GUINT_TO_POINTER (1));
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_context_default (), cb_nice_recv, GUINT_TO_POINTER (2));

  while (!global_lagent_gathering_done)
    g_main_context_iteration (NULL, TRUE);
  g_assert (global_lagent_gathering_done == TRUE);
  while (!global_ragent_gathering_done)
    g_main_context_iteration (NULL, TRUE);
  g_assert (global_ragent_gathering_done == TRUE);

  set_credentials (lagent, ls_id, ragent, rs_id);

  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      remove_non_relay, force_relay);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      remove_non_relay, force_relay);

  while (global_lagent_state[0] != NICE_COMPONENT_STATE_READY ||
      global_ragent_state[0] != NICE_COMPONENT_STATE_READY)
    g_main_context_iteration (NULL, TRUE);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  nice_agent_close_async (lagent, cb_closed, &lagent_closed);
  nice_agent_close_async (ragent, cb_closed, &ragent_closed);

  g_clear_object(&lagent);
  g_clear_object(&ragent);

  while (!lagent_closed || !ragent_closed) {
    g_main_context_iteration (NULL, TRUE);
  }

  g_source_remove (timer_id);

}

guint global_turn_port;

static void
udp_no_force_no_remove_udp (void)
{
  run_test(global_turn_port, FALSE /* is_ipv6 */,
      TRUE /* ice_udp */,
      FALSE /* ice_tcp */,
      FALSE /* force_relay */,
      FALSE /* remove_non_relay */,
      NICE_RELAY_TYPE_TURN_UDP);
}

static void
udp_no_force_remove_udp (void)
{
  run_test(global_turn_port, FALSE /* is_ipv6 */,
      TRUE /* ice_udp */,
      FALSE /* ice_tcp */,
      FALSE /* force_relay */,
      TRUE /* remove_non_relay */,
      NICE_RELAY_TYPE_TURN_UDP);
}

static void
udp_force_no_remove_udp (void)
{
  run_test(global_turn_port, FALSE /* is_ipv6 */,
      TRUE /* ice_udp */,
      FALSE /* ice_tcp */,
      TRUE /* force_relay */,
      FALSE /* remove_non_relay */,
      NICE_RELAY_TYPE_TURN_UDP);
}

static void
udp_no_force_no_remove_tcp (void)
{
  run_test(global_turn_port, FALSE /* is_ipv6 */,
      TRUE /* ice_udp */,
      FALSE /* ice_tcp */,
      FALSE /* force_relay */,
      FALSE /* remove_non_relay */,
      NICE_RELAY_TYPE_TURN_TCP);
}

static void
udp_no_force_remove_tcp (void)
{
  run_test(global_turn_port, FALSE /* is_ipv6 */,
      TRUE /* ice_udp */,
      FALSE /* ice_tcp */,
      FALSE /* force_relay */,
      TRUE /* remove_non_relay */,
      NICE_RELAY_TYPE_TURN_TCP);
}

static void
udp_force_no_remove_tcp (void)
{
  run_test(global_turn_port, FALSE /* is_ipv6 */,
      TRUE /* ice_udp */,
      FALSE /* ice_tcp */,
      TRUE /* force_relay */,
      FALSE /* remove_non_relay */,
      NICE_RELAY_TYPE_TURN_TCP);
}





int
main (int argc, char **argv)
{
  GSubprocess *sp;
  GError *error = NULL;
  gchar portstr[10];
  int ret;
  gchar *out_str = NULL;
  gchar *err_str = NULL;

  g_test_init (&argc, &argv, NULL);

  global_turn_port = g_random_int_range (10000, 60000);
  snprintf(portstr, 9, "%u", global_turn_port);

  if (g_spawn_command_line_sync ("turnserver --help", &out_str, &err_str, NULL,
          NULL) && err_str) {
    if (!strstr(err_str, "--user")) {
      g_print ("rfc5766-turn-server not installed, skipping turn test\n");
      return 0;
    }
  } else {
    g_print ("rfc5766-turn-server not installed, skipping turn test\n");
    return 0;
  }
  g_free (err_str);
  g_free (out_str);

  sp = g_subprocess_new (G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &error,
      "turnserver",
      "--user", "toto:0xaae440b3348d50265b63703117c7bfd5",
      "--realm", "realm",
      "--listening-port", portstr,
      NULL);

  g_test_add_func ("/nice/turn/udp", udp_no_force_no_remove_udp);
  g_test_add_func ("/nice/turn/udp/remove_non_turn",
      udp_no_force_remove_udp);
  g_test_add_func ("/nice/turn/udp/force_relay",
      udp_force_no_remove_udp);
  g_test_add_func ("/nice/turn/udp/over-tcp", udp_no_force_no_remove_tcp);
  g_test_add_func ("/nice/turn/udp/over-tcp/remove_non_turn",
      udp_no_force_remove_tcp);
  g_test_add_func ("/nice/turn/udp/over-tcp/force_relay",
      udp_force_no_remove_tcp);

  ret = g_test_run ();

  g_subprocess_force_exit (sp);
  g_subprocess_wait (sp, NULL, NULL);
  g_clear_object (&sp);

  return ret;
}
