/*
 * This file is part of the Nice GLib ICE library.
 *
 * Unit test for ICE full-mode related features.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Kai Vehmanen, Nokia
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "agent.h"

#include <stdlib.h>
#include <string.h>

static NiceComponentState global_lagent_state[2] = { NICE_COMPONENT_STATE_LAST, NICE_COMPONENT_STATE_LAST };
static NiceComponentState global_ragent_state[2] = { NICE_COMPONENT_STATE_LAST, NICE_COMPONENT_STATE_LAST };
static guint global_components_ready = 0;
static guint global_components_ready_exit = 0;
static guint global_components_failed = 0;
static guint global_components_failed_exit = 0;
static GMainLoop *global_mainloop = NULL;
static gboolean global_lagent_gathering_done = FALSE;
static gboolean global_ragent_gathering_done = FALSE;
static gboolean global_lagent_ibr_received = FALSE;
static gboolean global_ragent_ibr_received = FALSE;
static gboolean global_ready_reached = FALSE;
static int global_lagent_cands = 0;
static int global_ragent_cands = 0;
static gint global_ragent_read = 0;
static guint global_exit_when_ibr_received = 0;

static void priv_print_global_status (void)
{
  g_debug ("\tgathering_done=%d", global_lagent_gathering_done && global_ragent_gathering_done);
  g_debug ("\tlstate[rtp]=%d [rtcp]=%d", global_lagent_state[0], global_lagent_state[1]);
  g_debug ("\trstate[rtp]=%d [rtcp]=%d", global_ragent_state[0], global_ragent_state[1]);
  g_debug ("\tL cands=%d R cands=%d", global_lagent_cands, global_ragent_cands);
}

static gboolean timer_cb (gpointer pointer)
{
  g_debug ("test-icetcp:%s: %p", G_STRFUNC, pointer);

  /* signal status via a global variable */

  /* note: should not be reached, abort */
  g_error ("ERROR: test has got stuck, aborting...");

  return FALSE;
}

static void cb_writable (NiceAgent*agent, guint stream_id, guint component_id)
{
    g_debug ("Transport is now writable, stopping mainloop");
    g_main_loop_quit (global_mainloop);
}

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  g_debug ("test-icetcp:%s: %p", G_STRFUNC, user_data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)component_id; (void)buf;

  /*
   * Lets ignore stun packets that got through
   */
  if (len < 8)
    return;
  if (strncmp ("12345678", buf, 8))
    return;

  if (GPOINTER_TO_UINT (user_data) == 2) {
    g_debug ("right agent received %d bytes, stopping mainloop", len);
    global_ragent_read = len;
    g_main_loop_quit (global_mainloop);
  }
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-icetcp:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    global_lagent_gathering_done = TRUE;
  else if (GPOINTER_TO_UINT (data) == 2)
    global_ragent_gathering_done = TRUE;

  if (global_lagent_gathering_done &&
      global_ragent_gathering_done)
    g_main_loop_quit (global_mainloop);

  /* XXX: dear compiler, these are for you: */
  (void)agent;
}

static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  gboolean ready_to_connected = FALSE;
  g_debug ("test-icetcp:%s: %p", G_STRFUNC, data);

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
  if (state == NICE_COMPONENT_STATE_FAILED)
    global_components_failed++;

  g_debug ("test-icetcp: checks READY/EXIT-AT %u/%u.", global_components_ready, global_components_ready_exit);
  g_debug ("test-icetcp: checks FAILED/EXIT-AT %u/%u.", global_components_failed, global_components_failed_exit);

  /* signal status via a global variable */
  if (global_components_ready == global_components_ready_exit &&
      global_components_failed == global_components_failed_exit &&
      global_ready_reached == FALSE) {
    g_debug ("Components ready/failed achieved. Stopping mailoop");
    global_ready_reached = TRUE;
    g_main_loop_quit (global_mainloop); 
    return;
  }

#if 0
  /* signal status via a global variable */
  if (global_components_failed == global_components_failed_exit) {
    g_main_loop_quit (global_mainloop); 
    return;
  }
#endif

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data; (void)component_id;
}

static void cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, 
				 gchar *lfoundation, gchar* rfoundation, gpointer data)
{
  g_debug ("test-icetcp:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    ++global_lagent_cands;
  else if (GPOINTER_TO_UINT (data) == 2)
    ++global_ragent_cands;

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)component_id; (void)lfoundation; (void)rfoundation;
}

static void cb_new_candidate(NiceAgent *agent, guint stream_id, guint component_id, 
			     gchar *foundation, gpointer data)
{
  g_debug ("test-icetcp:%s: %p", G_STRFUNC, data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data; (void)component_id; (void)foundation;
}

static void cb_initial_binding_request_received(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-icetcp:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    global_lagent_ibr_received = TRUE;
  else if (GPOINTER_TO_UINT (data) == 2)
    global_ragent_ibr_received = TRUE;

  if (global_exit_when_ibr_received) {
    g_debug ("Received initial binding request. Stopping mailoop");
    g_main_loop_quit (global_mainloop);
  }

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data;
}

static void set_candidates (NiceAgent *from, guint from_stream,
    NiceAgent *to, guint to_stream, guint component)
{
  GSList *cands = NULL, *i;

  cands = nice_agent_get_local_candidates (from, from_stream, component);

 restart:
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
      cands = g_slist_remove (cands, cand);
      nice_candidate_free (cand);
      goto restart;
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

static int run_full_test (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr, guint ready, guint failed)
{
  guint ls_id, rs_id;
  gint ret;

  /* XXX: dear compiler, this is for you */
  (void)baseaddr;

  /* step: initialize variables modified by the callbacks */
  global_components_ready = 0;
  global_components_ready_exit = ready;
  global_components_failed = 0;
  global_components_failed_exit = failed;
  global_lagent_gathering_done = FALSE;
  global_ragent_gathering_done = FALSE;
  global_lagent_ibr_received =
    global_ragent_ibr_received = FALSE;
  global_lagent_cands =
    global_ragent_cands = 0;
  global_ready_reached = FALSE;

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  /* step: add one stream, with RTP+RTCP components, to each agent */
  ls_id = nice_agent_add_stream (lagent, 2);

  rs_id = nice_agent_add_stream (ragent, 2);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);

  /* Gather candidates */
  g_assert (nice_agent_gather_candidates (lagent, ls_id) == TRUE);
  g_assert (nice_agent_gather_candidates (ragent, rs_id) == TRUE);

  {
    GSList *cands = NULL, *i;
    NiceCandidate *cand = NULL;

    cands = nice_agent_get_local_candidates (lagent, ls_id, 1);
    g_assert (g_slist_length (cands) == 2);
    cand = cands->data;
    g_assert (cand->type == NICE_CANDIDATE_TYPE_HOST);
    g_assert (cand->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ||
              cand->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE);
    cand = cands->next->data;
    g_assert (cand->type == NICE_CANDIDATE_TYPE_HOST);
    g_assert (cand->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ||
              cand->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE);
    for (i = cands; i; i = i->next)
      nice_candidate_free ((NiceCandidate *) i->data);
    g_slist_free (cands);
  }

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (1));
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (1));
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (2));
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (2));

  /* step: run mainloop until local candidates are ready
   *       (see timer_cb() above) */
  if (global_lagent_gathering_done != TRUE ||
      global_ragent_gathering_done != TRUE) {
    g_debug ("test-icetcp: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  set_credentials (lagent, ls_id, ragent, rs_id);

  /* step: pass the remote candidates to agents  */
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTCP);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTP);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTCP);

  g_debug ("test-icetcp: Set properties, next running mainloop until connectivity checks succeed...");

  /* step: run the mainloop until connectivity checks succeed
   *       (see timer_cb() above) */
  g_main_loop_run (global_mainloop);

  /* note: verify that STUN binding requests were sent */
  g_assert (global_lagent_ibr_received == TRUE);
  g_assert (global_ragent_ibr_received == TRUE);

  /* note: test payload send and receive */
  global_ragent_read = 0;
  ret = nice_agent_send (lagent, ls_id, 1, 16, "1234567812345678");
  if (ret == -1)
  {
    gboolean reliable = FALSE;
    g_object_get (G_OBJECT (lagent), "reliable", &reliable, NULL);
    g_debug ("Sending data returned -1 in %s mode", reliable?"Reliable":"Non-reliable");
    if (reliable) {
      gulong signal_handler;
      signal_handler = g_signal_connect (G_OBJECT (lagent),
          "reliable-transport-writable", G_CALLBACK (cb_writable), NULL);
      g_debug ("Running mainloop until transport is writable");
      g_main_loop_run (global_mainloop);
      g_signal_handler_disconnect(G_OBJECT (lagent), signal_handler);

      ret = nice_agent_send (lagent, ls_id, 1, 16, "1234567812345678");
    }
  }
  g_debug ("Sent %d bytes", ret);
  g_assert (ret == 16);
  g_main_loop_run (global_mainloop);
  g_assert (global_ragent_read == 16);

  g_debug ("test-icetcp: Ran mainloop, removing streams...");

  /* step: clean up resources and exit */

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  return 0;
}

int main (void)
{
  NiceAgent *lagent, *ragent;      /* agent's L and R */
  NiceAddress baseaddr;
  int result;
  guint timer_id;

#ifdef G_OS_WIN32
  WSADATA w;

  WSAStartup(0x0202, &w);
#endif
  g_type_init ();
#if !GLIB_CHECK_VERSION(2,31,8)
  g_thread_init(NULL);
#endif

  global_mainloop = g_main_loop_new (NULL, FALSE);

  /* step: create the agents L and R */
  lagent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_RFC5245);
  ragent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_RFC5245);

  g_object_set (G_OBJECT (lagent), "ice-udp", FALSE,  NULL);
  g_object_set (G_OBJECT (ragent), "ice-udp", FALSE,  NULL);
  nice_agent_set_software (lagent, "Test-icetcp, Left Agent");
  nice_agent_set_software (ragent, "Test-icetcp, Right Agent");

  /* step: add a timer to catch state changes triggered by signals */
  timer_id = g_timeout_add (30000, timer_cb, NULL);

  /* step: specify which local interface to use */
  if (!nice_address_set_from_string (&baseaddr, "127.0.0.1"))
    g_assert_not_reached ();
  nice_agent_add_local_address (lagent, &baseaddr);
  nice_agent_add_local_address (ragent, &baseaddr);

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
  g_signal_connect (G_OBJECT (lagent), "new-candidate",
      G_CALLBACK (cb_new_candidate), GUINT_TO_POINTER (1));
  g_signal_connect (G_OBJECT (ragent), "new-candidate",
      G_CALLBACK (cb_new_candidate), GUINT_TO_POINTER (2));
  g_signal_connect (G_OBJECT (lagent), "initial-binding-request-received",
      G_CALLBACK (cb_initial_binding_request_received),
      GUINT_TO_POINTER (1));
  g_signal_connect (G_OBJECT (ragent), "initial-binding-request-received",
      G_CALLBACK (cb_initial_binding_request_received),
      GUINT_TO_POINTER (2));

  /* step: run test the first time */
  g_debug ("test-icetcp: TEST STARTS / running test for the 1st time");
  result = run_full_test (lagent, ragent, &baseaddr, 4 ,0);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands >= 2);
  g_assert (global_ragent_cands >= 2);


  /* step: run test again without unref'ing agents */
  g_debug ("test-icetcp: TEST STARTS / running test for the 2nd time");
  result = run_full_test (lagent, ragent, &baseaddr, 4, 0);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands >= 2);
  g_assert (global_ragent_cands >= 2);

  g_object_unref (lagent);
  g_object_unref (ragent);

  g_main_loop_unref (global_mainloop);
  global_mainloop = NULL;

  g_source_remove (timer_id);
#ifdef G_OS_WIN32
  WSACleanup();
#endif
  return result;
}
