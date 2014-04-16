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


#define USE_TURN 0
#define USE_LOOPBACK 1
#define USE_PROXY 0
#define USE_UPNP 0
#define USE_RELIABLE 0
#define TEST_GOOGLE 0

#define PROXY_IP "127.0.0.1"
#define PROXY_PORT 1080
#define PROXY_USERNAME NULL
#define PROXY_PASSWORD NULL

#if USE_PROXY
#define PROXY_TYPE NICE_PROXY_TYPE_SOCKS5
#else
#define PROXY_TYPE NICE_PROXY_TYPE_NONE
#endif

#if TEST_GOOGLE
#define NICE_COMPATIBILITY NICE_COMPATIBILITY_GOOGLE

#if USE_TURN
#undef USE_LOOPBACK
#define USE_LOOPBACK 0

#define TURN_IP "209.85.163.126"
#define TURN_PORT 443
#define TURN_USER "ih9ppiM0P6vN34DB"
#define TURN_PASS ""
#define TURN_USER2 TURN_USER
#define TURN_PASS2 TURN_PASS
#define TURN_TYPE NICE_RELAY_TYPE_TURN_TLS

#endif

#else
#define NICE_COMPATIBILITY NICE_COMPATIBILITY_RFC5245
#if USE_LOOPBACK
#define USE_TURN_SERVER_ORG 1
#else
#define USE_TURN_SERVER_ORG 0
#endif

#define NUMB_IP "64.251.22.149"
#define NUMB_PORT 3478
#define NUMB_USER "youness.alaoui@collabora.co.uk"
#define NUMB_PASS "badger"

#define TSORG_IP "127.0.0.1"
#define TSORG_PORT 3478
#define TSORG_USER "toto"
#define TSORG_PASS "password"


#if USE_TURN_SERVER_ORG
#define TURN_IP TSORG_IP
#define TURN_PORT TSORG_PORT
#define TURN_USER TSORG_USER
#define TURN_PASS TSORG_PASS
#define TURN_USER2 TSORG_USER
#define TURN_PASS2 TSORG_PASS
#define TURN_TYPE NICE_RELAY_TYPE_TURN_TCP
#else
#define TURN_IP NUMB_IP
#define TURN_PORT NUMB_PORT
#define TURN_USER NUMB_USER
#define TURN_PASS NUMB_PASS
#define TURN_USER2 NUMB_USER
#define TURN_PASS2 NUMB_PASS
#define TURN_TYPE NICE_RELAY_TYPE_TURN_UDP
#endif

#endif


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
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, pointer);

  /* signal status via a global variable */

  /* note: should not be reached, abort */
  g_error ("ERROR: test has got stuck, aborting...");

  return FALSE;
}

static void cb_writable (NiceAgent*agent, guint stream_id, guint component_id,
    gpointer user_data)
{
  guint *ls_id = user_data;

  if (stream_id == *ls_id && component_id == 1) {
    g_debug ("Transport is now writable, stopping mainloop");
    *ls_id = 0;
  }
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

  if (component_id == 2)
    return;

  if (GPOINTER_TO_UINT (user_data) == 2) {
    g_debug ("right agent received %d bytes, stopping mainloop", len);
    global_ragent_read = len;
    g_main_loop_quit (global_mainloop);
  }
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, data);

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
  if (state == NICE_COMPONENT_STATE_FAILED)
    global_components_failed++;

  g_debug ("test-fullmode: checks READY/EXIT-AT %u/%u.", global_components_ready, global_components_ready_exit);
  g_debug ("test-fullmode: checks FAILED/EXIT-AT %u/%u.", global_components_failed, global_components_failed_exit);

  /* signal status via a global variable */
  if (global_components_ready == global_components_ready_exit &&
      global_components_failed == global_components_failed_exit) {
    g_debug ("Components ready/failed achieved. Stopping mailoop");
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
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, data);

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
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data; (void)component_id; (void)foundation;
}

static void cb_initial_binding_request_received(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, data);

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
    NiceAgent *to, guint to_stream, guint component, gboolean remove_non_relay)
{
  GSList *cands = NULL, *i;

  cands = nice_agent_get_local_candidates (from, from_stream, component);
  if (remove_non_relay) {
  restart:
    for (i = cands; i; i = i->next) {
      NiceCandidate *cand = i->data;
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

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  /* step: add one stream, with RTP+RTCP components, to each agent */
  ls_id = nice_agent_add_stream (lagent, 2);

  rs_id = nice_agent_add_stream (ragent, 2);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);
#if USE_TURN
  nice_agent_set_relay_info(lagent, ls_id, 1,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
  nice_agent_set_relay_info(lagent, ls_id, 2,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
  nice_agent_set_relay_info(ragent, rs_id, 1,
      TURN_IP, TURN_PORT, TURN_USER2, TURN_PASS2, TURN_TYPE);
  nice_agent_set_relay_info(ragent, rs_id, 2,
      TURN_IP, TURN_PORT, TURN_USER2, TURN_PASS2, TURN_TYPE);
#endif


  /* Gather candidates and test nice_agent_set_port_range */
  nice_agent_set_port_range (lagent, ls_id, 1, 10000, 10000);
  nice_agent_set_port_range (lagent, ls_id, 2, 10001, 10001);
  nice_agent_set_port_range (ragent, rs_id, 1, 12345, 12345);
  nice_agent_set_port_range (ragent, rs_id, 2, 10000, 10001);
  g_assert (nice_agent_gather_candidates (lagent, ls_id) == TRUE);
  g_assert (nice_agent_gather_candidates (ragent, rs_id) == FALSE);
  g_assert (nice_agent_get_local_candidates (ragent, rs_id, 1) == NULL);
  g_assert (nice_agent_get_local_candidates (ragent, rs_id, 2) == NULL);
  nice_agent_set_port_range (ragent, rs_id, 2, 10000, 10002);
  g_assert (nice_agent_gather_candidates (ragent, rs_id) == TRUE);

#if USE_LOOPBACK
  {
    GSList *cands = NULL, *i;
    NiceCandidate *cand = NULL;

    cands = nice_agent_get_local_candidates (lagent, ls_id, 1);
    g_assert (g_slist_length (cands) == 1);
    cand = cands->data;
    g_assert (cand->type == NICE_CANDIDATE_TYPE_HOST);
    g_assert (nice_address_get_port (&cand->addr) == 10000);
    for (i = cands; i; i = i->next)
      nice_candidate_free ((NiceCandidate *) i->data);
    g_slist_free (cands);

    cands = nice_agent_get_local_candidates (lagent, ls_id, 2);
    g_assert (g_slist_length (cands) == 1);
    cand = cands->data;
    g_assert (cand->type == NICE_CANDIDATE_TYPE_HOST);
    g_assert (nice_address_get_port (&cand->addr) == 10001);
    for (i = cands; i; i = i->next)
      nice_candidate_free ((NiceCandidate *) i->data);
    g_slist_free (cands);

    cands = nice_agent_get_local_candidates (ragent, rs_id, 1);
    g_assert (g_slist_length (cands) == 1);
    cand = cands->data;
    g_assert (cand->type == NICE_CANDIDATE_TYPE_HOST);
    g_assert (nice_address_get_port (&cand->addr) == 12345);
    for (i = cands; i; i = i->next)
      nice_candidate_free ((NiceCandidate *) i->data);
    g_slist_free (cands);

    cands = nice_agent_get_local_candidates (ragent, rs_id, 2);
    g_assert (g_slist_length (cands) == 1);
    cand = cands->data;
    g_assert (cand->type == NICE_CANDIDATE_TYPE_HOST);
    g_assert (nice_address_get_port (&cand->addr) == 10002);
    for (i = cands; i; i = i->next)
      nice_candidate_free ((NiceCandidate *) i->data);
    g_slist_free (cands);

  }
#endif

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
    g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  set_credentials (lagent, ls_id, ragent, rs_id);

  /* step: pass the remote candidates to agents  */
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTP, USE_TURN);
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, USE_TURN);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTP, USE_TURN);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, USE_TURN);

  g_debug ("test-fullmode: Set properties, next running mainloop until connectivity checks succeed...");

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
      guint ls_id_copy = ls_id;

      signal_handler = g_signal_connect (G_OBJECT (lagent),
          "reliable-transport-writable", G_CALLBACK (cb_writable), &ls_id_copy);
      g_debug ("Running mainloop until transport is writable");
      while (ls_id_copy == ls_id)
        g_main_context_iteration (NULL, TRUE);
      g_signal_handler_disconnect(G_OBJECT (lagent), signal_handler);

      ret = nice_agent_send (lagent, ls_id, 1, 16, "1234567812345678");
    }
  }
  g_debug ("Sent %d bytes", ret);
  g_assert (ret == 16);
  while (global_ragent_read != 16)
    g_main_context_iteration (NULL, TRUE);
  g_assert (global_ragent_read == 16);

  g_debug ("test-fullmode: Ran mainloop, removing streams...");

  /* step: clean up resources and exit */

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  return 0;
}

/*
 * Simulate the case where answer to the offer is delayed and
 * some STUN connectivity checks reach the offering party
 * before it gets the remote SDP information.
 */
static int run_full_test_delayed_answer (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr, guint ready, guint failed)
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
  global_exit_when_ibr_received = 1;
  global_lagent_cands =
    global_ragent_cands = 0;

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  /* step: add one stream, with RTP+RTCP components, to each agent */
  ls_id = nice_agent_add_stream (lagent, 2);

  rs_id = nice_agent_add_stream (ragent, 2);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);

  /* We don't try this with TURN because as long as both agents don't
     have the remote candidates, they won't be able to create the
     permission on the TURN server, so the connchecks will never go through */

  nice_agent_gather_candidates (lagent, ls_id);
  nice_agent_gather_candidates (ragent, rs_id);

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
    g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  set_credentials (lagent, ls_id, ragent, rs_id);

  /* step: set remote candidates for agent R (answering party) */
  /* We have to disable TURN for this test because with the delayed answer,
     we can't create turn permissions, so we won't receive any connchecks */
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTP, FALSE);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, FALSE);

  g_debug ("test-fullmode: Set properties, next running mainloop until first check is received...");

  /* step: run the mainloop until first connectivity check receveid */
  g_main_loop_run (global_mainloop);
  global_exit_when_ibr_received = 0;

  /* note: verify that STUN binding requests were sent */
  g_assert (global_lagent_ibr_received == TRUE);

  g_debug ("test-fullmode: Delayed answer received, continuing processing..");

  /* step: pass remove candidates to agent L (offering party) */
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTP, FALSE);
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, FALSE);

  g_debug ("test-fullmode: Running mainloop until connectivity checks succeeed.");

  g_main_loop_run (global_mainloop);
  g_assert (global_ragent_ibr_received == TRUE);
  g_assert (global_components_failed == 0);

  /* note: test payload send and receive */
  global_ragent_read = 0;
  ret = nice_agent_send (lagent, ls_id, 1, 16, "1234567812345678");
  if (ret == -1) {
    gboolean reliable = FALSE;
    g_object_get (G_OBJECT (lagent), "reliable", &reliable, NULL);
    if (reliable) {
      gulong signal_handler;
      guint ls_id_copy = ls_id;

      signal_handler = g_signal_connect (G_OBJECT (lagent),
          "reliable-transport-writable", G_CALLBACK (cb_writable), &ls_id_copy);
      g_debug ("Running mainloop until transport is writable");
      while (ls_id_copy == ls_id)
        g_main_context_iteration (NULL, TRUE);
      g_signal_handler_disconnect(G_OBJECT (lagent), signal_handler);

      ret = nice_agent_send (lagent, ls_id, 1, 16, "1234567812345678");
    }
  }
  global_ragent_read = 0;
  g_assert (ret == 16);
  g_main_loop_run (global_mainloop);
  g_assert (global_ragent_read == 16);

  g_debug ("test-fullmode: Ran mainloop, removing streams...");

  /* step: clean up resources and exit */

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  return 0;
}

static int run_full_test_wrong_password (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr)
{
  guint ls_id, rs_id;

  /* XXX: dear compiler, this is for you */
  (void)baseaddr;

  global_components_ready = 0;
  global_components_ready_exit = 0;
  global_components_failed = 0;
  global_components_failed_exit = 2;
  global_lagent_state[0] =   global_lagent_state[1] = 
    global_ragent_state[0] = global_ragent_state[1] 
    = NICE_COMPONENT_STATE_LAST;
  global_lagent_gathering_done = 
    global_ragent_gathering_done = FALSE;
  global_lagent_cands = 
    global_ragent_cands = 0;

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  /* step: add one stream, with one component, to each agent */
  ls_id = nice_agent_add_stream (lagent, 1);

  rs_id = nice_agent_add_stream (ragent, 1);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);

#if USE_TURN
  nice_agent_set_relay_info(lagent, ls_id, 1,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
  nice_agent_set_relay_info(ragent, rs_id, 1,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
#endif

  nice_agent_gather_candidates (lagent, ls_id);
  nice_agent_gather_candidates (ragent, rs_id);

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (1));
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (2));

  /* step: run mainloop until local candidates are ready
   *       (see timer_cb() above) */
  if (global_lagent_gathering_done != TRUE ||
      global_ragent_gathering_done != TRUE) {
    g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  g_debug ("test-fullmode: Got local candidates...");

  set_credentials (lagent, ls_id, ragent, rs_id);
  nice_agent_set_remote_credentials (ragent, rs_id, "wrong", "password");
  nice_agent_set_remote_credentials (lagent, ls_id, "wrong2", "password2");


  /* step: pass the remote candidates to agents  */
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTP, USE_TURN);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTP, USE_TURN);

  g_debug ("test-fullmode: Set properties, next running mainloop until connectivity checks succeed...");

  /* step: run the mainloop until connectivity checks succeed
   *       (see timer_cb() above) */
  g_main_loop_run (global_mainloop);

  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands == 0);
  g_assert (global_ragent_cands == 0);

  g_debug ("test-fullmode: Ran mainloop, removing streams...");

  /* step: clean up resources and exit */

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  return 0;
}

static int run_full_test_control_conflict (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr, gboolean role)
{
  guint ls_id, rs_id;

  /* XXX: dear compiler, this is for you */
  (void)baseaddr;

  global_components_ready = 0;
  global_components_ready_exit = 2;
  global_components_failed = 0;
  global_components_failed_exit = 0;
  global_lagent_gathering_done =
    global_ragent_gathering_done = FALSE;
  global_lagent_cands = 
    global_ragent_cands = 0;
  global_lagent_ibr_received =
    global_ragent_ibr_received = FALSE;

  g_object_set (G_OBJECT (lagent), "controlling-mode", role, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", role, NULL);

  /* step: add one stream, with one component, to each agent */
  ls_id = nice_agent_add_stream (lagent, 1);

  rs_id = nice_agent_add_stream (ragent, 1);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);

#if USE_TURN
  nice_agent_set_relay_info(lagent, ls_id, 1,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
  nice_agent_set_relay_info(ragent, rs_id, 1,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
#endif

  nice_agent_gather_candidates (lagent, ls_id);
  nice_agent_gather_candidates (ragent, rs_id);

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (1));
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (2));

  /* step: run mainloop until local candidates are ready 
   *       (see timer_cb() above) */
  if (global_lagent_gathering_done != TRUE ||
      global_ragent_gathering_done != TRUE) {
    g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  g_debug ("test-fullmode: Got local candidates...");

  set_credentials (lagent, ls_id, ragent, rs_id);

  /* step: pass the remote candidates to agents  */
  set_candidates (ragent, rs_id, lagent, ls_id, NICE_COMPONENT_TYPE_RTP, USE_TURN);
  set_candidates (lagent, ls_id, ragent, rs_id, NICE_COMPONENT_TYPE_RTP, USE_TURN);

  g_debug ("test-fullmode: Set properties, next running mainloop until connectivity checks succeed...");

  /* step: run the mainloop until connectivity checks succeed
   *       (see timer_cb() above) */
  g_main_loop_run (global_mainloop);

  /* When using TURN, we get peer reflexive candidates for the host cands
     that we removed so we can get another new_selected_pair signal later
     depending on timing/racing, we could double (or not) the amount we expected
  */
#if !(USE_TURN)
  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands == 1);
  g_assert (global_ragent_cands == 1);
#endif

  g_debug ("test-fullmode: Ran mainloop, removing streams...");

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
  const char *stun_server = NULL, *stun_server_port = NULL;

#ifdef G_OS_WIN32
  WSADATA w;

  WSAStartup(0x0202, &w);
#endif
  g_type_init ();
  g_thread_init(NULL);

  global_mainloop = g_main_loop_new (NULL, FALSE);

  /* Note: impl limits ...
   * - no multi-stream support
   * - no IPv6 support
   */

  /* step: create the agents L and R */
#if USE_RELIABLE
  lagent = nice_agent_new_reliable (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY);
  ragent = nice_agent_new_reliable (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY);
#else
  lagent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY);
  ragent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY);
#endif

  g_object_set (G_OBJECT (lagent), "ice-tcp", FALSE,  NULL);
  g_object_set (G_OBJECT (ragent), "ice-tcp", FALSE,  NULL);


  nice_agent_set_software (lagent, "Test-fullmode, Left Agent");
  nice_agent_set_software (ragent, "Test-fullmode, Right Agent");

  /* step: add a timer to catch state changes triggered by signals */
#if USE_TURN
  timer_id = g_timeout_add (300000, timer_cb, NULL);
#else
  timer_id = g_timeout_add (30000, timer_cb, NULL);
#endif

  /* step: specify which local interface to use */
#if USE_LOOPBACK
  if (!nice_address_set_from_string (&baseaddr, "127.0.0.1"))
    g_assert_not_reached ();
  nice_agent_add_local_address (lagent, &baseaddr);
  nice_agent_add_local_address (ragent, &baseaddr);
#endif

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

  stun_server = getenv ("NICE_STUN_SERVER");
  stun_server_port = getenv ("NICE_STUN_SERVER_PORT");
  if (stun_server) {
    g_object_set (G_OBJECT (lagent), "stun-server", stun_server,  NULL);
    g_object_set (G_OBJECT (lagent), "stun-server-port", atoi (stun_server_port),  NULL);
    g_object_set (G_OBJECT (ragent), "stun-server", stun_server,  NULL);
    g_object_set (G_OBJECT (ragent), "stun-server-port", atoi (stun_server_port),  NULL);
  }

  g_object_set (G_OBJECT (lagent), "upnp", USE_UPNP,  NULL);
  g_object_set (G_OBJECT (lagent), "proxy-ip", PROXY_IP,  NULL);
  g_object_set (G_OBJECT (lagent), "proxy-port", PROXY_PORT, NULL);
  g_object_set (G_OBJECT (lagent), "proxy-type", PROXY_TYPE, NULL);
  g_object_set (G_OBJECT (lagent), "proxy-username", PROXY_USERNAME, NULL);
  g_object_set (G_OBJECT (lagent), "proxy-password", PROXY_PASSWORD, NULL);
  g_object_set (G_OBJECT (ragent), "upnp", USE_UPNP,  NULL);
  g_object_set (G_OBJECT (ragent), "proxy-ip", PROXY_IP,  NULL);
  g_object_set (G_OBJECT (ragent), "proxy-port", PROXY_PORT, NULL);
  g_object_set (G_OBJECT (ragent), "proxy-type", PROXY_TYPE, NULL);
  g_object_set (G_OBJECT (ragent), "proxy-username", PROXY_USERNAME, NULL);
  g_object_set (G_OBJECT (ragent), "proxy-password", PROXY_PASSWORD, NULL);

  /* step: test setter/getter functions for properties */
  {
    guint max_checks = 0;
    gchar *string = NULL;
    guint port = 0;
    gboolean mode = FALSE;
    g_object_get (G_OBJECT (lagent), "stun-server", &string, NULL);
    g_assert (stun_server == NULL || strcmp (string, stun_server) == 0);
    g_free (string);
    g_object_get (G_OBJECT (lagent), "stun-server-port", &port, NULL);
    g_assert (stun_server_port == NULL || port == (guint)atoi (stun_server_port));
    g_object_get (G_OBJECT (lagent), "proxy-ip", &string, NULL);
    g_assert (strcmp (string, PROXY_IP) == 0);
    g_free (string);
    g_object_get (G_OBJECT (lagent), "proxy-port", &port, NULL);
    g_assert (port == PROXY_PORT);
    g_object_get (G_OBJECT (lagent), "controlling-mode", &mode, NULL);
    g_assert (mode == TRUE);
    g_object_set (G_OBJECT (lagent), "max-connectivity-checks", 300, NULL);
    g_object_get (G_OBJECT (lagent), "max-connectivity-checks", &max_checks, NULL);
    g_assert (max_checks == 300);
  }

  /* step: run test the first time */
  g_debug ("test-fullmode: TEST STARTS / running test for the 1st time");
  result = run_full_test (lagent, ragent, &baseaddr, 4 ,0);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
  /* When using TURN, we get peer reflexive candidates for the host cands
     that we removed so we can get another new_selected_pair signal later
     depending on timing/racing, we could double (or not) the amount we expected
  */
#if !(USE_TURN)
  /* note: verify that correct number of local candidates were reported */
    g_assert (global_lagent_cands == 2);
    g_assert (global_ragent_cands == 2);
#endif


  /* step: run test again without unref'ing agents */
  g_debug ("test-fullmode: TEST STARTS / running test for the 2nd time");
  result = run_full_test (lagent, ragent, &baseaddr, 4, 0);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
  /* When using TURN, we get peer reflexive candidates for the host cands
     that we removed so we can get another new_selected_pair signal later
     depending on timing/racing, we could double (or not) the amount we expected
  */
#if !(USE_TURN)
  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands == 2);
  g_assert (global_ragent_cands == 2);
#endif


  /* step: run test simulating delayed SDP answer */
  g_debug ("test-fullmode: TEST STARTS / delayed SDP answer");
  result = run_full_test_delayed_answer (lagent, ragent, &baseaddr, 4, 0);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
  /* note: verify that correct number of local candidates were reported */
  /* When using TURN, we get peer reflexive candidates for the host cands
     that we removed so we can get another new_selected_pair signal later
     depending on timing/racing, we could double (or not) the amount we expected
  */
#if !(USE_TURN)
  g_assert (global_lagent_cands == 2);
  g_assert (global_ragent_cands == 2);
#endif

#if TEST_GOOGLE
  return result;
#endif

  /* run test with incorrect credentials (make sure process fails) */
  g_debug ("test-fullmode: TEST STARTS / incorrect credentials");
  result = run_full_test_wrong_password (lagent, ragent, &baseaddr);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_FAILED);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_LAST);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_FAILED);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_LAST);

  /* The max connectivity checks test can't be run with TURN because
     we'll have 3 local candidates instead of 1 and the checks will
     be random, so we can't predict how many will fail/succeed */
#if USE_TURN == 0

  /* step: run test with a hard limit for connecitivity checks */
  g_debug ("test-fullmode: TEST STARTS / max connectivity checks");
  g_object_set (G_OBJECT (lagent), "max-connectivity-checks", 1, NULL);
  g_object_set (G_OBJECT (ragent), "max-connectivity-checks", 1, NULL);
  result = run_full_test (lagent, ragent, &baseaddr, 2, 2);
  priv_print_global_status ();
  g_assert (result == 0);
  /* should FAIL as agent L can't send any checks: */
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_FAILED ||
	    global_lagent_state[1] == NICE_COMPONENT_STATE_FAILED);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_FAILED ||
	    global_lagent_state[1] == NICE_COMPONENT_STATE_FAILED);
#endif

  g_object_set (G_OBJECT (lagent), "max-connectivity-checks", 100, NULL);
  g_object_set (G_OBJECT (ragent), "max-connectivity-checks", 100, NULL);
  result = run_full_test (lagent, ragent, &baseaddr, 4, 0);
  priv_print_global_status ();
  /* should SUCCEED as agent L can send the checks: */
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_CONNECTED ||
      global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_CONNECTED ||
      global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_CONNECTED ||
      global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_CONNECTED ||
      global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
  g_object_set (G_OBJECT (lagent), "max-connectivity-checks", 100, NULL);

  /* run test with a conflict in controlling mode: controlling-controlling */
  g_debug ("test-fullmode: TEST STARTS / controlling mode conflict case-1");
  result = run_full_test_control_conflict (lagent, ragent, &baseaddr, TRUE);
  priv_print_global_status ();
  g_assert (result == 0);

  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);

  /* run test with a conflict in controlling mode: controlled-controlled */
  g_debug ("test-fullmode: TEST STARTS / controlling mode conflict case-2");
  result = run_full_test_control_conflict (lagent, ragent, &baseaddr, FALSE);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);

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
