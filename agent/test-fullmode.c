/*
 * This file is part of the Nice GLib ICE library.
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

#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "udp-bsd.h"

static NiceComponentState global_lagent_state = NICE_COMPONENT_STATE_LAST;
static NiceComponentState global_ragent_state = NICE_COMPONENT_STATE_LAST;
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

static void priv_print_global_status (void)
{
  g_debug ("\tgathering_done=%d", global_lagent_gathering_done && global_ragent_gathering_done);
  g_debug ("\tlstate=%d", global_lagent_state);
  g_debug ("\trstate=%d", global_ragent_state);
}

static gboolean timer_cb (gpointer pointer)
{
  g_debug ("%s: %p", G_STRFUNC, pointer);

  /* signal status via a global variable */

  /* note: should not be reached, abort */
  g_debug ("ERROR: test has got stuck, aborting...");
  exit (-1);

}

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  g_debug ("%s: %p", G_STRFUNC, user_data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)component_id; (void)buf;

  if ((int)user_data == 2) {
    global_ragent_read = len;
    g_main_loop_quit (global_mainloop);
  }
}

static void cb_candidate_gathering_done(NiceAgent *agent, gpointer data)
{
  g_debug ("%s: %p", G_STRFUNC, data);

  if ((int)data == 1)
    global_lagent_gathering_done = TRUE;
  else if ((int)data == 2)
    global_ragent_gathering_done = TRUE;

  if (global_lagent_gathering_done &&
      global_ragent_gathering_done)
    g_main_loop_quit (global_mainloop);

  /* XXX: dear compiler, these are for you: */
  (void)agent;
}

#if 0
static void cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  g_debug ("%s: %p", __func__, data);

  if ((int)data == 1)
    global_lagent_state = state;
  else if ((int)data == 2)
    global_ragent_state = state;

  /* signal status via a global variable */
  if (global_lagent_state == NICE_COMPONENT_STATE_READY &&
      global_ragent_state == NICE_COMPONENT_STATE_READY) {
    g_main_loop_quit (global_mainloop); 
    return;
  }

  /* signal status via a global variable */
  if (global_lagent_state == NICE_COMPONENT_STATE_FAILED &&
      global_ragent_state == NICE_COMPONENT_STATE_FAILED) {
    g_main_loop_quit (global_mainloop); 
    return;
  }

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data;
}
#endif

static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  g_debug ("%s: %p", __func__, data);

  if ((int)data == 1)
    global_lagent_state = state;
  else if ((int)data == 2)
    global_ragent_state = state;
  
  if (state == NICE_COMPONENT_STATE_READY)
    global_components_ready++;
  if (state == NICE_COMPONENT_STATE_FAILED)
    global_components_failed++;

  g_debug ("READY %u exit at %u.", global_components_ready, global_components_ready_exit);

  /* signal status via a global variable */
  if (global_components_ready == global_components_ready_exit) {
    g_main_loop_quit (global_mainloop); 
    return;
  }

  /* signal status via a global variable */
  if (global_components_failed == global_components_failed_exit) {
    g_main_loop_quit (global_mainloop); 
    return;
  }

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data; (void)component_id;
}

static void cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, 
				 gchar *lfoundation, gchar* rfoundation, gpointer data)
{
  g_debug ("%s: %p", __func__, data);

  if ((int)data == 1)
    ++global_lagent_cands;
  else if ((int)data == 2)
    ++global_ragent_cands;

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)component_id;
}

static void cb_new_candidate(NiceAgent *agent, guint stream_id, guint component_id, 
			     gchar *foundation, gpointer data)
{
  g_debug ("%s: %p", __func__, data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data; (void)component_id;
}

static void cb_initial_binding_request_received(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("%s: %p", __func__, data);

  if ((int)data == 1)
    global_lagent_ibr_received = TRUE;
  else if ((int)data == 2)
    global_ragent_ibr_received = TRUE;

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data;
}

static void priv_get_local_addr (NiceAgent *agent, guint stream_id, guint component_id, NiceAddress *dstaddr)
{
  GSList *cands, *i;
  cands = nice_agent_get_local_candidates(agent, stream_id, component_id);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      g_assert (dstaddr);
      *dstaddr = cand->addr;
    }
  }
  g_slist_free (cands);
}

static int run_full_test (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr)
{
  NiceAddress laddr, raddr, laddr_rtcp, raddr_rtcp;   
  NiceCandidateDesc cdes = {       /* candidate description (no ports) */
    (gchar *)"1",                  /* foundation */
    0,                             /* component-id; filled later */
    NICE_CANDIDATE_TRANSPORT_UDP,  /* transport */
    100000,  /* priority */
    NULL,    /* address */
    NICE_CANDIDATE_TYPE_HOST, /* type */ 
    NULL     /* base-address */
  };
  GSList *cands;
  guint ls_id, rs_id;

  /* step: initialize variables modified by the callbacks */
  global_components_ready = 0;
  global_components_ready_exit = 4;
  global_components_failed = 0;
  global_components_failed_exit = 4;
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

  /* step: run mainloop until local candidates are ready 
   *       (see timer_cb() above) */
  if (global_lagent_gathering_done != TRUE ||
      global_ragent_gathering_done != TRUE) {
    g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  /* step: find out the local candidates of each agent */

  priv_get_local_addr (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, &raddr);
  g_debug ("test-fullmode: local RTP port R %u", raddr.port);

  priv_get_local_addr (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, &laddr);
  g_debug ("test-fullmode: local RTP port L %u", laddr.port);

  priv_get_local_addr (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, &raddr_rtcp);
  g_debug ("test-fullmode: local RTCP port R %u", raddr_rtcp.port);

  priv_get_local_addr (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, &laddr_rtcp);
  g_debug ("test-fullmode: local RTCP port L %u", laddr_rtcp.port);

  g_debug ("test-fullmode: Got local candidates...");
 
  /* step: pass the remote candidates to agents  */
  cands = g_slist_append (NULL, &cdes);
  {
      const gchar *ufrag = NULL, *password = NULL;
      nice_agent_get_local_credentials(lagent, ls_id, &ufrag, &password);
      nice_agent_set_remote_credentials (ragent,
					 rs_id, ufrag, password);
      nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
      nice_agent_set_remote_credentials (lagent,
					 ls_id, ufrag, password);
  }
  cdes.component_id = NICE_COMPONENT_TYPE_RTP;
  cdes.addr = &raddr;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.addr = &laddr;  
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.component_id = NICE_COMPONENT_TYPE_RTCP;
  cdes.addr = &raddr_rtcp;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, cands);
  cdes.addr = &laddr_rtcp;  
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, cands);

  g_slist_free (cands);

  g_debug ("test-fullmode: Set properties, next running mainloop until connectivity checks succeed...");

  /* step: run the mainloop until connectivity checks succeed 
   *       (see timer_cb() above) */
  g_main_loop_run (global_mainloop);

  /* note: verify that STUN binding requests were sent */
  g_assert (global_lagent_ibr_received == TRUE);
  g_assert (global_ragent_ibr_received == TRUE);

  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands == 2);
  g_assert (global_ragent_cands == 2);

  /* note: test payload send and receive */
  global_ragent_read = 0;
  g_assert (nice_agent_send (lagent, ls_id, 1, 16, "1234567812345678") == 16);
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
  NiceAddress laddr, raddr;   
  NiceCandidateDesc cdes = {       /* candidate description (no ports) */
    (gchar *)"1",                  /* foundation */
    NICE_COMPONENT_TYPE_RTP,
    NICE_CANDIDATE_TRANSPORT_UDP,  /* transport */
    100000,  /* priority */
    NULL,    /* address */
    NICE_CANDIDATE_TYPE_HOST, /* type */ 
    NULL     /* base-address */
  };
  GSList *cands, *i;
  guint ls_id, rs_id;

  global_components_ready = 0;
  global_components_ready_exit = 2;
  global_components_failed = 0;
  global_components_failed_exit = 2;
  global_lagent_state = 
    global_ragent_state = NICE_COMPONENT_STATE_LAST;
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

  /* step: run mainloop until local candidates are ready 
   *       (see timer_cb() above) */
  if (global_lagent_gathering_done != TRUE ||
      global_ragent_gathering_done != TRUE) {
    g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  /* step: find out the local candidates of each agent */
  cands = nice_agent_get_local_candidates(lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      g_debug ("test-fullmode: local port L %u", cand->addr.port);
      laddr = cand->addr;
    }
  }
  g_slist_free (cands);

  cands = nice_agent_get_local_candidates(ragent, rs_id, NICE_COMPONENT_TYPE_RTP);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      g_debug ("test-fullmode: local port R %u", cand->addr.port);
      raddr = cand->addr;
    }
  }
  g_slist_free (cands);
  g_debug ("test-fullmode: Got local candidates...");
 
  /* step: pass the remote candidates to agents  */
  cands = g_slist_append (NULL, &cdes);
  {
      const gchar *ufrag = NULL, *password = NULL;
      nice_agent_get_local_credentials(lagent, ls_id, &ufrag, &password);
      nice_agent_set_remote_credentials (ragent,
					 rs_id, "wrong", password);
      nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
      nice_agent_set_remote_credentials (lagent,
					 ls_id, ufrag, "wrong2");
  }
  cdes.addr = &raddr;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.addr = &laddr;  
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, cands);
  g_slist_free (cands);

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
  NiceAddress laddr, raddr;   
  NiceCandidateDesc cdes = {       /* candidate description (no ports) */
    (gchar *)"1",                  /* foundation */
    NICE_COMPONENT_TYPE_RTP,
    NICE_CANDIDATE_TRANSPORT_UDP,  /* transport */
    100000,  /* priority */
    NULL,    /* address */
    NICE_CANDIDATE_TYPE_HOST, /* type */ 
    NULL     /* base-address */
  };
  GSList *cands, *i;
  guint ls_id, rs_id;

  global_components_ready = 0;
  global_components_ready_exit = 2;
  global_components_failed = 0;
  global_components_failed_exit = 2;
  global_lagent_state =
    global_ragent_state = NICE_COMPONENT_STATE_LAST;
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

  /* step: run mainloop until local candidates are ready 
   *       (see timer_cb() above) */
  if (global_lagent_gathering_done != TRUE ||
      global_ragent_gathering_done != TRUE) {
    g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert (global_lagent_gathering_done == TRUE);
    g_assert (global_ragent_gathering_done == TRUE);
  }

  /* step: find out the local candidates of each agent */
  cands = nice_agent_get_local_candidates(lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      g_debug ("test-fullmode: local port L %u", cand->addr.port);
      laddr = cand->addr;
    }
  }
  g_slist_free (cands);

  cands = nice_agent_get_local_candidates(ragent, rs_id, NICE_COMPONENT_TYPE_RTP);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      g_debug ("test-fullmode: local port R %u", cand->addr.port);
      raddr = cand->addr;
    }
  }
  g_slist_free (cands);
  g_debug ("test-fullmode: Got local candidates...");
 
  /* step: pass the remote candidates to agents  */
  cands = g_slist_append (NULL, &cdes);
  {
      const gchar *ufrag = NULL, *password = NULL;
      nice_agent_get_local_credentials(lagent, ls_id, &ufrag, &password);
      nice_agent_set_remote_credentials (ragent,
					 rs_id, ufrag, password);
      nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
      nice_agent_set_remote_credentials (lagent,
					 ls_id, ufrag, password);
  }
  cdes.addr = &raddr;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.addr = &laddr;  
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, cands);
  g_slist_free (cands);

  g_debug ("test-fullmode: Set properties, next running mainloop until connectivity checks succeed...");

  /* step: run the mainloop until connectivity checks succeed 
   *       (see timer_cb() above) */
  g_main_loop_run (global_mainloop);

  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands == 1);
  g_assert (global_ragent_cands == 1);

  g_debug ("test-fullmode: Ran mainloop, removing streams...");

  /* step: clean up resources and exit */

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  return 0;
}

int main (void)
{
  NiceAgent *lagent, *ragent;      /* agent's L and R */
  NiceUDPSocketFactory udpfactory;
  NiceAddress baseaddr;
  int result;
  guint timer_id;
  const char *stun_server = NULL, *stun_server_port = NULL;

  g_type_init ();
  global_mainloop = g_main_loop_new (NULL, FALSE);

  /* Note: impl limits ...
   * - no multi-stream support
   * - no IPv6 support
   */

  nice_udp_bsd_socket_factory_init (&udpfactory);

  /* step: create the agents L and R */
  lagent = nice_agent_new (&udpfactory);
  ragent = nice_agent_new (&udpfactory);

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_main_context_attach (lagent, g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)1);
  nice_agent_main_context_attach (ragent, g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)2);

  /* step: add a timer to catch state changes triggered by signals */
  timer_id = g_timeout_add (30000, timer_cb, NULL);

  /* step: specify which local interface to use */
  if (!nice_address_set_ipv4_from_string (&baseaddr, "127.0.0.1"))
    g_assert_not_reached ();
  nice_agent_add_local_address (lagent, &baseaddr);
  nice_agent_add_local_address (ragent, &baseaddr);

  g_signal_connect (G_OBJECT (lagent), "candidate-gathering-done", 
		    G_CALLBACK (cb_candidate_gathering_done), (gpointer)1);
  g_signal_connect (G_OBJECT (ragent), "candidate-gathering-done", 
		    G_CALLBACK (cb_candidate_gathering_done), (gpointer)2);
  g_signal_connect (G_OBJECT (lagent), "component-state-changed", 
		    G_CALLBACK (cb_component_state_changed), (gpointer)1);
  g_signal_connect (G_OBJECT (ragent), "component-state-changed", 
		    G_CALLBACK (cb_component_state_changed), (gpointer)2);
  g_signal_connect (G_OBJECT (lagent), "new-selected-pair", 
		    G_CALLBACK (cb_new_selected_pair), (gpointer)1);
  g_signal_connect (G_OBJECT (ragent), "new-selected-pair", 
		    G_CALLBACK (cb_new_selected_pair), (gpointer)2);
  g_signal_connect (G_OBJECT (lagent), "new-candidate", 
		    G_CALLBACK (cb_new_candidate), (gpointer)1);
  g_signal_connect (G_OBJECT (ragent), "new-candidate", 
		    G_CALLBACK (cb_new_candidate), (gpointer)2);
  g_signal_connect (G_OBJECT (lagent), "initial-binding-request-received", 
		    G_CALLBACK (cb_initial_binding_request_received), (gpointer)1);
  g_signal_connect (G_OBJECT (ragent), "initial-binding-request-received", 
		    G_CALLBACK (cb_initial_binding_request_received), (gpointer)2);

  stun_server = getenv ("NICE_STUN_SERVER");
  stun_server_port = getenv ("NICE_STUN_SERVER_PORT");
  if (stun_server) {
    g_object_set (G_OBJECT (lagent), "stun-server", stun_server,  NULL);
    g_object_set (G_OBJECT (lagent), "stun-server-port", atoi (stun_server_port),  NULL);
    g_object_set (G_OBJECT (ragent), "stun-server", stun_server,  NULL);
    g_object_set (G_OBJECT (ragent), "stun-server-port", atoi (stun_server_port),  NULL);
  }

  {
    gpointer pointer;
    gchar *string = NULL;
    guint port = 0;
    gboolean mode = FALSE;
    g_object_get (G_OBJECT (lagent), "socket-factory", &pointer, NULL);
    g_assert (pointer == (gpointer)&udpfactory);
    g_object_get (G_OBJECT (lagent), "stun-server", &string, NULL);
    g_assert (stun_server == NULL || strcmp (string, stun_server) == 0);
    g_object_get (G_OBJECT (lagent), "stun-server-port", &port, NULL);
    g_assert (stun_server_port == NULL || port == (guint)atoi (stun_server_port));
    g_object_get (G_OBJECT (lagent), "turn-server", &string, NULL);
    g_object_get (G_OBJECT (lagent), "turn-server-port", &port, NULL);
    g_object_get (G_OBJECT (lagent), "controlling-mode", &mode, NULL);
    g_assert (mode == TRUE);
  }

  /* step: run test the first time */
  g_debug ("test-fullmode: TEST STARTS / running test for the 1st time");
  result = run_full_test (lagent, ragent, &baseaddr);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state == NICE_COMPONENT_STATE_READY);

  /* step: run test again without unref'ing agents */
  g_debug ("test-fullmode: TEST STARTS / running test for the 2nd time");
  result = run_full_test (lagent, ragent, &baseaddr);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state == NICE_COMPONENT_STATE_READY);

  /* run test with incorrect credentials (make sure process fails) */
  g_debug ("test-fullmode: TEST STARTS / incorrect credentials");
  result = run_full_test_wrong_password (lagent, ragent, &baseaddr);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_FAILED);
  g_assert (global_ragent_state == NICE_COMPONENT_STATE_FAILED);

  /* run test with a conflict in controlling mode: controlling-controlling */
  g_debug ("test-fullmode: TEST STARTS / controlling mode conflict case-1");
  result = run_full_test_control_conflict (lagent, ragent, &baseaddr, TRUE);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state == NICE_COMPONENT_STATE_READY);

  /* run test with a conflict in controlling mode: controlled-controlled */
  g_debug ("test-fullmode: TEST STARTS / controlling mode conflict case-2");
  result = run_full_test_control_conflict (lagent, ragent, &baseaddr, FALSE);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state == NICE_COMPONENT_STATE_READY);

  g_object_unref (lagent);
  g_object_unref (ragent);

  nice_udp_socket_factory_close (&udpfactory);

  g_main_loop_unref (global_mainloop),
    global_mainloop = NULL;

  g_source_remove (timer_id);

  return result;
}
