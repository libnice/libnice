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

#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "udp-bsd.h"

static const guint test_component_id = 1;

static NiceComponentState global_lagent_state = NICE_COMPONENT_STATE_LAST;
static NiceComponentState global_ragent_state = NICE_COMPONENT_STATE_LAST;
static GMainLoop *global_mainloop = NULL;
static gboolean global_candidate_gathering_done = FALSE;
static gboolean global_lagent_ibr_received = FALSE;
static gboolean global_ragent_ibr_received = FALSE;
static int global_lagent_cands = 0;
static int global_ragent_cands = 0;

static gboolean timer_cb (gpointer pointer)
{
  g_debug ("%s: %p", G_STRFUNC, pointer);

  /* signal status via a global variable */

  g_debug ("\tgathering_done=%d", global_candidate_gathering_done);
  g_debug ("\tlstate=%d", global_lagent_state);
  g_debug ("\trstate=%d", global_ragent_state);

  if (global_candidate_gathering_done != TRUE &&
      global_lagent_state == NICE_COMPONENT_STATE_GATHERING &&
      global_ragent_state == NICE_COMPONENT_STATE_GATHERING) {
    global_candidate_gathering_done = TRUE;
    g_main_loop_quit (global_mainloop);
    return TRUE;
  }
  /* signal status via a global variable */
  else if (global_candidate_gathering_done == TRUE &&
      global_lagent_state == NICE_COMPONENT_STATE_READY &&
      global_ragent_state == NICE_COMPONENT_STATE_READY) {
    g_main_loop_quit (global_mainloop); 
    return TRUE;
  }

  /* note: should not be reached, abort */
  g_debug ("ERROR: test has got stuck, aborting...");
  exit (-1);

}

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  g_debug ("%s: %p", G_STRFUNC, user_data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)component_id; (void)len; (void)buf;
  (void)user_data;
}

static void cb_candidate_gathering_done(NiceAgent *agent, gpointer data)
{
  g_debug ("%s: %p", G_STRFUNC, data);

  if ((int)data == 1)
    global_lagent_state = NICE_COMPONENT_STATE_GATHERING;
  else if ((int)data == 2)
    global_ragent_state = NICE_COMPONENT_STATE_GATHERING;

  /* XXX: dear compiler, these are for you: */
  (void)agent;
}

static void cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  g_debug ("%s: %p", __func__, data);

  g_assert (test_component_id == component_id);

  if ((int)data == 1)
    global_lagent_state = state;
  else if ((int)data == 2)
    global_ragent_state = state;

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data;
}

static void cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, 
				 gchar *lfoundation, gchar* rfoundation, gpointer data)
{
  g_debug ("%s: %p", __func__, data);
  g_assert (test_component_id == component_id);

  if ((int)data == 1)
    ++global_lagent_cands;
  else if ((int)data == 2)
    ++global_ragent_cands;

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id;
}

static void cb_new_candidate(NiceAgent *agent, guint stream_id, guint component_id, 
			     gchar *foundation, gpointer data)
{
  g_debug ("%s: %p", __func__, data);
  g_assert (test_component_id == component_id);
  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data;
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

static int run_full_test (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr)
{
  NiceAddress laddr, raddr;   
  NiceCandidateDesc cdes = {       /* candidate description (no ports) */
    "1",     /* foundation */
    test_component_id,
    NICE_CANDIDATE_TRANSPORT_UDP,  /* transport */
    100000,  /* priority */
    NULL,    /* address */
    NICE_CANDIDATE_TYPE_HOST, /* type */ 
    NULL     /* base-address */
  };
  GSList *cands, *i;
  guint ls_id, rs_id;

  /* step: add one stream, with one component, to each agent */
  ls_id = nice_agent_add_stream (lagent, 1);
  rs_id = nice_agent_add_stream (ragent, 1);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (lagent), "controlling-mode", FALSE, NULL);

  /* step: run mainloop until local candidates are ready 
   *       (see timer_cb() above) */
  g_debug ("test-fullmode: Added streams, running mainloop until 'candidate-gathering-done'...");
  g_main_loop_run (global_mainloop);
  g_assert (global_candidate_gathering_done == TRUE);

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

  /* note: verify that STUN binding requests were sent */
  g_assert (global_lagent_ibr_received == TRUE);
  g_assert (global_ragent_ibr_received == TRUE);

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
  nice_agent_main_context_attach (lagent, g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);
  nice_agent_main_context_attach (ragent, g_main_loop_get_context (global_mainloop), cb_nice_recv, NULL);

  /* step: add a timer to catch state changes triggered by signals */
  timer_id = g_timeout_add (2000, timer_cb, NULL);

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

  g_debug ("test-fullmode: running test for the 1st time");
  result = run_full_test (lagent, ragent, &baseaddr);

  /* step: check results of first run */
  g_assert (result == 0);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state == NICE_COMPONENT_STATE_READY);

  /* step: run test again without unref'ing agents */

  global_lagent_state = NICE_COMPONENT_STATE_LAST;
  global_ragent_state = NICE_COMPONENT_STATE_LAST;
  global_candidate_gathering_done = FALSE;
  global_lagent_ibr_received =
    global_ragent_ibr_received = FALSE;
  global_lagent_cands = 
    global_ragent_cands = 0;

  g_debug ("test-fullmode: running test the 2nd time");
  result = run_full_test (lagent, ragent, &baseaddr);

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
