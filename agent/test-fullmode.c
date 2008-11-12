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
#define TEST_GOOGLE 0

#if TEST_GOOGLE
#define NICE_COMPATIBILITY NICE_COMPATIBILITY_GOOGLE

#if USE_TURN
#undef USE_LOOPBACK
#define USE_LOOPBACK 0

#define TURN_IP "209.85.163.126"
#define TURN_PORT 19295
#define TURN_USER "ih9ppiM0P6vN34DB"
#define TURN_PASS ""
#define TURN_USER2 TURN_USER
#define TURN_PASS2 TURN_PASS
#define TURN_TYPE NICE_RELAY_TYPE_TURN_UDP

#endif

#else
#define NICE_COMPATIBILITY NICE_COMPATIBILITY_DRAFT19
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
#define TURN_TYPE NICE_RELAY_TYPE_TURN_UDP
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

  if ((int)user_data == 2) {
    global_ragent_read = len;
    g_main_loop_quit (global_mainloop);
  }
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-fullmode:%s: %p", G_STRFUNC, data);

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

static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  g_debug ("test-fullmode:%s: %p", __func__, data);

  if ((int)data == 1)
    global_lagent_state[component_id - 1] = state;
  else if ((int)data == 2)
    global_ragent_state[component_id - 1] = state;
  
  if (state == NICE_COMPONENT_STATE_READY)
    global_components_ready++;
  if (state == NICE_COMPONENT_STATE_FAILED)
    global_components_failed++;

  g_debug ("test-fullmode: checks READY/EXIT-AT %u/%u.", global_components_ready, global_components_ready_exit);
  g_debug ("test-fullmode: checks FAILED/EXIT-AT %u/%u.", global_components_failed, global_components_failed_exit);

  /* signal status via a global variable */
  if (global_components_ready == global_components_ready_exit &&
      global_components_failed == global_components_failed_exit) {
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
  g_debug ("test-fullmode:%s: %p", __func__, data);

  if ((int)data == 1)
    ++global_lagent_cands;
  else if ((int)data == 2)
    ++global_ragent_cands;

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)component_id; (void)lfoundation; (void)rfoundation;
}

static void cb_new_candidate(NiceAgent *agent, guint stream_id, guint component_id, 
			     gchar *foundation, gpointer data)
{
  g_debug ("test-fullmode:%s: %p", __func__, data);

  /* XXX: dear compiler, these are for you: */
  (void)agent; (void)stream_id; (void)data; (void)component_id; (void)foundation;
}

static void cb_initial_binding_request_received(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-fullmode:%s: %p", __func__, data);

  if ((int)data == 1)
    global_lagent_ibr_received = TRUE;
  else if ((int)data == 2)
    global_ragent_ibr_received = TRUE;

  if (global_exit_when_ibr_received)
    g_main_loop_quit (global_mainloop);     

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


static GSList *priv_get_local_candidate (NiceAgent *agent, guint stream_id, guint component_id)
{
  GSList *cands, *i;
  GSList *result = NULL;
  NiceCandidate *out_cand = NULL;
  cands = nice_agent_get_local_candidates(agent, stream_id, component_id);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      out_cand = cand;
    }
  }
  g_slist_free (cands);
  result = g_slist_append (result, out_cand);
  return result;
}



static void init_candidate (NiceCandidate *cand)
{
  memset (cand, 0, sizeof(NiceCandidate));

  cand->priority = 10000;
  strcpy (cand->foundation, "1");
  cand->type = NICE_CANDIDATE_TYPE_HOST;
  cand->transport = NICE_CANDIDATE_TRANSPORT_UDP;
}

static int run_full_test (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr, guint ready, guint failed)
{
  //  NiceAddress laddr, raddr, laddr_rtcp, raddr_rtcp;   
  NiceCandidate cdes;
  GSList *cands;
  guint ls_id, rs_id;

  init_candidate (&cdes);

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


  nice_agent_gather_candidates (lagent, ls_id);
  nice_agent_gather_candidates (ragent, rs_id);

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)1);
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)1);
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)2);
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)2);

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

  /* priv_get_local_addr (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, &raddr);
  g_debug ("test-fullmode: local RTP port R %u",
           nice_address_get_port (&raddr));

  priv_get_local_addr (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, &laddr);
  g_debug ("test-fullmode: local RTP port L %u",
           nice_address_get_port (&laddr));

  priv_get_local_addr (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, &raddr_rtcp);
  g_debug ("test-fullmode: local RTCP port R %u",
           nice_address_get_port (&raddr_rtcp));

  priv_get_local_addr (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, &laddr_rtcp);
  g_debug ("test-fullmode: local RTCP port L %u",
  nice_address_get_port (&laddr_rtcp));*/

  /* step: pass the remote candidates to agents  */
  //cands = g_slist_append (NULL, &cdes);
  {
      const gchar *ufrag = NULL, *password = NULL;
      nice_agent_get_local_credentials(lagent, ls_id, &ufrag, &password);
      nice_agent_set_remote_credentials (ragent,
					 rs_id, ufrag, password);
      nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
      nice_agent_set_remote_credentials (lagent,
					 ls_id, ufrag, password);
  }
  /*  cdes.component_id = NICE_COMPONENT_TYPE_RTP;
  cdes.addr = raddr;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.addr = laddr;
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.component_id = NICE_COMPONENT_TYPE_RTCP;
  cdes.addr = raddr_rtcp;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, cands);
  cdes.addr = laddr_rtcp;
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, cands);

  g_slist_free (cands);*/
  cands = priv_get_local_candidate (ragent, rs_id, NICE_COMPONENT_TYPE_RTP);
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  g_slist_free (cands);
  cands = priv_get_local_candidate (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP);
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, cands);
  g_slist_free (cands);
  cands = priv_get_local_candidate (lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, cands);
  g_slist_free (cands);
  cands = priv_get_local_candidate (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP);
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, cands);
  g_slist_free (cands);

  g_debug ("test-fullmode: Set properties, next running mainloop until connectivity checks succeed...");

  /* step: run the mainloop until connectivity checks succeed
   *       (see timer_cb() above) */
  g_main_loop_run (global_mainloop);

  /* note: verify that STUN binding requests were sent */
  g_assert (global_lagent_ibr_received == TRUE);
  g_assert (global_ragent_ibr_received == TRUE);

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

/**
 * Simulate the case where answer to the offer is delayed and
 * some STUN connectivity checks reach the offering party
 * before it gets the remote SDP information.
 */
static int run_full_test_delayed_answer (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr, guint ready, guint failed)
{
  NiceAddress laddr, raddr, laddr_rtcp, raddr_rtcp;   
  NiceCandidate cdes;
  GSList *cands;
  guint ls_id, rs_id;

  init_candidate (&cdes);

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
#if USE_TURN
  nice_agent_set_relay_info(lagent, ls_id, 1,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
  nice_agent_set_relay_info(lagent, ls_id, 2,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
  nice_agent_set_relay_info(ragent, rs_id, 1,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
  nice_agent_set_relay_info(ragent, rs_id, 2,
      TURN_IP, TURN_PORT, TURN_USER, TURN_PASS, TURN_TYPE);
#endif


  nice_agent_gather_candidates (lagent, ls_id);
  nice_agent_gather_candidates (ragent, rs_id);

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)1);
  nice_agent_attach_recv (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)1);
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)2);
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)2);

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
  g_debug ("test-fullmode: local RTP port R %u",
           nice_address_get_port (&raddr));

  priv_get_local_addr (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, &laddr);
  g_debug ("test-fullmode: local RTP port L %u",
           nice_address_get_port (&laddr));

  priv_get_local_addr (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, &raddr_rtcp);
  g_debug ("test-fullmode: local RTCP port R %u",
           nice_address_get_port (&raddr_rtcp));

  priv_get_local_addr (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, &laddr_rtcp);
  g_debug ("test-fullmode: local RTCP port L %u",
           nice_address_get_port (&laddr_rtcp));

  /* step: pass the remote candidates to agent R (answering party)  */
  {
      const gchar *ufrag = NULL, *password = NULL;
      nice_agent_get_local_credentials(lagent, ls_id, &ufrag, &password);
      nice_agent_set_remote_credentials (ragent,
					 rs_id, ufrag, password);
      nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
      nice_agent_set_remote_credentials (lagent,
					 ls_id, ufrag, password);
  }
  /* step: set remote candidates for agent R (answering party) */
  cands = g_slist_append (NULL, &cdes);
  cdes.component_id = NICE_COMPONENT_TYPE_RTP;
  cdes.addr = laddr;
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.component_id = NICE_COMPONENT_TYPE_RTCP;
  cdes.addr = laddr_rtcp;
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTCP, cands);

  g_debug ("test-fullmode: Set properties, next running mainloop until first check is received...");

  /* step: run the mainloop until first connectivity check receveid */
  g_main_loop_run (global_mainloop);
  global_exit_when_ibr_received = 0;

  /* note: verify that STUN binding requests were sent */
  g_assert (global_lagent_ibr_received == TRUE);

  g_debug ("test-fullmode: Delayed answer received, continuing processing..");

  /* step: pass the remote candidates to agent L (offering party)  */
  {
      const gchar *ufrag = NULL, *password = NULL;
      nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
      nice_agent_set_remote_credentials (lagent,
					 ls_id, ufrag, password);
      nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
      nice_agent_set_remote_credentials (lagent,
					 ls_id, ufrag, password);
  }

  /* step: pass remove candidates to agent L (offering party) */
  cdes.component_id = NICE_COMPONENT_TYPE_RTP;
  cdes.addr = raddr;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.component_id = NICE_COMPONENT_TYPE_RTCP;
  cdes.addr = raddr_rtcp;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTCP, cands);

  g_debug ("test-fullmode: Running mainloop until connectivity checks succeeed.");

  g_main_loop_run (global_mainloop);
  g_assert (global_ragent_ibr_received == TRUE);
  g_assert (global_components_failed == 0);

  /* note: test payload send and receive */
  global_ragent_read = 0;
  g_assert (nice_agent_send (lagent, ls_id, 1, 16, "1234567812345678") == 16);
  g_main_loop_run (global_mainloop);
  g_assert (global_ragent_read == 16);

  g_debug ("test-fullmode: Ran mainloop, removing streams...");

  /* step: clean up resources and exit */

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  g_slist_free (cands);

  return 0;
}

static int run_full_test_wrong_password (NiceAgent *lagent, NiceAgent *ragent, NiceAddress *baseaddr)
{
  NiceAddress laddr, raddr;   
  NiceCandidate cdes;
  GSList *cands, *i;
  guint ls_id, rs_id;

  init_candidate (&cdes);

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
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)1);
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)2);

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
      g_debug ("test-fullmode: local port L %u",
               nice_address_get_port (&cand->addr));
      laddr = cand->addr;
    }
  }
  g_slist_free (cands);

  cands = nice_agent_get_local_candidates(ragent, rs_id, NICE_COMPONENT_TYPE_RTP);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      g_debug ("test-fullmode: local port R %u",
               nice_address_get_port (&cand->addr));
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
  cdes.addr = raddr;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.addr = laddr;
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
  NiceCandidate cdes;
  GSList *cands, *i;
  guint ls_id, rs_id;

  init_candidate (&cdes);

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
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)1);
  nice_agent_attach_recv (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv, (gpointer)2);

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
      g_debug ("test-fullmode: local port L %u",
               nice_address_get_port (&cand->addr));
      laddr = cand->addr;
    }
  }
  g_slist_free (cands);

  cands = nice_agent_get_local_candidates(ragent, rs_id, NICE_COMPONENT_TYPE_RTP);
  for (i = cands; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (cand) {
      g_debug ("test-fullmode: local port R %u",
               nice_address_get_port (&cand->addr));
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
  cdes.addr = raddr;
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  cdes.addr = laddr;
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
  NiceAddress baseaddr;
  int result;
  guint timer_id;
  const char *stun_server = NULL, *stun_server_port = NULL;

  g_type_init ();
  g_thread_init (NULL);
  global_mainloop = g_main_loop_new (NULL, FALSE);

  /* Note: impl limits ...
   * - no multi-stream support
   * - no IPv6 support
   */

  /* step: create the agents L and R */
  lagent = nice_agent_new (g_main_loop_get_context (global_mainloop), NICE_COMPATIBILITY);
  ragent = nice_agent_new (g_main_loop_get_context (global_mainloop), NICE_COMPATIBILITY);

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
#else
  if (!nice_address_set_from_string (&baseaddr, "192.168.1.110"))
    g_assert_not_reached ();
  nice_agent_add_local_address (lagent, &baseaddr);
  nice_agent_add_local_address (ragent, &baseaddr);
#endif

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
  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands == 2);
  g_assert (global_ragent_cands == 2);


  /* step: run test again without unref'ing agents */
  g_debug ("test-fullmode: TEST STARTS / running test for the 2nd time");
  result = run_full_test (lagent, ragent, &baseaddr, 4, 0);
  priv_print_global_status ();
  g_assert (result == 0);
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
  /* note: verify that correct number of local candidates were reported */
  g_assert (global_lagent_cands == 2);
  g_assert (global_ragent_cands == 2);

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
  g_assert (global_lagent_cands == 2);
  g_assert (global_ragent_cands == 2);

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
  g_assert (global_lagent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_lagent_state[1] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[0] == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state[1] == NICE_COMPONENT_STATE_READY);
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

  return result;
}
