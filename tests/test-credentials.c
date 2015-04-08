/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2015 Rohan Garg <rohan@garg.io>
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
 *   Dafydd Harries, Collabora Ltd.
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
#include "agent-priv.h"
#include <string.h>
#include <stdio.h>

#define LEFT_AGENT GINT_TO_POINTER(1)
#define RIGHT_AGENT GINT_TO_POINTER(2)
#define USE_UPNP 0

static GMainLoop *loop = NULL;

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  g_debug ("test-credentials:%s: %p", G_STRFUNC, user_data);
}

static void set_credentials(NiceAgent *lagent, NiceAgent *ragent)
{
  gchar *ufrag = NULL, *password = NULL;

  g_debug ("test-credentials:%s", G_STRFUNC);

  nice_agent_get_local_credentials (lagent, 1, &ufrag, &password);
  nice_agent_set_remote_credentials (ragent, 1, ufrag, password);

  g_free (ufrag);
  g_free (password);

  nice_agent_get_local_credentials (ragent, 1, &ufrag, &password);
  nice_agent_set_remote_credentials (lagent, 1, ufrag, password);

  g_free (ufrag);
  g_free (password);
}

static void swap_candidates(NiceAgent *local, guint local_id, NiceAgent *remote, guint remote_id)
{
  GSList *cands = NULL;

  g_debug ("test-credentials:%s", G_STRFUNC);
  cands = nice_agent_get_local_candidates(local, local_id,
                                          NICE_COMPONENT_TYPE_RTP);
  g_assert(nice_agent_set_remote_candidates(remote, remote_id,
                                            NICE_COMPONENT_TYPE_RTP, cands));

  g_slist_free_full (cands, (GDestroyNotify) nice_candidate_free);
}


static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  static gboolean L_CAND_DONE = false, R_CAND_DONE = false;
  static NiceAgent *lagent = NULL, *ragent = NULL;

  g_debug ("test-credentials:%s: %p", G_STRFUNC, data);
  if (GPOINTER_TO_UINT(data) == 1) {
    g_debug ("lagent finished gathering candidates");
    L_CAND_DONE = true;
    lagent = agent;
  } else if (GPOINTER_TO_UINT(data) == 2) {
    g_debug ("ragent finished gathering candidates");
    R_CAND_DONE = true;
    ragent = agent;
  }

  if (L_CAND_DONE && R_CAND_DONE) {
    set_credentials (lagent, ragent);
    swap_candidates (lagent, 1, ragent, 1);
    swap_candidates (ragent, 1, lagent, 1);
  }
}

static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  if (state == NICE_COMPONENT_STATE_READY) {
    g_main_loop_quit(loop);
  }
}

static void setup(NiceAgent *lagent, NiceAgent *ragent)
{
  NiceAddress addr;

  g_assert (nice_agent_add_stream (lagent, 1) == 1);
  g_assert (nice_agent_add_stream (ragent, 1) == 1);
  g_assert (NULL != lagent->streams);
  g_assert (NULL != ragent->streams);

  nice_address_init (&addr);
  g_assert (nice_address_set_from_string (&addr, "127.0.0.1"));
  nice_agent_add_local_address (lagent, &addr);
  nice_agent_add_local_address (ragent, &addr);

  nice_agent_attach_recv (lagent, 1, NICE_COMPONENT_TYPE_RTP,
                   g_main_context_default (),
                   cb_nice_recv, LEFT_AGENT);
  nice_agent_attach_recv (ragent, 1, NICE_COMPONENT_TYPE_RTP,
                   g_main_context_default (),
                   cb_nice_recv, RIGHT_AGENT);

  g_signal_connect(G_OBJECT(lagent), "candidate-gathering-done",
                   G_CALLBACK(cb_candidate_gathering_done), LEFT_AGENT);
  g_signal_connect(G_OBJECT(ragent), "candidate-gathering-done",
                   G_CALLBACK(cb_candidate_gathering_done), RIGHT_AGENT);

  g_signal_connect(G_OBJECT(lagent), "component-state-changed",
                  G_CALLBACK(cb_component_state_changed), LEFT_AGENT);

  g_object_set (G_OBJECT (lagent), "ice-tcp", FALSE,  NULL);
  g_object_set (G_OBJECT (ragent), "ice-tcp", FALSE,  NULL);

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  g_object_set (G_OBJECT (lagent), "upnp", USE_UPNP, NULL);
  g_object_set (G_OBJECT (ragent), "upnp", USE_UPNP, NULL);

  g_object_set_data (G_OBJECT (lagent), "other-agent", ragent);
  g_object_set_data (G_OBJECT (ragent), "other-agent", lagent);
}

static void teardown(NiceAgent *lagent, NiceAgent *ragent)
{
  nice_agent_remove_stream (lagent, 1);
  nice_agent_remove_stream (ragent, 1);
}

int main (void)
{
  NiceAgent *lagent = NULL, *ragent = NULL;
  gchar *ufrag = NULL, *password = NULL;

#ifdef G_OS_WIN32
  WSADATA w;
  WSAStartup(0x0202, &w);
#endif
  g_type_init ();
  g_thread_init (NULL);

  loop = g_main_loop_new (NULL, FALSE);

  lagent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);
  ragent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);

  setup (lagent, ragent);

  nice_agent_set_local_credentials (lagent, 1, "unicorns", "awesome");
  nice_agent_get_local_credentials (lagent, 1, &ufrag, &password);
  g_assert (g_strcmp0("unicorns", ufrag) == 0);
  g_assert (g_strcmp0("awesome", password) == 0);

  nice_agent_gather_candidates (lagent, 1);
  nice_agent_gather_candidates (ragent, 1);

  g_main_loop_run (loop);

  teardown (lagent, ragent);

  g_object_unref (lagent);
  g_object_unref (ragent);

#ifdef G_OS_WIN32
  WSACleanup();
#endif
  return 0;
}
