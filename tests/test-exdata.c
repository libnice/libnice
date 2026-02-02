/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2026 Collabora Ltd.
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

#include <gio/giptosmessage.h>
#include <netinet/ip.h>

static GMainLoop *global_mainloop = NULL;
static gboolean global_lagent_gathering_done = FALSE;
static gboolean global_ragent_gathering_done = FALSE;
static gboolean global_lagent_selected_pair = FALSE;
static gboolean global_ragent_selected_pair = FALSE;

static const gchar MSG_PAYLOAD[] = "tostest";
#define DSCP_VAL IPTOS_THROUGHPUT
#define ECN_VAL G_ECN_ECT_CE

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, NiceMessageExtraData *exdata, gpointer user_data)
{
  GIPTosMessage *msg;

  g_assert_cmpstr (MSG_PAYLOAD, ==, buf);

  g_assert_nonnull (exdata);
  msg = G_IP_TOS_MESSAGE (nice_message_extra_data_get_tos (exdata));
  g_assert_nonnull (msg);

  g_assert_cmpint (g_ip_tos_message_get_dscp (msg), ==, DSCP_VAL);
  g_assert_cmpint (g_ip_tos_message_get_ecn (msg), ==, ECN_VAL);

  g_clear_object (&msg);

  g_main_loop_quit (global_mainloop);
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-exdata:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    global_lagent_gathering_done = TRUE;
  else if (GPOINTER_TO_UINT (data) == 2)
    global_ragent_gathering_done = TRUE;

  if (global_lagent_gathering_done && global_ragent_gathering_done) {
    g_main_loop_quit (global_mainloop);
  }
}

static void cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, 
                 gchar *lfoundation, gchar* rfoundation, gpointer data)
{
  g_debug ("test-exdata:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    global_lagent_selected_pair = TRUE;
  else if (GPOINTER_TO_UINT (data) == 2)
    global_ragent_selected_pair = TRUE;

  if (global_lagent_selected_pair && global_ragent_selected_pair) {
    g_main_loop_quit (global_mainloop);
  }
}

int main (void)
{
  NiceAgent *lagent, *ragent;
  NiceAddress baseaddr;
  GSList *cands;
  GError *error = NULL;
  guint ls_id, rs_id;

  GOutputVector vec = {
    MSG_PAYLOAD, sizeof (MSG_PAYLOAD)
  };
  NiceOutputMessage omsg = { &vec, 1 };

  global_mainloop = g_main_loop_new (NULL, FALSE);

  lagent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_RFC5245);
  ragent = nice_agent_new_full (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_RFC5245, NICE_AGENT_OPTION_RECV_TOS);

  if (!nice_address_set_from_string (&baseaddr, "127.0.0.1")) {
    g_assert_not_reached ();
  }
  nice_agent_add_local_address (lagent, &baseaddr);
  nice_agent_add_local_address (ragent, &baseaddr);

  g_signal_connect (G_OBJECT (lagent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), GUINT_TO_POINTER(1));
  g_signal_connect (G_OBJECT (ragent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), GUINT_TO_POINTER (2));
  g_signal_connect (G_OBJECT (lagent), "new-selected-pair",
      G_CALLBACK (cb_new_selected_pair), GUINT_TO_POINTER(1));
  g_signal_connect (G_OBJECT (ragent), "new-selected-pair",
      G_CALLBACK (cb_new_selected_pair), GUINT_TO_POINTER (2));

  g_debug ("test-tos: running test");

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  /* An application using more than one NiceAgent instance may crash due to
   * a race in gUPnP.
   *
   * UPnP can be re-enabled here and in other libnice tests once gUPnP
   * 1.1.2 / 1.0.4 is released.
   *
   * See https://gitlab.gnome.org/GNOME/gupnp/commit/0123e574595e0a547ce26422633df72d63d3d0e0
   */
  g_object_set (G_OBJECT (lagent), "upnp", FALSE, NULL);
  g_object_set (G_OBJECT (ragent), "upnp", FALSE, NULL);

  ls_id = nice_agent_add_stream (lagent, 1);
  g_assert_cmpuint (ls_id, >, 0);

  rs_id = nice_agent_add_stream (ragent, 1);
  g_assert_cmpuint (rs_id, >, 0);

  nice_agent_gather_candidates (lagent, ls_id);
  nice_agent_gather_candidates (ragent, rs_id);

  /* step: attach to mainloop (needed to register the fds) */
  nice_agent_attach_recv_ex (lagent, ls_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (1), NULL);
  nice_agent_attach_recv_ex (ragent, rs_id, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (global_mainloop), cb_nice_recv,
      GUINT_TO_POINTER (2), NULL);

  if (global_lagent_gathering_done != TRUE || global_ragent_gathering_done != TRUE) {
    g_debug ("test-exdata: Added streams, running mainloop until 'candidate-gathering-done'...");
    g_main_loop_run (global_mainloop);
    g_assert_true (global_lagent_gathering_done == TRUE);
    g_assert_true (global_ragent_gathering_done == TRUE);
  }

  {
    gchar *ufrag = NULL, *password = NULL;
    nice_agent_get_local_credentials(lagent, ls_id, &ufrag, &password);
    nice_agent_set_remote_credentials (ragent,
        rs_id, ufrag, password);
    g_free (ufrag);
    g_free (password);
    nice_agent_get_local_credentials(ragent, rs_id, &ufrag, &password);
    nice_agent_set_remote_credentials (lagent,
        ls_id, ufrag, password);
    g_free (ufrag);
    g_free (password);
  }
  cands = nice_agent_get_local_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP);
  nice_agent_set_remote_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, cands);
  g_slist_free_full (cands, (GDestroyNotify) nice_candidate_free);

  cands = nice_agent_get_local_candidates (lagent, ls_id, NICE_COMPONENT_TYPE_RTP);
  nice_agent_set_remote_candidates (ragent, rs_id, NICE_COMPONENT_TYPE_RTP, cands);
  g_slist_free_full (cands, (GDestroyNotify) nice_candidate_free);

  g_main_loop_run (global_mainloop);  

  nice_agent_set_stream_tos (lagent, ls_id, (DSCP_VAL << 2) | ECN_VAL);
  nice_agent_send_messages_nonblocking (lagent, ls_id, NICE_COMPONENT_TYPE_RTP, &omsg, 1, NULL, &error);
  g_assert_no_error (error);
  g_main_loop_run (global_mainloop);

  g_debug ("test-exdata: Ran mainloop, removing streams...");

  nice_agent_remove_stream (lagent, ls_id);
  nice_agent_remove_stream (ragent, rs_id);

  g_clear_object (&lagent);
  g_clear_object (&ragent);

  g_clear_pointer (&global_mainloop, g_main_loop_unref);

  return 0;
}
