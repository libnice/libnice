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
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

GMainLoop *error_loop;

volatile gint global_lagent_cands = 0;
volatile gint global_ragent_cands = 0;

volatile gint global_lagent_buffers = 0;
volatile gint global_ragent_buffers = 0;

/* Waits about 10 seconds for @var to be NULL/FALSE */
#define WAIT_UNTIL_UNSET(var, context)			\
  if (var)						\
    {							\
      int _i;						\
							\
      for (_i = 0; _i < 13 && (var); _i++)		\
	{						\
	  g_usleep (1000 * (1 << _i));			\
	  g_main_context_iteration (context, FALSE);	\
	}						\
							\
      g_assert (!(var));				\
    }

static gboolean timer_cb (gpointer pointer)
{
  g_debug ("test-thread:%s: %p", G_STRFUNC, pointer);

  /* note: should not be reached, abort */
  g_debug ("ERROR: test has got stuck, aborting...");
  exit (-1);

}

static gpointer
mainloop_thread (gpointer data)
{
  GMainLoop *loop = data;

  /* Synchronise thread starting. */
  while (!g_main_loop_is_running (error_loop));

  g_main_loop_run (loop);

  return NULL;
}


static void
cb_new_selected_pair(NiceAgent *agent,
    guint stream_id,
    guint component_id,
    gchar *lfoundation,
    gchar* rfoundation,
    gpointer data)
{
  g_debug ("test-thread:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT (data) == 1)
    g_atomic_int_inc (&global_lagent_cands);
  else if (GPOINTER_TO_UINT (data) == 2)
    g_atomic_int_inc (&global_ragent_cands);
}


static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  NiceAgent *other = g_object_get_data (G_OBJECT (agent), "other-agent");
  gchar *ufrag = NULL, *password = NULL;
  GSList *cands, *i;
  guint id, other_id;
  gpointer tmp;

  g_debug ("test-thread:%s", G_STRFUNC);

  tmp = g_object_get_data (G_OBJECT (agent), "id");
  id = GPOINTER_TO_UINT (tmp);
  tmp = g_object_get_data (G_OBJECT (other), "id");
  other_id = GPOINTER_TO_UINT (tmp);

  nice_agent_get_local_credentials(agent, id, &ufrag, &password);
  nice_agent_set_remote_credentials (other,
      other_id, ufrag, password);
  g_free (ufrag);
  g_free (password);

  cands = nice_agent_get_local_candidates(agent, id, 1);
  g_assert (cands != NULL);

  nice_agent_set_remote_candidates (other, other_id, 1, cands);

  for (i = cands; i; i = i->next)
    nice_candidate_free ((NiceCandidate *) i->data);
  g_slist_free (cands);
}



static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  gchar data[10];
  volatile gint *count = NULL;
  gint count_val;

  if (GPOINTER_TO_UINT (user_data) == 1)
    count = &global_lagent_buffers;
  else if (GPOINTER_TO_UINT (user_data) == 2)
    count = &global_ragent_buffers;
  else
    g_error ("Invalid agent ?");

  count_val = g_atomic_int_get (count);
  if (count_val == 10)
    return;

  g_assert (len == 10);

  memset (data, count_val + '1', 10);

  g_assert (memcmp (buf, data, 10) == 0);

  g_atomic_int_inc (count);

  if (g_atomic_int_get (&global_ragent_buffers) == 10 &&
      g_atomic_int_get (&global_lagent_buffers) == 10)
    g_main_loop_quit (error_loop);
}


static void cb_component_state_changed (NiceAgent *agent,
    guint stream_id,
    guint component_id,
    guint state,
    gpointer user_data)
{
  int i;
  gchar data[10];

  if (state != NICE_COMPONENT_STATE_READY)
    return;

  for (i=0; i<10; i++)
    {
      memset (data, i+'1', 10);

      nice_agent_send (agent, stream_id, component_id, 10, data);
    }
}

int main (void)
{
  NiceAgent *lagent, *ragent;      /* agent's L and R */
  NiceAddress baseaddr;
  const char *stun_server = NULL, *stun_server_port = NULL;
  GMainContext *lmainctx, *rmainctx;
  GMainLoop *lmainloop, *rmainloop;
  GThread *lthread, *rthread;
  guint ls_id, rs_id;
  GMainContext *ldmainctx, *rdmainctx;
  GMainLoop *ldmainloop, *rdmainloop;
  GThread *ldthread, *rdthread;

#ifdef G_OS_WIN32
  WSADATA w;
  WSAStartup(0x0202, &w);
#endif
  g_type_init ();
  g_thread_init(NULL);

  lmainctx = g_main_context_new ();
  rmainctx = g_main_context_new ();
  lmainloop = g_main_loop_new (lmainctx, FALSE);
  rmainloop = g_main_loop_new (rmainctx, FALSE);

  ldmainctx = g_main_context_new ();
  rdmainctx = g_main_context_new ();
  ldmainloop = g_main_loop_new (ldmainctx, FALSE);
  rdmainloop = g_main_loop_new (rdmainctx, FALSE);

  error_loop = g_main_loop_new (NULL, FALSE);


  /* step: create the agents L and R */
  lagent = nice_agent_new (lmainctx, NICE_COMPATIBILITY_MSN);
  ragent = nice_agent_new (rmainctx, NICE_COMPATIBILITY_MSN);

  g_object_set_data (G_OBJECT (lagent), "other-agent", ragent);
  g_object_set_data (G_OBJECT (ragent), "other-agent", lagent);

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);
  g_object_set (G_OBJECT (lagent), "upnp", FALSE, NULL);
  g_object_set (G_OBJECT (ragent), "upnp", FALSE, NULL);

  /* step: add a timer to catch state changes triggered by signals */
  g_timeout_add (30000, timer_cb, NULL);

  /* step: specify which local interface to use */
  if (!nice_address_set_from_string (&baseaddr, "127.0.0.1"))
    g_assert_not_reached ();
  nice_agent_add_local_address (lagent, &baseaddr);
  nice_agent_add_local_address (ragent, &baseaddr);

  g_signal_connect (G_OBJECT (lagent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), GUINT_TO_POINTER(1));
  g_signal_connect (G_OBJECT (ragent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), GUINT_TO_POINTER(2));
  g_signal_connect (G_OBJECT (lagent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), GUINT_TO_POINTER(1));
  g_signal_connect (G_OBJECT (ragent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), GUINT_TO_POINTER(2));
  g_signal_connect (G_OBJECT (lagent), "new-selected-pair",
      G_CALLBACK (cb_new_selected_pair), GUINT_TO_POINTER(1));
  g_signal_connect (G_OBJECT (ragent), "new-selected-pair",
      G_CALLBACK (cb_new_selected_pair), GUINT_TO_POINTER(2));

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
  g_debug ("test-thread: TEST STARTS / running test for the 1st time");

#if !GLIB_CHECK_VERSION(2,31,8)
  lthread = g_thread_create (mainloop_thread, lmainloop, TRUE, NULL);
  rthread = g_thread_create (mainloop_thread, rmainloop, TRUE, NULL);
#else
  lthread = g_thread_new ("lthread libnice", mainloop_thread, lmainloop);
  rthread = g_thread_new ("rthread libnice", mainloop_thread, rmainloop);
#endif

  g_assert (lthread);
  g_assert (rthread);

  ls_id = nice_agent_add_stream (lagent, 2);
  rs_id = nice_agent_add_stream (ragent, 2);
  g_assert (ls_id > 0);
  g_assert (rs_id > 0);

  g_object_set_data (G_OBJECT (lagent), "id", GUINT_TO_POINTER (ls_id));
  g_object_set_data (G_OBJECT (ragent), "id", GUINT_TO_POINTER (rs_id));

  nice_agent_gather_candidates (lagent, ls_id);
  nice_agent_gather_candidates (ragent, rs_id);

  nice_agent_attach_recv (lagent, ls_id, 1, ldmainctx, cb_nice_recv,
      GUINT_TO_POINTER (1));
  nice_agent_attach_recv (ragent, rs_id, 1, rdmainctx, cb_nice_recv,
      GUINT_TO_POINTER (2));

#if !GLIB_CHECK_VERSION(2,31,8)
  ldthread = g_thread_create (mainloop_thread, ldmainloop, TRUE, NULL);
  rdthread = g_thread_create (mainloop_thread, rdmainloop, TRUE, NULL);
#else
  ldthread = g_thread_new ("ldthread libnice", mainloop_thread, ldmainloop);
  rdthread = g_thread_new ("rdthread libnice", mainloop_thread, rdmainloop);
#endif
  g_assert (ldthread);
  g_assert (rdthread);

  /* Run loop for error timer */
  g_main_loop_run (error_loop);

  while (!g_main_loop_is_running (ldmainloop));
  while (g_main_loop_is_running (ldmainloop))
    g_main_loop_quit (ldmainloop);
  while (!g_main_loop_is_running (rdmainloop));
  while (g_main_loop_is_running (rdmainloop))
    g_main_loop_quit (rdmainloop);
  while (!g_main_loop_is_running (lmainloop));
  while (g_main_loop_is_running (lmainloop))
    g_main_loop_quit (lmainloop);
  while (!g_main_loop_is_running (rmainloop));
  while (g_main_loop_is_running (rmainloop))
    g_main_loop_quit (rmainloop);

  g_thread_join (ldthread);
  g_thread_join (rdthread);
  g_thread_join (lthread);
  g_thread_join (rthread);

  /* note: verify that correct number of local candidates were reported */
  g_assert (g_atomic_int_get (&global_lagent_cands) == 1);
  g_assert (g_atomic_int_get (&global_ragent_cands) == 1);

  g_object_add_weak_pointer (G_OBJECT (lagent), (gpointer *) &lagent);
  g_object_add_weak_pointer (G_OBJECT (ragent), (gpointer *) &ragent);

  g_object_unref (lagent);
  g_object_unref (ragent);

  WAIT_UNTIL_UNSET (lagent, lmainctx);
  WAIT_UNTIL_UNSET (ragent, rmainctx);

  g_main_loop_unref (lmainloop);
  g_main_loop_unref (rmainloop);
  g_main_loop_unref (ldmainloop);
  g_main_loop_unref (rdmainloop);

  g_main_loop_unref (error_loop);
#ifdef G_OS_WIN32
  WSACleanup();
#endif
  return 0;
}
