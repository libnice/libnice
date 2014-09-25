/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2014 Collabora Ltd.
 *  Contact: Philip Withnall
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
 *   Philip Withnall, Collabora Ltd.
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
#include "test-io-stream-common.h"

#include <stdlib.h>
#include <string.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

GMutex start_mutex;
GCond start_cond;
gboolean started;

/* Waits about 10 seconds for @var to be NULL/FALSE */
#define WAIT_UNTIL_UNSET(var, context)			\
  if (var)						\
    {							\
      int i;						\
							\
      for (i = 0; i < 13 && (var); i++)			\
	{						\
	  g_usleep (1000 * (1 << i));			\
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

static void
wait_for_start (TestIOStreamThreadData *data)
{
  g_mutex_lock (data->start_mutex);
  (*data->start_count)--;
  g_cond_broadcast (data->start_cond);
  while (*data->start_count > 0)
    g_cond_wait (data->start_cond, data->start_mutex);
  g_mutex_unlock (data->start_mutex);
}

static gpointer
write_thread_cb (gpointer user_data)
{
  TestIOStreamThreadData *data = user_data;
  GMainContext *main_context;
  GOutputStream *output_stream = NULL;

  main_context = g_main_context_new ();
  g_main_context_push_thread_default (main_context);

  /* Synchronise thread starting. */
  wait_for_start (data);

  /* Wait for the stream to be writeable. */
  g_mutex_lock (&data->write_mutex);
  while (!(data->stream_open && data->stream_ready))
    g_cond_wait (&data->write_cond, &data->write_mutex);
  g_mutex_unlock (&data->write_mutex);

  if (data->reliable)
    output_stream = g_io_stream_get_output_stream (data->io_stream);
  data->callbacks->write_thread (output_stream, data);

  g_main_context_pop_thread_default (main_context);
  g_main_context_unref (main_context);

  return NULL;
}

static gpointer
read_thread_cb (gpointer user_data)
{
  TestIOStreamThreadData *data = user_data;
  GMainContext *main_context;
  GInputStream *input_stream = NULL;

  main_context = g_main_context_new ();
  g_main_context_push_thread_default (main_context);

  /* Synchronise thread starting. */
  wait_for_start (data);

  if (data->reliable)
    input_stream = g_io_stream_get_input_stream (data->io_stream);
  data->callbacks->read_thread (input_stream, data);

  g_main_context_pop_thread_default (main_context);
  g_main_context_unref (main_context);

  return NULL;
}

static gpointer
main_thread_cb (gpointer user_data)
{
  TestIOStreamThreadData *data = user_data;

  g_main_context_push_thread_default (data->main_context);

  /* Synchronise thread starting. */
  wait_for_start (data);

  /* Run the main context. */
  g_main_loop_run (data->main_loop);

  g_main_context_pop_thread_default (data->main_context);

  return NULL;
}

static void
candidate_gathering_done_cb (NiceAgent *agent, guint stream_id,
    gpointer user_data)
{
  NiceAgent *other = g_object_get_data (G_OBJECT (agent), "other-agent");
  gchar *ufrag = NULL, *password = NULL;
  GSList *cands, *i;
  guint id, other_id;
  gpointer tmp;

  tmp = g_object_get_data (G_OBJECT (agent), "stream-id");
  id = GPOINTER_TO_UINT (tmp);
  tmp = g_object_get_data (G_OBJECT (other), "stream-id");
  other_id = GPOINTER_TO_UINT (tmp);

  nice_agent_get_local_credentials (agent, id, &ufrag, &password);
  nice_agent_set_remote_credentials (other,
      other_id, ufrag, password);
  g_free (ufrag);
  g_free (password);

  cands = nice_agent_get_local_candidates (agent, id, 1);
  g_assert (cands != NULL);

  nice_agent_set_remote_candidates (other, other_id, 1, cands);

  for (i = cands; i; i = i->next)
    nice_candidate_free ((NiceCandidate *) i->data);
  g_slist_free (cands);
}

static void
reliable_transport_writable_cb (NiceAgent *agent, guint stream_id,
    guint component_id, gpointer user_data)
{
  TestIOStreamThreadData *data = user_data;

  g_assert (data->reliable);

  /* Signal writeability. */
  g_mutex_lock (&data->write_mutex);
  data->stream_open = TRUE;
  g_cond_broadcast (&data->write_cond);
  g_mutex_unlock (&data->write_mutex);

  if (data->callbacks->reliable_transport_writable != NULL) {
    GIOStream *io_stream;
    GOutputStream *output_stream;

    io_stream = g_object_get_data (G_OBJECT (agent), "io-stream");
    g_assert (io_stream != NULL);
    output_stream = g_io_stream_get_output_stream (io_stream);

    data->callbacks->reliable_transport_writable (output_stream, agent,
       stream_id, component_id, data);
  }
}

static void
component_state_changed_cb (NiceAgent *agent, guint stream_id,
    guint component_id, guint state, gpointer user_data)
{
  TestIOStreamThreadData *data = user_data;

  if (state != NICE_COMPONENT_STATE_READY)
    return;

  /* Signal stream state. */
  g_mutex_lock (&data->write_mutex);
  data->stream_ready = TRUE;
  g_cond_broadcast (&data->write_cond);
  g_mutex_unlock (&data->write_mutex);
}

static void
new_selected_pair_cb (NiceAgent *agent, guint stream_id, guint component_id,
    gchar *lfoundation, gchar *rfoundation, gpointer user_data)
{
  TestIOStreamThreadData *data = user_data;

  if (data->callbacks->new_selected_pair != NULL) {
    data->callbacks->new_selected_pair (agent, stream_id, component_id,
        lfoundation, rfoundation, data);
  }
}

static NiceAgent *
create_agent (gboolean controlling_mode, TestIOStreamThreadData *data,
    GMainContext **main_context, GMainLoop **main_loop)
{
  NiceAgent *agent;
  NiceAddress base_addr;
  const gchar *stun_server, *stun_server_port;

  /* Create main contexts. */
  *main_context = g_main_context_new ();
  *main_loop = g_main_loop_new (*main_context, FALSE);

  /* Use Google compatibility to ignore credentials. */
  if (data->reliable)
    agent = nice_agent_new_reliable (*main_context, NICE_COMPATIBILITY_GOOGLE);
  else
    agent = nice_agent_new (*main_context, NICE_COMPATIBILITY_GOOGLE);

  g_object_set (G_OBJECT (agent),
      "controlling-mode", controlling_mode,
      "upnp", FALSE,
      NULL);

  /* Specify which local interface to use. */
  g_assert (nice_address_set_from_string (&base_addr, "127.0.0.1"));
  nice_agent_add_local_address (agent, &base_addr);

  /* Hook up signals. */
  g_signal_connect (G_OBJECT (agent), "candidate-gathering-done",
      (GCallback) candidate_gathering_done_cb,
      GUINT_TO_POINTER (controlling_mode));
  g_signal_connect (G_OBJECT (agent), "new-selected-pair",
      (GCallback) new_selected_pair_cb, data);
  g_signal_connect (G_OBJECT (agent), "component-state-changed",
    (GCallback) component_state_changed_cb, data);

  if (data->reliable) {
    g_signal_connect (G_OBJECT (agent), "reliable-transport-writable",
      (GCallback) reliable_transport_writable_cb, data);
  } else {
    data->stream_open = TRUE;
  }

  /* Configure the STUN server. */
  stun_server = g_getenv ("NICE_STUN_SERVER");
  stun_server_port = g_getenv ("NICE_STUN_SERVER_PORT");

  if (stun_server != NULL) {
    g_object_set (G_OBJECT (agent),
        "stun-server", stun_server,
        "stun-server-port", atoi (stun_server_port),
        NULL);
  }

  return agent;
}

static void
add_stream (NiceAgent *agent)
{
  guint stream_id;

  stream_id = nice_agent_add_stream (agent, 2);
  g_assert (stream_id > 0);

  g_object_set_data (G_OBJECT (agent), "stream-id",
      GUINT_TO_POINTER (stream_id));
}

static void
run_agent (TestIOStreamThreadData *data, NiceAgent *agent)
{
  guint stream_id;
  gpointer tmp;

  tmp = g_object_get_data (G_OBJECT (agent), "stream-id");
  stream_id = GPOINTER_TO_UINT (tmp);

  nice_agent_gather_candidates (agent, stream_id);

  if (data->reliable) {
    data->io_stream =
        G_IO_STREAM (nice_agent_get_io_stream (agent, stream_id, 1));
    g_object_set_data (G_OBJECT (agent), "io-stream", data->io_stream);
  } else {
    data->io_stream = NULL;
  }
}

GThread *
spawn_thread (const gchar *thread_name, GThreadFunc thread_func,
    gpointer user_data)
{
  GThread *thread;

#if !GLIB_CHECK_VERSION(2, 31, 8)
  thread = g_thread_create (thread_func, user_data, TRUE, NULL);
#else
  thread = g_thread_new (thread_name, thread_func, user_data);
#endif

  g_assert (thread);

  return thread;
}

void
run_io_stream_test (guint deadlock_timeout, gboolean reliable,
    const TestIOStreamCallbacks *callbacks,
    gpointer l_user_data, GDestroyNotify l_user_data_free,
    gpointer r_user_data, GDestroyNotify r_user_data_free)
{
  GMainLoop *error_loop;
  GThread *l_main_thread, *r_main_thread;
  GThread *l_write_thread, *l_read_thread, *r_write_thread, *r_read_thread;
  TestIOStreamThreadData l_data, r_data;
  GMutex mutex;
  GCond cond;
  guint start_count = 6;
  guint stream_id;

  g_mutex_init (&mutex);
  g_cond_init (&cond);

  error_loop = g_main_loop_new (NULL, FALSE);

  /* Set up data structures. */
  l_data.reliable = reliable;
  l_data.error_loop = error_loop;
  l_data.callbacks = callbacks;
  l_data.user_data = l_user_data;
  l_data.user_data_free = l_user_data_free;

  g_cond_init (&l_data.write_cond);
  g_mutex_init (&l_data.write_mutex);
  l_data.stream_open = FALSE;
  l_data.stream_ready = FALSE;
  l_data.start_mutex = &mutex;
  l_data.start_cond = &cond;
  l_data.start_count = &start_count;

  r_data.reliable = reliable;
  r_data.error_loop = error_loop;
  r_data.callbacks = callbacks;
  r_data.user_data = r_user_data;
  r_data.user_data_free = r_user_data_free;

  g_cond_init (&r_data.write_cond);
  g_mutex_init (&r_data.write_mutex);
  r_data.stream_open = FALSE;
  r_data.stream_ready = FALSE;
  r_data.start_mutex = &mutex;
  r_data.start_cond = &cond;
  r_data.start_count = &start_count;

  l_data.other = &r_data;
  r_data.other = &l_data;

  /* Create the L and R agents. */
  l_data.agent = create_agent (TRUE, &l_data,
      &l_data.main_context, &l_data.main_loop);
  r_data.agent = create_agent (FALSE, &r_data,
      &r_data.main_context, &r_data.main_loop);

  g_object_set_data (G_OBJECT (l_data.agent), "other-agent", r_data.agent);
  g_object_set_data (G_OBJECT (r_data.agent), "other-agent", l_data.agent);

  /* Add a timer to catch deadlocks. */
  g_timeout_add_seconds (deadlock_timeout, timer_cb, NULL);

  l_main_thread = spawn_thread ("libnice L main", main_thread_cb, &l_data);
  r_main_thread = spawn_thread ("libnice R main", main_thread_cb, &r_data);

  add_stream (l_data.agent);
  add_stream (r_data.agent);
  run_agent (&l_data, l_data.agent);
  run_agent (&r_data, r_data.agent);

  l_read_thread = spawn_thread ("libnice L read", read_thread_cb, &l_data);
  r_read_thread = spawn_thread ("libnice R read", read_thread_cb, &r_data);

  if (callbacks->write_thread != NULL) {
    l_write_thread = spawn_thread ("libnice L write", write_thread_cb, &l_data);
    r_write_thread = spawn_thread ("libnice R write", write_thread_cb, &r_data);
  } else {
    g_mutex_lock (&mutex);
    start_count -= 2;
    g_cond_broadcast (&cond);
    g_mutex_unlock (&mutex);

    l_write_thread = NULL;
    r_write_thread = NULL;
  }

  /* Run loop for error timer */
  g_main_loop_run (error_loop);

  /* Clean up the main loops and threads. */
  stop_main_loop (l_data.main_loop);
  stop_main_loop (r_data.main_loop);

  g_thread_join (l_read_thread);
  g_thread_join (r_read_thread);
  if (l_write_thread != NULL)
    g_thread_join (l_write_thread);
  if (r_write_thread != NULL)
    g_thread_join (r_write_thread);
  g_thread_join (l_main_thread);
  g_thread_join (r_main_thread);

  /* Free things. */
  if (r_data.user_data_free != NULL)
    r_data.user_data_free (r_data.user_data);

  if (l_data.user_data_free != NULL)
    l_data.user_data_free (l_data.user_data);

  g_cond_clear (&r_data.write_cond);
  g_mutex_clear (&r_data.write_mutex);
  g_cond_clear (&l_data.write_cond);
  g_mutex_clear (&l_data.write_mutex);

  if (r_data.io_stream != NULL)
    g_object_unref (r_data.io_stream);
  if (l_data.io_stream != NULL)
    g_object_unref (l_data.io_stream);

  stream_id =
    GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (r_data.agent), "stream-id"));
  if (stream_id != 0)
    nice_agent_remove_stream (r_data.agent, stream_id);
  stream_id =
    GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (l_data.agent), "stream-id"));
  if (stream_id != 0)
    nice_agent_remove_stream (l_data.agent, stream_id);

  g_object_add_weak_pointer (G_OBJECT (r_data.agent),
                             (gpointer *) &r_data.agent);
  g_object_add_weak_pointer (G_OBJECT (l_data.agent),
                             (gpointer *) &l_data.agent);

  g_object_unref (r_data.agent);
  g_object_unref (l_data.agent);

  WAIT_UNTIL_UNSET (r_data.agent, r_data.main_context);
  WAIT_UNTIL_UNSET (l_data.agent, l_data.main_context);

  g_main_loop_unref (r_data.main_loop);
  g_main_loop_unref (l_data.main_loop);

  g_main_context_unref (r_data.main_context);
  g_main_context_unref (l_data.main_context);

  g_main_loop_unref (error_loop);

  g_mutex_clear (&mutex);
  g_cond_clear (&cond);
}

/* Once we’ve received all the expected bytes, wait to finish sending all bytes,
 * then send and wait for the close message. Finally, remove the stream.
 *
 * This must only be called from the read thread implementation. */
void
check_for_termination (TestIOStreamThreadData *data, gsize *recv_count,
    gsize *other_recv_count, gsize *send_count, gsize expected_recv_count)
{
  guint stream_id;
  gpointer tmp;

  /* Wait for transmission to complete. */
  while (*send_count < expected_recv_count);

  /* Send a close message. */
  tmp = g_object_get_data (G_OBJECT (data->agent), "stream-id");
  stream_id = GPOINTER_TO_UINT (tmp);

  /* Can't be certain enough to test for termination on non-reliable streams.
   * There may be packet losses, etc
   */
  if (data->reliable) {
    guint8 buf[65536];
    gsize buf_len;
    gssize len;
    GError *error = NULL;

    g_assert_cmpuint (*recv_count, >=, expected_recv_count);

    buf_len = strlen ("Done");
    memcpy (buf, "Done", buf_len);
    len = nice_agent_send (data->agent, stream_id, 1, buf_len, (gchar *) buf);
    g_assert_cmpint (len, ==, buf_len);

    /* Wait for a done packet. */
    len = nice_agent_recv (data->agent, stream_id, 1, buf, buf_len, NULL,
        &error);
    g_assert_no_error (error);

    g_assert_cmpint (len, ==, strlen ("Done"));
    g_assert_cmpint (memcmp (buf, "Done", strlen ("Done")), ==, 0);

    *recv_count = *recv_count + 1;
  }

  /* Remove the stream and run away. */
  nice_agent_remove_stream (data->agent, stream_id);
  g_object_set_data (G_OBJECT (data->agent), "stream-id", GUINT_TO_POINTER (0));

  /* If both sides have finished, quit the test main loop. */
  if (*recv_count > expected_recv_count &&
      *other_recv_count > expected_recv_count) {
    g_main_loop_quit (data->error_loop);
  }
}

void
stop_main_loop (GMainLoop *loop)
{
  GSource *src = g_idle_source_new ();
  g_source_set_callback (src, (GSourceFunc) g_main_loop_quit,
      g_main_loop_ref (loop), (GDestroyNotify) g_main_loop_unref);
  g_source_attach (src, g_main_loop_get_context (loop));
  g_source_unref (src);
}
