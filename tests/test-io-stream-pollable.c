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

typedef struct {
  GMainLoop *read_loop;  /* unowned */

  gsize recv_count;
  gsize *other_recv_count;

  gsize send_count;
  gsize *other_send_count;
} ThreadData;

static gboolean
read_stream_cb (GObject *pollable_stream, gpointer _user_data)
{
  TestIOStreamThreadData *data = _user_data;
  ThreadData *user_data = data->user_data;
  gchar expected_data[MESSAGE_SIZE];
  GError *error = NULL;
  guint8 buf[MESSAGE_SIZE];
  gssize len;

  /* Try to receive some data. */
  len = g_pollable_input_stream_read_nonblocking (
      G_POLLABLE_INPUT_STREAM (pollable_stream), buf, sizeof (buf), NULL,
      &error);

  if (len == -1) {
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK);
    g_error_free (error);
    return TRUE;
  }

  g_assert_cmpint (len, ==, MESSAGE_SIZE);

  memset (expected_data, user_data->recv_count + '1', sizeof (expected_data));
  g_assert (memcmp (buf, expected_data, sizeof (expected_data)) == 0);

  user_data->recv_count++;

  if (user_data->recv_count == 10) {
    g_main_loop_quit (user_data->read_loop);
    return FALSE;
  }

  return TRUE;
}

static void
read_thread_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  GMainContext *main_context;
  GMainLoop *main_loop;
  GSource *stream_source;
  ThreadData *user_data = data->user_data;

  main_context = g_main_context_new ();
  main_loop = g_main_loop_new (main_context, FALSE);
  g_main_context_push_thread_default (main_context);

  stream_source =
      g_pollable_input_stream_create_source (
          G_POLLABLE_INPUT_STREAM (input_stream), NULL);

  g_source_set_callback (stream_source, (GSourceFunc) read_stream_cb,
      data, NULL);
  g_source_attach (stream_source, main_context);
  g_source_unref (stream_source);

  /* Run the main loop. */
  user_data->read_loop = main_loop;
  g_main_loop_run (main_loop);

  g_main_context_pop_thread_default (main_context);
  g_main_loop_unref (main_loop);
  g_main_context_unref (main_context);

  check_for_termination (data, &user_data->recv_count,
      user_data->other_recv_count, &user_data->send_count, 10);
}

static void
write_thread_cb (GOutputStream *output_stream, TestIOStreamThreadData *data)
{
  ThreadData *user_data = data->user_data;
  guint8 buf[MESSAGE_SIZE];

  for (user_data->send_count = 0;
       user_data->send_count < 10;
       user_data->send_count++) {
    GError *error = NULL;

    memset (buf, user_data->send_count + '1', MESSAGE_SIZE);

    g_pollable_output_stream_write_nonblocking (
        G_POLLABLE_OUTPUT_STREAM (output_stream), buf, sizeof (buf), NULL,
        &error);
    g_assert_no_error (error);
  }
}

int main (void)
{
  ThreadData *l_data, *r_data;

  const TestIOStreamCallbacks callbacks = {
    read_thread_cb,
    write_thread_cb,
    NULL,
    NULL,
  };

#ifdef G_OS_WIN32
  WSADATA w;
  WSAStartup (0x0202, &w);
#endif
  g_type_init ();
  g_thread_init (NULL);

  l_data = g_malloc0 (sizeof (ThreadData));
  r_data = g_malloc0 (sizeof (ThreadData));

  l_data->recv_count = 0;
  l_data->send_count = 0;
  l_data->other_recv_count = &r_data->recv_count;
  l_data->other_send_count = &r_data->send_count;

  r_data->recv_count = 0;
  r_data->send_count = 0;
  r_data->other_recv_count = &l_data->recv_count;
  r_data->other_send_count = &l_data->send_count;

  run_io_stream_test (30, TRUE, &callbacks, l_data, NULL, r_data, NULL);

  g_free (r_data);
  g_free (l_data);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif
  return 0;
}
