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
  gint recv_count;
  gint *other_recv_count;
} ClosingData;

#define NUM_MESSAGES 10

static void
read_thread_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  ClosingData *user_data = data->user_data;
  GOutputStream *output_stream;
  gpointer tmp;
  guint stream_id;
  GError *error = NULL;

  while (user_data->recv_count < NUM_MESSAGES) {
    gchar expected_data[MESSAGE_SIZE];
    guint8 buf[MESSAGE_SIZE];
    gssize len;
    gsize offset;

    /* Block on receiving some data. */
    len = g_input_stream_read (input_stream, buf, sizeof (buf), NULL, &error);
    g_assert_no_error (error);

    offset = 0;
    while (len > 0) {
      g_assert (len == MESSAGE_SIZE);
      g_assert (user_data->recv_count < NUM_MESSAGES);

      memset (expected_data, user_data->recv_count + '1', MESSAGE_SIZE);
      g_assert (
          memcmp (buf + offset, expected_data, sizeof (expected_data)) == 0);

      user_data->recv_count++;

      len -= MESSAGE_SIZE;
      offset += MESSAGE_SIZE;
    }

    g_assert (len == 0);
  }

  /* Signal completion. */
  output_stream = g_io_stream_get_output_stream (data->io_stream);
  g_output_stream_write (output_stream, "Done", strlen ("Done"), NULL, &error);
  g_assert_no_error (error);

  /* Wait for a done packet. */
  while (TRUE) {
    guint8 buf[4];
    gssize len;

    len = g_input_stream_read (input_stream, buf, sizeof (buf), NULL, &error);
    g_assert_no_error (error);

    g_assert (len == 4);
    g_assert (memcmp (buf, "Done", strlen ("Done")) == 0);

    break;
  }

  user_data->recv_count = -1;

  tmp = g_object_get_data (G_OBJECT (data->agent), "stream-id");
  stream_id = GPOINTER_TO_UINT (tmp);

  nice_agent_remove_stream (data->agent, stream_id);

  /* Have both threads finished? */
  if (user_data->recv_count == -1 &&
      *user_data->other_recv_count == -1) {
    g_main_loop_quit (data->error_loop);
  }
}

static void
write_thread_cb (GOutputStream *output_stream, TestIOStreamThreadData *data)
{
  gchar buf[MESSAGE_SIZE];
  guint i;

  for (i = 0; i < NUM_MESSAGES; i++) {
    GError *error = NULL;

    memset (buf, i + '1', MESSAGE_SIZE);

    g_output_stream_write (output_stream, buf, sizeof (buf), NULL, &error);
    g_assert_no_error (error);
  }
}

int main (void)
{
  ClosingData *l_data, *r_data;

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

  l_data = g_malloc0 (sizeof (ClosingData));
  r_data = g_malloc0 (sizeof (ClosingData));

  l_data->recv_count = 0;
  l_data->other_recv_count = &r_data->recv_count;

  r_data->recv_count = 0;
  r_data->other_recv_count = &l_data->recv_count;

  run_io_stream_test (30, TRUE, &callbacks, l_data, NULL, r_data, NULL);

  g_free (r_data);
  g_free (l_data);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif

  return 0;
}
