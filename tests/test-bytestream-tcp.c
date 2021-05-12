/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2013 Collabora Ltd.
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
  gsize recv_count;
  gsize *other_recv_count;

  gsize send_count;
  gsize *other_send_count;
} ThreadData;

static const gchar test_sequence[] = { '1', '2', '3', '4' };

static void
read_thread_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  ThreadData *user_data = data->user_data;
  guint8 buf[2];
  GError *error = NULL;

  g_input_stream_read_all (input_stream, buf, sizeof (buf), NULL, NULL, &error);
  g_assert_no_error (error);
  user_data->recv_count++;
  g_assert_cmpmem (buf, sizeof (buf), test_sequence, sizeof (buf));

  g_input_stream_read_all (input_stream, buf, sizeof (buf), NULL, NULL, &error);
  g_assert_no_error (error);
  user_data->recv_count++;
  g_assert_cmpmem (buf, sizeof (buf), test_sequence + 2, sizeof (buf));

  check_for_termination (data, &user_data->recv_count,
      user_data->other_recv_count, &user_data->send_count, 2);
}

static void
write_thread_cb (GOutputStream *output_stream, TestIOStreamThreadData *data)
{
  ThreadData *user_data = data->user_data;
  GError *error = NULL;

  g_output_stream_write_all (output_stream, test_sequence,
      sizeof (test_sequence), NULL, NULL, &error);
  g_assert_no_error (error);
  user_data->send_count += 2;
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

  l_data = g_malloc0 (sizeof (ThreadData));
  r_data = g_malloc0 (sizeof (ThreadData));

  l_data->recv_count = 0;
  l_data->other_recv_count = &r_data->recv_count;
  l_data->send_count = 0;
  l_data->other_send_count = &r_data->send_count;

  r_data->recv_count = 0;
  r_data->other_recv_count = &l_data->recv_count;
  r_data->send_count = 0;
  r_data->other_send_count = &l_data->send_count;

  run_io_stream_test (30, TRUE, &callbacks, l_data, NULL, r_data, NULL,
      TEST_IO_STREAM_OPTION_TCP_ONLY | TEST_IO_STREAM_OPTION_BYTESTREAM_TCP);

  g_free (r_data);
  g_free (l_data);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif
  return 0;
}
