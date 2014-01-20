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
  guint cand_count;
  guint *other_cand_count;

  gsize recv_count;
  gsize *other_recv_count;

  gsize send_count;
  gsize *other_send_count;
} ThreadData;

static void
read_thread_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  ThreadData *user_data = data->user_data;

  for (user_data->recv_count = 0;
       user_data->recv_count < 10;
       user_data->recv_count++) {
    guint8 expected_data[MESSAGE_SIZE];
    GError *error = NULL;
    guint8 buf[MESSAGE_SIZE];
    gssize len;

    /* Block on receiving some data. */
    len = g_input_stream_read (input_stream, buf, sizeof (buf), NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpint (len, ==, sizeof (buf));

    memset (expected_data, user_data->recv_count + '1', sizeof (expected_data));
    g_assert (memcmp (buf, expected_data, sizeof (expected_data)) == 0);
  }

  check_for_termination (data, &user_data->recv_count,
      user_data->other_recv_count, &user_data->send_count, 10);
}

static void
new_selected_pair_cb (NiceAgent *agent, guint stream_id, guint component_id,
    gchar *lfoundation, gchar *rfoundation, TestIOStreamThreadData *data)
{
  ThreadData *user_data = data->user_data;

  g_atomic_int_inc (&user_data->cand_count);
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

    g_output_stream_write (output_stream, buf, sizeof (buf), NULL, &error);
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
    new_selected_pair_cb,
  };

#ifdef G_OS_WIN32
  WSADATA w;
  WSAStartup (0x0202, &w);
#endif
  g_type_init ();
  g_thread_init (NULL);

  l_data = g_malloc0 (sizeof (ThreadData));
  r_data = g_malloc0 (sizeof (ThreadData));

  l_data->cand_count = 0;
  l_data->other_cand_count = &r_data->cand_count;
  l_data->recv_count = 0;
  l_data->other_recv_count = &r_data->recv_count;
  l_data->send_count = 0;
  l_data->other_send_count = &r_data->send_count;

  r_data->cand_count = 0;
  r_data->other_cand_count = &l_data->cand_count;
  r_data->recv_count = 0;
  r_data->other_recv_count = &l_data->recv_count;
  r_data->send_count = 0;
  r_data->other_send_count = &l_data->send_count;

  run_io_stream_test (30, TRUE, &callbacks, l_data, NULL, r_data, NULL);

  /* Verify that correct number of local candidates were reported. */
  g_assert (l_data->cand_count == 1);
  g_assert (r_data->cand_count == 1);

  g_free (r_data);
  g_free (l_data);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif
  return 0;
}
