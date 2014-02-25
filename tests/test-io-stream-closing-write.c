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

#define NUM_MESSAGES 10

guint count = 0;
GMutex count_lock;
GCond count_cond;

static void
read_thread_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  gpointer tmp;
  guint stream_id;
  GError *error = NULL;
  gssize len;
  guint8 buf[MESSAGE_SIZE];

  /* Block on receiving some data. */
  len = g_input_stream_read (input_stream, buf, sizeof (buf), NULL, &error);
  g_assert_cmpint (len, ==, sizeof(buf));

  g_mutex_lock (&count_lock);
  count++;
  g_cond_broadcast (&count_cond);
  if (data->user_data) {
    g_mutex_unlock (&count_lock);
    return;
  }

  while (count != 4)
    g_cond_wait (&count_cond, &count_lock);
  g_mutex_unlock (&count_lock);

  /* Now we remove the stream, lets see how the writer handles that */

  tmp = g_object_get_data (G_OBJECT (data->other->agent), "stream-id");
  stream_id = GPOINTER_TO_UINT (tmp);

  nice_agent_remove_stream (data->other->agent, stream_id);
}

static void
write_thread_cb (GOutputStream *output_stream, TestIOStreamThreadData *data)
{
  gchar buf[MESSAGE_SIZE] = {0};
  gssize ret;
  GError *error = NULL;

  g_mutex_lock (&count_lock);
  count++;
  g_cond_broadcast (&count_cond);
  g_mutex_unlock (&count_lock);

  do {
    g_assert_no_error (error);
    ret = g_output_stream_write (output_stream, buf, sizeof (buf), NULL,
        &error);

    if (!data->user_data) {
      g_assert_cmpint (ret, ==, sizeof (buf));
      return;
    }
  } while (ret > 0);
  g_assert_cmpint (ret, ==, -1);

  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED);
  g_clear_error (&error);

  stop_main_loop (data->error_loop);
}

int main (void)
{
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

  run_io_stream_test (30, TRUE, &callbacks, (gpointer) TRUE, NULL, NULL, NULL);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif

  return 0;
}
