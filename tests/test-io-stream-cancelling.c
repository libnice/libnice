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
  GCancellable *cancellable;  /* owned */

  GCond cond;
  GMutex mutex;
  gboolean blocking;  /* protected by @mutex */
} CancellationData;

static gpointer
cancellation_thread_cb (gpointer user_data)
{
  CancellationData *data = user_data;

  /* Wait to be signalled from read_thread_cb(). */
  g_mutex_lock (&data->mutex);
  while (!data->blocking)
    g_cond_wait (&data->cond, &data->mutex);
  g_mutex_unlock (&data->mutex);

  /* Try and ensure we cancel part-way through the read, rather than before the
   * read function is called. */
  g_usleep (100000);

  g_cancellable_cancel (data->cancellable);

  return NULL;
}

static void
read_thread_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  CancellationData *user_data = data->user_data;
  GError *error = NULL;
  guint8 buf[MESSAGE_SIZE];
  gssize len;

  /* Block on receiving some data or cancellation. */
  g_mutex_lock (&user_data->mutex);
  user_data->blocking = TRUE;
  g_cond_signal (&user_data->cond);
  g_mutex_unlock (&user_data->mutex);

  len = g_input_stream_read (input_stream, buf, sizeof (buf),
      user_data->cancellable, &error);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_error_free (error);
  g_assert (len == -1);

  g_main_loop_quit (data->error_loop);
}

int main (void)
{
  GThread *l_cancellation_thread, *r_cancellation_thread;
  CancellationData l_data, r_data;

  const TestIOStreamCallbacks callbacks = {
    read_thread_cb,
    NULL,
    NULL,
    NULL,
  };

#ifdef G_OS_WIN32
  WSADATA w;
  WSAStartup (0x0202, &w);
#endif
  g_type_init ();
  g_thread_init (NULL);

  l_data.cancellable = g_cancellable_new ();
  l_data.blocking = FALSE;
  g_cond_init (&l_data.cond);
  g_mutex_init (&l_data.mutex);

  r_data.cancellable = g_cancellable_new ();
  r_data.blocking = FALSE;
  g_cond_init (&r_data.cond);
  g_mutex_init (&r_data.mutex);

  l_cancellation_thread = spawn_thread ("libnice L cancel",
      cancellation_thread_cb, &l_data);
  r_cancellation_thread = spawn_thread ("libnice R cancel",
      cancellation_thread_cb, &r_data);

  run_io_stream_test (30, TRUE, &callbacks, &l_data, NULL, &r_data, NULL);

  g_thread_join (l_cancellation_thread);
  g_thread_join (r_cancellation_thread);

  /* Free things. */
  g_object_unref (r_data.cancellable);
  g_object_unref (l_data.cancellable);
  g_cond_clear (&l_data.cond);
  g_cond_clear (&r_data.cond);
  g_mutex_clear (&l_data.mutex);
  g_mutex_clear (&r_data.mutex);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif

  return 0;
}
