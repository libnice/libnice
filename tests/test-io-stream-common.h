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

#include <stdlib.h>
#include <string.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

/* Make the message sufficiently large to not hit Nagle’s algorithm in the
 * pseudo-TCP implementation, and hence run really slowly. */
#define MESSAGE_SIZE 1284 /* bytes */

typedef struct _TestIOStreamThreadData TestIOStreamThreadData;

typedef struct {
  void (*read_thread) (GInputStream *input_stream,
      TestIOStreamThreadData *data);
  void (*write_thread) (GOutputStream *output_stream,
      TestIOStreamThreadData *data);
  void (*reliable_transport_writable) (GOutputStream *output_stream,
      NiceAgent *agent, guint stream_id, guint component_id,
      TestIOStreamThreadData *data);
  void (*new_selected_pair) (NiceAgent *agent, guint stream_id,
      guint component_id, gchar *lfoundation, gchar *rfoundation,
      TestIOStreamThreadData *data);
} TestIOStreamCallbacks;

struct _TestIOStreamThreadData {
  NiceAgent *agent;
  GIOStream *io_stream;

  gboolean reliable;

  GMainLoop *main_loop;
  GMainLoop *error_loop;

  GMainContext *main_context;
  GMainContext *write_context;
  GMainContext *read_context;

  gpointer user_data;
  GDestroyNotify user_data_free;

  TestIOStreamThreadData *other;

  /*< private >*/
  const TestIOStreamCallbacks *callbacks;

  /* Condition signalling for the stream being open/writeable. */
  gboolean stream_open;
  gboolean stream_ready;
  GCond write_cond;
  GMutex write_mutex;

  GMutex *start_mutex;
  GCond *start_cond;
  guint *start_count;
};

GThread *spawn_thread (const gchar *thread_name, GThreadFunc thread_func,
    gpointer user_data);
void run_io_stream_test (guint deadlock_timeout, gboolean reliable,
    const TestIOStreamCallbacks *callbacks,
    gpointer l_user_data, GDestroyNotify l_user_data_free,
    gpointer r_user_data, GDestroyNotify r_user_data_free);
void check_for_termination (TestIOStreamThreadData *data, gsize *recv_count,
    gsize *other_recv_count, gsize *send_count, gsize expected_recv_count);

void stop_main_loop (GMainLoop *loop);
