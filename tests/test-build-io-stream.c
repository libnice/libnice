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

#include <string.h>

#include "agent.h"

#include "iostream.h"

static void
test_invalid_stream (NiceAddress *addr)
{
  NiceAgent *agent;
  GIOStream *io_stream;

  agent = nice_agent_new_reliable (NULL, NICE_COMPATIBILITY_RFC5245);
  nice_agent_add_local_address (agent, addr);

  /* Try building an I/O stream for an invalid stream. All its operations should
   * return G_IO_ERROR_BROKEN_PIPE. */
  io_stream = nice_agent_get_io_stream (agent, 5, 5);
  g_assert (io_stream == NULL);

  g_object_unref (agent);
}

static void
test_io_stream_properties (NiceAddress *addr)
{
  NiceAgent *agent;
  guint stream_id;
  GIOStream *io_stream;
  GInputStream *input_stream;
  GOutputStream *output_stream;

  agent = nice_agent_new_reliable (NULL, NICE_COMPATIBILITY_RFC5245);
  nice_agent_add_local_address (agent, addr);

  stream_id = nice_agent_add_stream (agent, 1);

  /* Try building an I/O stream around it. */
  io_stream = nice_agent_get_io_stream (agent, stream_id, 1);
  g_assert (G_IS_IO_STREAM (io_stream));
  g_assert (NICE_IS_IO_STREAM (io_stream));

  /* Check various initial properties. */
  g_assert (!g_io_stream_is_closed (G_IO_STREAM (io_stream)));
  g_assert (!g_io_stream_has_pending (G_IO_STREAM (io_stream)));

  /* Check the input stream’s properties. */
  input_stream = g_io_stream_get_input_stream (G_IO_STREAM (io_stream));
  g_assert (G_IS_INPUT_STREAM (input_stream));
  g_assert (NICE_IS_INPUT_STREAM (input_stream));

  g_assert (!g_input_stream_is_closed (input_stream));
  g_assert (!g_input_stream_has_pending (input_stream));

  /* Check the output stream’s properties. */
  output_stream = g_io_stream_get_output_stream (G_IO_STREAM (io_stream));
  g_assert (G_IS_OUTPUT_STREAM (output_stream));
  g_assert (NICE_IS_OUTPUT_STREAM (output_stream));

  g_assert (!g_output_stream_is_closing (output_stream));
  g_assert (!g_output_stream_is_closed (output_stream));
  g_assert (!g_output_stream_has_pending (output_stream));

  /* Remove the component and check that the I/O streams close. */
  nice_agent_remove_stream (agent, stream_id);

  g_assert (g_io_stream_is_closed (G_IO_STREAM (io_stream)));
  g_assert (g_input_stream_is_closed (input_stream));
  g_assert (g_output_stream_is_closed (output_stream));

  g_object_unref (io_stream);
  g_object_unref (agent);
}

static void
test_pollable_properties (NiceAddress *addr)
{
  NiceAgent *agent;
  guint stream_id;
  GIOStream *io_stream;
  GInputStream *input_stream;
  GOutputStream *output_stream;
  GPollableInputStream *pollable_input_stream;
  GPollableOutputStream *pollable_output_stream;
  guint8 buf[65536];
  GError *error = NULL;
  GSource *stream_source;

  agent = nice_agent_new_reliable (NULL, NICE_COMPATIBILITY_RFC5245);
  nice_agent_add_local_address (agent, addr);

  /* Add a stream. */
  stream_id = nice_agent_add_stream (agent, 1);

  /* Try building an I/O stream around it. */
  io_stream = nice_agent_get_io_stream (agent, stream_id, 1);
  g_assert (G_IS_IO_STREAM (io_stream));
  g_assert (NICE_IS_IO_STREAM (io_stream));

  /* Check the input stream’s properties. */
  input_stream = g_io_stream_get_input_stream (G_IO_STREAM (io_stream));
  g_assert (G_IS_POLLABLE_INPUT_STREAM (input_stream));
  pollable_input_stream = G_POLLABLE_INPUT_STREAM (input_stream);

  g_assert (g_pollable_input_stream_can_poll (pollable_input_stream));
  g_assert (!g_pollable_input_stream_is_readable (pollable_input_stream));

  g_assert (
      g_pollable_input_stream_read_nonblocking (pollable_input_stream,
          buf, sizeof (buf), NULL, &error) == -1);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK);
  g_clear_error (&error);

  stream_source =
      g_pollable_input_stream_create_source (pollable_input_stream, NULL);
  g_assert (stream_source != NULL);
  g_source_unref (stream_source);

  /* Check the output stream’s properties. */
  output_stream = g_io_stream_get_output_stream (G_IO_STREAM (io_stream));
  g_assert (G_IS_POLLABLE_OUTPUT_STREAM (output_stream));
  pollable_output_stream = G_POLLABLE_OUTPUT_STREAM (output_stream);

  g_assert (g_pollable_output_stream_can_poll (pollable_output_stream));
  g_assert (!g_pollable_output_stream_is_writable (pollable_output_stream));

  g_assert (
      g_pollable_output_stream_write_nonblocking (pollable_output_stream,
          buf, sizeof (buf), NULL, &error) == -1);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK);
  g_clear_error (&error);

  stream_source =
      g_pollable_output_stream_create_source (pollable_output_stream, NULL);
  g_assert (stream_source != NULL);
  g_source_unref (stream_source);

  /* Remove the component and check that the I/O streams close. */
  nice_agent_remove_stream (agent, stream_id);

  g_assert (!g_pollable_input_stream_is_readable (pollable_input_stream));
  g_assert (!g_pollable_output_stream_is_writable (pollable_output_stream));

  g_assert (
      g_pollable_input_stream_read_nonblocking (pollable_input_stream,
          buf, sizeof (buf), NULL, &error) == 0);
  g_assert_no_error (error);

  g_assert (
      g_pollable_output_stream_write_nonblocking (pollable_output_stream,
          buf, sizeof (buf), NULL, &error) == -1);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED);
  g_clear_error (&error);

  g_object_unref (io_stream);
  g_object_unref (agent);
}

static gboolean
source_cancel_cb (gpointer user_data)
{
  GCancellable *cancellable = user_data;

  g_cancellable_cancel (cancellable);

  return FALSE;
}

static gboolean
source_cancelled_cb (GObject *pollable_stream, gpointer user_data)
{
  GMainLoop *main_loop = user_data;

  /* Try and check that the callback was invoked due to cancellation rather than
   * a poll() event on the socket itself. */
  if (G_IS_POLLABLE_INPUT_STREAM (pollable_stream)) {
    g_assert (
        !g_pollable_input_stream_is_readable (
            G_POLLABLE_INPUT_STREAM (pollable_stream)));
  } else {
    g_assert (
        !g_pollable_output_stream_is_writable (
            G_POLLABLE_OUTPUT_STREAM (pollable_stream)));
  }

  g_main_loop_quit (main_loop);

  return FALSE;
}

static gboolean
source_timeout_cb (gpointer user_data)
{
  g_error ("check_pollable_source_cancellation() took too long. Aborting.");

  return FALSE;
}

/* Check that cancelling a GCancellable which is associated with a pollable
 * stream’s GSource invokes a callback from that source in the main loop. This
 * uses a main context with three sources: the pollable source, an idle source
 * to trigger the cancellation, and a timeout source to fail the test if it
 * takes too long. */
static void
check_pollable_source_cancellation (GSource *pollable_source,
    GCancellable *cancellable)
{
  GMainContext *main_context;
  GMainLoop *main_loop;
  GSource *idle_source, *timeout_source;

  main_context = g_main_context_new ();
  main_loop = g_main_loop_new (main_context, FALSE);

  /* Set up the pollable source. */
  g_source_set_callback (pollable_source, (GSourceFunc) source_cancelled_cb,
      main_loop, NULL);
  g_source_attach (pollable_source, main_context);

  /* Idle source to cancel the cancellable. */
  idle_source = g_idle_source_new ();
  g_source_set_callback (idle_source, (GSourceFunc) source_cancel_cb,
      cancellable, NULL);
  g_source_attach (idle_source, main_context);
  g_source_unref (idle_source);

  /* Timeout. */
  timeout_source = g_timeout_source_new (30000);
  g_source_set_callback (timeout_source, (GSourceFunc) source_timeout_cb,
      NULL, NULL);
  g_source_attach (timeout_source, main_context);
  g_source_unref (timeout_source);

  /* Run the main loop and expect to quit it immediately as the pollable source
   * is cancelled. */
  g_main_loop_run (main_loop);

  g_assert (g_cancellable_is_cancelled (cancellable));

  g_main_loop_unref (main_loop);
  g_main_context_unref (main_context);
}

static void
test_pollable_cancellation (NiceAddress *addr)
{
  NiceAgent *agent;
  guint stream_id;
  GIOStream *io_stream;
  GInputStream *input_stream;
  GOutputStream *output_stream;
  GPollableInputStream *pollable_input_stream;
  GPollableOutputStream *pollable_output_stream;
  guint8 buf[65536];
  GError *error = NULL;
  GSource *stream_source;
  GCancellable *cancellable;

  agent = nice_agent_new_reliable (NULL, NICE_COMPATIBILITY_RFC5245);
  nice_agent_add_local_address (agent, addr);

  /* Add a stream. */
  stream_id = nice_agent_add_stream (agent, 1);

  /* Try building an I/O stream around it. */
  io_stream = nice_agent_get_io_stream (agent, stream_id, 1);
  g_assert (G_IS_IO_STREAM (io_stream));
  g_assert (NICE_IS_IO_STREAM (io_stream));

  /* Grab the input and output streams. */
  input_stream = g_io_stream_get_input_stream (G_IO_STREAM (io_stream));
  g_assert (G_IS_POLLABLE_INPUT_STREAM (input_stream));
  pollable_input_stream = G_POLLABLE_INPUT_STREAM (input_stream);

  output_stream = g_io_stream_get_output_stream (G_IO_STREAM (io_stream));
  g_assert (G_IS_POLLABLE_OUTPUT_STREAM (output_stream));
  pollable_output_stream = G_POLLABLE_OUTPUT_STREAM (output_stream);

  /* Check the non-blocking read() and write() return immediately if called with
   * a cancelled cancellable. */
  cancellable = g_cancellable_new ();
  g_cancellable_cancel (cancellable);

  g_assert (
      g_pollable_input_stream_read_nonblocking (pollable_input_stream,
          buf, sizeof (buf), cancellable, &error) == -1);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_clear_error (&error);

  g_assert (
      g_pollable_output_stream_write_nonblocking (pollable_output_stream,
          buf, sizeof (buf), cancellable, &error) == -1);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_clear_error (&error);

  g_object_unref (cancellable);

  /* Check the GSources invoke a callback when run with the cancellable
   * cancelled. */
  cancellable = g_cancellable_new ();
  stream_source =
      g_pollable_input_stream_create_source (pollable_input_stream,
          cancellable);

  check_pollable_source_cancellation (stream_source, cancellable);

  g_source_unref (stream_source);
  g_object_unref (cancellable);

  /* And for the output stream. */
  cancellable = g_cancellable_new ();
  stream_source =
      g_pollable_output_stream_create_source (pollable_output_stream,
          cancellable);

  check_pollable_source_cancellation (stream_source, cancellable);

  g_object_unref (io_stream);
  g_source_unref (stream_source);
  g_object_unref (cancellable);
  g_object_unref (agent);
}

static void
test_zero_length_reads_writes (NiceAddress *addr)
{
  NiceAgent *agent;
  guint stream_id;
  GIOStream *io_stream;
  GInputStream *input_stream;
  GOutputStream *output_stream;
  GPollableInputStream *pollable_input_stream;
  GPollableOutputStream *pollable_output_stream;
  GError *error = NULL;
  guint8 buf[1];  /* should never be accessed */

  agent = nice_agent_new_reliable (NULL, NICE_COMPATIBILITY_RFC5245);
  nice_agent_add_local_address (agent, addr);

  /* Add a stream. */
  stream_id = nice_agent_add_stream (agent, 1);

  /* Try building an I/O stream around it. */
  io_stream = nice_agent_get_io_stream (agent, stream_id, 1);
  g_assert (G_IS_IO_STREAM (io_stream));
  g_assert (NICE_IS_IO_STREAM (io_stream));

  input_stream = g_io_stream_get_input_stream (G_IO_STREAM (io_stream));
  output_stream = g_io_stream_get_output_stream (G_IO_STREAM (io_stream));
  pollable_input_stream = G_POLLABLE_INPUT_STREAM (input_stream);
  pollable_output_stream = G_POLLABLE_OUTPUT_STREAM (output_stream);

  /* Check zero-length reads and writes complete immediately without error. */
  g_assert (g_input_stream_read (input_stream, buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  g_assert (g_output_stream_write (output_stream, buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  g_assert (
      g_pollable_input_stream_read_nonblocking (pollable_input_stream,
          buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  g_assert (
      g_pollable_output_stream_write_nonblocking (pollable_output_stream,
          buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  /* Remove the component and check that zero-length reads and writes still
   * result in a 0 response, rather than any error. */
  nice_agent_remove_stream (agent, stream_id);
  g_assert (g_io_stream_is_closed (G_IO_STREAM (io_stream)));

  g_assert (g_input_stream_read (input_stream, buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  g_assert (g_output_stream_write (output_stream, buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  g_assert (
      g_pollable_input_stream_read_nonblocking (pollable_input_stream,
          buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  g_assert (
      g_pollable_output_stream_write_nonblocking (pollable_output_stream,
          buf, 0, NULL, &error) == 0);
  g_assert_no_error (error);

  g_object_unref (io_stream);
  g_object_unref (agent);
}

int
main (void)
{
  NiceAddress addr;

#ifdef G_OS_WIN32
  WSADATA w;
  WSAStartup (0x0202, &w);
#endif
  nice_address_init (&addr);
  g_type_init ();
  g_thread_init (NULL);

  g_assert (nice_address_set_from_string (&addr, "127.0.0.1"));

  test_invalid_stream (&addr);
  test_io_stream_properties (&addr);
  test_pollable_properties (&addr);
  test_pollable_cancellation (&addr);
  test_zero_length_reads_writes (&addr);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif

  return 0;
}

