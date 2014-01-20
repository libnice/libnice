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

/**
 * This is a comprehensive unit test for send() and recv() behaviour in libnice,
 * covering all APIs except the old nice_agent_attach_recv() one. It aims to
 * test the correctness of reliable and non-reliable I/O through libnice, using
 * a variety of data and a variety of buffer sizes.
 *
 * Abnormal features like error handling, zero-length buffer handling, stream
 * closure and cancellation are not tested.
 *
 * This is *not* a performance test, and would require significant work to be
 * useful as one. It allocates all of its buffers dynamically, and walks over
 * them frequently to set and check data.
 *
 * Several of the strategies in the test make use of random numbers. The seed
 * values for these are deterministically set (in main()), but may be specified
 * on the command line to allow fuzzing.
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

typedef enum {
  STREAM_AGENT,  /* nice_agent_[send|recv]() */
  STREAM_AGENT_NONBLOCKING,  /* nice_agent_[send|recv]_nonblocking() */
  STREAM_GIO,  /* Nice[Input|Output]Stream */
  STREAM_GSOURCE,  /* GPollable[Input|Output]Stream */
} StreamApi;
#define STREAM_API_N_ELEMENTS (STREAM_GSOURCE + 1)

typedef enum {
  BUFFER_SIZE_CONSTANT_LARGE,  /* always 65535 bytes */
  BUFFER_SIZE_CONSTANT_SMALL,  /* always 1024 bytes */
  BUFFER_SIZE_CONSTANT_TINY,  /* always 1 byte */
  BUFFER_SIZE_ASCENDING,  /* ascending powers of 2 */
  BUFFER_SIZE_RANDOM,  /* random every time */
} BufferSizeStrategy;
#define BUFFER_SIZE_STRATEGY_N_ELEMENTS (BUFFER_SIZE_RANDOM + 1)

typedef enum {
  BUFFER_DATA_CONSTANT,  /* fill with 0xfe */
  BUFFER_DATA_ASCENDING,  /* ascending values for each byte */
  BUFFER_DATA_PSEUDO_RANDOM,  /* every byte is pseudo-random */
} BufferDataStrategy;
#define BUFFER_DATA_STRATEGY_N_ELEMENTS (BUFFER_DATA_PSEUDO_RANDOM + 1)

typedef struct {
  /* Test configuration (immutable per test run). */
  gboolean reliable;
  StreamApi stream_api;
  BufferSizeStrategy transmit_buffer_size_strategy;
  BufferSizeStrategy receive_buffer_size_strategy;
  BufferDataStrategy buffer_data_strategy;
  gsize n_bytes;

  /* Test state. */
  GRand *transmit_size_rand;
  GRand *receive_size_rand;
  gsize transmitted_bytes;
  gsize received_bytes;
  gsize *other_received_bytes;
} TestData;

/* Whether @stream_api is blocking (vs. non-blocking). */
static gboolean
stream_api_is_blocking (StreamApi stream_api)
{
  switch (stream_api) {
  case STREAM_AGENT:
  case STREAM_GIO:
    return TRUE;
  case STREAM_AGENT_NONBLOCKING:
  case STREAM_GSOURCE:
    return FALSE;
  default:
    g_assert_not_reached ();
  }
}

/* Whether @stream_api only works for reliable NiceAgents. */
static gboolean
stream_api_is_reliable_only (StreamApi stream_api)
{
  switch (stream_api) {
  case STREAM_GSOURCE:
  case STREAM_GIO:
    return TRUE;
  case STREAM_AGENT:
  case STREAM_AGENT_NONBLOCKING:
    return FALSE;
  default:
    g_assert_not_reached ();
  }
}

/* Generate a size for the @buffer_index-th buffer. Guaranteed to be in
 * the interval [1, 1 << 16). ((1 << 16) is the maximum message size.) */
static gsize
generate_buffer_size (BufferSizeStrategy strategy, GRand *rand,
    guint buffer_index)
{
  switch (strategy) {
  case BUFFER_SIZE_CONSTANT_LARGE:
    return (1 << 16) - 1;

  case BUFFER_SIZE_CONSTANT_SMALL:
    return 4096;

  case BUFFER_SIZE_CONSTANT_TINY:
    return 1;

  case BUFFER_SIZE_ASCENDING:
    return CLAMP (1L << buffer_index, 1, (1 << 16) - 1);

  case BUFFER_SIZE_RANDOM:
    return g_rand_int_range (rand, 1, 1 << 16);

  default:
    g_assert_not_reached ();
  }
}

/* Fill the given @buf with @buf_len bytes of generated data. The data is
 * deterministically generated, so that:
 *     generate_buffer_data(_, I, buf, 2)
 * and
 *     generate_buffer_data(_, I+1, buf+1, 1)
 * generate the same buf[I+1] byte, for all I.
 *
 * The generation strategies are generally chosen to produce data which makes
 * send/receive errors (insertions, swaps, elisions) obvious. */
static void
generate_buffer_data (BufferDataStrategy strategy, gsize buffer_offset,
    guint8 *buf, gsize buf_len)
{
  switch (strategy) {
  case BUFFER_DATA_CONSTANT:
    memset (buf, 0xfe, buf_len);
    break;

  case BUFFER_DATA_ASCENDING: {
    gsize i;

    for (i = 0; i < buf_len; i++) {
      buf[i] = (i + buffer_offset) & 0xff;
    }

    break;
  }

  case BUFFER_DATA_PSEUDO_RANDOM: {
    gsize i;

    /* This can’t use GRand, because then the number of calls to g_rand_*()
     * methods would affect its output, and the bytes generated here have to be
     * entirely deterministic on @buffer_offset.
     *
     * Instead, use something akin to a LCG, except without any feedback
     * (because that would make it non-deterministic). The objective is to
     * generate numbers which are sufficiently pseudo-random that it’s likely
     * transpositions, elisions and insertions will be detected.
     *
     * The constants come from ‘ANSI C’ in:
     * http://en.wikipedia.org/wiki/Linear_congruential_generator
     */
    for (i = 0; i < buf_len; i++) {
      buf[i] = (1103515245 * (buffer_offset + i) + 12345) & 0xff;
    }

    break;
  }

  default:
    g_assert_not_reached ();
  }
}

/* Choose a size and allocate a receive buffer in @buf, ready to receive bytes
 * starting at @buffer_offset into the stream. Fill the buffer with poison
 * values to hopefully make incorrect writes/reads more obvious.
 *
 * @buf must be freed with g_free(). */
static void
generate_buffer_to_receive (TestIOStreamThreadData *data, gsize buffer_offset,
    guint8 **buf, gsize *buf_len)
{
  TestData *test_data = data->user_data;

  /* Allocate the buffer. */
  *buf_len = generate_buffer_size (test_data->receive_buffer_size_strategy,
      test_data->receive_size_rand, buffer_offset);
  *buf = g_malloc (*buf_len);

  /* Fill it with poison to try and detect incorrect writes. */
  memset (*buf, 0xaa, *buf_len);
}

/* Validate the length and data of a received buffer of length @buf_len, filled
 * with @len valid bytes. Updates the internal state machine to mark the bytes
 * as received. This consumes @buf. */
static void
validate_received_buffer (TestIOStreamThreadData *data, gsize buffer_offset,
    guint8 **buf, gsize buf_len, gssize len)
{
  TestData *test_data = data->user_data;
  guint8 *expected_buf;

  g_assert_cmpint (len, <=, buf_len);
  g_assert_cmpint (len, >=, 0);

  if (stream_api_is_blocking (test_data->stream_api) && data->reliable)
    g_assert_cmpint (len, ==, buf_len);

  /* Validate the buffer contents. */
  expected_buf = g_malloc (buf_len);
  memset (expected_buf, 0xaa, buf_len);
  generate_buffer_data (test_data->buffer_data_strategy, buffer_offset,
      expected_buf, len);
  g_assert (memcmp (*buf, expected_buf, buf_len) == 0);
  g_free (expected_buf);

  test_data->received_bytes += len;

  g_free (*buf);
}

/* Determine a size for the next transmit buffer, allocate it, and fill it with
 * data to be transmitted. */
static void
generate_buffer_to_transmit (TestIOStreamThreadData *data, gsize buffer_offset,
    guint8 **buf, gsize *buf_len)
{
  TestData *test_data = data->user_data;

  /* Allocate the buffer. */
  *buf_len = generate_buffer_size (test_data->transmit_buffer_size_strategy,
      test_data->transmit_size_rand, buffer_offset);
  *buf_len = MIN (*buf_len, test_data->n_bytes - test_data->transmitted_bytes);
  *buf = g_malloc (*buf_len);

  /* Fill it with data. */
  generate_buffer_data (test_data->buffer_data_strategy, buffer_offset,
      *buf, *buf_len);
}

/* Validate the number of bytes transmitted, and update the test’s internal
 * state machine. Consumes @buf. */
static void
notify_transmitted_buffer (TestIOStreamThreadData *data, gsize buffer_offset,
    guint8 **buf, gsize buf_len, gssize len)
{
  TestData *test_data = data->user_data;

  g_assert_cmpint (len, <=, buf_len);
  g_assert_cmpint (len, >=, 0);

  test_data->transmitted_bytes += len;

  g_free (*buf);
}

/*
 * Implementation using nice_agent_recv() and nice_agent_send().
 */
static void
read_thread_agent_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  TestData *test_data = data->user_data;
  guint stream_id, component_id;
  gpointer tmp;

  tmp = g_object_get_data (G_OBJECT (data->agent), "stream-id");
  stream_id = GPOINTER_TO_UINT (tmp);
  component_id = 1;

  while (test_data->received_bytes < test_data->n_bytes) {
    GError *error = NULL;
    guint8 *buf = NULL;
    gsize buf_len = 0;
    gssize len;

    /* Initialise a receive buffer. */
    generate_buffer_to_receive (data, test_data->received_bytes, &buf,
        &buf_len);

    /* Trim the receive buffer to avoid blocking on bytes which will never
     * appear. */
    if (data->reliable)
      buf_len = MIN (buf_len, test_data->n_bytes - test_data->received_bytes);

    /* Block on receiving some data. */
    len = nice_agent_recv (data->agent, stream_id, component_id, buf, buf_len,
        NULL, &error);
    g_assert_no_error (error);

    /* Check the buffer and update the test’s state machine. */
    validate_received_buffer (data, test_data->received_bytes, &buf, buf_len,
        len);
  }

  check_for_termination (data, &test_data->received_bytes,
      test_data->other_received_bytes, &test_data->transmitted_bytes,
      test_data->n_bytes);
}

static void
write_thread_agent_cb (GOutputStream *output_stream,
    TestIOStreamThreadData *data)
{
  TestData *test_data = data->user_data;
  guint stream_id, component_id;
  gpointer tmp;

  tmp = g_object_get_data (G_OBJECT (data->agent), "stream-id");
  stream_id = GPOINTER_TO_UINT (tmp);
  component_id = 1;

  while (test_data->transmitted_bytes < test_data->n_bytes) {
    GError *error = NULL;
    guint8 *buf = NULL;
    gsize buf_len = 0;
    gssize _len;
    gssize len = 0;

    /* Generate a buffer to transmit. */
    generate_buffer_to_transmit (data, test_data->transmitted_bytes, &buf,
        &buf_len);

    /* Transmit it. */
    do {
      _len = nice_agent_send_full (data->agent, stream_id, component_id,
          buf + len, buf_len - len, NULL, &error);

      /* Busy loop on EWOULDBLOCK. */
      if (_len == -1 &&
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
        g_clear_error (&error);
        continue;
      } else if (_len > 0) {
        len += _len;
      } else {
        len = _len;
      }

      g_assert_no_error (error);
    } while (len != -1 && (gsize) len < buf_len);

    /* Update the test’s buffer generation state machine. */
    notify_transmitted_buffer (data, test_data->transmitted_bytes, &buf,
        buf_len, len);
  }
}

/*
 * Implementation using nice_agent_recv_nonblocking() and
 * nice_agent_send_nonblocking().
 */
static void
read_thread_agent_nonblocking_cb (GInputStream *input_stream,
    TestIOStreamThreadData *data)
{
  TestData *test_data = data->user_data;
  guint stream_id, component_id;
  gpointer tmp;

  tmp = g_object_get_data (G_OBJECT (data->agent), "stream-id");
  stream_id = GPOINTER_TO_UINT (tmp);
  component_id = 1;

  while (test_data->received_bytes < test_data->n_bytes) {
    GError *error = NULL;
    guint8 *buf = NULL;
    gsize buf_len = 0;
    gssize len;

    /* Initialise a receive buffer. */
    generate_buffer_to_receive (data, test_data->received_bytes, &buf,
        &buf_len);

    /* Trim the receive buffer to avoid consuming the ‘done’ message. */
    if (data->reliable)
      buf_len = MIN (buf_len, test_data->n_bytes - test_data->received_bytes);

    /* Busy loop on receiving some data. */
    do {
      g_clear_error (&error);
      len = nice_agent_recv_nonblocking (data->agent, stream_id, component_id,
          buf, buf_len, NULL, &error);
    } while (len == -1 &&
        g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK));
    g_assert_no_error (error);

    /* Check the buffer and update the test’s state machine. */
    validate_received_buffer (data, test_data->received_bytes, &buf, buf_len,
        len);
  }

  check_for_termination (data, &test_data->received_bytes,
      test_data->other_received_bytes, &test_data->transmitted_bytes,
      test_data->n_bytes);
}

static void
write_thread_agent_nonblocking_cb (GOutputStream *output_stream,
    TestIOStreamThreadData *data)
{
  /* FIXME: There is no nice_agent_send_nonblocking(); nice_agent_send() is
   * non-blocking by default. */
  write_thread_agent_cb (output_stream, data);
}

/*
 * Implementation using NiceInputStream and NiceOutputStream.
 */
static void
read_thread_gio_cb (GInputStream *input_stream, TestIOStreamThreadData *data)
{
  TestData *test_data = data->user_data;

  while (test_data->received_bytes < test_data->n_bytes) {
    GError *error = NULL;
    guint8 *buf = NULL;
    gsize buf_len = 0;
    gssize len;

    /* Initialise a receive buffer. */
    generate_buffer_to_receive (data, test_data->received_bytes, &buf,
        &buf_len);

    /* Trim the receive buffer to avoid blocking on bytes which will never
     * appear. */
    buf_len = MIN (buf_len, test_data->n_bytes - test_data->received_bytes);

    /* Block on receiving some data. */
    len = g_input_stream_read (input_stream, buf, buf_len, NULL, &error);
    g_assert_no_error (error);

    /* Check the buffer and update the test’s state machine. */
    validate_received_buffer (data, test_data->received_bytes, &buf, buf_len,
        len);
  }

  check_for_termination (data, &test_data->received_bytes,
      test_data->other_received_bytes, &test_data->transmitted_bytes,
      test_data->n_bytes);
}

static void
write_thread_gio_cb (GOutputStream *output_stream, TestIOStreamThreadData *data)
{
  TestData *test_data = data->user_data;

  while (test_data->transmitted_bytes < test_data->n_bytes) {
    GError *error = NULL;
    guint8 *buf = NULL;
    gsize buf_len = 0;
    gssize len;
    gsize total_len = 0;

    /* Generate a buffer to transmit. */
    generate_buffer_to_transmit (data, test_data->transmitted_bytes, &buf,
        &buf_len);

    /* Transmit it. */
    do {
      len = g_output_stream_write (output_stream, buf + total_len,
          buf_len - total_len, NULL, &error);
      g_assert_no_error (error);
      total_len += len;
    } while (total_len < buf_len);

    /* Update the test’s buffer generation state machine. */
    notify_transmitted_buffer (data, test_data->transmitted_bytes, &buf,
        buf_len, total_len);
  }
}

/*
 * Implementation using GPollableInputStream and GPollableOutputStream.
 *
 * GSourceData is effectively the closure for the ‘for’ loop in other stream API
 * implementations.
 */
typedef struct {
  TestIOStreamThreadData *data;
  GMainLoop *main_loop;
} GSourceData;

static gboolean
read_stream_cb (GObject *pollable_stream, gpointer _user_data)
{
  GSourceData *gsource_data = _user_data;
  TestIOStreamThreadData *data = gsource_data->data;
  TestData *test_data = data->user_data;
  GError *error = NULL;
  guint8 *buf = NULL;
  gsize buf_len = 0;
  gssize len;

  /* Initialise a receive buffer. */
  generate_buffer_to_receive (data, test_data->received_bytes, &buf, &buf_len);

  /* Trim the receive buffer to avoid consuming the ‘done’ message. */
  buf_len = MIN (buf_len, test_data->n_bytes - test_data->received_bytes);

  /* Try to receive some data. */
  len = g_pollable_input_stream_read_nonblocking (
      G_POLLABLE_INPUT_STREAM (pollable_stream), buf, buf_len, NULL, &error);

  if (len == -1) {
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK);
    g_free (buf);
    return TRUE;
  }

  g_assert_no_error (error);

  /* Check the buffer and update the test’s state machine. */
  validate_received_buffer (data, test_data->received_bytes, &buf, buf_len,
      len);

  /* Termination time? */
  if (test_data->received_bytes == test_data->n_bytes) {
    g_main_loop_quit (gsource_data->main_loop);
    return FALSE;
  }

  return TRUE;
}

static void
read_thread_gsource_cb (GInputStream *input_stream,
    TestIOStreamThreadData *data)
{
  TestData *test_data = data->user_data;
  GSourceData gsource_data;
  GMainContext *main_context;
  GMainLoop *main_loop;
  GSource *stream_source;

  main_context = g_main_context_ref_thread_default ();
  main_loop = g_main_loop_new (main_context, FALSE);

  gsource_data.data = data;
  gsource_data.main_loop = main_loop;

  stream_source =
      g_pollable_input_stream_create_source (
          G_POLLABLE_INPUT_STREAM (input_stream), NULL);

  g_source_set_callback (stream_source, (GSourceFunc) read_stream_cb,
      &gsource_data, NULL);
  g_source_attach (stream_source, main_context);

  /* Run the main loop. */
  g_main_loop_run (main_loop);

  g_source_destroy (stream_source);
  g_source_unref (stream_source);
  g_main_loop_unref (main_loop);
  g_main_context_unref (main_context);

  /* Termination? */
  check_for_termination (data, &test_data->received_bytes,
      test_data->other_received_bytes, &test_data->transmitted_bytes,
      test_data->n_bytes);
}

static gboolean
write_stream_cb (GObject *pollable_stream, gpointer _user_data)
{
  GSourceData *gsource_data = _user_data;
  TestIOStreamThreadData *data = gsource_data->data;
  TestData *test_data = data->user_data;
  GError *error = NULL;
  guint8 *buf = NULL;
  gsize buf_len = 0;
  gssize len;

  /* Initialise a receive buffer. */
  generate_buffer_to_transmit (data, test_data->transmitted_bytes, &buf,
      &buf_len);

  /* Try to transmit some data. */
  len = g_pollable_output_stream_write_nonblocking (
      G_POLLABLE_OUTPUT_STREAM (pollable_stream), buf, buf_len, NULL, &error);

  if (len == -1) {
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK);
    g_free (buf);
    return TRUE;
  }

  g_assert_no_error (error);

  /* Update the test’s buffer generation state machine. */
  notify_transmitted_buffer (data, test_data->transmitted_bytes, &buf, buf_len,
      len);

  /* Termination time? */
  if (test_data->transmitted_bytes == test_data->n_bytes) {
    g_main_loop_quit (gsource_data->main_loop);
    return FALSE;
  }

  return TRUE;
}

static void
write_thread_gsource_cb (GOutputStream *output_stream,
    TestIOStreamThreadData *data)
{
  GSourceData gsource_data;
  GMainContext *main_context;
  GMainLoop *main_loop;
  GSource *stream_source;

  main_context = g_main_context_ref_thread_default ();
  main_loop = g_main_loop_new (main_context, FALSE);

  gsource_data.data = data;
  gsource_data.main_loop = main_loop;

  stream_source =
      g_pollable_output_stream_create_source (
          G_POLLABLE_OUTPUT_STREAM (output_stream), NULL);

  g_source_set_callback (stream_source, (GSourceFunc) write_stream_cb,
      &gsource_data, NULL);
  g_source_attach (stream_source, main_context);

  /* Run the main loop. */
  g_main_loop_run (main_loop);

  g_source_destroy (stream_source);
  g_source_unref (stream_source);
  g_main_loop_unref (main_loop);
  g_main_context_unref (main_context);
}

static void
test_data_init (TestData *data, gboolean reliable, StreamApi stream_api,
    gsize n_bytes, BufferSizeStrategy transmit_buffer_size_strategy,
    BufferSizeStrategy receive_buffer_size_strategy,
    BufferDataStrategy buffer_data_strategy, guint32 transmit_seed,
    guint32 receive_seed, gsize *other_received_bytes)
{
  data->reliable = reliable;
  data->stream_api = stream_api;
  data->n_bytes = n_bytes;
  data->transmit_buffer_size_strategy = transmit_buffer_size_strategy;
  data->receive_buffer_size_strategy = receive_buffer_size_strategy;
  data->buffer_data_strategy = buffer_data_strategy;
  data->transmit_size_rand = g_rand_new_with_seed (transmit_seed);
  data->receive_size_rand = g_rand_new_with_seed (receive_seed);
  data->transmitted_bytes = 0;
  data->received_bytes = 0;
  data->other_received_bytes = other_received_bytes;
}

/*
 * Test closures.
 */
static void
test_data_clear (TestData *data)
{
  g_rand_free (data->receive_size_rand);
  g_rand_free (data->transmit_size_rand);
}

static void
test (gboolean reliable, StreamApi stream_api, gsize n_bytes,
    BufferSizeStrategy transmit_buffer_size_strategy,
    BufferSizeStrategy receive_buffer_size_strategy,
    BufferDataStrategy buffer_data_strategy,
    guint32 transmit_seed, guint32 receive_seed,
    guint deadlock_timeout)
{
  TestData l_data, r_data;

  /* Indexed by StreamApi. */
  const TestIOStreamCallbacks callbacks[] = {
    { read_thread_agent_cb,
      write_thread_agent_cb, NULL, NULL, },  /* STREAM_AGENT */
    { read_thread_agent_nonblocking_cb, write_thread_agent_nonblocking_cb,
      NULL, NULL, },  /* STREAM_AGENT_NONBLOCKING */
    { read_thread_gio_cb, write_thread_gio_cb, NULL, NULL, },  /* STREAM_GIO */
    { read_thread_gsource_cb, write_thread_gsource_cb,
      NULL, NULL },  /* STREAM_GSOURCE */
  };

  test_data_init (&l_data, reliable, stream_api, n_bytes,
      transmit_buffer_size_strategy, receive_buffer_size_strategy,
      buffer_data_strategy, transmit_seed, receive_seed,
      &r_data.received_bytes);
  test_data_init (&r_data, reliable, stream_api, n_bytes,
      transmit_buffer_size_strategy, receive_buffer_size_strategy,
      buffer_data_strategy, transmit_seed, receive_seed,
      &l_data.received_bytes);

  run_io_stream_test (deadlock_timeout, reliable, &callbacks[stream_api],
      &l_data, NULL, &r_data, NULL);

  test_data_clear (&r_data);
  test_data_clear (&l_data);
}

/* Options with default values. */
guint32 option_transmit_seed = 0;
guint32 option_receive_seed = 0;
gsize option_n_bytes = 100000;
guint option_timeout = 1200;  /* seconds */
gboolean option_long_mode = FALSE;

static GOptionEntry entries[] = {
  { "transmit-seed", 0, 0, G_OPTION_ARG_INT, &option_transmit_seed,
    "Seed for transmission RNG", "S" },
  { "receive-seed", 0, 0, G_OPTION_ARG_INT, &option_receive_seed,
    "Seed for reception RNG", "S" },
  { "n-bytes", 'n', 0, G_OPTION_ARG_INT64, &option_n_bytes,
    "Number of bytes to send in each test (default 100000)", "N" },
  { "timeout", 't', 0, G_OPTION_ARG_INT, &option_timeout,
    "Deadlock detection timeout length, in seconds (default: 1200)", "S" },
  { "long-mode", 'l', 0, G_OPTION_ARG_NONE, &option_long_mode,
    "Enable all tests, rather than a fast subset", NULL },
  { NULL },
};

int
main (int argc, char *argv[])
{
  gboolean reliable;
  StreamApi stream_api;
  BufferSizeStrategy transmit_buffer_size_strategy;
  BufferSizeStrategy receive_buffer_size_strategy;
  BufferDataStrategy buffer_data_strategy;
  guint32 transmit_seed;
  guint32 receive_seed;
  gsize n_bytes;
  guint deadlock_timeout;
  gboolean long_mode;
  GOptionContext *context;
  GError *error = NULL;

  /* Argument parsing. Allow some of the test parameters to be specified on the
   * command line. */
  context = g_option_context_new ("— test send()/recv() correctness");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("Option parsing failed: %s\n", error->message);
    g_error_free (error);
    exit (1);
  }

  /* Set up the defaults. */
  transmit_seed = option_transmit_seed;
  receive_seed = option_receive_seed;
  n_bytes = option_n_bytes;
  deadlock_timeout = option_timeout;
  long_mode = option_long_mode;

#ifdef G_OS_WIN32
  WSADATA w;
  WSAStartup (0x0202, &w);
#endif
  g_type_init ();
  g_thread_init (NULL);

  if (!long_mode) {
    /* Quick mode. Just test each of the stream APIs in reliable and
     * non-reliable mode, with a single pair of buffer strategies, and a single
     * data strategy. */

    /* Reliability. */
    for (reliable = 0; reliable < 2; reliable++) {
      /* Stream API. */
      for (stream_api = 0;
           (guint) stream_api < STREAM_API_N_ELEMENTS;
           stream_api++) {
        /* GIO streams must always be reliable. */
        if (!reliable && stream_api_is_reliable_only (stream_api))
          continue;

        /* Non-reliable socket receives require large buffers. */
        if (reliable) {
          receive_buffer_size_strategy = BUFFER_SIZE_RANDOM;
        } else {
          receive_buffer_size_strategy = BUFFER_SIZE_CONSTANT_LARGE;
        }

        transmit_buffer_size_strategy = BUFFER_SIZE_RANDOM;
        buffer_data_strategy = BUFFER_DATA_PSEUDO_RANDOM;

        g_debug ("Running test (%u, %u, %" G_GSIZE_FORMAT ", %u, "
            "%u, %u, %u, %u)…",
            reliable, stream_api, n_bytes, transmit_buffer_size_strategy,
            receive_buffer_size_strategy, buffer_data_strategy,
            transmit_seed, receive_seed);
        test (reliable, stream_api, n_bytes, transmit_buffer_size_strategy,
            receive_buffer_size_strategy, buffer_data_strategy,
            transmit_seed, receive_seed,
            deadlock_timeout / 20  /* arbitrary reduction */);
      }
    }

    goto done;
  }

  /* Transmit buffer strategy. */
  for (transmit_buffer_size_strategy = 0;
       (guint) transmit_buffer_size_strategy < BUFFER_SIZE_STRATEGY_N_ELEMENTS;
       transmit_buffer_size_strategy++) {
    /* Receive buffer strategy. */
    for (receive_buffer_size_strategy = 0;
         (guint) receive_buffer_size_strategy < BUFFER_SIZE_STRATEGY_N_ELEMENTS;
         receive_buffer_size_strategy++) {
      /* Transmit data strategy. */
      for (buffer_data_strategy = 0;
           (guint) buffer_data_strategy < BUFFER_DATA_STRATEGY_N_ELEMENTS;
           buffer_data_strategy++) {
        /* Reliability. */
        for (reliable = 0; reliable < 2; reliable++) {
          /* Stream API. */
          for (stream_api = 0;
               (guint) stream_api < STREAM_API_N_ELEMENTS;
               stream_api++) {
            /* GIO streams must always be reliable. */
            if (!reliable && stream_api_is_reliable_only (stream_api))
              continue;

            /* Non-reliable socket receives require large buffers. We don’t
             * claim to support using them with small (<< 65535B) buffers, so
             * don’t test them. */
            if (!reliable &&
                receive_buffer_size_strategy != BUFFER_SIZE_CONSTANT_LARGE)
              continue;

            /* Non-reliable socket transmits will always block with huge
             * buffers. */
            if (!reliable &&
                transmit_buffer_size_strategy == BUFFER_SIZE_CONSTANT_LARGE)
              continue;

            g_debug ("Running test (%u, %u, %" G_GSIZE_FORMAT ", %u, "
                "%u, %u, %u, %u)…",
                reliable, stream_api, n_bytes, transmit_buffer_size_strategy,
                receive_buffer_size_strategy, buffer_data_strategy,
                transmit_seed, receive_seed);
            test (reliable, stream_api, n_bytes, transmit_buffer_size_strategy,
                receive_buffer_size_strategy, buffer_data_strategy,
                transmit_seed, receive_seed,
                deadlock_timeout);
          }
        }
      }
    }
  }

done:
#ifdef G_OS_WIN32
  WSACleanup ();
#endif

  return 0;
}
