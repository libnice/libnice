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

/* Maximum IP payload ((1 << 16) - 1), minus IP header, minus UDP header. */
#define MAX_MESSAGE_SIZE (65535 - 20 - 8) /* bytes */

typedef enum {
  STREAM_AGENT,  /* nice_agent_[send|recv]() */
  STREAM_AGENT_NONBLOCKING,  /* nice_agent_[send|recv]_nonblocking() */
  STREAM_GIO,  /* Nice[Input|Output]Stream */
  STREAM_GSOURCE,  /* GPollable[Input|Output]Stream */
} StreamApi;
#define STREAM_API_N_ELEMENTS (STREAM_GSOURCE + 1)

typedef enum {
  BUFFER_SIZE_CONSTANT_LARGE,  /* always 65535 bytes */
  BUFFER_SIZE_CONSTANT_SMALL,  /* always 4096 bytes */
  BUFFER_SIZE_CONSTANT_TINY,  /* always 1 byte */
  BUFFER_SIZE_ASCENDING,  /* ascending powers of 2 */
  BUFFER_SIZE_RANDOM,  /* random every time */
} BufferSizeStrategy;
#define BUFFER_SIZE_STRATEGY_N_ELEMENTS (BUFFER_SIZE_RANDOM + 1)

typedef enum {
  BUFFER_COUNT_CONSTANT_ONE,  /* always a single buffer */
  BUFFER_COUNT_CONSTANT_TWO,  /* always two buffers */
  BUFFER_COUNT_RANDOM,  /* random every time */
} BufferCountStrategy;
#define BUFFER_COUNT_STRATEGY_N_ELEMENTS (BUFFER_COUNT_RANDOM + 1)

typedef enum {
  MESSAGE_COUNT_CONSTANT_ONE,  /* always a single message */
  MESSAGE_COUNT_CONSTANT_TWO,  /* always two messages */
  MESSAGE_COUNT_RANDOM,  /* random every time */
} MessageCountStrategy;
#define MESSAGE_COUNT_STRATEGY_N_ELEMENTS (MESSAGE_COUNT_RANDOM + 1)

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
  struct {
    BufferSizeStrategy buffer_size_strategy;
    BufferCountStrategy buffer_count_strategy;
    MessageCountStrategy message_count_strategy;
  } transmit;
  struct {
    BufferSizeStrategy buffer_size_strategy;
    BufferCountStrategy buffer_count_strategy;
    MessageCountStrategy message_count_strategy;
  } receive;
  BufferDataStrategy buffer_data_strategy;
  gsize n_bytes;
  guint n_messages;

  /* Test state. */
  GRand *transmit_size_rand;
  GRand *receive_size_rand;
  gsize transmitted_bytes;
  gsize received_bytes;
  gsize *other_received_bytes;
  guint transmitted_messages;
  guint received_messages;
  guint *other_received_messages;
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

/* Whether @stream_api supports vectored I/O (multiple buffers or messages). */
static gboolean
stream_api_supports_vectored_io (StreamApi stream_api)
{
  switch (stream_api) {
  case STREAM_AGENT:
  case STREAM_AGENT_NONBLOCKING:
    return TRUE;
  case STREAM_GSOURCE:
  case STREAM_GIO:
    return FALSE;
  default:
    g_assert_not_reached ();
  }
}

/* Generate a size for the buffer containing the @buffer_offset-th byte.
 * Guaranteed to be in the interval [1, 1 << 16). ((1 << 16) is the maximum
 * message size.) */
static gsize
generate_buffer_size (BufferSizeStrategy strategy, GRand *grand,
    gsize buffer_offset)
{
  switch (strategy) {
  case BUFFER_SIZE_CONSTANT_LARGE:
    return (1 << 16) - 1;

  case BUFFER_SIZE_CONSTANT_SMALL:
    return 4096;

  case BUFFER_SIZE_CONSTANT_TINY:
    return 1;

  case BUFFER_SIZE_ASCENDING:
    return CLAMP (1L << buffer_offset, 1, (1 << 16) - 1);

  case BUFFER_SIZE_RANDOM:
    return g_rand_int_range (grand, 1, 1 << 16);

  default:
    g_assert_not_reached ();
  }
}

/* Generate a number of buffers to allocate when receiving the @buffer_offset-th
 * byte. Guaranteed to be in the interval [1, 100], where 100 was chosen
 * arbitrarily.*/
static guint
generate_buffer_count (BufferCountStrategy strategy, GRand *grand,
    gsize buffer_offset)
{
  switch (strategy) {
  case BUFFER_COUNT_CONSTANT_ONE:
    return 1;

  case BUFFER_COUNT_CONSTANT_TWO:
    return 2;

  case BUFFER_COUNT_RANDOM:
    return g_rand_int_range (grand, 1, 100 + 1);

  default:
    g_assert_not_reached ();
  }
}

/* Generate a number of messages to allocate and receive into when receiving the
 * @buffer_offset-th byte. Guaranteed to be in the interval [1, 100], where 100
 * was chosen arbitrarily.*/
static guint
generate_message_count (MessageCountStrategy strategy, GRand *grand,
    guint buffer_index)
{
  switch (strategy) {
  case MESSAGE_COUNT_CONSTANT_ONE:
    return 1;

  case MESSAGE_COUNT_CONSTANT_TWO:
    return 2;

  case MESSAGE_COUNT_RANDOM:
    return g_rand_int_range (grand, 1, 100 + 1);

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
  *buf_len = generate_buffer_size (test_data->receive.buffer_size_strategy,
      test_data->receive_size_rand, buffer_offset);
  *buf = g_malloc (*buf_len);

  /* Fill it with poison to try and detect incorrect writes. */
  memset (*buf, 0xaa, *buf_len);
}

/* Similar to generate_buffer_to_receive(), but generate an entire message array
 * with multiple buffers instead.
 *
 * @max_buffer_size may be used to limit the total size of all the buffers in
 * all the messages, for example to avoid blocking on receiving data which will
 * never be sent. This only applies for blocking, reliable stream APIs.
 *
 * @max_n_messages may be used to limit the number of messages generated, to
 * avoid blocking on receiving messages which will never be sent. This only
 * applies for blocking, non-reliable stream APIs.
 *
 * @messages must be freed with g_free(), as must all of the buffer arrays and
 * the buffers themselves. */
static void
generate_messages_to_receive (TestIOStreamThreadData *data, gsize buffer_offset,
    NiceInputMessage **messages, guint *n_messages, gsize max_buffer_size,
    guint max_n_messages)
{
  TestData *test_data = data->user_data;
  guint i;

  /* Allocate the messages. */
  *n_messages =
      generate_message_count (test_data->receive.message_count_strategy,
          test_data->receive_size_rand, buffer_offset);

  if (!data->reliable)
    *n_messages = MIN (*n_messages, max_n_messages);

  *messages = g_malloc_n (*n_messages, sizeof (NiceInputMessage));

  for (i = 0; i < *n_messages; i++) {
    NiceInputMessage *message = &((*messages)[i]);
    guint j;

    message->n_buffers =
        generate_buffer_count (test_data->receive.buffer_count_strategy,
            test_data->receive_size_rand, buffer_offset);
    message->buffers = g_malloc_n (message->n_buffers, sizeof (GInputVector));
    message->from = NULL;
    message->length = 0;

    for (j = 0; j < (guint) message->n_buffers; j++) {
      GInputVector *buffer = &message->buffers[j];
      gsize buf_len;

      buf_len =
          generate_buffer_size (test_data->receive.buffer_size_strategy,
              test_data->receive_size_rand, buffer_offset);

      /* Trim the buffer length if it would otherwise cause the API to block. */
      if (data->reliable) {
        buf_len = MIN (buf_len, max_buffer_size);
        max_buffer_size -= buf_len;
      }

      buffer->size = buf_len;
      buffer->buffer = g_malloc (buffer->size);

      /* Fill it with poison to try and detect incorrect writes. */
      memset (buffer->buffer, 0xaa, buffer->size);

      /* If we’ve hit the max_buffer_size, adjust the buffer and message counts
       * and run away. */
      if (data->reliable && max_buffer_size == 0) {
        message->n_buffers = j + 1;
        *n_messages = i + 1;
        return;
      }
    }
  }
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

  /* Validate the buffer contents.
   *
   * Note: Buffers can only be validated up to valid_len. The buffer may
   * have been re-used internally (e.g. by receiving a STUN message, then
   * overwriting it with a data packet), so we can’t guarantee that the
   * bytes beyond valid_len have been untouched. */
  expected_buf = g_malloc (buf_len);
  memset (expected_buf, 0xaa, buf_len);
  generate_buffer_data (test_data->buffer_data_strategy, buffer_offset,
      expected_buf, len);
  g_assert (memcmp (*buf, expected_buf, len) == 0);
  g_free (expected_buf);

  test_data->received_bytes += len;

  g_free (*buf);
}

/* Similar to validate_received_buffer(), except it validates a message array
 * instead of a single buffer. This consumes @messages. */
static void
validate_received_messages (TestIOStreamThreadData *data, gsize buffer_offset,
    NiceInputMessage *messages, guint n_messages, gint n_valid_messages)
{
  TestData *test_data = data->user_data;
  guint i;
  gsize prev_message_len = G_MAXSIZE;

  g_assert_cmpint (n_valid_messages, <=, n_messages);
  g_assert_cmpint (n_valid_messages, >=, 0);

  if (stream_api_is_blocking (test_data->stream_api))
    g_assert_cmpint (n_valid_messages, ==, n_messages);

  test_data->received_messages += n_valid_messages;

  /* Validate the message contents. */
  for (i = 0; i < (guint) n_valid_messages; i++) {
    NiceInputMessage *message = &messages[i];
    guint j;
    gsize total_buf_len = 0;
    gsize message_len_remaining = message->length;

    g_assert_cmpint (message->n_buffers, >, 0);

    for (j = 0; j < (guint) message->n_buffers; j++) {
      GInputVector *buffer = &message->buffers[j];
      gsize valid_len;

      /* See note above about valid_len. */
      total_buf_len += buffer->size;
      valid_len = MIN (message_len_remaining, buffer->size);

      /* Only validate buffer content for reliable mode, anything could
       * be received in UDP mode
       */
      if (test_data->reliable) {
        guint8 *expected_buf;

        expected_buf = g_malloc (buffer->size);
        memset (expected_buf, 0xaa, buffer->size);
        generate_buffer_data (test_data->buffer_data_strategy, buffer_offset,
            expected_buf, valid_len);
        g_assert_cmpint (memcmp (buffer->buffer, expected_buf, valid_len), ==,
            0);
        g_free (expected_buf);
        buffer_offset += valid_len;
        message_len_remaining -= valid_len;
      }
      test_data->received_bytes += valid_len;
    }

    g_assert_cmpuint (message->length, <=, total_buf_len);
    g_assert_cmpuint (message->length, >=, 0);

    /* No non-empty messages can follow an empty message. */
    if (prev_message_len == 0)
      g_assert_cmpuint (message->length, ==, 0);
    prev_message_len = message->length;

    /* If the API was blocking, it should have completely filled the message. */
    if (stream_api_is_blocking (test_data->stream_api) && data->reliable)
      g_assert_cmpuint (message->length, ==, total_buf_len);

    g_assert (message->from == NULL);
  }

  /* Free all messages. */
  for (i = 0; i < (guint) n_messages; i++) {
    NiceInputMessage *message = &messages[i];
    guint j;

    for (j = 0; j < (guint) message->n_buffers; j++) {
      GInputVector *buffer = &message->buffers[j];

      g_free (buffer->buffer);
    }

    g_free (message->buffers);
  }

  g_free (messages);
}

/* Determine a size for the next transmit buffer, allocate it, and fill it with
 * data to be transmitted. */
static void
generate_buffer_to_transmit (TestIOStreamThreadData *data, gsize buffer_offset,
    guint8 **buf, gsize *buf_len)
{
  TestData *test_data = data->user_data;

  /* Allocate the buffer. */
  *buf_len = generate_buffer_size (test_data->transmit.buffer_size_strategy,
      test_data->transmit_size_rand, buffer_offset);
  *buf_len = MIN (*buf_len, test_data->n_bytes - test_data->transmitted_bytes);
  *buf = g_malloc (*buf_len);

  /* Fill it with data. */
  generate_buffer_data (test_data->buffer_data_strategy, buffer_offset,
      *buf, *buf_len);
}

/* Similar to generate_buffer_to_transmit(), except that it generates an array
 * of NiceOutputMessages rather than a single buffer. */
static void
generate_messages_to_transmit (TestIOStreamThreadData *data,
    gsize buffer_offset, NiceOutputMessage **messages, guint *n_messages)
{
  TestData *test_data = data->user_data;
  guint i;
  gsize total_buf_len = 0;

  /* Determine the number of messages to send. */
  *n_messages =
      generate_message_count (test_data->transmit.message_count_strategy,
          test_data->transmit_size_rand, buffer_offset);
  *n_messages =
      MIN (*n_messages,
          test_data->n_messages - test_data->transmitted_messages);

  *messages = g_malloc_n (*n_messages, sizeof (NiceOutputMessage));

  for (i = 0; i < *n_messages; i++) {
    NiceOutputMessage *message = &((*messages)[i]);
    guint j;
    gsize max_message_size;
    gsize message_len = 0;

    message->n_buffers =
        generate_buffer_count (test_data->transmit.buffer_count_strategy,
            test_data->transmit_size_rand, buffer_offset);
    message->buffers = g_malloc_n (message->n_buffers, sizeof (GOutputVector));

    /* Limit the overall message size to the smaller of (n_bytes / n_messages)
     * and MAX_MESSAGE_SIZE, to ensure each message is non-empty. */
    max_message_size =
        MIN ((test_data->n_bytes / test_data->n_messages), MAX_MESSAGE_SIZE);

    for (j = 0; j < (guint) message->n_buffers; j++) {
      GOutputVector *buffer = &message->buffers[j];
      gsize buf_len;
      guint8 *buf;

      buf_len =
          generate_buffer_size (test_data->transmit.buffer_size_strategy,
              test_data->transmit_size_rand, buffer_offset);
      buf_len =
          MIN (buf_len,
              test_data->n_bytes - test_data->transmitted_bytes - total_buf_len);
      buf_len = MIN (buf_len, max_message_size - message_len);

      buffer->size = buf_len;
      buf = g_malloc (buffer->size);
      buffer->buffer = buf;
      message_len += buf_len;
      total_buf_len += buf_len;

      /* Fill it with data. */
      generate_buffer_data (test_data->buffer_data_strategy, buffer_offset,
          buf, buf_len);

      buffer_offset += buf_len;

      /* Reached the maximum UDP payload size? */
      if (message_len >= max_message_size) {
        message->n_buffers = j + 1;
        break;
      }
    }

    g_assert_cmpuint (message_len, <=, max_message_size);
  }
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

static gsize
output_message_get_size (const NiceOutputMessage *message)
{
  guint i;
  gsize message_len = 0;

  /* Find the total size of the message */
  for (i = 0;
       (message->n_buffers >= 0 && i < (guint) message->n_buffers) ||
           (message->n_buffers < 0 && message->buffers[i].buffer != NULL);
       i++)
    message_len += message->buffers[i].size;

  return message_len;
}

/* Similar to notify_transmitted_buffer(), except it operates on an array of
 * messages from generate_messages_to_transmit(). */
static void
notify_transmitted_messages (TestIOStreamThreadData *data, gsize buffer_offset,
    NiceOutputMessage **messages, guint n_messages, gint n_sent_messages)
{
  TestData *test_data = data->user_data;
  guint i;

  g_assert_cmpint (n_sent_messages, <=, n_messages);
  g_assert_cmpint (n_sent_messages, >=, 0);

  test_data->transmitted_messages += n_sent_messages;

  for (i = 0; i < n_messages; i++) {
    NiceOutputMessage *message = &((*messages)[i]);
    guint j;

    if (i < (guint) n_sent_messages)
      test_data->transmitted_bytes += output_message_get_size (message);

    for (j = 0; j < (guint) message->n_buffers; j++) {
      GOutputVector *buffer = &message->buffers[j];

      g_free ((guint8 *) buffer->buffer);
    }

    g_free (message->buffers);
  }

  g_free (*messages);
}

/*
 * Implementation using nice_agent_recv_messages() and nice_agent_send().
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
    NiceInputMessage *messages;
    guint n_messages;
    gint n_valid_messages;

    /* Initialise an array of messages to receive into. */
    generate_messages_to_receive (data, test_data->received_bytes, &messages,
        &n_messages, test_data->n_bytes - test_data->received_bytes,
        test_data->n_messages - test_data->received_messages);

    /* Block on receiving some data. */
    n_valid_messages = nice_agent_recv_messages (data->agent, stream_id,
        component_id, messages, n_messages, NULL, &error);
    g_assert_no_error (error);

    /* Check the messages and update the test’s state machine. */
    validate_received_messages (data, test_data->received_bytes, messages,
        n_messages, n_valid_messages);
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
    NiceOutputMessage *messages;
    guint n_messages;
    gint n_sent_messages;

    /* Generate a buffer to transmit. */
    generate_messages_to_transmit (data, test_data->transmitted_bytes,
        &messages, &n_messages);

    /* Busy loop on receiving some data. */
    do {
      g_clear_error (&error);
      n_sent_messages = nice_agent_send_messages_nonblocking (data->agent,
          stream_id, component_id, messages, n_messages, NULL, &error);
    } while (n_sent_messages == -1 &&
        g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK));
    g_assert_no_error (error);

    /* Update the test’s buffer generation state machine. */
    notify_transmitted_messages (data, test_data->transmitted_bytes, &messages,
        n_messages, n_sent_messages);
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
    NiceInputMessage *messages;
    guint n_messages;
    gint n_valid_messages;

    /* Initialise an array of messages to receive into. */
    generate_messages_to_receive (data, test_data->received_bytes, &messages,
        &n_messages, test_data->n_bytes - test_data->received_bytes,
        test_data->n_messages - test_data->received_messages);

    /* Trim n_messages to avoid consuming the ‘done’ message. */
    n_messages =
        MIN (n_messages, test_data->n_messages - test_data->received_messages);

    /* Busy loop on receiving some data. */
    do {
      g_clear_error (&error);
      n_valid_messages = nice_agent_recv_messages_nonblocking (data->agent,
          stream_id, component_id, messages, n_messages, NULL, &error);
    } while (n_valid_messages == -1 &&
        g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK));
    g_assert_no_error (error);

    /* Check the messages and update the test’s state machine. */
    validate_received_messages (data, test_data->received_bytes, messages,
        n_messages, n_valid_messages);
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
    g_error_free (error);
    g_free (buf);
    return G_SOURCE_CONTINUE;
  }

  g_assert_no_error (error);

  /* Check the buffer and update the test’s state machine. */
  validate_received_buffer (data, test_data->received_bytes, &buf, buf_len,
      len);

  /* Termination time? */
  if (test_data->received_bytes == test_data->n_bytes) {
    g_main_loop_quit (gsource_data->main_loop);
    return G_SOURCE_REMOVE;
  }

  return G_SOURCE_CONTINUE;
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
    return G_SOURCE_CONTINUE;
  }

  g_assert_no_error (error);

  /* Update the test’s buffer generation state machine. */
  notify_transmitted_buffer (data, test_data->transmitted_bytes, &buf, buf_len,
      len);

  /* Termination time? */
  if (test_data->transmitted_bytes == test_data->n_bytes) {
    g_main_loop_quit (gsource_data->main_loop);
    return G_SOURCE_REMOVE;
  }

  return G_SOURCE_CONTINUE;
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
    gsize n_bytes, guint n_messages,
    BufferSizeStrategy transmit_buffer_size_strategy,
    BufferCountStrategy transmit_buffer_count_strategy,
    MessageCountStrategy transmit_message_count_strategy,
    BufferSizeStrategy receive_buffer_size_strategy,
    BufferCountStrategy receive_buffer_count_strategy,
    MessageCountStrategy receive_message_count_strategy,
    BufferDataStrategy buffer_data_strategy, guint32 transmit_seed,
    guint32 receive_seed, gsize *other_received_bytes,
    guint *other_received_messages)
{
  data->reliable = reliable;
  data->stream_api = stream_api;
  data->n_bytes = n_bytes;
  data->n_messages = n_messages;
  data->transmit.buffer_size_strategy = transmit_buffer_size_strategy;
  data->transmit.buffer_count_strategy = transmit_buffer_count_strategy;
  data->transmit.message_count_strategy = transmit_message_count_strategy;
  data->receive.buffer_size_strategy = receive_buffer_size_strategy;
  data->receive.buffer_count_strategy = receive_buffer_count_strategy;
  data->receive.message_count_strategy = receive_message_count_strategy;
  data->buffer_data_strategy = buffer_data_strategy;
  data->transmit_size_rand = g_rand_new_with_seed (transmit_seed);
  data->receive_size_rand = g_rand_new_with_seed (receive_seed);
  data->transmitted_bytes = 0;
  data->received_bytes = 0;
  data->other_received_bytes = other_received_bytes;
  data->transmitted_messages = 0;
  data->received_messages = 0;
  data->other_received_messages = other_received_messages;
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
test (gboolean reliable, StreamApi stream_api, gsize n_bytes, guint n_messages,
    BufferSizeStrategy transmit_buffer_size_strategy,
    BufferCountStrategy transmit_buffer_count_strategy,
    MessageCountStrategy transmit_message_count_strategy,
    BufferSizeStrategy receive_buffer_size_strategy,
    BufferCountStrategy receive_buffer_count_strategy,
    MessageCountStrategy receive_message_count_strategy,
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

  test_data_init (&l_data, reliable, stream_api, n_bytes, n_messages,
      transmit_buffer_size_strategy, transmit_buffer_count_strategy,
      transmit_message_count_strategy, receive_buffer_size_strategy,
      receive_buffer_count_strategy, receive_message_count_strategy,
      buffer_data_strategy, transmit_seed, receive_seed,
      &r_data.received_bytes, &r_data.received_messages);
  test_data_init (&r_data, reliable, stream_api, n_bytes, n_messages,
      transmit_buffer_size_strategy, transmit_buffer_count_strategy,
      transmit_message_count_strategy, receive_buffer_size_strategy,
      receive_buffer_count_strategy, receive_message_count_strategy,
      buffer_data_strategy, transmit_seed, receive_seed,
      &l_data.received_bytes, &l_data.received_messages);

  run_io_stream_test (deadlock_timeout, reliable, &callbacks[stream_api],
      &l_data, NULL, &r_data, NULL);

  test_data_clear (&r_data);
  test_data_clear (&l_data);
}

/* Options with default values. */
guint32 option_transmit_seed = 0;
guint32 option_receive_seed = 0;
gsize option_n_bytes = 10000;
guint option_n_messages = 50;
guint option_timeout = 1200;  /* seconds */
gboolean option_long_mode = FALSE;

static GOptionEntry entries[] = {
  { "transmit-seed", 0, 0, G_OPTION_ARG_INT, &option_transmit_seed,
    "Seed for transmission RNG", "S" },
  { "receive-seed", 0, 0, G_OPTION_ARG_INT, &option_receive_seed,
    "Seed for reception RNG", "S" },
  { "n-bytes", 'n', 0, G_OPTION_ARG_INT64, &option_n_bytes,
    "Number of bytes to send in each test (default 10000)", "N" },
  { "n-messages", 'm', 0, G_OPTION_ARG_INT64, &option_n_messages,
    "Number of messages to send in each test (default 50)", "M" },
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
  BufferCountStrategy transmit_buffer_count_strategy;
  MessageCountStrategy transmit_message_count_strategy;
  BufferSizeStrategy receive_buffer_size_strategy;
  BufferCountStrategy receive_buffer_count_strategy;
  MessageCountStrategy receive_message_count_strategy;
  BufferDataStrategy buffer_data_strategy;
  guint32 transmit_seed;
  guint32 receive_seed;
  gsize n_bytes;
  guint n_messages;
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
    g_option_context_free (context);
    exit (1);
  }

  /* Set up the defaults. */
  transmit_seed = option_transmit_seed;
  receive_seed = option_receive_seed;
  n_bytes = option_n_bytes;
  n_messages = option_n_messages;
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

        if (stream_api_supports_vectored_io (stream_api)) {
          transmit_buffer_count_strategy = BUFFER_COUNT_RANDOM;
          transmit_message_count_strategy = MESSAGE_COUNT_RANDOM;
          receive_buffer_count_strategy = BUFFER_COUNT_RANDOM;
          receive_message_count_strategy = MESSAGE_COUNT_RANDOM;
        } else {
          transmit_buffer_count_strategy = BUFFER_COUNT_CONSTANT_ONE;
          transmit_message_count_strategy = MESSAGE_COUNT_CONSTANT_ONE;
          receive_buffer_count_strategy = BUFFER_COUNT_CONSTANT_ONE;
          receive_message_count_strategy = MESSAGE_COUNT_CONSTANT_ONE;
        }

        g_debug ("Running test (%u, %u, %" G_GSIZE_FORMAT ", %u, %u, "
            "%u, %u, %u, %u)…",
            reliable, stream_api, n_bytes, n_messages,
            transmit_buffer_size_strategy,
            receive_buffer_size_strategy, buffer_data_strategy,
            transmit_seed, receive_seed);
        test (reliable, stream_api, n_bytes, n_messages,
            transmit_buffer_size_strategy,
            transmit_buffer_count_strategy, transmit_message_count_strategy,
            receive_buffer_size_strategy, receive_buffer_count_strategy,
            receive_message_count_strategy, buffer_data_strategy,
            transmit_seed, receive_seed,
            deadlock_timeout);
      }
    }

    goto done;
  }

#define STRATEGY_LOOP(V, L) for (V = 0; (guint) V < L##_N_ELEMENTS; V++)
  STRATEGY_LOOP(transmit_buffer_size_strategy, BUFFER_SIZE_STRATEGY)
  STRATEGY_LOOP(transmit_buffer_count_strategy, BUFFER_COUNT_STRATEGY)
  STRATEGY_LOOP(transmit_message_count_strategy, MESSAGE_COUNT_STRATEGY)
  STRATEGY_LOOP(receive_buffer_size_strategy, BUFFER_SIZE_STRATEGY)
  STRATEGY_LOOP(receive_buffer_count_strategy, BUFFER_COUNT_STRATEGY)
  STRATEGY_LOOP(receive_message_count_strategy, MESSAGE_COUNT_STRATEGY)
  STRATEGY_LOOP(buffer_data_strategy, BUFFER_DATA_STRATEGY)
  /* Reliability. */
  for (reliable = 0; reliable < 2; reliable++) {
    /* Stream API. */
    for (stream_api = 0;
         (guint) stream_api < STREAM_API_N_ELEMENTS;
         stream_api++) {
      /* GIO streams must always be reliable. */
      if (!reliable && stream_api_is_reliable_only (stream_api))
        continue;

      /* Non-reliable socket receives require large buffers. We don’t claim to
       * support using them with small (< 65536B) buffers, so don’t test
       * them. */
      if (!reliable &&
          receive_buffer_size_strategy != BUFFER_SIZE_CONSTANT_LARGE)
        continue;

      /* Non-reliable socket transmits will always block with huge buffers. */
      if (!reliable &&
          transmit_buffer_size_strategy == BUFFER_SIZE_CONSTANT_LARGE)
        continue;

      /* Stream APIs which don’t support vectored I/O must not be passed
       * I/O vectors. */
      if (!stream_api_supports_vectored_io (stream_api) &&
          (transmit_buffer_count_strategy != BUFFER_COUNT_CONSTANT_ONE ||
           transmit_message_count_strategy != MESSAGE_COUNT_CONSTANT_ONE ||
           receive_buffer_count_strategy != BUFFER_COUNT_CONSTANT_ONE ||
           receive_message_count_strategy != MESSAGE_COUNT_CONSTANT_ONE))
        continue;

      g_debug ("Running test (%u, %u, %" G_GSIZE_FORMAT ", %u, %u, "
          "%u, %u, %u, %u, %u, %u, %u, %u)…",
          reliable, stream_api, n_bytes, n_messages,
          transmit_buffer_size_strategy,
          transmit_buffer_count_strategy, transmit_message_count_strategy,
          receive_buffer_size_strategy, receive_buffer_count_strategy,
          receive_message_count_strategy, buffer_data_strategy,
          transmit_seed, receive_seed);
      test (reliable, stream_api, n_bytes, n_messages,
          transmit_buffer_size_strategy,
          transmit_buffer_count_strategy, transmit_message_count_strategy,
          receive_buffer_size_strategy, receive_buffer_count_strategy,
          receive_message_count_strategy, buffer_data_strategy,
          transmit_seed, receive_seed,
          deadlock_timeout);
    }
  }

done:
  g_option_context_free (context);

#ifdef G_OS_WIN32
  WSACleanup ();
#endif

  return 0;
}
