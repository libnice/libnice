/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2015 Kurento.
 *  Contact: Jose Antonio Santos Cadenas
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
 *   Jose Antonio Santos Cadenas, Kurento.
 *   Martin Nordholts, Axis Communications AB, 2025.
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

#include <gst/check/gstcheck.h>
#include "agent.h"
#include "instrument-send.h"

#define TEST_STATE_KEY "libnice-test-gstreamer-test-state"
#define RTP_HEADER_SIZE 12
#define RTP_PAYLOAD_SIZE 1024

/* If GLib is compiled with HAVE_SENDMMSG then the number of messages sent in
 * one sycall will be capped to IOV_MAX which typically is 1024. Trying to
 * send more messages than that requires a retry-loop. Make the buffer list size
 * twice as big to trigger this case in the test.
 */
#define RTP_PACKETS 2000

/* Since we want to inject synthetic EWOULDBLOCK errors, make sure we do many
 * distinct send calls.
 */
#define TIMES_TO_SEND 100

/* Since we are dealing with UDP, we still need to expect some package loss on
 * the receiver side. Mostly due to the limited default SO_RCVBUF of ~200kB. If
 * you run the tests with temporarily very high /proc/sys/net/core/rmem_default
 * you are likely to see no packet loss at all.
 *
 * Since we really dislike flakiness, we put this very low at 1% to make it
 * likely to work with the default SO_RCVBUF size.
 */
#define RECEIVED_PACKETS_PERCENTAGE_FOR_PASS 1

#define MIN_MESSAGES_TO_SEND_FOR_PASS ((size_t) RTP_PACKETS * (size_t) TIMES_TO_SEND)

#define MIN_BYTES_RECEIVED_FOR_PASS \
  ((TIMES_TO_SEND * RTP_PACKETS * (RTP_HEADER_SIZE + RTP_PAYLOAD_SIZE) * \
    RECEIVED_PACKETS_PERCENTAGE_FOR_PASS) / \
   100)


static GstStaticPadTemplate sinktemplate = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

typedef struct _TestState {
  GMainLoop *loop;
  gint ready;
  guint bytes_received;
} TestState;


static guint
get_bytes_received (TestState *test_state)
{
  guint received = 0;
  g_mutex_lock (&mutex);
  received = test_state->bytes_received;
  g_mutex_unlock (&mutex);
  return received;
}

/* We always access `test_state->loop` from the main thread to avoid locks. */
static gboolean
quit_main_loop_cb (gpointer user_data)
{
  TestState *test_state = user_data;
  if (test_state->loop) {
    g_main_loop_quit (test_state->loop);
  }
  return G_SOURCE_REMOVE;
}

static void
check_if_done (gpointer user_data)
{
  TestState *test_state = user_data;

  g_debug (
      "messages sent = %zu / %zu (%.1f%%), bytes received = %u / %u (%.1f%%)",
      nice_test_instrument_send_get_messages_sent (),
      MIN_MESSAGES_TO_SEND_FOR_PASS,
      (float) nice_test_instrument_send_get_messages_sent () /
          (float) MIN_MESSAGES_TO_SEND_FOR_PASS * 100.0f,
      get_bytes_received (test_state),
      MIN_BYTES_RECEIVED_FOR_PASS,
      (float) get_bytes_received (test_state) / (float) MIN_BYTES_RECEIVED_FOR_PASS * 100.0f);

  if (nice_test_instrument_send_get_messages_sent () >= MIN_MESSAGES_TO_SEND_FOR_PASS &&
      get_bytes_received (test_state) >= MIN_BYTES_RECEIVED_FOR_PASS) {
    g_idle_add (quit_main_loop_cb, test_state);
  }
}

static gboolean
count_bytes (GstBuffer ** buffer, guint idx, gpointer data)
{
  TestState *test_state = data;
  gsize size = gst_buffer_get_size (*buffer);

  g_mutex_lock(&mutex);
  test_state->bytes_received += size;
  g_mutex_unlock (&mutex);

  check_if_done (data);

  return TRUE;
}

static GstFlowReturn
sink_chain_list_function (GstPad * pad, GstObject * parent,
    GstBufferList * list)
{
  TestState *test_state = g_object_get_data (G_OBJECT (pad), TEST_STATE_KEY);

  gst_buffer_list_foreach (list, count_bytes, test_state);

  gst_buffer_list_unref (list);

  return GST_FLOW_OK;
}

static GstFlowReturn
sink_chain_function (GstPad * pad, GstObject * parent, GstBuffer * buffer)
{
  TestState *test_state = g_object_get_data (G_OBJECT (pad), TEST_STATE_KEY);

  count_bytes (&buffer, 0, test_state);

  gst_buffer_unref (buffer);

  return GST_FLOW_OK;
}

/*
 * This function is get from gst-plugins-good tests tests/check/elements/udpsink.c
 */
static GstBuffer *
create_buffer (guint16 seqnum)
{
  /* Create the RTP header buffer */
  GstBuffer *rtp_buffer = gst_buffer_new_allocate (NULL, RTP_HEADER_SIZE, NULL);
  gst_buffer_memset (rtp_buffer, 0, 0, RTP_HEADER_SIZE);
  guint16 seqnum_n = htons (seqnum); /* Ease debugging of dropped packets with synthetic seqnum. */
  gst_buffer_fill (rtp_buffer, 2, &seqnum_n, sizeof (seqnum_n));
  guint8 version = (2 << 6); /* Enables RTP decoding in Wireshark */
  gst_buffer_fill (rtp_buffer, 0, &version, sizeof (version));

  /* Create the buffer that holds the payload */
  GstBuffer *data_buffer = gst_buffer_new_allocate (NULL, RTP_PAYLOAD_SIZE, NULL);
  gst_buffer_memset (data_buffer, 0, 0, RTP_PAYLOAD_SIZE);

  /* Create a new group to hold the rtp header and the payload */
  return gst_buffer_append (rtp_buffer, data_buffer);
}

static GstBufferList *
create_buffer_list (void)
{
  GstBufferList *list = gst_buffer_list_new ();

  for (guint seqnum = 0; seqnum < RTP_PACKETS; seqnum++) {
    gst_buffer_list_add (list, create_buffer (seqnum));
  }

  return list;
}

static void
recv_cb (NiceAgent * agent,
    guint stream_id, guint component_id, guint len, gchar * buf, gpointer data)
{
  g_debug ("Received data on agent %p, stream: %d, compoment: %d", agent,
      stream_id, component_id);
}

static void
print_candidate (gpointer data, gpointer user_data)
{
  NiceCandidate *cand = data;
  gchar str_addr[INET6_ADDRSTRLEN];

  nice_address_to_string (&cand->addr, str_addr);
  g_debug ("Candidate: %s:%d", str_addr, nice_address_get_port (&cand->addr));
}

static void
cb_candidate_gathering_done (NiceAgent * agent, guint stream_id, gpointer data)
{
  GSList *candidates;

  g_debug ("Candidates gathered on agent %p, stream: %d",
      agent, stream_id);

  candidates = nice_agent_get_local_candidates (agent, stream_id, NICE_COMPONENT_TYPE_RTP);

  nice_agent_set_remote_candidates (NICE_AGENT (data), stream_id, NICE_COMPONENT_TYPE_RTP,
      candidates);

  g_debug ("Got %d candidates", g_slist_length (candidates));
  g_slist_foreach (candidates, print_candidate, NULL);

  g_slist_free_full (candidates, (GDestroyNotify) nice_candidate_free);
}

static void
credentials_negotiation (NiceAgent * a_agent, NiceAgent * b_agent,
    guint a_stream, guint b_stream)
{
  gchar *user = NULL;
  gchar *passwd = NULL;

  nice_agent_get_local_credentials (a_agent, a_stream, &user, &passwd);
  nice_agent_set_remote_credentials (b_agent, b_stream, user, passwd);
  g_debug ("Agent: %p User: %s", a_agent, user);
  g_debug ("Agent: %p Passwd: %s", a_agent, passwd);

  g_free (user);
  g_free (passwd);
}

static gboolean
bus_callback (GstBus * bus, GstMessage * message, gpointer data)
{
  switch (GST_MESSAGE_TYPE (message))
    {
      case GST_MESSAGE_ERROR:
      {
        gchar *element_name = NULL;
        gchar *debug = NULL;
        GError *err = NULL;
        element_name = gst_object_get_name (message->src);
        gst_message_parse_error (message, &err, &debug);
        g_error ("Aborting test (without resource cleanup): %s: %s: %s", element_name, err->message, debug);
      }
      default:
        break;
    }

  return G_SOURCE_CONTINUE;
}

static void
cb_component_state_changed (NiceAgent * agent, guint stream_id,
    guint component_id, guint state, gpointer user_data)
{
  TestState *test_state = user_data;

  g_debug ("State changed: %p to %s", agent,
      nice_component_state_to_string (state));

  if (state == NICE_COMPONENT_STATE_READY) {
    test_state->ready++;
    if (test_state->ready >= 2) {
      g_main_loop_quit (test_state->loop);
    }
  }
}

GST_START_TEST (buffer_list_test)
{
  GstElement *nicesink_pipeline, *appsrc;
  GstFlowReturn flow_ret;
  GstBus *bus;
  GstElement *nicesink, *nicesrc;
  GstPad *sinkpad;
  GstBufferList *list;
  NiceAgent *sink_agent, *src_agent;
  guint sink_stream, src_stream;
  NiceAddress *addr;
  TestState *test_state;
  test_state = g_new0 (TestState, 1);
  test_state->loop = g_main_loop_new (NULL, FALSE);

  /* Initialize nice agents */
  addr = nice_address_new ();
  nice_address_set_from_string (addr, "127.0.0.1");

  sink_agent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);
  src_agent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);

  g_object_set (G_OBJECT (sink_agent), "upnp", FALSE, NULL);
  g_object_set (G_OBJECT (src_agent), "upnp", FALSE, NULL);

  nice_agent_add_local_address (sink_agent, addr);
  nice_agent_add_local_address (src_agent, addr);

  sink_stream = nice_agent_add_stream (sink_agent, NICE_COMPONENT_TYPE_RTP);
  src_stream = nice_agent_add_stream (src_agent, NICE_COMPONENT_TYPE_RTP);

  nice_agent_attach_recv (sink_agent, sink_stream, NICE_COMPONENT_TYPE_RTP,
      NULL, recv_cb, NULL);
  nice_agent_attach_recv (src_agent, src_stream, NICE_COMPONENT_TYPE_RTP,
      NULL, recv_cb, NULL);

  g_signal_connect (G_OBJECT (sink_agent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), src_agent);
  g_signal_connect (G_OBJECT (src_agent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), sink_agent);

  g_signal_connect (G_OBJECT (sink_agent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), test_state);
  g_signal_connect (G_OBJECT (src_agent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), test_state);

  credentials_negotiation (sink_agent, src_agent, sink_stream, src_stream);
  credentials_negotiation (src_agent, sink_agent, src_stream, src_stream);

  nice_agent_gather_candidates (sink_agent, sink_stream);
  nice_agent_gather_candidates (src_agent, src_stream);

  /* Create nicesink pipeline */
  nicesink_pipeline = gst_pipeline_new("nicesink-pipeline");
  appsrc = gst_check_setup_element ("appsrc");
  nicesink = gst_check_setup_element ("nicesink");
  bus = gst_pipeline_get_bus (GST_PIPELINE (nicesink_pipeline));
  gst_bus_add_watch (bus, bus_callback, NULL);
  gst_bin_add_many (GST_BIN (nicesink_pipeline), appsrc, nicesink, NULL);
  g_assert (gst_element_link_many (appsrc, nicesink, NULL));

  /* Create nicesrc pipeline */
  nicesrc = gst_check_setup_element ("nicesrc");

  g_object_set (nicesink, "agent", sink_agent, "stream", sink_stream,
      "component", NICE_COMPONENT_TYPE_RTP, NULL);
  g_object_set (nicesrc, "agent", src_agent, "stream", src_stream, "component",
      NICE_COMPONENT_TYPE_RTP, NULL);

  sinkpad = gst_check_setup_sink_pad_by_name (nicesrc, &sinktemplate, "src");
  g_object_set_data (G_OBJECT (sinkpad), TEST_STATE_KEY, test_state);

  gst_pad_set_chain_list_function_full (sinkpad, sink_chain_list_function, NULL,
      NULL);
  gst_pad_set_chain_function_full (sinkpad, sink_chain_function, NULL, NULL);

  gst_element_set_state (nicesink_pipeline, GST_STATE_PLAYING);

  gst_element_set_state (nicesrc, GST_STATE_PLAYING);
  gst_pad_set_active (sinkpad, TRUE);

  list = create_buffer_list ();

  g_debug ("Waiting for agents to be ready ready");

  g_main_loop_run (test_state->loop);

  /* Now that we are ready to send data, set up synthetic EWOULDBLOCK errors to
   * get good code coverage. We inject EWOULDBLOCK every second call. That is
   * quite aggressive, but the components under test should be able to cope with
   * this.
   */
  nice_test_instrument_send_set_post_increment_callback (check_if_done, test_state);
  nice_test_instrument_send_set_calls_until_next_ewouldblock (2);
  for (int i = 0; i < TIMES_TO_SEND; i++) {
    g_signal_emit_by_name (appsrc, "push-buffer-list", list, &flow_ret);
  }
  gst_buffer_list_unref(list);
  fail_unless_equals_int (flow_ret, GST_FLOW_OK);

  g_debug ("Waiting for buffers");

  /* It is important that we run the main loop since that's where internal
   * libnice callbacks (e.g. for G_IO_OUT) will be handled. Once we are done,
   * check_if_done() will call g_main_loop_quit().
   */
  g_main_loop_run (test_state->loop);

  g_assert_cmpuint (
      nice_test_instrument_send_get_messages_sent (),
      >=,
      MIN_MESSAGES_TO_SEND_FOR_PASS);
  g_assert_cmpuint (get_bytes_received (test_state), >=, MIN_MESSAGES_TO_SEND_FOR_PASS);
  g_debug ("We received expected data size");

  gst_element_set_state (nicesink_pipeline, GST_STATE_NULL);
  gst_object_unref (nicesink_pipeline);

#if GST_CHECK_VERSION(1, 18, 0)
  gst_check_teardown_pad_by_name (nicesrc, "src");
#else
  /* CI on centos:8 uses GStreamer v1.16.1 which lacks
   * https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/9861ad2e12011aeece51f838a94dbc5712f98bfb
   * The first stable GStreamer release with that fix is v1.18.0. So manually do
   * a teardown since we're on a version older than that.
   */
  gst_object_unref (sinkpad);
#endif
  gst_check_teardown_element (nicesrc);

  nice_address_free (addr);
  g_main_loop_unref (test_state->loop);
  test_state->loop = NULL;
}

GST_END_TEST;

static Suite *
udpsink_suite (void)
{
  Suite *s = suite_create ("nice_gstreamer_test");
  TCase *tc_chain = tcase_create ("nice");

  suite_add_tcase (s, tc_chain);

  tcase_add_test (tc_chain, buffer_list_test);

  return s;
}

GST_CHECK_MAIN (udpsink)
