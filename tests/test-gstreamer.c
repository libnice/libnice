/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 1015 Kurento.
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
#include <nice/agent.h>

#define RTP_HEADER_SIZE 12
#define RTP_PAYLOAD_SIZE 1024

static GstStaticPadTemplate srctemplate = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

static GstStaticPadTemplate sinktemplate = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

GMainLoop *loop;
gint ready = 0;

static guint bytes_received;
guint data_size;

static gboolean
count_bytes (GstBuffer ** buffer, guint idx, gpointer data)
{
  gsize size = gst_buffer_get_size (*buffer);

  GST_DEBUG ("received %" G_GSIZE_FORMAT " bytes", size);
  bytes_received += size;

  return TRUE;
}

static GstFlowReturn
sink_chain_list_function (GstPad * pad, GstObject * parent,
    GstBufferList * list)
{
  gst_buffer_list_foreach (list, count_bytes, NULL);

  if (data_size <= bytes_received) {
    GST_DEBUG ("We received expected data size");
    g_main_loop_quit (loop);
  }

  return GST_FLOW_OK;
}

static GstFlowReturn
sink_chain_function (GstPad * pad, GstObject * parent, GstBuffer * buffer)
{
  gsize size = gst_buffer_get_size (buffer);

  GST_DEBUG ("received %" G_GSIZE_FORMAT " bytes", size);
  bytes_received += size;

  if (data_size <= bytes_received) {
    GST_DEBUG ("We received expected data size");
    g_main_loop_quit (loop);
  }

  return GST_FLOW_OK;
}

/*
 * This function is get from gst-plugins-good tests tests/check/elements/udpsink.c
 */
static GstBufferList *
create_buffer_list (void)
{
  GstBufferList *list;
  GstBuffer *rtp_buffer;
  GstBuffer *data_buffer;
  gint total_size = 0;

  list = gst_buffer_list_new ();

  /*** First group, i.e. first packet. **/

  /* Create the RTP header buffer */
  rtp_buffer = gst_buffer_new_allocate (NULL, RTP_HEADER_SIZE, NULL);
  gst_buffer_memset (rtp_buffer, 0, 0, RTP_HEADER_SIZE);

  /* Create the buffer that holds the payload */
  data_buffer = gst_buffer_new_allocate (NULL, RTP_PAYLOAD_SIZE, NULL);
  gst_buffer_memset (data_buffer, 0, 0, RTP_PAYLOAD_SIZE);

  /* Create a new group to hold the rtp header and the payload */
  gst_buffer_list_add (list, gst_buffer_append (rtp_buffer, data_buffer));

  total_size += gst_buffer_get_size (rtp_buffer);

  /***  Second group, i.e. second packet. ***/

  /* Create the RTP header buffer */
  rtp_buffer = gst_buffer_new_allocate (NULL, RTP_HEADER_SIZE, NULL);
  gst_buffer_memset (rtp_buffer, 0, 0, RTP_HEADER_SIZE);

  /* Create the buffer that holds the payload */
  data_buffer = gst_buffer_new_allocate (NULL, RTP_PAYLOAD_SIZE, NULL);
  gst_buffer_memset (data_buffer, 0, 0, RTP_PAYLOAD_SIZE);

  /* Create a new group to hold the rtp header and the payload */
  gst_buffer_list_add (list, gst_buffer_append (rtp_buffer, data_buffer));

  total_size += gst_buffer_get_size (rtp_buffer);

  /* Calculate the size of the data */
  data_size = 2 * RTP_HEADER_SIZE + 2 * RTP_PAYLOAD_SIZE;

  return list;
}

static void
recv_cb (NiceAgent * agent,
    guint stream_id, guint component_id, guint len, gchar * buf, gpointer data)
{
  GST_INFO ("Received data on agent %" GST_PTR_FORMAT
      ", stream: %d, compoment: %d", agent, stream_id, component_id);
}

static void
print_candidate (gpointer data, gpointer user_data)
{
  NiceCandidate *cand = data;
  gchar str_addr[INET6_ADDRSTRLEN];

  nice_address_to_string (&cand->addr, str_addr);
  GST_INFO ("Cadidate: %s:%d", str_addr, nice_address_get_port (&cand->addr));
}

static void
cb_candidate_gathering_done (NiceAgent * agent, guint stream_id, gpointer data)
{
  GSList *candidates;

  GST_INFO ("Candidates gathered on agent %" GST_PTR_FORMAT ", stream: %d",
      agent, stream_id);

  candidates = nice_agent_get_local_candidates (agent, stream_id, 1);

  nice_agent_set_remote_candidates (NICE_AGENT (data), stream_id, 1,
      candidates);

  GST_INFO ("Got %d candidates", g_slist_length (candidates));
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
  GST_DEBUG_OBJECT (a_agent, "User: %s", user);
  GST_DEBUG_OBJECT (a_agent, "Passwd: %s", passwd);

  g_free (user);
  g_free (passwd);
}

static void
cb_component_state_changed (NiceAgent * agent, guint stream_id,
    guint component_id, guint state, gpointer user_data)
{
  GST_DEBUG ("State changed: %" GST_PTR_FORMAT " to %s", agent,
      nice_component_state_to_string (state));

  if (state == NICE_COMPONENT_STATE_READY) {
    ready++;
    if (ready >= 2) {
      g_main_loop_quit (loop);
    }
  }
}

GST_START_TEST (buffer_list_test)
{
  GstSegment segment;
  GstElement *nicesink, *nicesrc;
  GstPad *srcpad, *sinkpad;
  GstBufferList *list;
  NiceAgent *sink_agent, *src_agent;
  guint sink_stream, src_stream;
  NiceAddress *addr;

  loop = g_main_loop_new (NULL, TRUE);

  /* Initialize nice agents */
  addr = nice_address_new ();
  nice_address_set_from_string (addr, "127.0.0.1");

  sink_agent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);
  src_agent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);

  nice_agent_add_local_address (sink_agent, addr);
  nice_agent_add_local_address (src_agent, addr);

  sink_stream = nice_agent_add_stream (sink_agent, 1);
  src_stream = nice_agent_add_stream (src_agent, 1);

  nice_agent_attach_recv (sink_agent, sink_stream, NICE_COMPONENT_TYPE_RTP,
      NULL, recv_cb, NULL);
  nice_agent_attach_recv (src_agent, src_stream, NICE_COMPONENT_TYPE_RTP,
      NULL, recv_cb, NULL);

  g_signal_connect (G_OBJECT (sink_agent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), src_agent);
  g_signal_connect (G_OBJECT (src_agent), "candidate-gathering-done",
      G_CALLBACK (cb_candidate_gathering_done), sink_agent);

  g_signal_connect (G_OBJECT (sink_agent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), NULL);
  g_signal_connect (G_OBJECT (src_agent), "component-state-changed",
      G_CALLBACK (cb_component_state_changed), NULL);

  credentials_negotiation (sink_agent, src_agent, sink_stream, src_stream);
  credentials_negotiation (src_agent, sink_agent, src_stream, src_stream);

  nice_agent_gather_candidates (sink_agent, sink_stream);
  nice_agent_gather_candidates (src_agent, src_stream);

  /* Create gstreamer elements */
  nicesink = gst_check_setup_element ("nicesink");
  nicesrc = gst_check_setup_element ("nicesrc");

  g_object_set (nicesink, "agent", sink_agent, "stream", sink_stream,
      "component", 1, NULL);
  g_object_set (nicesrc, "agent", src_agent, "stream", src_stream, "component",
      1, NULL);

  srcpad = gst_check_setup_src_pad_by_name (nicesink, &srctemplate, "sink");
  sinkpad = gst_check_setup_sink_pad_by_name (nicesrc, &sinktemplate, "src");

  gst_pad_set_chain_list_function_full (sinkpad, sink_chain_list_function, NULL,
      NULL);
  gst_pad_set_chain_function_full (sinkpad, sink_chain_function, NULL, NULL);

  gst_element_set_state (nicesink, GST_STATE_PLAYING);
  gst_pad_set_active (srcpad, TRUE);

  gst_element_set_state (nicesrc, GST_STATE_PLAYING);
  gst_pad_set_active (sinkpad, TRUE);

  gst_pad_push_event (srcpad, gst_event_new_stream_start ("test"));

  gst_segment_init (&segment, GST_FORMAT_TIME);
  gst_pad_push_event (srcpad, gst_event_new_segment (&segment));

  list = create_buffer_list ();

  GST_DEBUG ("Waiting for agents to be ready ready");

  g_main_loop_run (loop);

  fail_unless_equals_int (gst_pad_push_list (srcpad, list), GST_FLOW_OK);

  GST_DEBUG ("Waiting for buffers");
  g_main_loop_run (loop);

  fail_unless_equals_int (data_size, bytes_received);

  gst_check_teardown_pad_by_name (nicesink, "sink");
  gst_check_teardown_element (nicesink);

  gst_check_teardown_pad_by_name (nicesrc, "src");
  gst_check_teardown_element (nicesrc);

  nice_address_free (addr);
  g_main_loop_unref (loop);
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
