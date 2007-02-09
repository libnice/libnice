
#include <string.h>

#include <gst/gst.h>

#include <nice/nice.h>

#include "gstnice.h"

// hack!
NiceAgent *agent;

gboolean
handle_signal (GIOChannel *io, GIOCondition cond, gpointer data)
{
  gchar **bits;
  NiceAddress addr;
  NiceUDPSocket *sock = data;
  NiceAddress recv_addr;
  guint len;
  gchar buf[1024];

  len = nice_udp_socket_recv (sock, &recv_addr, 1024, buf);
  buf[len] = '\0';
  g_debug (">> %s", buf);

  if (buf[0] != '0')
    return TRUE;

  bits = g_strsplit (buf, " ", 7);

  if (g_strv_length (bits) != 7)
    {
      g_strfreev (bits);
      return 3;
    }

  if (!nice_address_set_ipv4_from_string (&addr, bits[3]))
    g_assert_not_reached ();

  addr.port = atoi (bits[4]);
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &addr, bits[5], bits[6]);
  return TRUE;
}

int
main (gint argc, gchar *argv[])
{
  GstElement *src;
  GstElement *pipeline;
  NiceUDPSocketFactory factory;
  NiceUDPSocket sock;
  NiceAddress addr = {0,};
  NiceAddress recv_addr;
  NiceAddress send_addr;
  guint stream_id = 1;
  guint component_id = 1;
  gchar buf[1024];
  guint len;

  gst_init (&argc, &argv);

  if (!nice_address_set_ipv4_from_string (&addr, "127.0.0.1"))
    return 1;

  addr.port = 1234;
  nice_udp_bsd_socket_factory_init (&factory);

  if (!nice_udp_socket_factory_make (&factory, &sock, &addr))
    return 1;

  // set up agent

  agent = nice_agent_new (&factory);
  // remove
  addr.port = 0;
  nice_agent_add_local_address (agent, &addr);
  nice_agent_add_stream (agent, 1);

  // accept incoming handshake

  len = nice_udp_socket_recv (&sock, &recv_addr, 1, buf);

  if (len != 1)
    {
      //ret = 1;
      //goto OUT;
      return 1;
    }

  if (buf[0] != '2')
    {
      //ret = 2;
      //goto OUT;
      return 2;
    }

  g_debug ("got handshake packet");

  // send handshake reply

  send_addr = recv_addr;
  send_addr.port = 1235;
  nice_udp_socket_send (&sock, &send_addr, 1, buf);

  // send codec

  strcpy (buf, "1 0 PCMU 0 8000 0");
  nice_udp_socket_send (&sock, &send_addr, strlen (buf), buf);
  strcpy (buf, "1 0 LAST 0 0 0");
  nice_udp_socket_send (&sock, &send_addr, strlen (buf), buf);

  // send candidate

    {
      NiceCandidate *candidate;

      candidate = nice_agent_get_local_candidates (agent)->data;
      len = g_snprintf (buf, 1024, "0 0 X1 127.0.0.1 %d %s %s",
          candidate->addr.port, candidate->username, candidate->password);
      nice_udp_socket_send (&sock, &send_addr, len, buf);
    }

  // set up signalling callback

    {
      GIOChannel *io;

      io = g_io_channel_unix_new (sock.fileno);
      g_io_add_watch (io, G_IO_IN, handle_signal, &sock);
    }

  // set up pipeline

  src = g_object_new (GST_TYPE_NICE_SRC,
      "agent", agent,
      "stream", stream_id,
      "component", component_id,
      NULL);

  pipeline = gst_pipeline_new (NULL);
  gst_bin_add (GST_BIN (pipeline), src);

    {
      GstElement *sink;

#if 0
      sink = gst_element_factory_make ("fakesink", NULL);
      g_object_set (sink, "dump", TRUE, NULL);
#endif

#if 0
      sink = gst_parse_bin_from_description (
          "rtppcmudepay ! mulawdec ! alsasink sync=false", TRUE, NULL);
#endif

      sink = g_object_new (GST_TYPE_NICE_SINK,
          "agent", agent,
          "stream", stream_id,
          "component", component_id,
          NULL);

      g_assert (sink);
      gst_bin_add (GST_BIN (pipeline), sink);
      g_assert (gst_element_link (src, sink));
    }

  gst_element_set_state (pipeline, GST_STATE_PLAYING);

  // loop

    {
      GMainLoop *loop;

      loop = g_main_loop_new (NULL, FALSE);
      g_main_loop_run (loop);
      g_main_loop_unref (loop);
    }

  // clean up

  nice_agent_free (agent);
  g_object_unref (pipeline);
  gst_deinit ();

  return 0;
}

