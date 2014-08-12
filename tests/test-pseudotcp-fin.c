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
# include "config.h"
#endif

#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>

#include "pseudotcp.h"


typedef struct {
  PseudoTcpSocket *left;  /* owned */
  PseudoTcpSocket *right;  /* owned */

  guint32 left_current_time;
  guint32 right_current_time;

  /* Data sent and received by each socket. */
  GQueue/*<owned GBytes>*/ *left_sent;  /* owned */
  GQueue/*<owned GBytes>*/ *right_sent;  /* owned */
} Data;

/* NOTE: Must match the on-the-wire flag values from pseudotcp.c. */
typedef enum {
  FLAG_NONE = 0,
  FLAG_FIN = 1 << 0,
  FLAG_SYN = 1 << 1,
  FLAG_RST = 1 << 2,
} SegmentFlags;

typedef void (*TestFunc) (Data *data, const void *next_funcs);


static void
data_clear (Data *data)
{
  if (data->left != NULL)
    g_object_unref (data->left);
  if (data->right != NULL)
    g_object_unref (data->right);

  if (data->left_sent != NULL)
    g_queue_free_full (data->left_sent, (GDestroyNotify) g_bytes_unref);
  if (data->right_sent != NULL)
    g_queue_free_full (data->right_sent, (GDestroyNotify) g_bytes_unref);
}


static gchar *
segment_flags_to_string (SegmentFlags flags)
{
  GString *str = g_string_new (NULL);

  if (flags & FLAG_SYN)
    g_string_append (str, "SYN,");
  if (flags & FLAG_FIN)
    g_string_append (str, "FIN,");
  if (flags & FLAG_RST)
    g_string_append (str, "RST,");

  /* Strip the trailing comma. */
  if (str->len > 0)
    g_string_truncate (str, str->len - 1);

  if (str->len == 0)
    g_string_append (str, "0");

  return g_string_free (str, FALSE);
}

static gchar *
segment_to_string (guint32 seq, guint32 ack, SegmentFlags flags)
{
  gchar *ctl, *out;

  ctl = segment_flags_to_string (flags);
  out = g_strdup_printf ("<SEQ=%u><ACK=%u><CTL=%s>", seq, ack, ctl);
  g_free (ctl);

  return out;
}

static gchar *
segment_bytes_to_string (const guint8 *bytes)
{
  union {
    const guint8 *u8;
    const guint32 *u32;
  } b;
  guint32 seq, ack;
  guint8 flags;

  b.u8 = bytes;

  seq = ntohl (b.u32[1]);
  ack = ntohl (b.u32[2]);
  flags = b.u8[13];

  return segment_to_string (seq, ack, flags);
}


static void
opened (PseudoTcpSocket *sock, gpointer data)
{
  g_debug ("Socket %p opened", sock);
}

static void
readable (PseudoTcpSocket *sock, gpointer data)
{
  g_debug ("Socket %p readable", sock);
}

static void
writable (PseudoTcpSocket *sock, gpointer data)
{
  g_debug ("Socket %p writeable", sock);
}

static void
closed (PseudoTcpSocket *sock, guint32 err, gpointer data)
{
  g_debug ("Socket %p closed: %s", sock, strerror (err));
}

static PseudoTcpWriteResult
write_packet (PseudoTcpSocket *sock, const gchar *buffer, guint32 len,
    gpointer user_data)
{
  Data *data = user_data;
  gchar *str;  /* owned */
  GQueue/*<owned GBytes>*/ *queue;  /* unowned */
  GBytes *segment;  /* owned */

  /* Debug output. */
  str = segment_bytes_to_string ((const guint8 *) buffer);
  g_debug ("%p sent: %s", sock, str);
  g_free (str);

  /* One of the sockets has outputted a packet. */
  if (sock == data->left)
    queue = data->left_sent;
  else if (sock == data->right)
    queue = data->right_sent;
  else
    g_assert_not_reached ();

  segment = g_bytes_new (buffer, len);
  g_queue_push_tail (queue, segment);

  return WR_SUCCESS;
}


static void
create_sockets (Data *data, gboolean support_fin_ack)
{
  PseudoTcpCallbacks cbs = {
    data, opened, readable, writable, closed, write_packet
  };

  data->left = g_object_new (PSEUDO_TCP_SOCKET_TYPE,
      "conversation", 0,
      "callbacks", &cbs,
      "support-fin-ack", support_fin_ack,
      NULL);
  data->right = g_object_new (PSEUDO_TCP_SOCKET_TYPE,
      "conversation", 0,
      "callbacks", &cbs,
      "support-fin-ack", support_fin_ack,
      NULL);

  g_debug ("Left: %p, right: %p", data->left, data->right);

  /* Control the socket clocks precisely. */
  pseudo_tcp_socket_set_time (data->left, 1);
  pseudo_tcp_socket_set_time (data->right, 1);

  /* Sanity check the socket state. */
  g_assert_cmpint (pseudo_tcp_socket_send (data->left, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data->left), ==, ENOTCONN);

  g_assert_cmpint (pseudo_tcp_socket_send (data->right, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data->right), ==, ENOTCONN);

  data->left_sent = g_queue_new ();
  data->right_sent = g_queue_new ();
}

static void
expect_segment (PseudoTcpSocket *socket, GQueue/*<owned GBytes>*/ *queue,
    guint32 seq, guint32 ack, guint32 len, SegmentFlags flags)
{
  GBytes *bytes;  /* unowned */
  union {
    const guint8 *u8;
    const guint32 *u32;
  } b;
  gsize size;
  gchar *str;

  str = segment_to_string (seq, ack, flags);
  g_debug ("%p expect: %s", socket, str);
  g_free (str);

  /* Grab the segment. */
  bytes = g_queue_peek_head (queue);
  g_assert (bytes != NULL);

  b.u8 = g_bytes_get_data (bytes, &size);
  g_assert_cmpuint (size, >=, 24);  /* minimum packet size */
  g_assert_cmpuint (size - 24, ==, len);

  /* Check the segment’s fields. */
  g_assert_cmpuint (ntohl (b.u32[1]), ==, seq);
  g_assert_cmpuint (ntohl (b.u32[2]), ==, ack);
  g_assert_cmpuint (b.u8[13], ==, flags);
}

static void
expect_syn_sent (Data *data)
{
  expect_segment (data->left, data->left_sent, 0, 0, 7, FLAG_SYN);
}

static void
expect_syn_received (Data *data)
{
  expect_segment (data->right, data->right_sent, 0, 7, 7, FLAG_SYN);
}

/* Return whether the socket accepted the packet. */
static gboolean
forward_segment (GQueue/*<owned GBytes>*/ *from, PseudoTcpSocket *to)
{
  GBytes *segment;  /* owned */
  const guint8 *b;
  gsize size;
  gboolean retval;

  segment = g_queue_pop_head (from);
  g_assert (segment != NULL);
  b = g_bytes_get_data (segment, &size);
  retval = pseudo_tcp_socket_notify_packet (to, (const gchar *) b, size);
  g_bytes_unref (segment);

  return retval;
}

static void
forward_segment_ltr (Data *data)
{
  g_assert (forward_segment (data->left_sent, data->right));
}

static void
forward_segment_rtl (Data *data)
{
  g_assert (forward_segment (data->right_sent, data->left));
}

static void
duplicate_segment (GQueue/*<owned GBytes>*/ *queue)
{
  GBytes *segment;  /* unowned */

  segment = g_queue_peek_head (queue);
  g_assert (segment != NULL);
  g_queue_push_head (queue, g_bytes_ref (segment));
}

static void
drop_segment (PseudoTcpSocket *socket, GQueue/*<owned GBytes>*/ *queue)
{
  GBytes *segment;  /* owned */
  gchar *str;

  segment = g_queue_pop_head (queue);
  g_assert (segment != NULL);

  str = segment_bytes_to_string (g_bytes_get_data (segment, NULL));
  g_debug ("%p drop: %s", socket, str);
  g_free (str);

  g_bytes_unref (segment);
}

/* Swap the order of the head-most two segments in the @queue. */
static void
reorder_segments (PseudoTcpSocket *socket, GQueue/*<owned GBytes>*/ *queue)
{
  GBytes *segment1, *segment2;  /* unowned */
  gchar *str;

  segment1 = g_queue_pop_head (queue);
  g_assert (segment1 != NULL);
  segment2 = g_queue_pop_head (queue);
  g_assert (segment2 != NULL);

  str = segment_bytes_to_string (g_bytes_get_data (segment1, NULL));
  g_debug ("%p reorder: %s", socket, str);
  g_free (str);
  str = segment_bytes_to_string (g_bytes_get_data (segment2, NULL));
  g_debug ("%p after:   %s", socket, str);
  g_free (str);

  g_queue_push_head (queue, segment1);
  g_queue_push_head (queue, segment2);
}

static void
expect_socket_state (PseudoTcpSocket *socket, PseudoTcpState expected_state)
{
  PseudoTcpState state;

  g_object_get (socket, "state", &state, NULL);
  g_assert_cmpuint (state, ==, expected_state);
}

static void
expect_sockets_connected (Data *data)
{
  expect_socket_state (data->left, TCP_ESTABLISHED);
  expect_socket_state (data->right, TCP_ESTABLISHED);
}

static void
expect_sockets_closed (Data *data)
{
  guint8 buf[100];

  expect_socket_state (data->left, TCP_CLOSED);
  expect_socket_state (data->right, TCP_CLOSED);

  g_assert_cmpint (pseudo_tcp_socket_send (data->left, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data->left), ==, EPIPE);
  g_assert_cmpint (pseudo_tcp_socket_recv (data->left, (char *) buf, sizeof (buf)), ==, 0);

  g_assert_cmpint (pseudo_tcp_socket_send (data->right, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data->right), ==, EPIPE);
  g_assert_cmpint (pseudo_tcp_socket_recv (data->right, (char *) buf, sizeof (buf)), ==, 0);
}

static void
increment_time (PseudoTcpSocket *socket, guint32 *counter, guint32 increment)
{
  g_debug ("Incrementing %p time by %u from %u to %u", socket, increment,
      *counter, *counter + increment);
  *counter = *counter + increment;

  pseudo_tcp_socket_set_time (socket, *counter);
  pseudo_tcp_socket_notify_clock (socket);
}

static void
increment_time_both (Data *data, guint32 increment)
{
  increment_time (data->left, &data->left_current_time, increment);
  increment_time (data->right, &data->right_current_time, increment);
}

static void
expect_fin (PseudoTcpSocket *socket, GQueue/*<owned GBytes>*/ *queue,
    guint32 seq, guint32 ack)
{
  expect_segment (socket, queue, seq, ack, 0, FLAG_FIN);
}

static void
expect_rst (PseudoTcpSocket *socket, GQueue/*<owned GBytes>*/ *queue,
    guint32 seq, guint32 ack)
{
  expect_segment (socket, queue, seq, ack, 0, FLAG_RST);
}

static void
expect_ack (PseudoTcpSocket *socket, GQueue/*<owned GBytes>*/ *queue,
    guint32 seq, guint32 ack)
{
  expect_segment (socket, queue, seq, ack, 0, FLAG_NONE);
}

static void
expect_data (PseudoTcpSocket *socket, GQueue/*<owned GBytes>*/ *queue,
    guint32 seq, guint32 ack, guint32 len)
{
  expect_segment (socket, queue, seq, ack, len, FLAG_NONE);
}

static void
close_socket (PseudoTcpSocket *socket)
{
  guint8 buf[100];

  pseudo_tcp_socket_close (socket, FALSE);

  g_assert_cmpint (pseudo_tcp_socket_send (socket, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (socket), ==, EPIPE);
  g_assert_cmpint (pseudo_tcp_socket_recv (socket, (char *) buf, sizeof (buf)), ==, 0);
}

/* Helper to create a socket pair and perform the SYN handshake. */
static void
establish_connection (Data *data)
{
  create_sockets (data, TRUE);
  pseudo_tcp_socket_connect (data->left);
  expect_syn_sent (data);
  forward_segment_ltr (data);
  expect_syn_received (data);
  forward_segment_rtl (data);
  increment_time_both (data, 110);
  expect_ack (data->left,  data->left_sent, 7, 7);
  forward_segment_ltr (data);
  expect_sockets_connected (data);
}

/* Helper to close the LHS of a socket pair which has not transmitted any
 * data (i.e. perform the first half of the FIN handshake). */
static void
close_lhs (Data *data)
{
  pseudo_tcp_socket_close (data->left, FALSE);

  expect_fin (data->left, data->left_sent, 7, 7);
  forward_segment_ltr (data);

  expect_ack (data->right, data->right_sent, 7, 8);
  forward_segment_rtl (data);
}

/* Helper to close the RHS of a socket pair which has not transmitted any
 * data (i.e. perform the second half of the FIN handshake). */
static void
close_rhs (Data *data)
{
  pseudo_tcp_socket_close (data->right, FALSE);

  expect_fin (data->right, data->right_sent, 7, 8);
  forward_segment_rtl (data);

  increment_time_both (data, 10);  /* TIME-WAIT */
  expect_ack (data->left, data->left_sent, 8, 8);
  forward_segment_ltr (data);
}

/* Check that establishing a connection then immediately closing it works, using
 * normal handshakes (FIN, ACK, FIN, ACK). See: RFC 793, Figure 13. */
static void
pseudotcp_close_normal (void)
{
  Data data = { 0, };
  guint8 buf[100];

  /* Establish a connection. */
  establish_connection (&data);

  /* Close it. Verify that sending fails. */
  close_socket (data.left);

  expect_fin (data.left, data.left_sent, 7, 7);
  forward_segment_ltr (&data);
  expect_ack (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);

  /* Check the RHS is closed. */
  g_assert_cmpint (pseudo_tcp_socket_recv (data.right, (char *) buf, sizeof (buf)), ==, 0);
  close_socket (data.right);

  expect_fin (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);
  increment_time_both (&data, 10);  /* TIME-WAIT */
  expect_ack (data.left, data.left_sent, 8, 8);
  forward_segment_ltr (&data);
  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that establishing a connection then immediately closing it works, using
 * simultaneous handshakes (FIN, FIN, ACK, ACK). See: RFC 793, Figure 14. */
static void
pseudotcp_close_simultaneous (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close both sides simultaneously. Verify that sending fails. */
  close_socket (data.left);
  close_socket (data.right);

  expect_fin (data.left, data.left_sent, 7, 7);
  expect_fin (data.right, data.right_sent, 7, 7);
  forward_segment_ltr (&data);
  forward_segment_rtl (&data);

  expect_ack (data.left, data.left_sent, 8, 8);
  expect_ack (data.right, data.right_sent, 8, 8);
  forward_segment_ltr (&data);
  forward_segment_rtl (&data);

  increment_time_both (&data, 10);  /* TIME-WAIT */
  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that establishing a connection then immediately closing it works, using
 * skewed handshakes. The segments are reordered so that the FIN and ACK from
 * the LHS arrive at the RHS in reverse order. The RHS sees the ACK has a higher
 * sequence number than the bytes it’s seen so far (as it hasn’t seen the LHS
 * FIN at that point) and thus emits two sequential ACKs: one from before
 * receiving the FIN (fast retransmit), and one from after.
 * See: RFC 793, Figure 14. */
static void
pseudotcp_close_skew1 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close both sides simultaneously. Verify that sending fails. */
  close_socket (data.left);
  close_socket (data.right);

  expect_fin (data.left, data.left_sent, 7, 7);

  expect_fin (data.right, data.right_sent, 7, 7);
  forward_segment_rtl (&data);

  reorder_segments (data.left, data.left_sent);
  expect_ack (data.left, data.left_sent, 8, 8);
  forward_segment_ltr (&data);
  forward_segment_ltr (&data);

  expect_ack (data.right, data.right_sent, 8, 7);
  forward_segment_rtl (&data);
  expect_ack (data.right, data.right_sent, 8, 8);
  forward_segment_rtl (&data);

  increment_time_both (&data, 10);  /* TIME-WAIT */
  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Same as pseudotcp_close_skew1() but with the packets reordered in a
 * different way. */
static void
pseudotcp_close_skew2 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close both sides simultaneously. Verify that sending fails. */
  close_socket (data.left);
  close_socket (data.right);

  expect_fin (data.right, data.right_sent, 7, 7);

  expect_fin (data.left, data.left_sent, 7, 7);
  forward_segment_ltr (&data);

  reorder_segments (data.right, data.right_sent);
  expect_ack (data.right, data.right_sent, 8, 8);
  forward_segment_rtl (&data);
  forward_segment_rtl (&data);

  expect_ack (data.left, data.left_sent, 8, 7);
  forward_segment_ltr (&data);
  expect_ack (data.left, data.left_sent, 8, 8);
  forward_segment_ltr (&data);

  increment_time_both (&data, 10);  /* TIME-WAIT */
  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that closing a connection recovers from the initial FIN segment being
 * dropped. Based on: RFC 793, Figure 13. */
static void
pseudotcp_close_normal_recovery1 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS and drop the FIN segment. */
  close_socket (data.left);

  expect_fin (data.left, data.left_sent, 7, 7);
  drop_segment (data.left, data.left_sent);

  increment_time_both (&data, 300);  /* retransmit timeout */

  expect_fin (data.left, data.left_sent, 7, 7);
  forward_segment_ltr (&data);

  expect_ack (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);

  /* Close the RHS. */
  close_rhs (&data);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that closing a connection recovers from the initial ACK segment being
 * dropped. Based on: RFC 793, Figure 13. */
static void
pseudotcp_close_normal_recovery2 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS and drop the ACK segment. The LHS should retransmit the
   * FIN. */
  close_socket (data.left);

  expect_fin (data.left, data.left_sent, 7, 7);
  forward_segment_ltr (&data);

  expect_ack (data.right, data.right_sent, 7, 8);
  drop_segment (data.right, data.right_sent);
  increment_time_both (&data, 300);  /* retransmit timeout */
  expect_fin (data.left, data.left_sent, 7, 7);
  forward_segment_ltr (&data);
  expect_ack (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);

  /* Close the RHS. */
  close_rhs (&data);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that closing a connection recovers from the second FIN segment being
 * dropped. Based on: RFC 793, Figure 13. */
static void
pseudotcp_close_normal_recovery3 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS. */
  close_lhs (&data);

  /* Close the RHS and drop the FIN segment. */
  close_socket (data.right);

  expect_fin (data.right, data.right_sent, 7, 8);
  drop_segment (data.right, data.right_sent);
  increment_time_both (&data, 300);  /* retransmit timeout */
  expect_fin (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);

  increment_time_both (&data, 10);  /* TIME-WAIT */
  expect_ack (data.left, data.left_sent, 8, 8);
  forward_segment_ltr (&data);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that closing a connection recovers from the second ACK segment being
 * dropped. Based on: RFC 793, Figure 13. */
static void
pseudotcp_close_normal_recovery4 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS. */
  close_lhs (&data);

  /* Close the RHS and drop the ACK segment. The RHS should retransmit the
   * FIN. The timers for the two peers are manipulated separately so the LHS
   * doesn’t exceed its TIME-WAIT while waiting for the retransmit. */
  close_socket (data.right);

  expect_fin (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);

  expect_ack (data.left, data.left_sent, 8, 8);
  drop_segment (data.left, data.left_sent);
  increment_time (data.right, &data.right_current_time, 300);  /* retransmit timeout */
  expect_fin (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);
  increment_time (data.left, &data.left_current_time, 10);  /* TIME-WAIT */
  expect_ack (data.left, data.left_sent, 8, 8);
  forward_segment_ltr (&data);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that if both FIN segments from a simultaneous FIN handshake are
 * dropped, the handshake recovers and completes successfully.
 * See: RFC 793, Figure 14. */
static void
pseudotcp_close_simultaneous_recovery1 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close both sides simultaneously and drop the FINs. */
  close_socket (data.left);
  close_socket (data.right);

  expect_fin (data.left, data.left_sent, 7, 7);
  expect_fin (data.right, data.right_sent, 7, 7);
  drop_segment (data.left, data.left_sent);
  drop_segment (data.right, data.right_sent);

  increment_time_both (&data, 400);  /* retransmit timeout */

  expect_fin (data.left, data.left_sent, 7, 7);
  expect_fin (data.right, data.right_sent, 7, 7);
  forward_segment_ltr (&data);
  forward_segment_rtl (&data);

  expect_ack (data.left, data.left_sent, 8, 8);
  expect_ack (data.right, data.right_sent, 8, 8);
  forward_segment_ltr (&data);
  forward_segment_rtl (&data);

  increment_time_both (&data, 10);  /* TIME-WAIT */
  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that if both ACK segments from a simultaneous FIN handshake are
 * dropped, the handshake recovers and completes successfully.
 * See: RFC 793, Figure 14. */
static void
pseudotcp_close_simultaneous_recovery2 (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close both sides simultaneously and forward the FINs. */
  close_socket (data.left);
  close_socket (data.right);

  expect_fin (data.left, data.left_sent, 7, 7);
  expect_fin (data.right, data.right_sent, 7, 7);
  forward_segment_ltr (&data);
  forward_segment_rtl (&data);

  /* Drop the ACKs. */
  expect_ack (data.left, data.left_sent, 8, 8);
  expect_ack (data.right, data.right_sent, 8, 8);
  drop_segment (data.left, data.left_sent);
  drop_segment (data.right, data.right_sent);

  increment_time_both (&data, 400);  /* retransmit timeout */

  expect_fin (data.left, data.left_sent, 7, 8);
  expect_fin (data.right, data.right_sent, 7, 8);
  forward_segment_ltr (&data);
  forward_segment_rtl (&data);

  expect_ack (data.left, data.left_sent, 8, 8);
  expect_ack (data.right, data.right_sent, 8, 8);
  forward_segment_ltr (&data);
  forward_segment_rtl (&data);

  increment_time_both (&data, 10);  /* TIME-WAIT */

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that closing a connection ignores a duplicate FIN segment.
 * Based on: RFC 793, Figure 13. */
static void
pseudotcp_close_duplicate_fin (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS. */
  close_lhs (&data);

  /* Close the RHS and duplicate the FIN segment. */
  close_socket (data.right);

  expect_fin (data.right, data.right_sent, 7, 8);
  duplicate_segment (data.right_sent);
  forward_segment_rtl (&data);
  forward_segment_rtl (&data);

  increment_time (data.left, &data.left_current_time, 10);  /* TIME-WAIT */
  expect_ack (data.left, data.left_sent, 8, 8);
  forward_segment_ltr (&data);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that closing a connection ignores a duplicate ACK segment.
 * Based on: RFC 793, Figure 13. */
static void
pseudotcp_close_duplicate_ack (void)
{
  Data data = { 0, };

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS. */
  close_lhs (&data);

  /* Close the RHS and duplicate the ACK segment. The RHS should reject the
   * duplicate with a RST segment. The LHS should then reject the RST. */
  close_socket (data.right);

  expect_fin (data.right, data.right_sent, 7, 8);
  forward_segment_rtl (&data);

  increment_time (data.left, &data.left_current_time, 10);  /* TIME-WAIT */
  expect_ack (data.left, data.left_sent, 8, 8);
  duplicate_segment (data.left_sent);
  forward_segment_ltr (&data);
  g_assert (!forward_segment (data.left_sent, data.right));
  expect_rst (data.right, data.right_sent, 8, 8);
  g_assert (!forward_segment (data.right_sent, data.left));

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that forcefully closing a connection by sending a RST segment works.
 * See: RFC 1122, §4.2.2.13. */
static void
pseudotcp_close_rst (void)
{
  Data data = { 0, };
  guint8 buf[100];

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS. */
  pseudo_tcp_socket_close (data.left, TRUE);

  g_assert_cmpint (pseudo_tcp_socket_send (data.left, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data.left), ==, EPIPE);
  g_assert_cmpint (pseudo_tcp_socket_recv (data.left, (char *) buf, sizeof (buf)), ==, 0);

  expect_rst (data.left, data.left_sent, 7, 7);
  g_assert (!forward_segment (data.left_sent, data.right));

  /* Check the RHS is closed. */
  g_assert_cmpint (pseudo_tcp_socket_send (data.right, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data.right), ==, EPIPE);
  g_assert_cmpint (pseudo_tcp_socket_recv (data.right, (char *) buf, sizeof (buf)), ==, 0);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that an RST is sent if a connection is closed with pending data in the
 * local receive buffer. See: RFC 1122, §4.2.2.13. */
static void
pseudotcp_close_pending_received (void)
{
  Data data = { 0, };
  guint8 buf[100];

  /* Establish a connection. */
  establish_connection (&data);

  /* Send some data from RHS to LHS. Do *not* read the data from the LHS receive
   * buffer. */
  g_assert_cmpint (pseudo_tcp_socket_send (data.right, "foo", 3), ==, 3);
  expect_data (data.right, data.right_sent, 7, 7, 3);
  forward_segment_rtl (&data);

  /* Close the LHS. */
  g_assert_cmpint (pseudo_tcp_socket_get_available_bytes (data.left), ==, 3);
  close_socket (data.left);

  expect_rst (data.left, data.left_sent, 7, 10);
  g_assert (!forward_segment (data.left_sent, data.right));

  /* Check the RHS is closed. */
  g_assert_cmpint (pseudo_tcp_socket_send (data.right, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data.right), ==, EPIPE);
  g_assert_cmpint (pseudo_tcp_socket_recv (data.right, (char *) buf, sizeof (buf)), ==, 0);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that an RST is sent if data is received on a socket after close() has
 * been called. See: RFC 1122, §4.2.2.13. */
static void
pseudotcp_close_rst_afterwards (void)
{
  Data data = { 0, };
  guint8 buf[100];

  /* Establish a connection. */
  establish_connection (&data);

  /* Close the LHS. */
  g_assert_cmpint (pseudo_tcp_socket_get_available_bytes (data.left), ==, 0);
  close_socket (data.left);

  expect_fin (data.left, data.left_sent, 7, 7);
  drop_segment (data.left, data.left_sent);  /* just to get it out of the way */

  /* Send some data from RHS to LHS, which should result in an RST. */
  g_assert_cmpint (pseudo_tcp_socket_send (data.right, "foo", 3), ==, 3);
  expect_data (data.right, data.right_sent, 7, 7, 3);
  g_assert (!forward_segment (data.right_sent, data.left));

  expect_rst (data.left, data.left_sent, 7, 7);
  g_assert (!forward_segment (data.left_sent, data.right));

  /* Check the RHS is closed. */
  g_assert_cmpint (pseudo_tcp_socket_send (data.right, "foo", 3), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data.right), ==, EPIPE);
  g_assert_cmpint (pseudo_tcp_socket_recv (data.right, (char *) buf, sizeof (buf)), ==, 0);

  expect_sockets_closed (&data);

  data_clear (&data);
}

/* Check that two pseudo-TCP sockets interact correctly even if FIN–ACK support
 * is disabled on one of them. */
static void
pseudotcp_compatibility (void)
{
  Data data = { 0, };
  guint8 buf[100];
  guint64 timeout;

  /* Establish a connection. Note the sequence numbers should start at 4 this
   * time, rather than the 7 in other tests, because the FIN–ACK option should
   * not be being sent. */
  create_sockets (&data, FALSE);
  pseudo_tcp_socket_connect (data.left);
  expect_segment (data.left, data.left_sent, 0, 0, 4, FLAG_SYN);
  forward_segment_ltr (&data);
  expect_segment (data.right, data.right_sent, 0, 4, 4, FLAG_SYN);
  forward_segment_rtl (&data);
  increment_time_both (&data, 110);
  expect_ack (data.left,  data.left_sent, 4, 4);
  forward_segment_ltr (&data);
  expect_sockets_connected (&data);

  /* Close it. Sending shouldn’t fail. */
  pseudo_tcp_socket_close (data.left, FALSE);
  g_assert (!pseudo_tcp_socket_is_closed (data.left));

  g_assert_cmpint (pseudo_tcp_socket_send (data.left, "foo", 3), ==, 3);
  g_assert_cmpint (pseudo_tcp_socket_recv (data.left, (char *) buf, sizeof (buf)), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data.left), ==, EWOULDBLOCK);

  expect_data (data.left, data.left_sent, 4, 4, 3);
  forward_segment_ltr (&data);

  increment_time_both (&data, 100);

  expect_ack (data.right, data.right_sent, 4, 7);
  forward_segment_rtl (&data);

  /* Advance the timers; now the LHS should be closed, as the RHS has ACKed all
   * outstanding data. */
  increment_time_both (&data, 50);

  g_assert (!pseudo_tcp_socket_get_next_clock (data.left, &timeout));

  /* Check the RHS can be closed after receiving the data just sent. */
  g_assert_cmpint (pseudo_tcp_socket_recv (data.right, (char *) buf, sizeof (buf)), ==, 3);
  g_assert_cmpint (pseudo_tcp_socket_recv (data.right, (char *) buf, sizeof (buf)), ==, -1);
  g_assert_cmpint (pseudo_tcp_socket_get_error (data.right), ==, EWOULDBLOCK);

  pseudo_tcp_socket_close (data.right, FALSE);

  g_assert (!pseudo_tcp_socket_get_next_clock (data.right, &timeout));

  expect_sockets_closed (&data);

  data_clear (&data);
}

int
main (int argc, char *argv[])
{
  setlocale (LC_ALL, "");
  g_test_init (&argc, &argv, NULL);
  pseudo_tcp_set_debug_level (PSEUDO_TCP_DEBUG_VERBOSE);

  /* There are four possible scenarios for the FIN handshake, if the possibility
   * of dropped or duplicated segments is ignored (but reordered segments are
   * allowed: normal, simultaneous, and two types of skew.
   *
   * These can be generated by considering the events happening at a single peer
   * during connection closure: sending the FIN (SF), receiving a FIN and
   * sending a FIN-ACK (RF), receiving a FIN-ACK (RA). These have the following
   * permutations:
   *  • SF, RF, RA
   *  • SF, RA, RF
   *  • RF, SF, RA
   * Other permutations are disallowed because SF must come before RA.
   *
   * The permutations of one peer’s (1) behaviour with a second (2) can then be
   * considered:
   *  • 1: SF, RF, RA; 2: SF, RF, RA  (simultaneous)
   *  • 1: SF, RF, RA; 2: SF, RA, RF  (skew 1)
   *  • 1: SF, RF, RA; 2: RF, SF, RA  (skew 2)
   *  • 1: SF, RA, RF; 2: RF, SF, RA  (normal)
   * Other permutations are disallowed because SF on one peer must come before
   * RF on the other; similarly RF on one must come before RA on the other.
   *
   * Thus, the following unit tests provably cover all possible scenarios where
   * segments can be reordered but not dropped or duplicated. */
  g_test_add_func ("/pseudotcp/close/normal",
      pseudotcp_close_normal);
  g_test_add_func ("/pseudotcp/close/simultaneous",
      pseudotcp_close_simultaneous);
  g_test_add_func ("/pseudotcp/close/skew1",
      pseudotcp_close_skew1);
  g_test_add_func ("/pseudotcp/close/skew2",
      pseudotcp_close_skew2);

  /* An arbitrary (less methodical) selection of unit tests for dropped and
   * duplicated packets. */
  g_test_add_func ("/pseudotcp/close/normal/recovery1",
      pseudotcp_close_normal_recovery1);
  g_test_add_func ("/pseudotcp/close/normal/recovery2",
      pseudotcp_close_normal_recovery2);
  g_test_add_func ("/pseudotcp/close/normal/recovery3",
      pseudotcp_close_normal_recovery3);
  g_test_add_func ("/pseudotcp/close/normal/recovery4",
      pseudotcp_close_normal_recovery4);
  g_test_add_func ("/pseudotcp/close/simultaneous/recovery1",
      pseudotcp_close_simultaneous_recovery1);
  g_test_add_func ("/pseudotcp/close/simultaneous/recovery2",
      pseudotcp_close_simultaneous_recovery2);
  g_test_add_func ("/pseudotcp/close/duplicate-fin",
      pseudotcp_close_duplicate_fin);
  g_test_add_func ("/pseudotcp/close/duplicate-ack",
      pseudotcp_close_duplicate_ack);

  g_test_add_func ("/pseudotcp/close/rst",
      pseudotcp_close_rst);
  g_test_add_func ("/pseudotcp/close/pending-received",
      pseudotcp_close_pending_received);
  g_test_add_func ("/pseudotcp/close/rst-afterwards",
      pseudotcp_close_rst_afterwards);

  g_test_add_func ("/pseudotcp/compatibility",
      pseudotcp_compatibility);

  g_test_run ();

  return 0;
}
