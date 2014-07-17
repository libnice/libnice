/* vim: et ts=2 sw=2 tw=80: */
/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2010, 2014 Collabora Ltd.
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
 *   Youness Alaoui, Collabora Ltd.
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
#include "config.h"
#endif

#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>

#include "pseudotcp.h"


/**
 * A fuzzing test for the pseudotcp socket. This connects two sockets in a
 * loopback arrangement, with the packet output from one being fed to the other,
 * and vice-versa. Fuzzing happens on the packet interface between the two,
 * mutating the packets slightly and seeing what happens.
 *
 * The input data to the left-most socket is read from a file. The output data
 * from the loopback is written to another file, although this probably isn’t
 * very useful. If no files are provided, a small amount of dummy data is sent
 * through the sockets instead. This almost certainly won’t catch any bugs, and
 * is just present to allow this test to be run as part of `make check` so it
 * doesn’t bit rot.
 *
 * A good command to generate an input file is:
 *     dd if=/dev/urandom of=rand count=10000 ibs=1024
 *
 * None of the data is validated, and the test results are effectively the 1-bit
 * value of ‘did it crash?’. In particular, the output file is not validated,
 * and the TCP packets emitted by both sockets are not checked for validity.
 *
 * It is suggested that this test is run under GDB and Valgrind. Any crashes or
 * errors which are detected can be reproduced by providing the same input file
 * and seed (using the --seed option). The seed is printed out at the beginning
 * of each test run.
 */


PseudoTcpSocket *left;
PseudoTcpSocket *right;
GMainLoop *main_loop = NULL;
GRand *prng = NULL;
gint retval = 0;
FILE *in = NULL;
FILE *out = NULL;
int total_read = 0;
int total_wrote = 0;
guint left_clock = 0;
guint right_clock = 0;
gboolean left_closed = FALSE;
gboolean right_closed = FALSE;
gboolean reading_done = FALSE;

/* Number of bytes of payload each socket has received so far. */
guint32 left_stream_pos = 0;
guint32 right_stream_pos = 0;

/* Configuration options. */
gint64 seed = 0;
guint32 fuzz_start_pos = 1;  /* bytes into stream payload; after the SYN-ACKs */
guint n_changes_lambda = 2;  /* lambda parameter for a Poisson distribution
                              * controlling the number of mutations made to each
                              * packet */


static void
adjust_clock (PseudoTcpSocket *sock);


static void
write_to_sock (PseudoTcpSocket *sock)
{
  gchar buf[1024];
  gsize len;
  gint wlen;
  guint total = 0;

  while (TRUE) {
    len = fread (buf, 1, sizeof(buf), in);
    if (len == 0) {
      g_debug ("Done reading data from file");
      g_assert (feof (in));
      reading_done = TRUE;
      pseudo_tcp_socket_close (sock, FALSE);
      break;
    } else {
      wlen = pseudo_tcp_socket_send (sock, buf, len);
      g_debug ("Sending %" G_GSIZE_FORMAT " bytes : %d", len, wlen);
      total += wlen;
      total_read += wlen;
      if (wlen < (gint) len) {
        g_debug ("seeking  %ld from %lu", wlen - len, ftell (in));
        fseek (in, wlen - len, SEEK_CUR);
        g_assert (!feof (in));
        g_debug ("Socket queue full after %d bytes written", total);
        break;
      }
    }
  }
  adjust_clock (sock);
}

static void
opened (PseudoTcpSocket *sock, gpointer data)
{
  g_debug ("Socket %p Opened", sock);
  if (sock == left) {
    if (in)
      write_to_sock (sock);
    else {
      pseudo_tcp_socket_send (sock, "abcdefghijklmnopqrstuvwxyz", 26);
      reading_done = TRUE;
      pseudo_tcp_socket_close (sock, FALSE);
    }
  }
}

static void
readable (PseudoTcpSocket *sock, gpointer data)
{
  gchar buf[1024];
  gint len;
  g_debug ("Socket %p Readable", sock);

  do {
    len = pseudo_tcp_socket_recv (sock, buf, sizeof(buf));

    if (len > 0) {
      g_debug ("Read %d bytes", len);
      if (out) {
        if (fwrite (buf, len, 1, out) == 0)
          g_debug ("Error writing to output file");
        else {
          total_wrote += len;

          g_assert (total_wrote <= total_read);
          g_debug ("Written %d bytes, need %d bytes", total_wrote, total_read);
          if (total_wrote == total_read && feof (in)) {
            g_assert (reading_done);
            pseudo_tcp_socket_close (sock, FALSE);
          }
        }
      } else {
        pseudo_tcp_socket_close (sock, FALSE);
      }
    } else if (len == 0) {
      pseudo_tcp_socket_close (sock, FALSE);
    }
  } while (len > 0);

  if (len == -1 &&
      pseudo_tcp_socket_get_error (sock) != EWOULDBLOCK) {
    g_printerr ("Error reading from socket %p: %s.\n",
        sock, g_strerror (pseudo_tcp_socket_get_error (sock)));

    retval = -1;
    g_main_loop_quit (main_loop);
    return;
  }
}

static void
writable (PseudoTcpSocket *sock, gpointer data)
{
  g_debug ("Socket %p Writable", sock);
  if (in && sock == left)
    write_to_sock (sock);
}

static void
closed (PseudoTcpSocket *sock, guint32 err, gpointer data)
{
  /* Don’t treat this as an error, since we’re throwing rubbish into the
   * socket and can hardly expect it to complete successfully. */
  g_debug ("Socket %p Closed: %s", sock, g_strerror (err));
  retval = 0;
  g_main_loop_quit (main_loop);
}

struct notify_data {
  PseudoTcpSocket *sock;
  guint32 len;
  guint32 stream_pos;
  guint8 buffer[];
};

/**
 * random_int_poisson:
 * @lambda: Lambda parameter for the distribution function, which must be
 * non-zero
 *
 * Generate a random variable from a Poisson distribution with parameter
 * @lambda. This consumes one %gdouble’s worth of randomness from the global
 * @prng.
 *
 * This is implemented using the inverse transform of the Poisson CDF, and is
 * guaranteed to return in time linearly proportional to @lambda.
 *
 * Returns: Poisson-distributed pseudo-random variable
 */
static guint32
random_int_poisson (guint lambda)
{
  gdouble U;
  guint32 i;
  gdouble p, F;

  g_return_val_if_fail (lambda > 0, 0);

  /*
   * Reference: http://www.cs.bgu.ac.il/~mps042/invtransnote.htm,
   * §Simulating a Poisson random variable.
   */
  U = g_rand_double (prng);  /* step 1 */
  i = 0;
  p = exp (0.0 - (gdouble) lambda);
  F = p;  /* step 2 */

  while (U >= F) {  /* step 3 */
    p = (lambda * p) / (i + 1);
    F += p;
    i += 1;  /* step 4 and 5 */
  }

  return i;
}

static guint32
fuzz_packet (guint8 *buf, guint32 len, guint32 stream_pos)
{
  guint32 i;
  guint n_changes;
#define TCP_HEADER_LENGTH 32 /* bytes; or thereabouts (include some options) */

  /* Do we want to fuzz this packet? */
  if (stream_pos < fuzz_start_pos) {
    return len;
  }

  /* Get fuzzing. Only bother fuzzing the header; fuzzing the payload is
   * pointless. Weight the number of changes towards having only a few changes,
   * since that makes them less likely to be summarily rejected. */
  n_changes = random_int_poisson (n_changes_lambda);
  g_debug ("Making %u changes for bytes at stream position %u:",
      n_changes, stream_pos);

  for (i = 0; i < n_changes; i++) {
    guint32 pos = g_rand_int_range (prng, 0, MIN (len, TCP_HEADER_LENGTH));
    g_debug (" • Changing byte %u.", stream_pos + pos);
    buf[pos] = g_rand_int_range (prng, 0, G_MAXUINT8 + 1);
  }

  return len;
}

static gboolean
notify_packet (gpointer user_data)
{
  struct notify_data *data = (struct notify_data*) user_data;

  /* Fuzz the packet. */
  data->len = fuzz_packet (data->buffer, data->len, data->stream_pos);

  pseudo_tcp_socket_notify_packet (data->sock,
      (gchar *) data->buffer, data->len);
  adjust_clock (data->sock);

  g_free (data);
  return FALSE;
}

static PseudoTcpWriteResult
write_packet (PseudoTcpSocket *sock, const gchar *buffer, guint32 len,
    gpointer user_data)
{
  struct notify_data *data;
  PseudoTcpState state;
  g_object_get (sock, "state", &state, NULL);

  data = g_malloc (sizeof(struct notify_data) + len);

  g_debug ("Socket %p(%d) Writing : %d bytes", sock, state, len);

  memcpy (data->buffer, buffer, len);
  data->len = len;

  if (sock == left) {
    data->stream_pos = left_stream_pos;
    left_stream_pos += len;
    data->sock = right;
  } else {
    data->stream_pos = right_stream_pos;
    right_stream_pos += len;
    data->sock = left;
  }

  g_idle_add (notify_packet, data);

  return WR_SUCCESS;
}


static gboolean notify_clock (gpointer data)
{
  PseudoTcpSocket *sock = (PseudoTcpSocket *)data;
  //g_debug ("Socket %p: Notifying clock", sock);
  pseudo_tcp_socket_notify_clock (sock);
  adjust_clock (sock);
  return FALSE;
}

static void adjust_clock (PseudoTcpSocket *sock)
{
  guint64 timeout = 0;

  if (pseudo_tcp_socket_get_next_clock (sock, &timeout)) {
    timeout -= g_get_monotonic_time () / 1000;
    g_debug ("Socket %p: Adjusting clock to %ld ms", sock, timeout);
    if (sock == left) {
      if (left_clock != 0)
         g_source_remove (left_clock);
      left_clock = g_timeout_add (timeout, notify_clock, sock);
    } else {
      if (right_clock != 0)
         g_source_remove (right_clock);
      right_clock = g_timeout_add (timeout, notify_clock, sock);
    }
  } else {
    g_debug ("Socket %p should be destroyed, it's done", sock);
    if (sock == left)
      left_closed = TRUE;
    else
      right_closed = TRUE;
    if (left_closed && right_closed)
      g_main_loop_quit (main_loop);
  }
}

static GOptionEntry entries[] = {
  { "seed", 's', 0, G_OPTION_ARG_INT64, &seed, "PRNG seed", "N" },
  { "fuzz-start-position", 'p', 0, G_OPTION_ARG_INT, &fuzz_start_pos,
    "Number of bytes into the stream to start fuzzing after", "B" },
  { "fuzz-n-changes-lambda", 'l', 0, G_OPTION_ARG_INT, &n_changes_lambda,
    "Lambda value for the Poisson distribution controlling the number of "
    "changes made to each packet", "λ" },
  { NULL }
};

int main (int argc, char *argv[])
{
  PseudoTcpCallbacks cbs = {
    NULL, opened, readable, writable, closed, write_packet
  };
  GOptionContext *context;
  GError *error = NULL;

  setlocale (LC_ALL, "");
  g_type_init ();

  /* Configuration. */
  context = g_option_context_new ("— fuzz-test the pseudotcp socket");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("Option parsing failed: %s\n", error->message);
    goto context_error;
  }

  if (n_changes_lambda == 0) {
    g_printerr ("Option parsing failed: %s\n",
        "Lambda values must be positive.");
    goto context_error;
  }

  g_option_context_free (context);

  /* Tweak the configuration. */
  if (seed == 0) {
    seed = g_get_real_time ();
  }

  /* Open the input and output files */
  if (argc >= 3) {
    in = fopen (argv[1], "r");
    out = fopen (argv[2], "w");
  }

  /* Set up the main loop and sockets. */
  main_loop = g_main_loop_new (NULL, FALSE);

  g_print ("Using seed: %" G_GINT64_FORMAT ", start position: %u, λ: %u\n",
      seed, fuzz_start_pos, n_changes_lambda);
  prng = g_rand_new_with_seed (seed);

  pseudo_tcp_set_debug_level (PSEUDO_TCP_DEBUG_VERBOSE);

  left = pseudo_tcp_socket_new (0, &cbs);
  right = pseudo_tcp_socket_new (0, &cbs);
  g_debug ("Left: %p. Right: %p", left, right);

  pseudo_tcp_socket_notify_mtu (left, 1496);
  pseudo_tcp_socket_notify_mtu (right, 1496);

  pseudo_tcp_socket_connect (left);
  adjust_clock (left);
  adjust_clock (right);

  /* Run the main loop. */
  g_main_loop_run (main_loop);
  g_main_loop_unref (main_loop);

  g_object_unref (left);
  g_object_unref (right);

  g_rand_free (prng);

  if (in != NULL)
    fclose (in);
  if (out != NULL)
    fclose (out);

  return retval;

context_error:
  g_printerr ("\n%s\n", g_option_context_get_help (context, TRUE, NULL));
  g_option_context_free (context);

  return 1;
}
