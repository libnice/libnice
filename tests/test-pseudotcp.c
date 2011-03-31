/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2010 Collabora Ltd.
 *  Contact: Youness Alaoui
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
# include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "pseudotcp.h"

PseudoTcpSocket *left;
PseudoTcpSocket *right;
GMainLoop *mainloop = NULL;
FILE *in = NULL;
FILE *out = NULL;
int total_read = 0;
int total_wrote = 0;
guint left_clock = 0;
guint right_clock = 0;

static void adjust_clock (PseudoTcpSocket *sock);

static void write_to_sock (PseudoTcpSocket *sock)
{
  gchar buf[1024];
  guint len;
  guint wlen;
  guint total = 0;

  while (TRUE) {
    len = fread (buf, 1, sizeof(buf), in);
    if (len == 0) {
      g_debug ("Done reading data from file");
      pseudo_tcp_socket_close (sock, FALSE);
      break;
    } else {
      wlen = pseudo_tcp_socket_send (sock, buf, len);
      g_debug ("Sending %d bytes : %d", len, wlen);
      total += wlen;
      total_read += wlen;
      if (wlen < len) {
        fseek (in, wlen - len, SEEK_CUR);
        g_debug ("Socket queue full after %d bytes written", total);
        break;
      }
    }
  }
  adjust_clock (sock);
}

static void opened (PseudoTcpSocket *sock, gpointer data)
{
  g_debug ("Socket %p Opened", sock);
  if (sock == left) {
    if (in)
      write_to_sock (sock);
    else {
      pseudo_tcp_socket_send (sock, "abcdefghijklmnopqrstuvwxyz", 26);
      pseudo_tcp_socket_close (sock, FALSE);
    }
  }
}

static void readable (PseudoTcpSocket *sock, gpointer data)
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

          g_debug ("Written %d bytes, need %d bytes", total_wrote, total_read);
          if (total_wrote >= total_read && feof (in)) {
            pseudo_tcp_socket_close (left, FALSE);
            pseudo_tcp_socket_close (right, FALSE);
          }
        }
      } else {
        if (len == 26 && strncmp (buf, "abcdefghijklmnopqrstuvwxyz", len) == 0) {
          pseudo_tcp_socket_close (left, FALSE);
          pseudo_tcp_socket_close (right, FALSE);
        } else {
          g_debug ("Error reading data.. read %d bytes : %s", len, buf);
          exit (-1);
        }
      }
    }
  } while (len > 0);

  if (len == -1 &&
      pseudo_tcp_socket_get_error (sock) != EWOULDBLOCK) {
    g_debug ("Error reading from socket : %d",
        pseudo_tcp_socket_get_error (sock));
    exit (-1);
  }

  adjust_clock (sock);
}

static void writable (PseudoTcpSocket *sock, gpointer data)
{
  g_debug ("Socket %p Writable", sock);
  if (in)
    write_to_sock (sock);
}

static void closed (PseudoTcpSocket *sock, guint32 err, gpointer data)
{
  g_debug ("Socket %p Closed : %d", sock, err);
}

struct notify_data {
  PseudoTcpSocket *sock;
  gchar *buffer;
  guint32 len;
};

static gboolean notify_packet (gpointer user_data)
{
  struct notify_data *data = (struct notify_data*) user_data;
  if (!data->sock || (data->sock != left && data->sock != right))
    return FALSE;
  pseudo_tcp_socket_notify_packet (data->sock, data->buffer, data->len);
  adjust_clock (data->sock);
  g_free (data->buffer);
  g_free (data);
  return FALSE;
}

static PseudoTcpWriteResult write (PseudoTcpSocket *sock,
    const gchar *buffer, guint32 len, gpointer user_data)
{
  struct notify_data *data;
  PseudoTcpState state;
  int drop_rate = rand () % 100;
  g_object_get (sock, "state", &state, NULL);

  if (drop_rate < 5) {
    g_debug ("*********************Dropping packet (%d)", drop_rate);
    return WR_SUCCESS;
  }

  data = g_new0 (struct notify_data,1);

  g_debug ("Socket %p(%d) Writing : %d bytes", sock, state, len);

  data->buffer = g_malloc (len);
  memcpy (data->buffer, buffer, len);
  data->len = len;

  if (sock == left) {
    data->sock = right;
  } else {
    data->sock = left;
  }

  g_idle_add (notify_packet, data);

  return WR_SUCCESS;
}


static gboolean notify_clock (gpointer data)
{
  PseudoTcpSocket *sock = (PseudoTcpSocket *)data;
  if (sock != left && sock != right)
    return FALSE;
  //g_debug ("Socket %p: Notifying clock", sock);
  pseudo_tcp_socket_notify_clock (sock);
  adjust_clock (sock);
  return FALSE;
}

static void adjust_clock (PseudoTcpSocket *sock)
{
  long timeout = 0;
  if (pseudo_tcp_socket_get_next_clock (sock, &timeout)) {
    //g_debug ("Socket %p: Adjuting clock to %ld ms", sock, timeout);
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
    g_debug ("Socket %p should be destroyed", sock);
    g_object_unref (sock);
    if (sock == left)
      left = NULL;
    else
      right = NULL;
    if (left == right)
      g_main_loop_quit (mainloop);
  }
}


int main (int argc, char *argv[])
{
  PseudoTcpCallbacks cbs = {NULL, opened, readable, writable, closed, write};

  mainloop = g_main_loop_new (NULL, FALSE);

  g_type_init ();

  pseudo_tcp_set_debug_level (PSEUDO_TCP_DEBUG_VERBOSE);

  left = pseudo_tcp_socket_new (0, &cbs);
  right = pseudo_tcp_socket_new (0, &cbs);
  g_debug ("Left: %p. Right: %p", left, right);

  pseudo_tcp_socket_notify_mtu (left, 1496);
  pseudo_tcp_socket_notify_mtu (right, 1496);

  pseudo_tcp_socket_connect (left);
  adjust_clock (left);
  adjust_clock (right);

  if (argc == 3) {
    in = fopen (argv[1], "r");
    out = fopen (argv[2], "w");
  }

  g_main_loop_run (mainloop);

  if (in)
    fclose (in);
  if (out)
    fclose (out);

  return 0;
}

