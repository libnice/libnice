/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation. All rights reserved.
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

/*
 * Implementation of TCP relay socket interface using TCP Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "http.h"
#include "agent-priv.h"
#include "socket-priv.h"

#include <string.h>
#include <stdlib.h>


#ifndef G_OS_WIN32
#include <unistd.h>
#endif


#define HTTP_USER_AGENT "libnice"

typedef enum {
  HTTP_STATE_INIT,
  HTTP_STATE_HEADERS,
  HTTP_STATE_BODY,
  HTTP_STATE_CONNECTED,
  HTTP_STATE_ERROR
} HttpState;

typedef struct {
  HttpState state;
  NiceSocket *base_socket;
  NiceAddress addr;
  gchar *username;
  gchar *password;
  GQueue send_queue;

  /* Ring buffer for receiving HTTP headers into before they’re parsed. */
  guint8 *recv_buf;
  gsize recv_buf_length;  /* allocation size of @recv_buf */
  gsize recv_buf_pos;  /* offset from @recv_buf of the 0th byte in the buffer */
  gsize recv_buf_fill;  /* number of bytes occupied in the buffer */

  /* Parsed from the Content-Length header provided by the other endpoint. */
  gsize content_length;
} HttpPriv;


static void socket_close (NiceSocket *sock);
static gint socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages);
static gint socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages);
static gint socket_send_messages_reliable (NiceSocket *sock,
    const NiceAddress *to, const NiceOutputMessage *messages, guint n_messages);
static gboolean socket_is_reliable (NiceSocket *sock);
static gboolean socket_can_send (NiceSocket *sock, NiceAddress *addr);
static void socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data);

NiceSocket *
nice_http_socket_new (NiceSocket *base_socket,
    NiceAddress *addr, gchar *username, gchar *password)
{
  HttpPriv *priv;
  NiceSocket *sock = NULL;

  if (addr) {
    sock = g_slice_new0 (NiceSocket);
    sock->priv = priv = g_slice_new0 (HttpPriv);

    priv->base_socket = base_socket;
    priv->addr = *addr;
    priv->username = g_strdup (username);
    priv->password = g_strdup (password);
    priv->recv_buf = NULL;
    priv->recv_buf_length = 0;
    priv->recv_buf_pos = 0;
    priv->recv_buf_fill = 0;
    priv->content_length = 0;

    sock->type = NICE_SOCKET_TYPE_HTTP;
    sock->fileno = priv->base_socket->fileno;
    sock->addr = priv->base_socket->addr;
    sock->send_messages = socket_send_messages;
    sock->send_messages_reliable = socket_send_messages_reliable;
    sock->recv_messages = socket_recv_messages;
    sock->is_reliable = socket_is_reliable;
    sock->can_send = socket_can_send;
    sock->set_writable_callback = socket_set_writable_callback;
    sock->close = socket_close;

    /* Send HTTP CONNECT */
    {
      gchar *msg = NULL;
      gchar *credential = NULL;
      gchar host[INET6_ADDRSTRLEN];
      gint port = nice_address_get_port (&priv->addr);
      GOutputVector local_bufs;
      NiceOutputMessage local_messages;

      nice_address_to_string (&priv->addr, host);

      if (username) {
        gchar * userpass = g_strdup_printf ("%s:%s", username,
            password ? password : "");
        gchar * auth = g_base64_encode ((guchar *)userpass, strlen (userpass));
        credential = g_strdup_printf ("Proxy-Authorization: Basic %s\r\n", auth);
        g_free (auth);
        g_free (userpass);
      }
      msg = g_strdup_printf ("CONNECT %s:%d HTTP/1.0\r\n"
          "Host: %s\r\n"
          "User-Agent: %s\r\n"
          "Content-Length: 0\r\n"
          "Proxy-Connection: Keep-Alive\r\n"
          "Connection: Keep-Alive\r\n"
          "Cache-Control: no-cache\r\n"
          "Pragma: no-cache\r\n"
          "%s\r\n", host, port, host, HTTP_USER_AGENT,
          credential? credential : "" );
      g_free (credential);

      local_bufs.buffer = msg;
      local_bufs.size = strlen (msg);
      local_messages.buffers = &local_bufs;
      local_messages.n_buffers = 1;

      nice_socket_send_messages_reliable (priv->base_socket, NULL,
          &local_messages, 1);
      priv->state = HTTP_STATE_INIT;
      g_free (msg);
    }
  }

  return sock;
}


static void
socket_close (NiceSocket *sock)
{
  HttpPriv *priv = sock->priv;

  if (priv->base_socket)
    nice_socket_free (priv->base_socket);

  if (priv->username)
    g_free (priv->username);

  if (priv->password)
    g_free (priv->password);

  if (priv->recv_buf)
    g_free (priv->recv_buf);

  nice_socket_free_send_queue (&priv->send_queue);

  g_slice_free(HttpPriv, sock->priv);
  sock->priv = NULL;
}

static void
assert_ring_buffer_valid (HttpPriv *priv)
{
  g_assert (priv->recv_buf_fill <= priv->recv_buf_length);
  g_assert (priv->recv_buf_pos == 0 ||
      priv->recv_buf_pos < priv->recv_buf_length);
  g_assert (priv->recv_buf_length == 0 || priv->recv_buf != NULL);
}

/* Pops up to @buffer_length bytes off the ring buffer and copies them into
 * @buffer. Returns the number of bytes copied. */
static gsize
memcpy_ring_buffer_to_buffer (HttpPriv *priv,
    guint8 *buffer, gsize buffer_length)
{
  gsize len, consumed = 0;
  gboolean has_wrapped;

  has_wrapped =
      (priv->recv_buf_pos + priv->recv_buf_fill) > priv->recv_buf_length;

  if (has_wrapped) {
    len = MIN (priv->recv_buf_length - priv->recv_buf_pos, buffer_length);
    memcpy (buffer, priv->recv_buf + priv->recv_buf_pos, len);
    consumed += len;

    buffer += len;
    buffer_length -= len;

    len = MIN (priv->recv_buf_fill - len, buffer_length);
    memcpy (buffer, priv->recv_buf, len);
    consumed += len;
  } else {
    len = MIN (priv->recv_buf_fill, buffer_length);
    memcpy (buffer, priv->recv_buf + priv->recv_buf_pos, len);
    consumed += len;
  }

  priv->recv_buf_pos =
      (priv->recv_buf_pos + consumed) % priv->recv_buf_length;
  priv->recv_buf_fill -= consumed;

  return consumed;
}

/* Returns the number of messages touched. Silently drops any data from @buffer
 * which doesn’t fit in @messages. Updates the ring buffer to pop the copied
 * data off it. Treats all #GInputVectors in @messages the same; there is no
 * differentiation between different #NiceInputMessages. */
static gint
memcpy_ring_buffer_to_input_messages (HttpPriv *priv,
    NiceInputMessage *messages, guint n_messages)
{
  guint i, j;

  for (i = 0; priv->recv_buf_fill > 0 && i < n_messages; i++) {
    NiceInputMessage *message = &messages[i];

    for (j = 0;
         priv->recv_buf_fill > 0 &&
         ((message->n_buffers >= 0 && j < (guint) message->n_buffers) ||
          (message->n_buffers < 0 && message->buffers[j].buffer != NULL));
         j++) {
      message->buffers[j].size =
          memcpy_ring_buffer_to_buffer (priv,
              message->buffers[j].buffer, message->buffers[j].size);
    }
  }

  return i;
}

/* FIXME: The current implementation of socket_recv_message() is a fast
 * pass-through to nice_socket_recv_message() if the HTTP socket is connected,
 * but is a slow state machine otherwise, using multiple memcpy()s. Spruce it up
 * to better to use the recv_messages to avoid the memcpy()s. */
static gint
socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  HttpPriv *priv = sock->priv;
  gint ret = -1;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return 0;

  if (priv->state == HTTP_STATE_CONNECTED) {
    guint i;

    /* Fast path: pass through to the base socket once we’re connected. */
    if (priv->base_socket) {
      ret = nice_socket_recv_messages (priv->base_socket,
          recv_messages, n_recv_messages);
    }

    if (ret <= 0)
      return ret;

    /* After successfully receiving into at least one NiceInputMessage,
     * update the from address in each valid NiceInputMessage. */
    for (i = 0; i < (guint) ret; i++) {
      if (recv_messages[i].from != NULL)
        *recv_messages[i].from = priv->addr;
    }

    return ret;
  } else {
    /* Slow path: read into a local ring buffer until we’re parsed enough of the
     * headers. Double the buffer in size every time it fills up. */
    gboolean has_wrapped;
    GInputVector local_recv_bufs[2];
    NiceInputMessage local_recv_message = { local_recv_bufs, 2, NULL, 0 };

    /* Has the buffer filled up? Start with an initial buffer of 1KB, which
     * should cover the average size of HTTP response headers. Source:
     * http://dev.chromium.org/spdy/spdy-whitepaper */
    if (priv->recv_buf_fill == priv->recv_buf_length) {
      priv->recv_buf_length = MAX (priv->recv_buf_length * 2, 1024);
      priv->recv_buf = g_realloc (priv->recv_buf, priv->recv_buf_length);
    }

    assert_ring_buffer_valid (priv);

    /* Read some data into the buffer. Use two GInputVectors: one for the tail
     * of the buffer and one for the head. */
    has_wrapped =
        (priv->recv_buf_pos + priv->recv_buf_fill) > priv->recv_buf_length;

    if (has_wrapped) {
      local_recv_bufs[0].buffer =
           priv->recv_buf + (priv->recv_buf_pos + priv->recv_buf_fill) %
           priv->recv_buf_length;
      local_recv_bufs[0].size = priv->recv_buf_length - priv->recv_buf_fill;
      local_recv_bufs[1].buffer = NULL;
      local_recv_bufs[1].size = 0;
    } else {
      local_recv_bufs[0].buffer =
          priv->recv_buf + priv->recv_buf_pos + priv->recv_buf_fill;
      local_recv_bufs[0].size =
          priv->recv_buf_length - (priv->recv_buf_pos + priv->recv_buf_fill);
      local_recv_bufs[1].buffer = priv->recv_buf;
      local_recv_bufs[1].size = priv->recv_buf_pos;
    }

    if (priv->base_socket) {
      ret = nice_socket_recv_messages (priv->base_socket,
          &local_recv_message, 1);
    }

    if (ret <= 0)
      return ret;

    /* Update the buffer’s metadata. */
    priv->recv_buf_fill += local_recv_message.length;
    assert_ring_buffer_valid (priv);

    /* Fall through and try parsing the newly received data. */
  }

#define GET_BYTE(pos) \
  priv->recv_buf[(pos + priv->recv_buf_pos) % priv->recv_buf_length]
#define EAT_WHITESPACE(pos) \
  while (pos < priv->recv_buf_fill && GET_BYTE(pos) == ' ') \
    pos++; \
  if (pos >= priv->recv_buf_fill) \
    goto not_enough_data;

retry:
  nice_debug ("Receiving from HTTP proxy (state %d) : %" G_GSSIZE_FORMAT " \n"
      "'%s'", priv->state, priv->recv_buf_fill,
      priv->recv_buf + priv->recv_buf_pos);

  switch (priv->state) {
    case HTTP_STATE_INIT:
      {
        /* This is a logical position in the recv_buf; add
         * (priv->recv_buf + priv->recv_buf_pos) to get the actual byte in
         * memory. */
        guint pos = 0;

        /* Eat leading whitespace and check we have enough data. */
        EAT_WHITESPACE (pos);

        if (pos + 7 > priv->recv_buf_fill)
          goto not_enough_data;
        if (GET_BYTE (pos + 0) != 'H' ||
            GET_BYTE (pos + 1) != 'T' ||
            GET_BYTE (pos + 2) != 'T' ||
            GET_BYTE (pos + 3) != 'P' ||
            GET_BYTE (pos + 4) != '/' ||
            GET_BYTE (pos + 5) != '1' ||
            GET_BYTE (pos + 6) != '.')
          goto error;
        pos += 7;

        if (pos >= priv->recv_buf_fill)
          goto not_enough_data;
        if (GET_BYTE (pos) != '0' && GET_BYTE (pos) != '1')
          goto error;
        pos++;

        /* Make sure we have a space after the HTTP version */
        if (pos >= priv->recv_buf_fill)
          goto not_enough_data;
        if (GET_BYTE (pos) != ' ')
          goto error;

        EAT_WHITESPACE (pos);

        /* Check for a successful 2xx code */
        if (pos + 3 > priv->recv_buf_fill)
          goto not_enough_data;
        if (GET_BYTE (pos) != '2' ||
            GET_BYTE (pos + 1) < '0' || GET_BYTE (pos + 1) > '9' ||
            GET_BYTE (pos + 2) < '0' || GET_BYTE (pos + 2) > '9')
          goto error;

        /* Clear any trailing chars */
        while (pos + 1 < priv->recv_buf_fill &&
            GET_BYTE (pos) != '\r' && GET_BYTE (pos + 1) != '\n')
          pos++;
        if (pos + 1 >= priv->recv_buf_fill)
          goto not_enough_data;
        pos += 2;

        /* Consume the data we just parsed. */
        priv->recv_buf_pos = (priv->recv_buf_pos + pos) % priv->recv_buf_length;
        priv->recv_buf_fill -= pos;

        priv->content_length = 0;
        priv->state = HTTP_STATE_HEADERS;

        goto retry;
      }
      break;
    case HTTP_STATE_HEADERS:
      {
        guint pos = 0;

        if (pos + 15 < priv->recv_buf_fill &&
            (GET_BYTE (pos +  0) == 'C' || GET_BYTE (pos +  0) == 'c') &&
            (GET_BYTE (pos +  1) == 'o' || GET_BYTE (pos +  1) == 'O') &&
            (GET_BYTE (pos +  2) == 'n' || GET_BYTE (pos +  2) == 'N') &&
            (GET_BYTE (pos +  3) == 't' || GET_BYTE (pos +  3) == 'T') &&
            (GET_BYTE (pos +  4) == 'e' || GET_BYTE (pos +  4) == 'E') &&
            (GET_BYTE (pos +  5) == 'n' || GET_BYTE (pos +  5) == 'N') &&
            (GET_BYTE (pos +  6) == 't' || GET_BYTE (pos +  6) == 'T') &&
             GET_BYTE (pos +  7) == '-' &&
            (GET_BYTE (pos +  8) == 'L' || GET_BYTE (pos +  8) == 'l') &&
            (GET_BYTE (pos +  9) == 'e' || GET_BYTE (pos +  9) == 'E') &&
            (GET_BYTE (pos + 10) == 'n' || GET_BYTE (pos + 10) == 'N') &&
            (GET_BYTE (pos + 11) == 'g' || GET_BYTE (pos + 11) == 'G') &&
            (GET_BYTE (pos + 12) == 't' || GET_BYTE (pos + 12) == 'T') &&
            (GET_BYTE (pos + 13) == 'h' || GET_BYTE (pos + 13) == 'H') &&
             GET_BYTE (pos + 14) == ':') {
          /* Found a Content-Length header. Parse and store the value. Note that
           * the HTTP standard allows for arbitrarily-big content lengths. We
           * limit it to G_MAXSIZE for sanity’s sake.
           *
           * The code below is equivalent to strtoul(input, NULL, 10), but
           * operates on a ring buffer. */
          pos += 15;
          EAT_WHITESPACE (pos);
          priv->content_length = 0;

          while (TRUE) {
            guint8 byte = GET_BYTE (pos);
            gint val = g_ascii_digit_value (byte);

            if (byte == '\r') {
              /* Reached the end of the value; fall out to the code below which
               * will grab the \n. */
              break;
            } else if (val == -1) {
              priv->content_length = 0;
              goto error;
            }

            /* Check for overflow. Don’t flag it as an error; just fall through
             * to the code below which will skip to the \r\n. */
            if (priv->content_length > G_MAXSIZE / 10 ||
                priv->content_length * 10 > G_MAXSIZE - val) {
              priv->content_length = 0;
              break;
            }

            priv->content_length = (priv->content_length * 10) + val;

            if (pos + 1 > priv->recv_buf_fill)
              goto not_enough_data;
            pos++;
          }
        }

        /* Skip over the header. */
        while (pos + 1 < priv->recv_buf_fill &&
            GET_BYTE (pos) != '\r' && GET_BYTE (pos + 1) != '\n')
          pos++;

        nice_debug ("pos = %u, fill = %" G_GSSIZE_FORMAT,
            pos, priv->recv_buf_fill);

        if (pos + 1 >= priv->recv_buf_fill)
          goto not_enough_data;
        pos += 2;

        /* Consume the data we just parsed. */
        priv->recv_buf_pos = (priv->recv_buf_pos + pos) % priv->recv_buf_length;
        priv->recv_buf_fill -= pos;

        if (pos == 2)
          priv->state = HTTP_STATE_BODY;

        goto retry;
      }
      break;
    case HTTP_STATE_BODY:
      {
        gsize consumed;

        if (priv->content_length == 0) {
          priv->state = HTTP_STATE_CONNECTED;
          goto retry;
        }

        if (priv->recv_buf_fill == 0)
          goto not_enough_data;

        consumed = MIN (priv->content_length, priv->recv_buf_fill);

        priv->recv_buf_pos =
            (priv->recv_buf_pos + consumed) % priv->recv_buf_length;
        priv->recv_buf_fill -= consumed;
        priv->content_length -= consumed;

        goto retry;
      }
      break;
    case HTTP_STATE_CONNECTED:
      {
        gsize len;

        len = memcpy_ring_buffer_to_input_messages (priv,
            recv_messages, n_recv_messages);

        /* Send the pending data */
        nice_socket_flush_send_queue (priv->base_socket,
            &priv->send_queue);

        return len;
      }
      break;
    case HTTP_STATE_ERROR:
    default:
      /* Unknown status */
      goto error;
  }

 not_enough_data:
  return 0;

 error:
  nice_debug ("http error");
  if (priv->base_socket)
    nice_socket_free (priv->base_socket);
  priv->base_socket = NULL;
  priv->state = HTTP_STATE_ERROR;

  return -1;
}

static gint
socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  HttpPriv *priv = sock->priv;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return -1;

  if (priv->state == HTTP_STATE_CONNECTED) {
    /* Fast path. */
    if (!priv->base_socket)
      return -1;

    return nice_socket_send_messages (priv->base_socket, to, messages,
        n_messages);
  } else if (priv->state == HTTP_STATE_ERROR) {
    return -1;
  } else {
    return 0;
  }

  return n_messages;
}

static gint
socket_send_messages_reliable (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  HttpPriv *priv = sock->priv;

  if (priv->state == HTTP_STATE_CONNECTED) {
    /* Fast path. */
    if (!priv->base_socket)
      return -1;

    return nice_socket_send_messages_reliable (priv->base_socket, to, messages,
        n_messages);
  } else if (priv->state == HTTP_STATE_ERROR) {
    return -1;
  } else {
    nice_socket_queue_send (&priv->send_queue, to, messages, n_messages);
  }

  return n_messages;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  HttpPriv *priv = sock->priv;

  return nice_socket_is_reliable (priv->base_socket);
}

static gboolean
socket_can_send (NiceSocket *sock, NiceAddress *addr)
{
  HttpPriv *priv = sock->priv;

  return nice_socket_can_send (priv->base_socket, addr);
}

static void
socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data)
{
  HttpPriv *priv = sock->priv;

  nice_socket_set_writable_callback (priv->base_socket, callback, user_data);
}
