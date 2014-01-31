/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008-2009 Nokia Corporation. All rights reserved.
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


#include <glib.h>

#include "socket.h"


/**
 * nice_socket_recv_messages:
 * @sock: a #NiceSocket
 * @recv_messages: (array length=n_recv_messages) (out caller-allocates):
 * array of #NiceInputMessages to return received messages in
 * @n_recv_messages: number of elements in the @recv_messages array
 *
 * Receive up to @n_recv_messages message on the socket, in a non-reliable,
 * non-blocking fashion. The total size of the buffers in each #NiceInputMessage
 * must be big enough to contain an entire message (65536 bytes), or excess
 * bytes will be silently dropped.
 *
 * On success, the number of messages received into @recv_messages is returned,
 * which may be less than @n_recv_messages if the call would have blocked
 * part-way through. If the socket would have blocked to begin with, or if
 * @n_recv_messages is zero, zero is returned. On failure, a negative value is
 * returned, but no further error information is available. Calling this
 * function on a socket which has closed is an error, and a negative value is
 * returned.
 *
 * If a positive N is returned, the first N messages in @recv_messages are
 * valid. Each valid message is guaranteed to have a non-zero
 * #NiceInputMessage::length, and its buffers are guaranteed to be filled
 * sequentially up to that number of bytes  If #NiceInputMessage::from was
 * non-%NULL for a valid message, it may be set to the address of the sender of
 * that received message.
 *
 * If the return value is zero or negative, the from return address and length
 * in every #NiceInputMessage in @recv_messages are guaranteed to be unmodified.
 * The buffers may have been modified.
 *
 * The base addresses and sizes of the buffers in a #NiceInputMessage are never
 * modified. Neither is the base address of #NiceInputMessage::from, nor the
 * base address and length of the #NiceInputMessage::buffers array.
 *
 * Returns: number of valid messages returned in @recv_messages, or a negative
 * value on error
 *
 * Since: 0.1.5
 */
gint
nice_socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  g_return_val_if_fail (sock != NULL, -1);
  g_return_val_if_fail (n_recv_messages == 0 || recv_messages != NULL, -1);

  return sock->recv_messages (sock, recv_messages, n_recv_messages);
}

/**
 * nice_socket_send_messages:
 * @sock: a #NiceSocket
 * @messages: (array length=n_messages) (in caller-allocates):
 * array of #NiceOutputMessages containing the messages to send
 * @n_messages: number of elements in the @messages array
 *
 * Send up to @n_messages on the socket, in a non-reliable, non-blocking
 * fashion. The total size of the buffers in each #NiceOutputMessage
 * must be at most the maximum UDP payload size (65535 bytes), or excess
 * bytes will be silently dropped.
 *
 * On success, the number of messages transmitted from @messages is returned,
 * which may be less than @n_messages if the call would have blocked
 * part-way through. If the socket would have blocked to begin with, or if
 * @n_messages is zero, zero is returned. On failure, a negative value is
 * returned, but no further error information is available. Calling this
 * function on a socket which has closed is an error, and a negative value is
 * returned.
 *
 * If a positive N is returned, the first N messages in @messages have been
 * sent in full, and the remaining messages have not been sent at all.
 *
 * If #NiceOutputMessage::to is specified for a message, that will be used as
 * the destination address for the message. Otherwise, if %NULL, the default
 * destination for @sock will be used.
 *
 * Every field of every #NiceOutputMessage is guaranteed to be unmodified when
 * this function returns.
 *
 * Returns: number of messages successfully sent from @messages, or a negative
 * value on error
 *
 * Since: 0.1.5
 */
gint
nice_socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  g_return_val_if_fail (sock != NULL, -1);
  g_return_val_if_fail (n_messages == 0 || messages != NULL, -1);

  return sock->send_messages (sock, to, messages, n_messages);
}

/* Convenience wrapper around nice_socket_send_messages(). Returns the number of
 * bytes sent on success (which will be @len), zero if sending would block, or
 * -1 on error. */
gssize
nice_socket_send (NiceSocket *sock, const NiceAddress *to, gsize len,
    const gchar *buf)
{
  GOutputVector local_buf = { buf, len };
  NiceOutputMessage local_message = { &local_buf, 1};
  gint ret;

  ret = sock->send_messages (sock, to, &local_message, 1);
  if (ret == 1)
    return len;
  return ret;
}

gboolean
nice_socket_is_reliable (NiceSocket *sock)
{
  return sock->is_reliable (sock);
}

void
nice_socket_free (NiceSocket *sock)
{
  if (sock) {
    sock->close (sock);
    g_slice_free (NiceSocket,sock);
  }
}
