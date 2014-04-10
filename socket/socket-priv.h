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

#ifndef _SOCKET_PRIV_H
#define _SOCKET_PRIV_H

#include "socket.h"

G_BEGIN_DECLS

/**
 * nice_socket_queue_send:
 * @send_queue: The queue to add to
 * @to : Destination
 * @messages: Messages to queue
 * @n_messages: Number of messages to queue
 *
 * Queue messages to be sent later into the GQueue
 */
void nice_socket_queue_send (GQueue *send_queue, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages);

/**
 * nice_socket_queue_send_with_callback:
 * @send_queue: The queue to add to
 * @message: The message to queue
 * @message_offset: Number of bytes to skip in the message
 * @message_len: Total length of the message
 * @head: Whether to add the message to the head of the queue or the tail
 * @gsock: The #GSocket to create the callback on
 * @io_source: Pointer to #GSource pointer to store the created source
 * @context: #GMainContext to attach the @io_source to
 * @cb: Callback function to call when the @gsock is writable
 * @user_data: User data for @cb
 *
 * Queue (partial) message to be sent later and create a source to call @cb
 * when the @gsock becomes writable.
 * The @message_offset can be used if a partial write happened and some bytes
 * were already written, in which case @head should be set to TRUE to add the
 * message to the head of the queue.
 */
void nice_socket_queue_send_with_callback (GQueue *send_queue,
    const NiceOutputMessage *message, gsize message_offset, gsize message_len,
    gboolean head, GSocket *gsock, GSource **io_source, GMainContext *context,
    GSourceFunc cb, gpointer user_data);

/**
 * nice_socket_flush_send_queue:
 * @base_socket: Base socket to send on
 * @send_queue: Queue to flush
 *
 * Send all the queued messages reliably to the base socket. We assume only
 * reliable messages were queued and the underlying socket will handle the
 * send.
 */
void nice_socket_flush_send_queue (NiceSocket *base_socket, GQueue *send_queue);

/**
 * nice_socket_flush_send_queue_to_socket:
 * @gsock: GSocket to send on
 * @send_queue: Queue to flush
 *
 * Send all the queued messages to the socket. If any message fails to be sent
 * it will be readded to the queue and #FALSE will be returned, in which case
 * the IO source must be kept to allow flushing the next time the socket
 * is writable.
 * If the queue gets flushed, #TRUE will be returned, in which case, the IO
 * source should be destroyed.
 *
 * Returns: #TRUE if the queue was emptied, #FALSE if the socket would block.
 */
gboolean nice_socket_flush_send_queue_to_socket (GSocket *gsock,
    GQueue *send_queue);

/**
 * nice_socket_free_send_queue:
 * @send_queue: The send queue
 *
 * Frees every item in the send queue without sending them and empties the queue
 */
void nice_socket_free_send_queue (GQueue *send_queue);

G_END_DECLS

#endif /* _SOCKET_PRIV_H */

