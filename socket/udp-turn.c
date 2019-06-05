/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation
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
 * Implementation of TURN
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#include "udp-turn.h"
#include "stun/stunagent.h"
#include "stun/usages/timer.h"
#include "agent-priv.h"

#define STUN_END_TIMEOUT 8000
#define STUN_MAX_MS_REALM_LEN 128 // as defined in [MS-TURN]
#define STUN_EXPIRE_TIMEOUT 60 /* Time we refresh before expiration  */
#define STUN_PERMISSION_TIMEOUT (300 - STUN_EXPIRE_TIMEOUT) /* 240 s */
#define STUN_BINDING_TIMEOUT (600 - STUN_EXPIRE_TIMEOUT) /* 540 s */

static GMutex mutex;

typedef struct {
  StunMessage message;
  uint8_t buffer[STUN_MAX_MESSAGE_SIZE];
  StunTimer timer;
} TURNMessage;

typedef struct {
  NiceAddress peer;
  uint16_t channel;
  gboolean renew;
  GSource *timeout_source;
} ChannelBinding;

typedef struct {
  GMainContext *ctx;
  StunAgent agent;
  GList *channels;
  GList *pending_bindings;
  ChannelBinding *current_binding;
  TURNMessage *current_binding_msg;
  GList *pending_permissions;
  GSource *tick_source_channel_bind;
  GSource *tick_source_create_permission;
  NiceSocket *base_socket;
  NiceAddress server_addr;
  uint8_t *username;
  gsize username_len;
  uint8_t *password;
  gsize password_len;
  NiceTurnSocketCompatibility compatibility;
  GQueue *send_requests;
  uint8_t ms_realm[STUN_MAX_MS_REALM_LEN + 1];
  uint8_t ms_connection_id[20];
  uint32_t ms_sequence_num;
  bool ms_connection_id_valid;
  GList *permissions;           /* the peers (NiceAddress) for which
                                   there is an installed permission */
  GList *sent_permissions; /* ongoing permission installed */
  GHashTable *send_data_queues; /* stores a send data queue for per peer */
  GSource *permission_timeout_source;      /* timer used to invalidate
                                           permissions */

  guint8 *cached_realm;
  uint16_t cached_realm_len;
  guint8 *cached_nonce;
  uint16_t cached_nonce_len;

  GByteArray *fragment_buffer;
  NiceAddress from;
} UdpTurnPriv;


typedef struct {
  StunTransactionId id;
  GSource *source;
  UdpTurnPriv *priv;
} SendRequest;

/* used to store data sent while obtaining a permission */
typedef struct {
  gchar *data;
  guint data_len;
  gboolean reliable;
} SendData;

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
static gboolean socket_is_based_on (NiceSocket *sock, NiceSocket *other);

static void priv_process_pending_bindings (UdpTurnPriv *priv);
static gboolean priv_retransmissions_tick_unlocked (UdpTurnPriv *priv);
static gboolean priv_retransmissions_tick (gpointer pointer);
static void priv_schedule_tick (UdpTurnPriv *priv);
static void priv_send_turn_message (UdpTurnPriv *priv, TURNMessage *msg);
static gboolean priv_send_create_permission (UdpTurnPriv *priv,
    const NiceAddress *peer);
static gboolean priv_send_channel_bind (UdpTurnPriv *priv,
    uint16_t channel,
    const NiceAddress *peer);
static gboolean priv_add_channel_binding (UdpTurnPriv *priv,
    const NiceAddress *peer);
static gboolean priv_forget_send_request_timeout (gpointer pointer);
static void priv_clear_permissions (UdpTurnPriv *priv);

static void
send_request_free (SendRequest *r)
{
    g_source_destroy (r->source);
    g_source_unref (r->source);

    stun_agent_forget_transaction (&r->priv->agent, r->id);

    g_slice_free (SendRequest, r);
}

static guint
priv_nice_address_hash (gconstpointer data)
{
  gchar address[NICE_ADDRESS_STRING_LEN];

  nice_address_to_string ((NiceAddress *) data, address);

  return g_str_hash(address);
}

static void
priv_send_data_queue_destroy (gpointer user_data)
{
  GQueue *send_queue = (GQueue *) user_data;
  GList *i;

  for (i = g_queue_peek_head_link (send_queue); i; i = i->next) {
    SendData *data = (SendData *) i->data;

    g_free (data->data);
    g_slice_free (SendData, data);
  }
  g_queue_free (send_queue);
}

NiceSocket *
nice_udp_turn_socket_new (GMainContext *ctx, NiceAddress *addr,
    NiceSocket *base_socket, const NiceAddress *server_addr,
    const gchar *username, const gchar *password,
    NiceTurnSocketCompatibility compatibility)
{
  UdpTurnPriv *priv;
  NiceSocket *sock = g_slice_new0 (NiceSocket);

  if (!sock) {
    return NULL;
  }

  priv = g_new0 (UdpTurnPriv, 1);

  if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC5389,
        STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS);
  } else if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_NO_INDICATION_AUTH);
  } else if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
  } else if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_OC2007,
        STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
  }

  priv->channels = NULL;
  priv->current_binding = NULL;
  priv->base_socket = base_socket;
  if (ctx)
    priv->ctx = g_main_context_ref (ctx);

  if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN ||
      compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
    priv->username = g_base64_decode (username, &priv->username_len);
    priv->password = g_base64_decode (password, &priv->password_len);
  } else {
    priv->username = (uint8_t *)g_strdup (username);
    priv->username_len = (gsize) strlen (username);
    if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      priv->password = NULL;
      priv->password_len = 0;
    } else {
      priv->password = (uint8_t *)g_strdup (password);
      priv->password_len = (gsize) strlen (password);
    }
  }
  priv->server_addr = *server_addr;
  priv->compatibility = compatibility;
  priv->send_requests = g_queue_new ();

  priv->send_data_queues =
      g_hash_table_new_full (priv_nice_address_hash,
          (GEqualFunc) nice_address_equal,
          (GDestroyNotify) nice_address_free,
          priv_send_data_queue_destroy);

  sock->type = NICE_SOCKET_TYPE_UDP_TURN;
  sock->fileno = NULL;
  sock->addr = *addr;
  sock->send_messages = socket_send_messages;
  sock->send_messages_reliable = socket_send_messages_reliable;
  sock->recv_messages = socket_recv_messages;
  sock->is_reliable = socket_is_reliable;
  sock->can_send = socket_can_send;
  sock->set_writable_callback = socket_set_writable_callback;
  sock->is_based_on = socket_is_based_on;
  sock->close = socket_close;
  sock->priv = (void *) priv;

  return sock;
}



static void
socket_close (NiceSocket *sock)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) sock->priv;
  GList *i = NULL;

  g_mutex_lock (&mutex);

  for (i = priv->channels; i; i = i->next) {
    ChannelBinding *b = i->data;
    if (b->timeout_source) {
      g_source_destroy (b->timeout_source);
      g_source_unref (b->timeout_source);
    }
    g_free (b);
  }
  g_list_free (priv->channels);

  g_list_free_full (priv->pending_bindings, (GDestroyNotify) nice_address_free);

  if (priv->tick_source_channel_bind != NULL) {
    g_source_destroy (priv->tick_source_channel_bind);
    g_source_unref (priv->tick_source_channel_bind);
    priv->tick_source_channel_bind = NULL;
  }

  if (priv->tick_source_create_permission != NULL) {
    g_source_destroy (priv->tick_source_create_permission);
    g_source_unref (priv->tick_source_create_permission);
    priv->tick_source_create_permission = NULL;
  }

  g_queue_free_full (priv->send_requests, (GDestroyNotify) send_request_free);

  priv_clear_permissions (priv);
  g_list_free_full (priv->sent_permissions, (GDestroyNotify) nice_address_free);
  g_hash_table_destroy (priv->send_data_queues);

  if (priv->permission_timeout_source) {
    g_source_destroy (priv->permission_timeout_source);
    g_source_unref (priv->permission_timeout_source);
    priv->permission_timeout_source = NULL;
  }

  if (priv->ctx)
    g_main_context_unref (priv->ctx);

  g_free (priv->current_binding);
  g_free (priv->current_binding_msg);
  g_list_free_full (priv->pending_permissions, g_free);
  g_free (priv->username);
  g_free (priv->password);
  g_free (priv->cached_realm);
  g_free (priv->cached_nonce);

  if (priv->fragment_buffer) {
    g_byte_array_free(priv->fragment_buffer, TRUE);
  }

  g_free (priv);

  sock->priv = NULL;

  g_mutex_unlock (&mutex);
}

static gint
socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) sock->priv;
  gint n_messages;
  gint n_output_messages = 0;
  guint i;
  gboolean error = FALSE;

  /* Make sure socket has not been freed: */
  g_assert (sock->priv != NULL);

  nice_debug_verbose ("received message on TURN socket");

  if (priv->fragment_buffer) {
    /* Fill as many recv_messages as possible with RFC4571-framed data we
     * already hold in our buffer before reading more from the base socket. */
    guint8 *f_buffer = priv->fragment_buffer->data;
    guint f_buffer_len = priv->fragment_buffer->len;

    for (i = 0; i < n_recv_messages && f_buffer_len >= sizeof (guint16); ++i) {
      guint32 msg_len = ((f_buffer[0] << 8) | f_buffer[1]) + sizeof (guint16);

      if (msg_len > f_buffer_len) {
        /* The next message in the buffer isn't complete yet. Wait for more
         * data from the base socket. */
        break;
      }

      /* We have a full message in the buffer. Copy it into the user-provided
       * NiceInputMessage. */
      memcpy_buffer_to_input_message (&recv_messages[i], f_buffer, msg_len);
      *recv_messages[i].from = priv->from;

      f_buffer += msg_len;
      f_buffer_len -= msg_len;
      ++n_output_messages;
    }

    /* Adjust recv_messages with the number of messages we've just filled. */
    recv_messages += n_output_messages;
    n_recv_messages -= n_output_messages;

    /* Shrink the fragment buffer, deallocate it if empty. */
    g_byte_array_remove_range (priv->fragment_buffer, 0,
                               priv->fragment_buffer->len - f_buffer_len);
    if (priv->fragment_buffer->len == 0) {
      g_byte_array_free (priv->fragment_buffer, TRUE);
      priv->fragment_buffer = NULL;
    }
  }

  n_messages = nice_socket_recv_messages (priv->base_socket,
      recv_messages, n_recv_messages);

  if (n_messages < 0)
    return n_messages;

  /* Process all the messages. Those which fail parsing are re-used for the next
   * message.
   *
   * FIXME: This needs a fast path which avoids allocations or memcpy()s.
   * Implementing such a path means rewriting the TURN parser (and hence the
   * STUN message code) to operate on vectors of buffers, rather than a
   * monolithic buffer. */
  for (i = 0; i < (guint) n_messages; ++i) {
    NiceInputMessage *message = &recv_messages[i];
    NiceSocket *dummy;
    NiceAddress from;
    guint8 *buffer;
    gsize buffer_length;
    gint parsed_buffer_length;
    gboolean allocated_buffer = FALSE;

    if (message->length == 0)
      continue;

    /* Compact the message’s buffers into a single one for parsing. Avoid this
     * in the (hopefully) common case of a single-element buffer vector. */
    if (message->n_buffers == 1 ||
        (message->n_buffers == -1 &&
         message->buffers[0].buffer != NULL &&
         message->buffers[1].buffer == NULL)) {
      buffer = message->buffers[0].buffer;
      buffer_length = message->length;
    } else {
      nice_debug_verbose ("%s: **WARNING: SLOW PATH**", G_STRFUNC);

      buffer = compact_input_message (message, &buffer_length);
      allocated_buffer = TRUE;
    }

    /* Parse in-place. */
    parsed_buffer_length = nice_udp_turn_socket_parse_recv (sock, &dummy,
        &from, buffer_length, buffer,
        message->from, buffer, buffer_length);
    message->length = MAX (parsed_buffer_length, 0);

    if (parsed_buffer_length < 0) {
      error = TRUE;
    } else if (parsed_buffer_length > 0) {
      *message->from = from;
    }
    /* parsed_buffer_length == 0 means this is a TURN control message which
     * needs ignoring. */

    if (nice_socket_is_reliable (sock) && parsed_buffer_length > 0) {
      /* Determine the portion of the current NiceInputMessage we can already
       * return. */
      gint32 msg_len = 0;
      if (!priv->fragment_buffer) {
        msg_len = ((buffer[0] << 8) | buffer[1]) + sizeof (guint16);
        if (msg_len > parsed_buffer_length) {
          /* The RFC4571 frame is larger than the current TURN message, need to
           * buffer it and wait for more data. */
          msg_len = 0;
        }
      }

      if (msg_len != parsed_buffer_length && !priv->fragment_buffer) {
        /* Start of message fragmenting detected. Allocate fragment buffer
         * large enough for the recv_message's we haven't parsed yet. */
        gint j;
        guint buffer_len = 0;

        for (j = i; j < n_messages; ++j) {
          buffer_len += recv_messages[j].length;
        }
        priv->fragment_buffer = g_byte_array_sized_new (buffer_len);
      }

      if (priv->fragment_buffer) {
        /* The messages are fragmented. Store the excess data (after msg_len
         * bytes) into fragment buffer for reassembly. */
        g_byte_array_append (priv->fragment_buffer, buffer + msg_len,
            parsed_buffer_length - msg_len);

        parsed_buffer_length = msg_len;
        message->length = msg_len;
        priv->from = from;
      }
    }

    /* Split up the monolithic buffer again into the caller-provided buffers. */
    if (parsed_buffer_length > 0 && allocated_buffer) {
      memcpy_buffer_to_input_message (message, buffer,
          parsed_buffer_length);
    }

    if (allocated_buffer)
      g_free (buffer);

    if (error)
      break;

    ++n_output_messages;
  }

  /* Was there an error processing the first message? */
  if (error && i == 0)
    return -1;

  return n_output_messages;
}

/* interval is given in milliseconds */
static GSource *
priv_timeout_add_with_context (UdpTurnPriv *priv, guint interval,
    GSourceFunc function, gpointer data)
{
  GSource *source = NULL;

  g_return_val_if_fail (function != NULL, NULL);

  source = g_timeout_source_new (interval);

  g_source_set_callback (source, function, data, NULL);
  g_source_attach (source, priv->ctx);

  return source;
}

/* interval is given in seconds */
static GSource *
priv_timeout_add_seconds_with_context (UdpTurnPriv *priv, guint interval,
    GSourceFunc function, gpointer data)
{
  GSource *source = NULL;

  g_return_val_if_fail (function != NULL, NULL);

  source = g_timeout_source_new_seconds (interval);

  g_source_set_callback (source, function, data, NULL);
  g_source_attach (source, priv->ctx);

  return source;
}

static StunMessageReturn
stun_message_append_ms_connection_id(StunMessage *msg,
    uint8_t *ms_connection_id, uint32_t ms_sequence_num)
{
  union {
    uint8_t buf8[24];
    uint32_t buf32[24/4];
  } buf;

  memcpy(buf.buf8, ms_connection_id, 20);
  buf.buf32[5] = htonl(ms_sequence_num);
  return stun_message_append_bytes (msg, STUN_ATTRIBUTE_MS_SEQUENCE_NUMBER,
      buf.buf8, 24);
}

static void
stun_message_ensure_ms_realm(StunMessage *msg, uint8_t *realm)
{
  /* With MS-TURN, original clients do not send REALM attribute in Send and Set
   * Active Destination requests, but use it to compute MESSAGE-INTEGRITY. We
   * simply append cached realm value to the message and use it in subsequent
   * stun_agent_finish_message() call. Messages with this additional attribute
   * are handled correctly on OCS Access Edge working as TURN server. */
  if (stun_message_get_method(msg) == STUN_SEND ||
      stun_message_get_method(msg) == STUN_OLD_SET_ACTIVE_DST) {
    stun_message_append_bytes (msg, STUN_ATTRIBUTE_REALM, realm,
        strlen((char *)realm));
  }
}

static gboolean
priv_is_peer_in_list (const GList *list, const NiceAddress *peer)
{
  const GList *iter;

  for (iter = list ; iter ; iter = g_list_next (iter)) {
    NiceAddress *address = (NiceAddress *) iter->data;

    if (nice_address_equal (address, peer))
      return TRUE;
  }

  return FALSE;
}

static gboolean
priv_has_permission_for_peer (UdpTurnPriv *priv, const NiceAddress *peer)
{
  return priv_is_peer_in_list (priv->permissions, peer);
}

static gboolean
priv_has_sent_permission_for_peer (UdpTurnPriv *priv, const NiceAddress *peer)
{
  return priv_is_peer_in_list (priv->sent_permissions, peer);
}

static void
priv_add_permission_for_peer (UdpTurnPriv *priv, const NiceAddress *peer)
{
  priv->permissions =
      g_list_append (priv->permissions, nice_address_dup (peer));
}

static void
priv_add_sent_permission_for_peer (UdpTurnPriv *priv, const NiceAddress *peer)
{
  priv->sent_permissions =
      g_list_append (priv->sent_permissions, nice_address_dup (peer));
}

static GList *
priv_remove_peer_from_list (GList *list, const NiceAddress *peer)
{
  GList *iter;

  for (iter = list ; iter ; iter = g_list_next (iter)) {
    NiceAddress *address = (NiceAddress *) iter->data;

    if (nice_address_equal (address, peer)) {
      GList *prev = iter->prev;

      nice_address_free (address);
      list = g_list_delete_link (list, iter);
      iter = prev;
      if (iter)
        iter = list;
    }
  }

  return list;
}

static void
priv_remove_sent_permission_for_peer (UdpTurnPriv *priv, const NiceAddress *peer)
{
  priv->sent_permissions =
      priv_remove_peer_from_list (priv->sent_permissions, peer);
}

static void
priv_clear_permissions (UdpTurnPriv *priv)
{
  g_list_free_full (priv->permissions, (GDestroyNotify) nice_address_free);
  priv->permissions = NULL;
}

static gint
_socket_send_messages_wrapped (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages, gboolean reliable)
{
  if (!nice_socket_is_reliable (sock)) {
    if (reliable)
      return nice_socket_send_messages_reliable (sock, to, messages, n_messages);
    else
      return nice_socket_send_messages (sock, to, messages, n_messages);
  } else {
    GOutputVector *local_bufs;
    NiceOutputMessage local_message;
    const NiceOutputMessage *message;
    gsize message_len;
    guint n_bufs = 0;
    guint16 rfc4571_frame;
    guint i;
    gint ret;

    g_assert (n_messages == 1);
    message = &messages[0];
    message_len = output_message_get_size (message);
    g_assert (message_len <= G_MAXUINT16);

    /* ICE-TCP requires that all packets be framed with RFC4571 */

    /* Count the number of buffers. */
    if (message->n_buffers == -1) {
      for (i = 0; message->buffers[i].buffer != NULL; i++)
        n_bufs++;
    } else {
      n_bufs = message->n_buffers;
    }

    local_bufs = g_alloca ((n_bufs + 1) * sizeof (GOutputVector));
    local_message.buffers = local_bufs;
    local_message.n_buffers = n_bufs + 1;

    rfc4571_frame = htons (message_len);
    local_bufs[0].buffer = &rfc4571_frame;
    local_bufs[0].size = sizeof (guint16);

    for (i = 0; i < n_bufs; i++) {
      local_bufs[i + 1].buffer = message->buffers[i].buffer;
      local_bufs[i + 1].size = message->buffers[i].size;
    }


    if (reliable)
      ret = nice_socket_send_messages_reliable (sock, to,
          &local_message, 1);
    else
      ret = nice_socket_send_messages (sock, to, &local_message, 1);

    if (ret == 1)
      ret = message_len;

    return ret;
  }
}

static gssize
_socket_send_wrapped (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf, gboolean reliable)
{
  gint ret;

  if (!nice_socket_is_reliable (sock)) {
    GOutputVector local_buf = { buf, len };
    NiceOutputMessage local_message = { &local_buf, 1};

    ret = _socket_send_messages_wrapped (sock, to, &local_message, 1, reliable);
    if (ret == 1)
      return len;
    return ret;
  } else {
    guint16 rfc4571_frame = htons (len);
    GOutputVector local_buf[2] = {{&rfc4571_frame, 2}, { buf, len }};
    NiceOutputMessage local_message = { local_buf, 2};

    if (reliable)
      ret = nice_socket_send_messages_reliable (sock, to, &local_message, 1);
    else
      ret = nice_socket_send_messages (sock, to, &local_message, 1);

    if (ret == 1)
      return len;
    return ret;
  }
}

static void
socket_enqueue_data(UdpTurnPriv *priv, const NiceAddress *to,
    guint len, const gchar *buf, gboolean reliable)
{
  SendData *data = g_slice_new0 (SendData);
  GQueue *queue = g_hash_table_lookup (priv->send_data_queues, to);

  if (queue == NULL) {
    queue = g_queue_new ();
    g_hash_table_insert (priv->send_data_queues, nice_address_dup (to),
        queue);
  }

  data->data = g_memdup(buf, len);
  data->data_len = len;
  data->reliable = reliable;
  g_queue_push_tail (queue, data);
}

static void
socket_dequeue_all_data (UdpTurnPriv *priv, const NiceAddress *to)
{
  GQueue *send_queue = g_hash_table_lookup (priv->send_data_queues, to);

  if (send_queue) {
    while (!g_queue_is_empty (send_queue)) {
      SendData *data =
          (SendData *) g_queue_pop_head(send_queue);

      nice_debug_verbose ("dequeuing data");
      _socket_send_wrapped (priv->base_socket, &priv->server_addr,
          data->data_len, data->data, data->reliable);

      g_free (data->data);
      g_slice_free (SendData, data);
    }

    /* remove queue from table */
    g_hash_table_remove (priv->send_data_queues, to);
  }
}


static gssize
socket_send_message (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *message, gboolean reliable)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) sock->priv;
  StunMessage msg;
  uint8_t buffer[STUN_MAX_MESSAGE_SIZE];
  size_t msg_len;
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } sa;
  GList *i;
  ChannelBinding *binding = NULL;
  gint ret;

  /* Make sure socket has not been freed: */
  g_assert (sock->priv != NULL);

  for (i = priv->channels; i; i = i->next) {
    ChannelBinding *b = i->data;
    if (nice_address_equal (&b->peer, to)) {
      binding = b;
      break;
    }
  }

  nice_address_copy_to_sockaddr (to, &sa.addr);

  if (binding) {
    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      gsize message_len = output_message_get_size (message);

      if (message_len + sizeof(uint32_t) <= sizeof(buffer)) {
        guint j;
        uint16_t len16, channel16;
        gsize message_offset = 0;

        len16 = htons ((uint16_t) message_len);
        channel16 = htons (binding->channel);

        memcpy (buffer, &channel16, sizeof(uint16_t));
        memcpy (buffer + sizeof(uint16_t), &len16, sizeof(uint16_t));

        /* FIXME: Slow path! This should be replaced by code which manipulates
         * the GOutputVector array, rather than the buffer contents
         * themselves. */
        for (j = 0;
             (message->n_buffers >= 0 && j < (guint) message->n_buffers) ||
             (message->n_buffers < 0 && message->buffers[j].buffer != NULL);
             j++) {
          const GOutputVector *out_buf = &message->buffers[j];
          gsize out_len;

          out_len = MIN (message_len - message_offset, out_buf->size);
          memcpy (buffer + sizeof (uint32_t) + message_offset,
              out_buf->buffer, out_len);
          message_offset += out_len;
        }

        msg_len = message_len + sizeof(uint32_t);
      } else {
        goto error;
      }
    } else {
      ret = _socket_send_messages_wrapped (priv->base_socket,
          &priv->server_addr, message, 1, reliable);

      if (ret == 1)
        return output_message_get_size (message);
      return ret;
    }
  } else {
    guint8 *compacted_buf;
    gsize compacted_buf_len;

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      if (!stun_agent_init_indication (&priv->agent, &msg,
              buffer, sizeof(buffer), STUN_IND_SEND))
        goto error;
      if (stun_message_append_xor_addr (&msg, STUN_ATTRIBUTE_PEER_ADDRESS,
              &sa.storage, sizeof(sa)) !=
          STUN_MESSAGE_RETURN_SUCCESS)
        goto error;
    } else {
      if (!stun_agent_init_request (&priv->agent, &msg,
              buffer, sizeof(buffer), STUN_SEND))
        goto error;

      if (stun_message_append32 (&msg, STUN_ATTRIBUTE_MAGIC_COOKIE,
              TURN_MAGIC_COOKIE) != STUN_MESSAGE_RETURN_SUCCESS)
        goto error;
      if (priv->username != NULL && priv->username_len > 0) {
        if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_USERNAME,
                priv->username, priv->username_len) !=
            STUN_MESSAGE_RETURN_SUCCESS)
          goto error;
      }
      if (stun_message_append_addr (&msg, STUN_ATTRIBUTE_DESTINATION_ADDRESS,
              &sa.addr, sizeof(sa)) !=
          STUN_MESSAGE_RETURN_SUCCESS)
        goto error;

      if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE &&
          priv->current_binding &&
          nice_address_equal (&priv->current_binding->peer, to)) {
        stun_message_append32 (&msg, STUN_ATTRIBUTE_OPTIONS, 1);
      }
    }

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
      stun_message_append32(&msg, STUN_ATTRIBUTE_MS_VERSION, 1);

      if (priv->ms_connection_id_valid)
        stun_message_append_ms_connection_id(&msg, priv->ms_connection_id,
            ++priv->ms_sequence_num);

      stun_message_ensure_ms_realm(&msg, priv->ms_realm);
    }

    /* Slow path! We have to compact the buffers to append them to the message.
     * FIXME: This could be improved by adding vectored I/O support to
      * stun_message_append_bytes(). */
    compacted_buf = compact_output_message (message, &compacted_buf_len);

    if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_DATA,
            compacted_buf, compacted_buf_len) != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (compacted_buf);
      goto error;
    }

    g_free (compacted_buf);

    /* Finish the message. */
    msg_len = stun_agent_finish_message (&priv->agent, &msg,
        priv->password, priv->password_len);
    if (msg_len > 0 && stun_message_get_class (&msg) == STUN_REQUEST &&
        priv->compatibility != NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
      SendRequest *req = g_slice_new0 (SendRequest);

      req->priv = priv;
      stun_message_id (&msg, req->id);
      req->source = priv_timeout_add_with_context (priv,
          STUN_END_TIMEOUT, priv_forget_send_request_timeout, req);
      g_queue_push_tail (priv->send_requests, req);
    }
  }

  if (msg_len > 0) {
    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766 &&
        !priv_has_permission_for_peer (priv, to)) {
      if (!priv_has_sent_permission_for_peer (priv, to)) {
        priv_send_create_permission (priv, to);
      }

      /* enque data */
      nice_debug_verbose ("enqueuing data");
      socket_enqueue_data(priv, to, msg_len, (gchar *)buffer, reliable);

      return msg_len;
    } else {
      GOutputVector local_buf = { buffer, msg_len };
      NiceOutputMessage local_message = {&local_buf, 1};

      ret = _socket_send_messages_wrapped (priv->base_socket,
          &priv->server_addr, &local_message, 1, reliable);

      if (ret == 1)
        return msg_len;
      return ret;
    }
  }

  /* Error condition pass through to the base socket. */
  ret = _socket_send_messages_wrapped (priv->base_socket, to, message, 1,
      reliable);
  if (ret == 1)
    return output_message_get_size (message);
  return ret;
error:
  return -1;
}

static gint
socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  guint i;

  g_mutex_lock (&mutex);

  /* Make sure socket has not been freed: */
  g_assert (sock->priv != NULL);

  for (i = 0; i < n_messages; i++) {
    const NiceOutputMessage *message = &messages[i];
    gssize len;

    len = socket_send_message (sock, to, message, FALSE);

    if (len < 0) {
      /* Error. */
      if (i > 0)
        break;
      g_mutex_unlock (&mutex);
      return len;
    } else if (len == 0) {
      /* EWOULDBLOCK. */
      break;
    }
  }

  g_mutex_unlock (&mutex);

  return i;
}

static gint
socket_send_messages_reliable (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) sock->priv;
  guint i;

  g_mutex_lock (&mutex);

  /* TURN can depend either on tcp-turn or udp-bsd as a base socket
   * if we allow reliable send and need to create permissions and we queue the
   * data, then we must be sure that the reliable send will succeed later, so
   * we check for udp-bsd here as the base socket and don't allow it.
   */
  if (priv->base_socket->type == NICE_SOCKET_TYPE_UDP_BSD) {
    g_mutex_unlock (&mutex);
    return -1;
  }

  for (i = 0; i < n_messages; i++) {
    const NiceOutputMessage *message = &messages[i];
    gssize len;

    len = socket_send_message (sock, to, message, TRUE);

    if (len < 0) {
      /* Error. */
      g_mutex_unlock (&mutex);
      return len;
    } else if (len == 0) {
      /* EWOULDBLOCK. */
      break;
    }
  }

  g_mutex_unlock (&mutex);
  return i;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) sock->priv;

  return nice_socket_is_reliable (priv->base_socket);
}

static gboolean
socket_can_send (NiceSocket *sock, NiceAddress *addr)
{
  UdpTurnPriv *priv = sock->priv;

  return nice_socket_can_send (priv->base_socket, addr);
}

static void
socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data)
{
  UdpTurnPriv *priv = sock->priv;

  nice_socket_set_writable_callback (priv->base_socket, callback, user_data);
}

static gboolean
socket_is_based_on (NiceSocket *sock, NiceSocket *other)
{
  UdpTurnPriv *priv = sock->priv;

  return (sock == other) ||
      (priv && nice_socket_is_based_on (priv->base_socket, other));
}

static gboolean
priv_forget_send_request_timeout (gpointer pointer)
{
  SendRequest *req = pointer;

  g_mutex_lock (&mutex);
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in turn.c:priv_forget_send_request");
    g_mutex_unlock (&mutex);
    return G_SOURCE_REMOVE;
  }

  send_request_free (req);
  g_queue_remove (req->priv->send_requests, req);

  g_mutex_unlock (&mutex);

  return G_SOURCE_REMOVE;
}

static gboolean
priv_permission_timeout (gpointer data)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) data;

  nice_debug ("Permission is about to timeout, schedule renewal");

  g_mutex_lock (&mutex);

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. Avoided race condition in "
                "udp-turn.c:priv_permission_timeout");

    g_mutex_unlock (&mutex);
    return G_SOURCE_REMOVE;
  }


  /* remove all permissions for this agent (the permission for the peer
     we are sending to will be renewed) */
  priv_clear_permissions (priv);
  g_mutex_unlock (&mutex);

  return TRUE;
}

static gboolean
priv_binding_expired_timeout (gpointer data)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) data;
  GList *i;
  GSource *source = NULL;

  g_mutex_lock (&mutex);
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. Avoided race condition in "
                "udp-turn.c:priv_permission_timeout");

    g_mutex_unlock (&mutex);
    return G_SOURCE_REMOVE;
  }

  nice_debug ("Permission expired, refresh failed");

  /* find current binding and destroy it */
  for (i = priv->channels ; i; i = i->next) {
    ChannelBinding *b = i->data;
    if (b->timeout_source == source) {
      priv->channels = g_list_remove (priv->channels, b);
      /* Make sure we don't free a currently being-refreshed binding */
      if (priv->current_binding_msg && !priv->current_binding) {
        union {
          struct sockaddr_storage storage;
          struct sockaddr addr;
        } sa;
        socklen_t sa_len = sizeof(sa);
        NiceAddress to;

        /* look up binding associated with peer */
        stun_message_find_xor_addr (
            &priv->current_binding_msg->message,
            STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &sa.storage, &sa_len);
        nice_address_set_from_sockaddr (&to, &sa.addr);

        /* If the binding is being refreshed, then move it to
           priv->current_binding so it counts as a 'new' binding and
           will get readded to the list if it succeeds */
        if (nice_address_equal (&b->peer, &to)) {
          priv->current_binding = b;
          break;
        }
      }
      /* In case the binding timed out before it could be processed, add it to
         the pending list */
      priv_add_channel_binding (priv, &b->peer);
      g_free (b);
      break;
    }
  }

  g_mutex_unlock (&mutex);
  return G_SOURCE_REMOVE;
}

static gboolean
priv_binding_timeout (gpointer data)
{
  UdpTurnPriv *priv = (UdpTurnPriv *) data;
  GList *i;
  GSource *source = NULL;

  g_mutex_lock (&mutex);
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. Avoided race condition in "
                "udp-turn.c:priv_permission_timeout");

    g_mutex_unlock (&mutex);
    return G_SOURCE_REMOVE;
  }

  nice_debug ("Permission is about to timeout, sending binding renewal");
  source = g_main_current_source ();

  /* find current binding and mark it for renewal */
  for (i = priv->channels ; i; i = i->next) {
    ChannelBinding *b = i->data;

    if (b->timeout_source == source) {
      b->renew = TRUE;

      /* Remove any existing timer */
      if (b->timeout_source) {
        g_source_destroy (b->timeout_source);
        g_source_unref (b->timeout_source);
      }

      /* Install timer to expire the permission */
      b->timeout_source = priv_timeout_add_seconds_with_context (priv,
          STUN_EXPIRE_TIMEOUT, priv_binding_expired_timeout, priv);

      /* Send renewal */
      if (!priv->current_binding_msg)
        priv_send_channel_bind (priv, b->channel, &b->peer);
      break;
    }
  }

  g_mutex_unlock (&mutex);

  return G_SOURCE_REMOVE;
}

static void
nice_udp_turn_socket_cache_realm_nonce_locked (NiceSocket *sock,
    StunMessage *msg)
{
  UdpTurnPriv *priv = sock->priv;
  gconstpointer tmp;

  g_assert (sock->type == NICE_SOCKET_TYPE_UDP_TURN);

  g_free (priv->cached_realm);
  priv->cached_realm = NULL;
  priv->cached_realm_len = 0;

  g_free (priv->cached_nonce);
  priv->cached_nonce = NULL;
  priv->cached_nonce_len = 0;

  tmp = stun_message_find (msg, STUN_ATTRIBUTE_REALM, &priv->cached_realm_len);
  if (tmp && priv->cached_realm_len < 764)
    priv->cached_realm = g_memdup (tmp, priv->cached_realm_len);

  tmp = stun_message_find (msg, STUN_ATTRIBUTE_NONCE, &priv->cached_nonce_len);
  if (tmp && priv->cached_nonce_len < 764)
    priv->cached_nonce = g_memdup (tmp, priv->cached_nonce_len);

}

void
nice_udp_turn_socket_cache_realm_nonce (NiceSocket *sock,
    StunMessage *msg)
{
  g_mutex_lock (&mutex);
  nice_udp_turn_socket_cache_realm_nonce_locked (sock, msg);
  g_mutex_unlock (&mutex);
}

guint
nice_udp_turn_socket_parse_recv_message (NiceSocket *sock, NiceSocket **from_sock,
    NiceInputMessage *message)
{
  /* TODO: Speed this up in the common reliable case of having a 24-byte header
   * buffer to begin with, followed by one or more massive buffers. */
  guint8 *buf;
  gsize buf_len, len;

  if (message->n_buffers == 1 ||
      (message->n_buffers == -1 &&
       message->buffers[0].buffer != NULL &&
       message->buffers[1].buffer == NULL)) {
    /* Fast path. Single massive buffer. */
    len = nice_udp_turn_socket_parse_recv (sock, from_sock,
        message->from, message->length, message->buffers[0].buffer,
        message->from, message->buffers[0].buffer, message->length);

    g_assert_cmpuint (len, <=, message->length);

    message->length = len;

    return (len > 0) ? 1 : 0;
  }

  /* Slow path. */
  nice_debug_verbose ("%s: **WARNING: SLOW PATH**", G_STRFUNC);

  buf = compact_input_message (message, &buf_len);
  len = nice_udp_turn_socket_parse_recv (sock, from_sock,
      message->from, buf_len, buf,
      message->from, buf, buf_len);
  len = memcpy_buffer_to_input_message (message, buf, len);
  g_free (buf);

  return (len > 0) ? 1 : 0;
}

gsize
nice_udp_turn_socket_parse_recv (NiceSocket *sock, NiceSocket **from_sock,
    NiceAddress *from, gsize len, guint8 *buf,
    const NiceAddress *recv_from, const guint8 *_recv_buf, gsize recv_len)
{

  UdpTurnPriv *priv = (UdpTurnPriv *) sock->priv;
  StunValidationStatus valid;
  StunMessage msg;
  GList *l;
  ChannelBinding *binding = NULL;

  union {
    const guint8 *u8;
    const guint16 *u16;
  } recv_buf;

  g_mutex_lock (&mutex);

  /* In the case of a reliable UDP-TURN-OVER-TCP (which means MS-TURN)
   * we must use RFC4571 framing */
  if (nice_socket_is_reliable (sock)) {
    recv_buf.u8 = _recv_buf + sizeof(guint16);
    recv_len -= sizeof(guint16);
  } else {
    recv_buf.u8 = _recv_buf;
  }

  if (nice_address_equal (&priv->server_addr, recv_from)) {
    valid = stun_agent_validate (&priv->agent, &msg,
        recv_buf.u8, recv_len, NULL, NULL);

    if (valid == STUN_VALIDATION_SUCCESS) {
      if (priv->compatibility != NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 &&
          priv->compatibility != NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
        uint32_t cookie;
        if (stun_message_find32 (&msg, STUN_ATTRIBUTE_MAGIC_COOKIE,
                &cookie) != STUN_MESSAGE_RETURN_SUCCESS)
          goto recv;
        if (cookie != TURN_MAGIC_COOKIE)
          goto recv;
      }

      if (stun_message_get_method (&msg) == STUN_SEND) {
        if (stun_message_get_class (&msg) == STUN_RESPONSE) {
          SendRequest *req = NULL;
          GList *i = g_queue_peek_head_link (priv->send_requests);
          StunTransactionId msg_id;

          stun_message_id (&msg, msg_id);

          for (; i; i = i->next) {
            SendRequest *r = i->data;
            if (memcmp (&r->id, msg_id, sizeof(StunTransactionId)) == 0) {
              req = r;
              break;
            }
          }

          if (req) {
            g_queue_remove (priv->send_requests, req);
            send_request_free (req);
          }

          if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
            uint32_t opts = 0;
            if (stun_message_find32 (&msg, STUN_ATTRIBUTE_OPTIONS, &opts) ==
                STUN_MESSAGE_RETURN_SUCCESS && opts & 0x1)
              goto msn_google_lock;
          }
        }

        goto done;
      } else if (stun_message_get_method (&msg) == STUN_OLD_SET_ACTIVE_DST) {
        StunTransactionId request_id;
        StunTransactionId response_id;

        if (priv->current_binding && priv->current_binding_msg) {
          stun_message_id (&msg, response_id);
          stun_message_id (&priv->current_binding_msg->message, request_id);
          if (memcmp (request_id, response_id,
                  sizeof(StunTransactionId)) == 0) {
            g_free (priv->current_binding_msg);
            priv->current_binding_msg = NULL;

            if (stun_message_get_class (&msg) == STUN_RESPONSE &&
                (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007 ||
                 priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN)) {
              goto msn_google_lock;
            } else {
              g_free (priv->current_binding);
              priv->current_binding = NULL;
            }
          }
        }

        goto done;
      } else if (stun_message_get_method (&msg) == STUN_CHANNELBIND) {
        StunTransactionId request_id;
        StunTransactionId response_id;

        if (priv->current_binding_msg) {
          stun_message_id (&msg, response_id);
          stun_message_id (&priv->current_binding_msg->message, request_id);
          if (memcmp (request_id, response_id,
                  sizeof(StunTransactionId)) == 0) {

            if (priv->current_binding) {
              /* New channel binding */
              binding = priv->current_binding;
            } else {
              /* Existing binding refresh */
              GList *i;
              union {
                struct sockaddr_storage storage;
                struct sockaddr addr;
              } sa;
              socklen_t sa_len = sizeof(sa);
              NiceAddress to;

              /* look up binding associated with peer */
              stun_message_find_xor_addr (
                  &priv->current_binding_msg->message,
                  STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &sa.storage, &sa_len);
              nice_address_set_from_sockaddr (&to, &sa.addr);

              for (i = priv->channels; i; i = i->next) {
                ChannelBinding *b = i->data;
                if (nice_address_equal (&b->peer, &to)) {
                  binding = b;
                  break;
                }
              }
            }

            if (stun_message_get_class (&msg) == STUN_ERROR) {
              int code = -1;
              uint8_t *sent_realm = NULL;
              uint8_t *recv_realm = NULL;
              uint16_t sent_realm_len = 0;
              uint16_t recv_realm_len = 0;

              sent_realm =
                  (uint8_t *) stun_message_find (
                      &priv->current_binding_msg->message,
                      STUN_ATTRIBUTE_REALM, &sent_realm_len);
              recv_realm =
                  (uint8_t *) stun_message_find (&msg,
                      STUN_ATTRIBUTE_REALM, &recv_realm_len);

              /* check for unauthorized error response */
              if (stun_message_find_error (&msg, &code) ==
                  STUN_MESSAGE_RETURN_SUCCESS &&
                  (code == STUN_ERROR_STALE_NONCE ||
                      (code == STUN_ERROR_UNAUTHORIZED &&
                          !(recv_realm != NULL &&
                              recv_realm_len > 0 &&
                              recv_realm_len == sent_realm_len &&
                              sent_realm != NULL &&
                              memcmp (sent_realm, recv_realm,
                                  sent_realm_len) == 0)))) {

                g_free (priv->current_binding_msg);
                priv->current_binding_msg = NULL;
                nice_udp_turn_socket_cache_realm_nonce_locked (sock, &msg);
                if (binding)
                  priv_send_channel_bind (priv, binding->channel,
                      &binding->peer);
              } else {
                g_free (priv->current_binding);
                priv->current_binding = NULL;
                g_free (priv->current_binding_msg);
                priv->current_binding_msg = NULL;
                priv_process_pending_bindings (priv);
              }
            } else if (stun_message_get_class (&msg) == STUN_RESPONSE) {
              g_free (priv->current_binding_msg);
              priv->current_binding_msg = NULL;

              /* If it's a new channel binding, then add it to the list */
              if (priv->current_binding)
                priv->channels = g_list_append (priv->channels,
                    priv->current_binding);
              priv->current_binding = NULL;

              if (binding) {
                binding->renew = FALSE;

                /* Remove any existing timer */
                if (binding->timeout_source) {
                  g_source_destroy (binding->timeout_source);
                  g_source_unref (binding->timeout_source);
                }
                /* Install timer to schedule refresh of the permission */
                binding->timeout_source =
                    priv_timeout_add_seconds_with_context (priv,
                    STUN_BINDING_TIMEOUT, priv_binding_timeout, priv);
              }
              priv_process_pending_bindings (priv);
            }
          }
        }
        goto done;
      } else if (stun_message_get_method (&msg) == STUN_CREATEPERMISSION) {
        StunTransactionId request_id;
        StunTransactionId response_id;
        GList *i, *next;
        TURNMessage *current_create_permission_msg;

        for (i = priv->pending_permissions; i; i = next) {
          current_create_permission_msg = (TURNMessage *) i->data;
          next = i->next;

          stun_message_id (&msg, response_id);
          stun_message_id (&current_create_permission_msg->message, request_id);

          if (memcmp (request_id, response_id,
                  sizeof(StunTransactionId)) == 0) {
            union {
              struct sockaddr_storage storage;
              struct sockaddr addr;
            } peer;
            socklen_t peer_len = sizeof(peer);
            NiceAddress to;
            gchar tmpbuf[INET6_ADDRSTRLEN];

            stun_message_find_xor_addr (
                &current_create_permission_msg->message,
                STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &peer.storage, &peer_len);
            nice_address_set_from_sockaddr (&to, &peer.addr);
            nice_address_to_string (&to, tmpbuf);
            nice_debug ("TURN: got response for CreatePermission "
                "with XOR_PEER_ADDRESS=[%s]:%u : %s",
                tmpbuf, nice_address_get_port (&to),
                stun_message_get_class (&msg) == STUN_ERROR ? "unauthorized" : "ok");

            /* unathorized => resend with realm and nonce */
            if (stun_message_get_class (&msg) == STUN_ERROR) {
              int code = -1;
              uint8_t *sent_realm = NULL;
              uint8_t *recv_realm = NULL;
              uint16_t sent_realm_len = 0;
              uint16_t recv_realm_len = 0;

              sent_realm =
                  (uint8_t *) stun_message_find (
                      &current_create_permission_msg->message,
                      STUN_ATTRIBUTE_REALM, &sent_realm_len);
              recv_realm =
                  (uint8_t *) stun_message_find (&msg,
                      STUN_ATTRIBUTE_REALM, &recv_realm_len);

              /* check for unauthorized error response */
              if (stun_message_find_error (&msg, &code) ==
                  STUN_MESSAGE_RETURN_SUCCESS &&
                  (code == STUN_ERROR_STALE_NONCE ||
                      (code == STUN_ERROR_UNAUTHORIZED &&
                          !(recv_realm != NULL &&
                              recv_realm_len > 0 &&
                              recv_realm_len == sent_realm_len &&
                              sent_realm != NULL &&
                              memcmp (sent_realm, recv_realm,
                                  sent_realm_len) == 0)))) {

                priv->pending_permissions = g_list_delete_link (
                    priv->pending_permissions, i);
                g_free (current_create_permission_msg);
                current_create_permission_msg = NULL;

                nice_udp_turn_socket_cache_realm_nonce_locked (sock, &msg);
                /* resend CreatePermission */
                priv_send_create_permission (priv, &to);
                goto done;
              }
            }
            /* If we get an error, we just assume the server somehow
               doesn't support permissions and we ignore the error and
               fake a successful completion. If the server needs a permission
               but it failed to create it, then the connchecks will fail. */
            priv_remove_sent_permission_for_peer (priv, &to);
            priv_add_permission_for_peer (priv, &to);

            /* install timer to schedule refresh of the permission */
            /* (will not schedule refresh if we got an error) */
            if (stun_message_get_class (&msg) == STUN_RESPONSE &&
                !priv->permission_timeout_source) {
              priv->permission_timeout_source =
                  priv_timeout_add_seconds_with_context (priv,
                      STUN_PERMISSION_TIMEOUT, priv_permission_timeout,
                      priv);
            }

            /* send enqued data */
            socket_dequeue_all_data (priv, &to);

            priv->pending_permissions = g_list_delete_link (
                priv->pending_permissions, i);
            g_free (current_create_permission_msg);
            current_create_permission_msg = NULL;

            break;
          }
        }

        goto done;
      } else if (stun_message_get_class (&msg) == STUN_INDICATION &&
          stun_message_get_method (&msg) == STUN_IND_DATA) {
        uint16_t data_len;
        uint8_t *data;
        union {
          struct sockaddr_storage storage;
          struct sockaddr addr;
        } sa;
        socklen_t from_len = sizeof (sa);

        if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
            priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
          if (stun_message_find_xor_addr (&msg, STUN_ATTRIBUTE_REMOTE_ADDRESS,
                  &sa.storage, &from_len) !=
              STUN_MESSAGE_RETURN_SUCCESS)
            goto recv;
        } else {
          if (stun_message_find_addr (&msg, STUN_ATTRIBUTE_REMOTE_ADDRESS,
                  &sa.storage, &from_len) !=
              STUN_MESSAGE_RETURN_SUCCESS)
            goto recv;
        }

        data = (uint8_t *) stun_message_find (&msg, STUN_ATTRIBUTE_DATA,
            &data_len);

        if (data == NULL)
          goto recv;

        nice_address_set_from_sockaddr (from, &sa.addr);

        if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766 &&
                !priv_has_permission_for_peer (priv, from)) {
          if (!priv_has_sent_permission_for_peer (priv, from)) {
            priv_send_create_permission (priv, from);
          }
        }

        *from_sock = sock;
        memmove (buf, data, len > data_len ? data_len : len);
        g_mutex_unlock (&mutex);
        return len > data_len ? data_len : len;
      } else {
        goto recv;
      }
    }
  }

 recv:
  for (l = priv->channels; l; l = l->next) {
    ChannelBinding *b = l->data;
    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      if (b->channel == ntohs(recv_buf.u16[0])) {
        recv_len = ntohs (recv_buf.u16[1]);
        recv_buf.u8 += sizeof(uint32_t);
        binding = b;
        break;
      }
    } else {
      binding = b;
      break;
    }
  }

  if (binding) {
    *from = binding->peer;
    *from_sock = sock;
  } else {
    *from = *recv_from;
  }

  memmove (buf, recv_buf.u8, len > recv_len ? recv_len : len);
  g_mutex_unlock (&mutex);
  return len > recv_len ? recv_len : len;

 msn_google_lock:

  if (priv->current_binding) {
    GList *i = priv->channels;
    for (; i; i = i->next) {
      ChannelBinding *b = i->data;
      g_free (b);
    }
    g_list_free (priv->channels);
    priv->channels = g_list_append (NULL, priv->current_binding);
    priv->current_binding = NULL;
    priv_process_pending_bindings (priv);
  }

 done:
  g_mutex_unlock (&mutex);
  return 0;
}

gboolean
nice_udp_turn_socket_set_peer (NiceSocket *sock, NiceAddress *peer)
{
  UdpTurnPriv *priv;
  gboolean ret;

  g_mutex_lock (&mutex);

  priv = (UdpTurnPriv *) sock->priv;

  ret = priv_add_channel_binding (priv, peer);

  g_mutex_unlock (&mutex);

  return ret;
}

static void
priv_process_pending_bindings (UdpTurnPriv *priv)
{
  gboolean ret = FALSE;

  while (priv->pending_bindings != NULL && ret == FALSE) {
    NiceAddress *peer = priv->pending_bindings->data;
    ret = priv_add_channel_binding (priv, peer);
    priv->pending_bindings = g_list_remove (priv->pending_bindings, peer);
    nice_address_free (peer);
  }

  /* If no new channel bindings are in progress and there are no
     pending bindings, then renew the soon to be expired bindings */
  if (priv->pending_bindings == NULL && priv->current_binding_msg == NULL) {
    GList *i = NULL;

    /* find binding to renew */
    for (i = priv->channels ; i; i = i->next) {
      ChannelBinding *b = i->data;
      if (b->renew) {
        priv_send_channel_bind (priv, b->channel, &b->peer);
        break;
      }
    }
  }
}


static gboolean
priv_retransmissions_tick_unlocked (UdpTurnPriv *priv)
{
  gboolean ret = FALSE;

  if (priv->current_binding_msg) {
    switch (stun_timer_refresh (&priv->current_binding_msg->timer)) {
      case STUN_USAGE_TIMER_RETURN_TIMEOUT:
        {
          /* Time out */
          StunTransactionId id;

          stun_message_id (&priv->current_binding_msg->message, id);
          stun_agent_forget_transaction (&priv->agent, id);

          g_free (priv->current_binding);
          priv->current_binding = NULL;
          g_free (priv->current_binding_msg);
          priv->current_binding_msg = NULL;


          priv_process_pending_bindings (priv);
          break;
        }
      case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
        /* Retransmit */
        _socket_send_wrapped (priv->base_socket, &priv->server_addr,
            stun_message_length (&priv->current_binding_msg->message),
            (gchar *)priv->current_binding_msg->buffer, FALSE);
        ret = TRUE;
        break;
      case STUN_USAGE_TIMER_RETURN_SUCCESS:
        ret = TRUE;
        break;
      default:
        /* Nothing to do. */
        break;
    }
  }

  if (ret)
    priv_schedule_tick (priv);
  return ret;
}

static gboolean
priv_retransmissions_create_permission_tick_unlocked (UdpTurnPriv *priv, GList *list_element)
{
  gboolean ret = FALSE;
  TURNMessage *current_create_permission_msg;

  current_create_permission_msg = (TURNMessage *)list_element->data;

  if (current_create_permission_msg) {
    switch (stun_timer_refresh (&current_create_permission_msg->timer)) {
      case STUN_USAGE_TIMER_RETURN_TIMEOUT:
        {
          /* Time out */
          StunTransactionId id;
          NiceAddress to;
          union {
            struct sockaddr_storage storage;
            struct sockaddr addr;
          } addr;
          socklen_t addr_len = sizeof(addr);

          stun_message_id (&current_create_permission_msg->message, id);
          stun_agent_forget_transaction (&priv->agent, id);
          stun_message_find_xor_addr (
              &current_create_permission_msg->message,
              STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &addr.storage, &addr_len);
          nice_address_set_from_sockaddr (&to, &addr.addr);

          priv_remove_sent_permission_for_peer (priv, &to);
          priv->pending_permissions = g_list_delete_link (
              priv->pending_permissions, list_element);
          g_free (current_create_permission_msg);
          current_create_permission_msg = NULL;

          /* we got a timeout when retransmitting a CreatePermission
             message, assume we can just send the data, the server
             might not support RFC TURN, or connectivity check will
             fail eventually anyway */
          priv_add_permission_for_peer (priv, &to);

          socket_dequeue_all_data (priv, &to);

          break;
        }
      case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
        /* Retransmit */
        _socket_send_wrapped (priv->base_socket, &priv->server_addr,
            stun_message_length (&current_create_permission_msg->message),
            (gchar *)current_create_permission_msg->buffer, FALSE);
        ret = TRUE;
        break;
      case STUN_USAGE_TIMER_RETURN_SUCCESS:
        ret = TRUE;
        break;
      default:
        /* Nothing to do. */
        break;
    }
  }

  return ret;
}

static gboolean
priv_retransmissions_tick (gpointer pointer)
{
  UdpTurnPriv *priv = pointer;

  g_mutex_lock (&mutex);
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. Avoided race condition in "
                "udp-turn.c:priv_permission_timeout");

    g_mutex_unlock (&mutex);
    return G_SOURCE_REMOVE;
  }

  if (priv_retransmissions_tick_unlocked (priv) == FALSE) {
    if (priv->tick_source_channel_bind != NULL) {
      g_source_destroy (priv->tick_source_channel_bind);
      g_source_unref (priv->tick_source_channel_bind);
      priv->tick_source_channel_bind = NULL;
    }
  }

  g_mutex_unlock (&mutex);

  return G_SOURCE_REMOVE;
}

static gboolean
priv_retransmissions_create_permission_tick (gpointer pointer)
{
  UdpTurnPriv *priv = pointer;

  g_mutex_lock (&mutex);
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. Avoided race condition in "
                "udp-turn.c:priv_permission_timeout");

    g_mutex_unlock (&mutex);
    return G_SOURCE_REMOVE;
  }

  /* This will call priv_retransmissions_create_permission_tick_unlocked() for
   * every pending permission with an expired timer and will create a new timer
   * if there are pending permissions that require it */
  priv_schedule_tick (priv);

  g_mutex_unlock (&mutex);

  return G_SOURCE_REMOVE;
}

static void
priv_schedule_tick (UdpTurnPriv *priv)
{
  GList *i, *next, *prev;
  TURNMessage *current_create_permission_msg;
  guint min_timeout = G_MAXUINT;

  if (priv->tick_source_channel_bind != NULL) {
    g_source_destroy (priv->tick_source_channel_bind);
    g_source_unref (priv->tick_source_channel_bind);
    priv->tick_source_channel_bind = NULL;
  }

  if (priv->current_binding_msg) {
    guint timeout = stun_timer_remainder (&priv->current_binding_msg->timer);
    if (timeout > 0) {
      priv->tick_source_channel_bind =
          priv_timeout_add_with_context (priv, timeout,
              priv_retransmissions_tick, priv);
    } else {
      priv_retransmissions_tick_unlocked (priv);
    }
  }

  if (priv->tick_source_create_permission != NULL) {
    g_source_destroy (priv->tick_source_create_permission);
    g_source_unref (priv->tick_source_create_permission);
    priv->tick_source_create_permission = NULL;
  }

  for (i = priv->pending_permissions, prev = NULL; i; i = next) {
    guint timeout;

    current_create_permission_msg = (TURNMessage *)i->data;
    next = i->next;

    timeout = stun_timer_remainder (&current_create_permission_msg->timer);

    if (timeout > 0) {
      min_timeout = MIN (min_timeout, timeout);
      prev = i;
    } else {
      /* This could either delete the permission from the list, or it could
       * refresh it, changing its timeout value */
      priv_retransmissions_create_permission_tick_unlocked (priv, i);
      if (prev == NULL)
        next = priv->pending_permissions;
      else
        next = prev->next;
    }
  }

  /* We create one timer for the minimal timeout we need */
  if (min_timeout != G_MAXUINT) {
    priv->tick_source_create_permission =
        priv_timeout_add_with_context (priv, min_timeout,
            priv_retransmissions_create_permission_tick,
            priv);
  }
}

static void
priv_send_turn_message (UdpTurnPriv *priv, TURNMessage *msg)
{
  size_t stun_len = stun_message_length (&msg->message);

  if (priv->current_binding_msg) {
    g_free (priv->current_binding_msg);
    priv->current_binding_msg = NULL;
  }

  if (nice_socket_is_reliable (priv->base_socket)) {
    _socket_send_wrapped (priv->base_socket, &priv->server_addr,
        stun_len, (gchar *)msg->buffer, TRUE);
    stun_timer_start_reliable (&msg->timer,
        STUN_TIMER_DEFAULT_RELIABLE_TIMEOUT);
  } else {
    if (_socket_send_wrapped (priv->base_socket, &priv->server_addr,
            stun_len, (gchar *)msg->buffer, TRUE) < 0)
      _socket_send_wrapped (priv->base_socket, &priv->server_addr,
          stun_len, (gchar *)msg->buffer, FALSE);
    stun_timer_start (&msg->timer, STUN_TIMER_DEFAULT_TIMEOUT,
        STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
  }

  priv->current_binding_msg = msg;
  priv_schedule_tick (priv);
}

static gboolean
priv_send_create_permission(UdpTurnPriv *priv,
    const NiceAddress *peer)
{
  guint msg_buf_len;
  gboolean res = FALSE;
  TURNMessage *msg = g_new0 (TURNMessage, 1);
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } addr;

  /* register this peer as being pening a permission (if not already pending) */
  if (!priv_has_sent_permission_for_peer (priv, peer)) {
    priv_add_sent_permission_for_peer (priv, peer);
  }

  nice_address_copy_to_sockaddr (peer, &addr.addr);

  /* send CreatePermission */
  msg_buf_len = stun_usage_turn_create_permission(&priv->agent, &msg->message,
      msg->buffer,
      sizeof(msg->buffer),
      priv->username,
      priv->username_len,
      priv->password,
      priv->password_len,
      priv->cached_realm, priv->cached_realm_len,
      priv->cached_nonce, priv->cached_nonce_len,
      &addr.storage,
      STUN_USAGE_TURN_COMPATIBILITY_RFC5766);

  if (msg_buf_len > 0) {
    if (nice_socket_is_reliable (priv->base_socket)) {
      res = _socket_send_wrapped (priv->base_socket, &priv->server_addr,
          msg_buf_len, (gchar *) msg->buffer, TRUE);
    } else {
      res = _socket_send_wrapped (priv->base_socket, &priv->server_addr,
          msg_buf_len, (gchar *) msg->buffer, TRUE);
      if (res < 0)
        res = _socket_send_wrapped (priv->base_socket, &priv->server_addr,
            msg_buf_len, (gchar *) msg->buffer, FALSE);
    }

    if (nice_socket_is_reliable (priv->base_socket)) {
      stun_timer_start_reliable (&msg->timer,
        STUN_TIMER_DEFAULT_RELIABLE_TIMEOUT);
    } else {
      stun_timer_start (&msg->timer, STUN_TIMER_DEFAULT_TIMEOUT,
        STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
    }

    priv->pending_permissions = g_list_append (priv->pending_permissions, msg);
    priv_schedule_tick (priv);
  } else {
    g_free(msg);
  }

  return res;
}

static gboolean
priv_send_channel_bind (UdpTurnPriv *priv, uint16_t channel,
    const NiceAddress *peer)
{
  uint32_t channel_attr = channel << 16;
  size_t stun_len;
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } sa;
  TURNMessage *msg = g_new0 (TURNMessage, 1);

  nice_address_copy_to_sockaddr (peer, &sa.addr);

  if (!stun_agent_init_request (&priv->agent, &msg->message,
          msg->buffer, sizeof(msg->buffer),
          STUN_CHANNELBIND)) {
    g_free (msg);
    return FALSE;
  }

  if (stun_message_append32 (&msg->message, STUN_ATTRIBUTE_CHANNEL_NUMBER,
          channel_attr) != STUN_MESSAGE_RETURN_SUCCESS) {
    g_free (msg);
    return FALSE;
  }

  if (stun_message_append_xor_addr (&msg->message, STUN_ATTRIBUTE_PEER_ADDRESS,
          &sa.storage,
          sizeof(sa))
      != STUN_MESSAGE_RETURN_SUCCESS) {
    g_free (msg);
    return FALSE;
  }

  if (priv->username != NULL && priv->username_len > 0 &&
      priv->cached_realm != NULL && priv->cached_realm_len > 0 &&
      priv->cached_nonce != NULL && priv->cached_nonce_len > 0) {

    if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_USERNAME,
            priv->username, priv->username_len)
        != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return FALSE;
    }

    if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_REALM,
            priv->cached_realm,  priv->cached_realm_len)
        != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return 0;
    }

    if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_NONCE,
            priv->cached_nonce, priv->cached_nonce_len)
        != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return 0;
    }
  }

  stun_len = stun_agent_finish_message (&priv->agent, &msg->message,
      priv->password, priv->password_len);

  if (stun_len > 0) {
    priv_send_turn_message (priv, msg);
    return TRUE;
  }

  g_free (msg);
  return FALSE;
}

static gboolean
priv_add_channel_binding (UdpTurnPriv *priv, const NiceAddress *peer)
{
  size_t stun_len;
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } sa;

  nice_address_copy_to_sockaddr (peer, &sa.addr);

  if (priv->current_binding) {
    NiceAddress * pending= nice_address_new ();
    *pending = *peer;
    priv->pending_bindings = g_list_append (priv->pending_bindings, pending);
    return FALSE;
  }

  if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
    uint16_t channel = 0x4000;
    GList *i = priv->channels;
    for (; i; i = i->next) {
      ChannelBinding *b = i->data;
      if (channel == b->channel) {
        i = priv->channels;
        channel++;
        continue;
      }
    }

    if (channel >= 0x4000 && channel < 0xffff) {
      gboolean ret = priv_send_channel_bind (priv, channel, peer);
      if (ret) {
        priv->current_binding = g_new0 (ChannelBinding, 1);
        priv->current_binding->channel = channel;
        priv->current_binding->peer = *peer;
      }
      return ret;
    }
    return FALSE;
  } else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN ||
      priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
    TURNMessage *msg = g_new0 (TURNMessage, 1);
    if (!stun_agent_init_request (&priv->agent, &msg->message,
            msg->buffer, sizeof(msg->buffer),
            STUN_OLD_SET_ACTIVE_DST)) {
      g_free (msg);
      return FALSE;
    }

    if (stun_message_append32 (&msg->message, STUN_ATTRIBUTE_MAGIC_COOKIE,
            TURN_MAGIC_COOKIE)
        != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return FALSE;
    }

    if (priv->username != NULL && priv->username_len > 0) {
      if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_USERNAME,
              priv->username, priv->username_len)
          != STUN_MESSAGE_RETURN_SUCCESS) {
        g_free (msg);
        return FALSE;
      }
    }

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
      if (priv->ms_connection_id_valid)
        stun_message_append_ms_connection_id(&msg->message,
            priv->ms_connection_id, ++priv->ms_sequence_num);

      stun_message_ensure_ms_realm(&msg->message, priv->ms_realm);
    }

    if (stun_message_append_addr (&msg->message,
            STUN_ATTRIBUTE_DESTINATION_ADDRESS,
            &sa.addr, sizeof(sa))
        != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return FALSE;
    }

    stun_len = stun_agent_finish_message (&priv->agent, &msg->message,
        priv->password, priv->password_len);

    if (stun_len > 0) {
      priv->current_binding = g_new0 (ChannelBinding, 1);
      priv->current_binding->channel = 0;
      priv->current_binding->peer = *peer;
      priv_send_turn_message (priv, msg);
      return TRUE;
    }
    g_free (msg);
    return FALSE;
  } else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    priv->current_binding = g_new0 (ChannelBinding, 1);
    priv->current_binding->channel = 0;
    priv->current_binding->peer = *peer;
    return TRUE;
  } else {
    return FALSE;
  }

  return FALSE;
}

void
nice_udp_turn_socket_set_ms_realm(NiceSocket *sock, StunMessage *msg)
{
  UdpTurnPriv *priv = (UdpTurnPriv *)sock->priv;
  uint16_t alen;
  const uint8_t *realm = stun_message_find(msg, STUN_ATTRIBUTE_REALM, &alen);

  if (realm && alen <= STUN_MAX_MS_REALM_LEN) {
    g_mutex_lock (&mutex);
    memcpy(priv->ms_realm, realm, alen);
    priv->ms_realm[alen] = '\0';
    g_mutex_unlock (&mutex);
  }
}

void
nice_udp_turn_socket_set_ms_connection_id (NiceSocket *sock, StunMessage *msg)
{
  UdpTurnPriv *priv = (UdpTurnPriv *)sock->priv;
  uint16_t alen;
  const uint8_t *ms_seq_num = stun_message_find(msg,
      STUN_ATTRIBUTE_MS_SEQUENCE_NUMBER, &alen);


  if (ms_seq_num && alen == 24) {
    g_mutex_lock (&mutex);
    memcpy (priv->ms_connection_id, ms_seq_num, 20);
    priv->ms_sequence_num = ntohl((uint32_t)*(ms_seq_num + 20));
    priv->ms_connection_id_valid = TRUE;
    g_mutex_unlock (&mutex);
  }
}
