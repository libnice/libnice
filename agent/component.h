/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2010 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2010 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
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
 *   Dafydd Harries, Collabora Ltd.
 *   Youness Alaoui, Collabora Ltd.
 *   Kai Vehmanen, Nokia
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

#ifndef _NICE_COMPONENT_H
#define _NICE_COMPONENT_H

#include <glib.h>

typedef struct _NiceComponent NiceComponent;

#include "agent.h"
#include "agent-priv.h"
#include "candidate.h"
#include "stun/stunagent.h"
#include "stun/usages/timer.h"
#include "pseudotcp.h"
#include "stream.h"
#include "socket.h"

G_BEGIN_DECLS


/* (ICE §4.1.1.1, ID-19)
 * ""For RTP-based media streams, the RTP itself has a component
 * ID of 1, and RTCP a component ID of 2.  If an agent is using RTCP it MUST
 * obtain a candidate for it.  If an agent is using both RTP and RTCP, it
 * would end up with 2*K host candidates if an agent has K interfaces.""
 */

typedef struct _CandidatePair CandidatePair;
typedef struct _CandidatePairKeepalive CandidatePairKeepalive;
typedef struct _IncomingCheck IncomingCheck;

struct _CandidatePairKeepalive
{
  GSource *tick_source;
  guint stream_id;
  guint component_id;
  StunTimer timer;
  uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE_IPV6];
  StunMessage stun_message;
};

struct _CandidatePair
{
  NiceCandidate *local;
  NiceCandidate *remote;
  guint64 priority;           /* candidate pair priority */
  guint32 prflx_priority;
  CandidatePairKeepalive keepalive;
};

struct _IncomingCheck
{
  NiceAddress from;
  NiceSocket *local_socket;
  guint32 priority;
  gboolean use_candidate;
  uint8_t *username;
  uint16_t username_len;
};

void
incoming_check_free (IncomingCheck *icheck);

/* A pair of a socket and the GSource which polls it from the main loop. All
 * GSources in a Component must be attached to the same main context:
 * component->ctx.
 *
 * Socket must be non-NULL, but source may be NULL if it has been detached.
 *
 * The Component is stored so this may be used as the user data for a GSource
 * callback. */
typedef struct {
  NiceSocket *socket;
  GSource *source;
  NiceComponent *component;
} SocketSource;


/* A message which has been received and processed (so is guaranteed not
 * to be a STUN packet, or to contain pseudo-TCP header bytes, for example), but
 * which hasn’t yet been sent to the client in an I/O callback. This could be
 * due to the main context not being run, or due to the I/O callback being
 * detached.
 *
 * The @offset member gives the byte offset into @buf which has already been
 * sent to the client. #IOCallbackData buffers remain in the
 * #Component::pending_io_messages queue until all of their bytes have been sent
 * to the client.
 *
 * @offset is guaranteed to be smaller than @buf_len. */
typedef struct {
  guint8 *buf;  /* owned */
  gsize buf_len;
  gsize offset;
} IOCallbackData;

IOCallbackData *
io_callback_data_new (const guint8 *buf, gsize buf_len);
void
io_callback_data_free (IOCallbackData *data);

#define NICE_TYPE_COMPONENT nice_component_get_type()
#define NICE_COMPONENT(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST ((obj), NICE_TYPE_COMPONENT, NiceComponent))
#define NICE_COMPONENT_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST ((klass), NICE_TYPE_COMPONENT, NiceComponentClass))
#define NICE_IS_COMPONENT(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NICE_TYPE_COMPONENT))
#define NICE_IS_COMPONENT_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE ((klass), NICE_TYPE_COMPONENT))
#define NICE_COMPONENT_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), NICE_TYPE_COMPONENT, NiceComponentClass))

struct _NiceComponent {
  /*< private >*/
  GObject parent;

  NiceComponentType type;
  guint id;                    /* component id */
  NiceComponentState state;
  GSList *local_candidates;    /* list of NiceCandidate objs */
  GSList *remote_candidates;   /* list of NiceCandidate objs */
  GList *valid_candidates;     /* list of owned remote NiceCandidates that are part of valid pairs */
  GSList *socket_sources;      /* list of SocketSource objs; must only grow monotonically */
  guint socket_sources_age;    /* incremented when socket_sources changes */
  GQueue incoming_checks;     /* list of IncomingCheck objs */
  GList *turn_servers;             /* List of TurnServer objs */
  CandidatePair selected_pair; /* independent from checklists, 
				    see ICE 11.1. "Sending Media" (ID-19) */
  gboolean fallback_mode;      /* in this case, accepts packets from all, ignore candidate validation */
  NiceCandidate *restart_candidate; /* for storing active remote candidate during a restart */
  NiceCandidate *turn_candidate; /* for storing active turn candidate if turn servers have been cleared */
  /* I/O handling. The main context must always be non-NULL, and is used for all
   * socket recv() operations. All io_callback emissions are invoked in this
   * context too.
   *
   * recv_messages and io_callback are mutually exclusive, but it is allowed for
   * both to be NULL if the Component is not currently ready to receive data. */
  GMutex io_mutex;                  /* protects io_callback, io_user_data,
                                         pending_io_messages and io_callback_id.
                                         immutable: can be accessed without
                                         holding the agent lock; if the agent
                                         lock is to be taken, it must always be
                                         taken before this one */
  NiceAgentRecvFunc io_callback;    /* function called on io cb */
  gpointer io_user_data;            /* data passed to the io function */
  GQueue pending_io_messages;       /* queue of messages which have been
                                         received but not passed to the client
                                         in an I/O callback or recv() call yet.
                                         each element is an owned
                                         IOCallbackData */
  guint io_callback_id;             /* GSource ID of the I/O callback */

  GMainContext *own_ctx;            /* own context for GSources for this
                                       component */
  GMainContext *ctx;                /* context for GSources for this
                                       component (possibly set from the app) */
  NiceInputMessage *recv_messages;  /* unowned messages for receiving into */
  guint n_recv_messages;            /* length of recv_messages */
  NiceInputMessageIter recv_messages_iter; /* current write position in
                                                recv_messages */
  GError **recv_buf_error;          /* error information about failed reads */

  GWeakRef agent_ref;
  guint stream_id;

  StunAgent stun_agent; /* This stun agent is used to validate all stun requests */


  GCancellable *stop_cancellable;
  GSource *stop_cancellable_source;  /* owned */

  PseudoTcpSocket *tcp;
  GSource* tcp_clock;
  guint64 last_clock_timeout;
  gboolean tcp_readable;
  GCancellable *tcp_writable_cancellable;

  GIOStream *iostream;

  guint min_port;
  guint max_port;

  /* Queue of messages received before a selected socket was available to send
   * ACKs on. The messages are dequeued to the pseudo-TCP socket once a selected
   * UDP socket is available. This is only used for reliable Components. */
  GQueue queued_tcp_packets;
};

typedef struct {
  GObjectClass parent_class;
} NiceComponentClass;

GType nice_component_get_type (void);

NiceComponent *
nice_component_new (guint component_id, NiceAgent *agent, NiceStream *stream);

void
nice_component_close (NiceAgent *agent, NiceComponent *component);

gboolean
nice_component_find_pair (NiceComponent *component, NiceAgent *agent,
    const gchar *lfoundation, const gchar *rfoundation, CandidatePair *pair);

void
nice_component_restart (NiceComponent *component);

void
nice_component_update_selected_pair (NiceAgent *agent, NiceComponent *component,
    const CandidatePair *pair);

NiceCandidate *
nice_component_find_remote_candidate (NiceComponent *component,
    const NiceAddress *addr, NiceCandidateTransport transport);

NiceCandidate *
nice_component_set_selected_remote_candidate (NiceComponent *component,
    NiceAgent *agent, NiceCandidate *candidate);

void
nice_component_attach_socket (NiceComponent *component, NiceSocket *nsocket);

void
nice_component_remove_socket (NiceAgent *agent, NiceComponent *component,
    NiceSocket *nsocket);
void
nice_component_detach_all_sockets (NiceComponent *component);

void
nice_component_free_socket_sources (NiceComponent *component);

GSource *
nice_component_input_source_new (NiceAgent *agent, guint stream_id,
    guint component_id, GPollableInputStream *pollable_istream,
    GCancellable *cancellable);

GMainContext *
nice_component_dup_io_context (NiceComponent *component);
void
nice_component_set_io_context (NiceComponent *component, GMainContext *context);
void
nice_component_set_io_callback (NiceComponent *component,
    NiceAgentRecvFunc func, gpointer user_data,
    NiceInputMessage *recv_messages, guint n_recv_messages,
    GError **error);
void
nice_component_emit_io_callback (NiceAgent *agent, NiceComponent *component,
    const guint8 *buf, gsize buf_len);
gboolean
nice_component_has_io_callback (NiceComponent *component);
void
nice_component_clean_turn_servers (NiceAgent *agent, NiceComponent *component);


TurnServer *
turn_server_new (const gchar *server_ip, guint server_port,
    const gchar *username, const gchar *password, NiceRelayType type);

TurnServer *
turn_server_ref (TurnServer *turn);

void
turn_server_unref (TurnServer *turn);

void
nice_component_add_valid_candidate (NiceAgent *agent, NiceComponent *component,
    const NiceCandidate *candidate);

gboolean
nice_component_verify_remote_candidate (NiceComponent *component,
    const NiceAddress *address, NiceSocket *nicesock);

GPtrArray *
nice_component_get_sockets (NiceComponent *component);

G_END_DECLS

#endif /* _NICE_COMPONENT_H */

