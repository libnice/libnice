/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
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

/*
 * @file component.c
 * @brief ICE component functions
 */

/* Simple tracking for the number of alive components. These must be accessed
 * atomically. */
static volatile unsigned int n_components_created = 0;
static volatile unsigned int n_components_destroyed = 0;

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include "debug.h"

#include "component.h"
#include "discovery.h"
#include "agent-priv.h"


static void
component_schedule_io_callback (Component *component);
static void
component_deschedule_io_callback (Component *component);


void
incoming_check_free (IncomingCheck *icheck)
{
  g_free (icheck->username);
  g_slice_free (IncomingCheck, icheck);
}

/* Must *not* take the agent lock, since it’s called from within
 * component_set_io_context(), which holds the Component’s I/O lock. */
static void
socket_source_attach (SocketSource *socket_source, GMainContext *context)
{
  GSource *source;

  /* Create a source. */
  source = g_socket_create_source (socket_source->socket->fileno,
      G_IO_IN, NULL);
  g_source_set_callback (source, (GSourceFunc) component_io_cb,
      socket_source, NULL);

  /* Add the source. */
  nice_debug ("Attaching source %p (socket %p, FD %d) to context %p", source,
      socket_source->socket, g_socket_get_fd (socket_source->socket->fileno),
      context);

  g_assert (socket_source->source == NULL);
  socket_source->source = source;
  g_source_attach (source, context);
}

static void
socket_source_detach (SocketSource *source)
{
  nice_debug ("Detaching source %p (socket %p, FD %d) from context %p",
      source->source, source->socket,
      (source->socket->fileno != NULL) ?
          g_socket_get_fd (source->socket->fileno) : 0,
      (source->source != NULL) ? g_source_get_context (source->source) : 0);

  if (source->source != NULL) {
    g_source_destroy (source->source);
    g_source_unref (source->source);
  }
  source->source = NULL;
}

static void
socket_source_free (SocketSource *source)
{
  socket_source_detach (source);
  nice_socket_free (source->socket);

  g_slice_free (SocketSource, source);
}

Component *
component_new (guint id, NiceAgent *agent, Stream *stream)
{
  Component *component;

  g_atomic_int_inc (&n_components_created);
  nice_debug ("Created NiceComponent (%u created, %u destroyed)",
      n_components_created, n_components_destroyed);

  component = g_slice_new0 (Component);
  component->id = id;
  component->state = NICE_COMPONENT_STATE_DISCONNECTED;
  component->restart_candidate = NULL;
  component->tcp = NULL;
  component->agent = agent;
  component->stream = stream;

  nice_agent_init_stun_agent (agent, &component->stun_agent);

  g_mutex_init (&component->io_mutex);
  g_queue_init (&component->pending_io_messages);
  component->io_callback_id = 0;

  component->own_ctx = g_main_context_new ();
  component->stop_cancellable = g_cancellable_new ();
  component->stop_cancellable_source =
      g_cancellable_source_new (component->stop_cancellable);
  g_source_set_dummy_callback (component->stop_cancellable_source);
  g_source_attach (component->stop_cancellable_source, component->own_ctx);
  component->ctx = g_main_context_ref (component->own_ctx);

  /* Start off with a fresh main context and all I/O paused. This
   * will be updated when nice_agent_attach_recv() or nice_agent_recv_messages()
   * are called. */
  component_set_io_context (component, NULL);
  component_set_io_callback (component, NULL, NULL, NULL, 0, NULL);

  g_queue_init (&component->queued_tcp_packets);

  return component;
}

void
component_clean_turn_servers (Component *cmp)
{
  GSList *i;

  g_list_free_full (cmp->turn_servers, (GDestroyNotify) turn_server_unref);
  cmp->turn_servers = NULL;

  for (i = cmp->local_candidates; i;) {
    NiceCandidate *candidate = i->data;
    GSList *next = i->next;

    if (candidate->type != NICE_CANDIDATE_TYPE_RELAYED) {
      i = next;
      continue;
    }

    /* note: do not remove the remote candidate that is
     *       currently part of the 'selected pair', see ICE
     *       9.1.1.1. "ICE Restarts" (ID-19)
     *
     * So what we do instead is that we put the selected candidate
     * in a special location and keep it "alive" that way. This is
     * especially important for TURN, because refresh requests to the
     * server need to keep happening.
     */
    if (candidate == cmp->selected_pair.local) {
      if (cmp->turn_candidate) {
        refresh_prune_candidate (cmp->agent, cmp->turn_candidate);
        discovery_prune_socket (cmp->agent, cmp->turn_candidate->sockptr);
        conn_check_prune_socket (cmp->agent, cmp->stream, cmp,
            cmp->turn_candidate->sockptr);
        component_detach_socket (cmp, cmp->turn_candidate->sockptr);
	nice_candidate_free (cmp->turn_candidate);
      }
      /* Bring the priority down to 0, so that it will be replaced
       * on the new run.
       */
      cmp->selected_pair.priority = 0;
      cmp->turn_candidate = candidate;
    } else {
      refresh_prune_candidate (cmp->agent, candidate);
      discovery_prune_socket (cmp->agent, candidate->sockptr);
      conn_check_prune_socket (cmp->agent, cmp->stream, cmp,
          candidate->sockptr);
      component_detach_socket (cmp, candidate->sockptr);
      agent_remove_local_candidate (cmp->agent, candidate);
      nice_candidate_free (candidate);
    }
    cmp->local_candidates = g_slist_delete_link (cmp->local_candidates, i);
    i = next;
  }
}

static void
component_clear_selected_pair (Component *component)
{
  if (component->selected_pair.keepalive.tick_source != NULL) {
    g_source_destroy (component->selected_pair.keepalive.tick_source);
    g_source_unref (component->selected_pair.keepalive.tick_source);
    component->selected_pair.keepalive.tick_source = NULL;
  }

  memset (&component->selected_pair, 0, sizeof(CandidatePair));
}

/* Must be called with the agent lock held as it touches internal Component
 * state. */
void
component_close (Component *cmp)
{
  IOCallbackData *data;
  GOutputVector *vec;

  /* Start closing the pseudo-TCP socket first. FIXME: There is a very big and
   * reliably triggerable race here. pseudo_tcp_socket_close() does not block
   * on the socket closing — it only sends the first packet of the FIN
   * handshake. component_close() will immediately afterwards close the
   * underlying component sockets, aborting the handshake.
   *
   * On the principle that starting the FIN handshake is better than not
   * starting it, even if it’s later truncated, call pseudo_tcp_socket_close().
   * A long-term fix is needed in the form of making component_close() (and all
   * its callers) async, so we can properly block on closure. */
  if (cmp->tcp) {
    pseudo_tcp_socket_close (cmp->tcp, TRUE);
  }

  if (cmp->restart_candidate)
    nice_candidate_free (cmp->restart_candidate),
      cmp->restart_candidate = NULL;

  if (cmp->turn_candidate)
    nice_candidate_free (cmp->turn_candidate),
        cmp->turn_candidate = NULL;

  while (cmp->local_candidates) {
    agent_remove_local_candidate (cmp->agent, cmp->local_candidates->data);
    nice_candidate_free (cmp->local_candidates->data);
    cmp->local_candidates = g_slist_delete_link (cmp->local_candidates,
        cmp->local_candidates);
  }

  g_slist_free_full (cmp->remote_candidates,
      (GDestroyNotify) nice_candidate_free);
  cmp->remote_candidates = NULL;
  component_free_socket_sources (cmp);
  g_slist_free_full (cmp->incoming_checks,
      (GDestroyNotify) incoming_check_free);
  cmp->incoming_checks = NULL;

  component_clean_turn_servers (cmp);

  if (cmp->tcp_clock) {
    g_source_destroy (cmp->tcp_clock);
    g_source_unref (cmp->tcp_clock);
    cmp->tcp_clock = NULL;
  }
  if (cmp->tcp_writable_cancellable) {
    g_cancellable_cancel (cmp->tcp_writable_cancellable);
    g_clear_object (&cmp->tcp_writable_cancellable);
  }

  while ((data = g_queue_pop_head (&cmp->pending_io_messages)) != NULL)
    io_callback_data_free (data);

  component_deschedule_io_callback (cmp);

  g_cancellable_cancel (cmp->stop_cancellable);

  while ((vec = g_queue_pop_head (&cmp->queued_tcp_packets)) != NULL) {
    g_free ((gpointer) vec->buffer);
    g_slice_free (GOutputVector, vec);
  }
}

/* Must be called with the agent lock released as it could dispose of
 * NiceIOStreams. */
void
component_free (Component *cmp)
{
  /* Component should have been closed already. */
  g_warn_if_fail (cmp->local_candidates == NULL);
  g_warn_if_fail (cmp->remote_candidates == NULL);
  g_warn_if_fail (cmp->incoming_checks == NULL);

  g_clear_object (&cmp->tcp);
  g_clear_object (&cmp->stop_cancellable);
  g_clear_object (&cmp->iostream);
  g_mutex_clear (&cmp->io_mutex);

  if (cmp->stop_cancellable_source != NULL) {
    g_source_destroy (cmp->stop_cancellable_source);
    g_source_unref (cmp->stop_cancellable_source);
  }

  if (cmp->ctx != NULL) {
    g_main_context_unref (cmp->ctx);
    cmp->ctx = NULL;
  }

  g_main_context_unref (cmp->own_ctx);

  g_slice_free (Component, cmp);

  g_atomic_int_inc (&n_components_destroyed);
  nice_debug ("Destroyed NiceComponent (%u created, %u destroyed)",
      n_components_created, n_components_destroyed);
}

/*
 * Finds a candidate pair that has matching foundation ids.
 *
 * @return TRUE if pair found, pointer to pair stored at 'pair'
 */
gboolean
component_find_pair (Component *cmp, NiceAgent *agent, const gchar *lfoundation, const gchar *rfoundation, CandidatePair *pair)
{
  GSList *i;
  CandidatePair result = { 0, };

  for (i = cmp->local_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    if (strncmp (candidate->foundation, lfoundation, NICE_CANDIDATE_MAX_FOUNDATION) == 0) {
      result.local = candidate;
      break;
    }
  }

  for (i = cmp->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    if (strncmp (candidate->foundation, rfoundation, NICE_CANDIDATE_MAX_FOUNDATION) == 0) {
      result.remote = candidate;
      break;
    }
  }

  if (result.local && result.remote) {
    result.priority = agent_candidate_pair_priority (agent, result.local, result.remote);
    if (pair)
      *pair = result;
    return TRUE;
  }

  return FALSE;
}

/*
 * Resets the component state to that of a ICE restarted
 * session.
 */
void
component_restart (Component *cmp)
{
  GSList *i;

  for (i = cmp->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;

    /* note: do not remove the local candidate that is
     *       currently part of the 'selected pair', see ICE
     *       9.1.1.1. "ICE Restarts" (ID-19) */
    if (candidate == cmp->selected_pair.remote) {
      if (cmp->restart_candidate)
	nice_candidate_free (cmp->restart_candidate);
      cmp->restart_candidate = candidate;
    }
    else 
      nice_candidate_free (candidate);
  }
  g_slist_free (cmp->remote_candidates),
    cmp->remote_candidates = NULL;

  g_slist_free_full (cmp->incoming_checks,
      (GDestroyNotify) incoming_check_free);
  cmp->incoming_checks = NULL;

  /* Reset the priority to 0 to make sure we get a new pair */
  cmp->selected_pair.priority = 0;

  /* note: component state managed by agent */
}

/*
 * Changes the selected pair for the component to 'pair'. Does not
 * emit the "selected-pair-changed" signal.
 */ 
void component_update_selected_pair (Component *component, const CandidatePair *pair)
{
  g_assert (component);
  g_assert (pair);
  nice_debug ("setting SELECTED PAIR for component %u: %s:%s (prio:%"
      G_GUINT64_FORMAT ").", component->id, pair->local->foundation,
      pair->remote->foundation, pair->priority);

  if (component->selected_pair.local &&
      component->selected_pair.local == component->turn_candidate) {
    refresh_prune_candidate (component->agent, component->turn_candidate);
    discovery_prune_socket (component->agent,
        component->turn_candidate->sockptr);
    conn_check_prune_socket (component->agent, component->stream, component,
        component->turn_candidate->sockptr);
    component_detach_socket (component, component->turn_candidate->sockptr);
    nice_candidate_free (component->turn_candidate);
    component->turn_candidate = NULL;
  }

  component_clear_selected_pair (component);

  component->selected_pair.local = pair->local;
  component->selected_pair.remote = pair->remote;
  component->selected_pair.priority = pair->priority;

}

/*
 * Finds a remote candidate with matching address and 
 * transport.
 *
 * @return pointer to candidate or NULL if not found
 */
NiceCandidate *
component_find_remote_candidate (const Component *component, const NiceAddress *addr, NiceCandidateTransport transport)
{
  GSList *i;

  for (i = component->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;

    if (nice_address_equal(&candidate->addr, addr) &&
	candidate->transport == transport)
      return candidate;

  }
  
  return NULL;
}

/*
 * Sets the desired remote candidate as the selected pair
 *
 * It will start sending on the highest priority pair available with
 * this candidate.
 */

NiceCandidate *
component_set_selected_remote_candidate (NiceAgent *agent, Component *component,
    NiceCandidate *candidate)
{
  NiceCandidate *local = NULL;
  NiceCandidate *remote = NULL;
  guint64 priority = 0;
  GSList *item = NULL;

  g_assert (candidate != NULL);

  for (item = component->local_candidates; item; item = g_slist_next (item)) {
    NiceCandidate *tmp = item->data;
    guint64 tmp_prio = 0;

    if (tmp->transport != candidate->transport ||
	tmp->addr.s.addr.sa_family != candidate->addr.s.addr.sa_family ||
        tmp->type != NICE_CANDIDATE_TYPE_HOST)
      continue;

    tmp_prio = agent_candidate_pair_priority (agent, tmp, candidate);

    if (tmp_prio > priority) {
      priority = tmp_prio;
      local = tmp;
    }
  }

  if (local == NULL)
    return NULL;

  remote = component_find_remote_candidate (component, &candidate->addr,
      candidate->transport);

  if (!remote) {
    remote = nice_candidate_copy (candidate);
    component->remote_candidates = g_slist_append (component->remote_candidates,
        remote);
    agent_signal_new_remote_candidate (agent, remote);
  }

  component_clear_selected_pair (component);

  component->selected_pair.local = local;
  component->selected_pair.remote = remote;
  component->selected_pair.priority = priority;

  return local;
}

static gint
_find_socket_source (gconstpointer a, gconstpointer b)
{
  const SocketSource *source_a = a;
  const NiceSocket *socket_b = b;

  return (source_a->socket == socket_b) ? 0 : 1;
}

/* This takes ownership of the socket.
 * It creates and attaches a source to the component’s context. */
void
component_attach_socket (Component *component, NiceSocket *nicesock)
{
  GSList *l;
  SocketSource *socket_source;

  g_assert (component != NULL);
  g_assert (nicesock != NULL);

  g_assert (component->ctx != NULL);

  if (nicesock->fileno == NULL)
    return;

  /* Find an existing SocketSource in the component which contains @socket, or
   * create a new one.
   *
   * Whenever a source is added or remove to socket_sources, socket_sources_age
   * must be incremented.
   */
  l = g_slist_find_custom (component->socket_sources, nicesock,
          _find_socket_source);
  if (l != NULL) {
    socket_source = l->data;
  } else {
    socket_source = g_slice_new0 (SocketSource);
    socket_source->socket = nicesock;
    socket_source->component = component;
    component->socket_sources =
        g_slist_prepend (component->socket_sources, socket_source);
    component->socket_sources_age++;
  }

  /* Create and attach a source */
  nice_debug ("Component %p (agent %p): Attach source (stream %u).",
      component, component->agent, component->stream->id);
  socket_source_attach (socket_source, component->ctx);
}

/* Reattaches socket handles of @component to the main context.
 *
 * Must *not* take the agent lock, since it’s called from within
 * component_set_io_context(), which holds the Component’s I/O lock. */
static void
component_reattach_all_sockets (Component *component)
{
  GSList *i;

  for (i = component->socket_sources; i != NULL; i = i->next) {
    SocketSource *socket_source = i->data;
    nice_debug ("Reattach source %p.", socket_source->source);
    socket_source_detach (socket_source);
    socket_source_attach (socket_source, component->ctx);
  }
}

/**
 * component_detach_socket:
 * @component: a #Component
 * @socket: the socket to detach the source for
 *
 * Detach the #GSource for the single specified @socket. It also closes it
 * and frees it!
 *
 * If the @socket doesn’t exist in this @component, do nothing.
 */
void
component_detach_socket (Component *component, NiceSocket *nicesock)
{
  GSList *l;
  SocketSource *socket_source;

  nice_debug ("Detach socket %p.", nicesock);

  /* Remove the socket from various lists. */
  for (l = component->incoming_checks; l != NULL;) {
    IncomingCheck *icheck = l->data;
    GSList *next = l->next;

    if (icheck->local_socket == nicesock) {
      component->incoming_checks =
          g_slist_delete_link (component->incoming_checks, l);
      incoming_check_free (icheck);
    }

    l = next;
  }

  /* Find the SocketSource for the socket. */
  l = g_slist_find_custom (component->socket_sources, nicesock,
          _find_socket_source);
  if (l == NULL)
    return;

  /* Detach the source. */
  socket_source = l->data;
  component->socket_sources = g_slist_delete_link (component->socket_sources, l);
  component->socket_sources_age++;

  socket_source_detach (socket_source);
  socket_source_free (socket_source);
}

/*
 * Detaches socket handles of @component from the main context. Leaves the
 * sockets themselves untouched.
 *
 * Must *not* take the agent lock, since it’s called from within
 * component_set_io_context(), which holds the Component’s I/O lock.
 */
void
component_detach_all_sockets (Component *component)
{
  GSList *i;

  for (i = component->socket_sources; i != NULL; i = i->next) {
    SocketSource *socket_source = i->data;
    nice_debug ("Detach source %p, socket %p.", socket_source->source,
        socket_source->socket);
    socket_source_detach (socket_source);
  }
}

void
component_free_socket_sources (Component *component)
{
  nice_debug ("Free socket sources for component %p.", component);

  g_slist_free_full (component->socket_sources,
      (GDestroyNotify) socket_source_free);
  component->socket_sources = NULL;
  component->socket_sources_age++;

  component_clear_selected_pair (component);
}

GMainContext *
component_dup_io_context (Component *component)
{
  return g_main_context_ref (component->own_ctx);
}

/* If @context is %NULL, it's own context is used, so component->ctx is always
 * guaranteed to be non-%NULL. */
void
component_set_io_context (Component *component, GMainContext *context)
{
  g_mutex_lock (&component->io_mutex);

  if (component->ctx != context) {
    if (context == NULL)
      context = g_main_context_ref (component->own_ctx);
    else
      g_main_context_ref (context);

    component_detach_all_sockets (component);
    g_main_context_unref (component->ctx);

    component->ctx = context;
    component_reattach_all_sockets (component);
  }

  g_mutex_unlock (&component->io_mutex);
}

/* (func, user_data) and (recv_messages, n_recv_messages) are mutually
 * exclusive. At most one of the two must be specified; if both are NULL, the
 * Component will not receive any data (i.e. reception is paused).
 *
 * Apart from during setup, this must always be called with the agent lock held,
 * and the I/O lock released (because it takes the I/O lock itself). Requiring
 * the agent lock to be held means it can’t be called between a packet being
 * dequeued from the kernel buffers in agent.c, and an I/O callback being
 * emitted for it (which could cause data loss if the I/O callback function was
 * unset in that time). */
void
component_set_io_callback (Component *component,
    NiceAgentRecvFunc func, gpointer user_data,
    NiceInputMessage *recv_messages, guint n_recv_messages,
    GError **error)
{
  g_assert (func == NULL || recv_messages == NULL);
  g_assert (n_recv_messages == 0 || recv_messages != NULL);
  g_assert (error == NULL || *error == NULL);

  g_mutex_lock (&component->io_mutex);

  if (func != NULL) {
    component->io_callback = func;
    component->io_user_data = user_data;
    component->recv_messages = NULL;
    component->n_recv_messages = 0;

    component_schedule_io_callback (component);
  } else {
    component->io_callback = NULL;
    component->io_user_data = NULL;
    component->recv_messages = recv_messages;
    component->n_recv_messages = n_recv_messages;

    component_deschedule_io_callback (component);
  }

  nice_input_message_iter_reset (&component->recv_messages_iter);
  component->recv_buf_error = error;

  g_mutex_unlock (&component->io_mutex);
}

gboolean
component_has_io_callback (Component *component)
{
  gboolean has_io_callback;

  g_mutex_lock (&component->io_mutex);
  has_io_callback = (component->io_callback != NULL);
  g_mutex_unlock (&component->io_mutex);

  return has_io_callback;
}

IOCallbackData *
io_callback_data_new (const guint8 *buf, gsize buf_len)
{
  IOCallbackData *data;

  data = g_slice_new0 (IOCallbackData);
  data->buf = g_memdup (buf, buf_len);
  data->buf_len = buf_len;
  data->offset = 0;

  return data;
}

void
io_callback_data_free (IOCallbackData *data)
{
  g_free (data->buf);
  g_slice_free (IOCallbackData, data);
}

/* This is called with the global agent lock released. It does not take that
 * lock, but does take the io_mutex. */
static gboolean
emit_io_callback_cb (gpointer user_data)
{
  Component *component = user_data;
  IOCallbackData *data;
  NiceAgentRecvFunc io_callback;
  gpointer io_user_data;
  guint stream_id, component_id;
  NiceAgent *agent;

  agent = component->agent;

  g_object_ref (agent);

  stream_id = component->stream->id;
  component_id = component->id;

  g_mutex_lock (&component->io_mutex);

  /* The members of Component are guaranteed not to have changed since this
   * GSource was attached in component_emit_io_callback(). The Component’s agent
   * and stream are immutable after construction, as are the stream and
   * component IDs. The callback and its user data may have changed, but are
   * guaranteed to be non-%NULL at the start as the idle source is removed when
   * the callback is set to %NULL. They may become %NULL during the io_callback,
   * so must be re-checked every loop iteration. The data buffer is copied into
   * the #IOCallbackData closure.
   *
   * If the component is destroyed (which happens if the agent or stream are
   * destroyed) between attaching the GSource and firing it, the GSource is
   * detached in component_free() and this callback is never invoked. If the
   * agent is destroyed during an io_callback, its weak pointer will be
   * nullified. Similarly, the Component needs to be re-queried for after every
   * iteration, just in case the client has removed the stream in the
   * callback. */
  while (TRUE) {
    io_callback = component->io_callback;
    io_user_data = component->io_user_data;
    data = g_queue_peek_head (&component->pending_io_messages);

    if (data == NULL || io_callback == NULL)
      break;

    g_mutex_unlock (&component->io_mutex);

    io_callback (agent, stream_id, component_id,
        data->buf_len - data->offset, (gchar *) data->buf + data->offset,
        io_user_data);

    /* Check for the user destroying things underneath our feet. */
    if (!agent_find_component (agent, stream_id, component_id,
            NULL, &component)) {
      nice_debug ("%s: Agent or component destroyed.", G_STRFUNC);
      goto done;
    }

    g_queue_pop_head (&component->pending_io_messages);
    io_callback_data_free (data);

    g_mutex_lock (&component->io_mutex);
  }

  component->io_callback_id = 0;
  g_mutex_unlock (&component->io_mutex);

 done:
  g_object_unref (agent);

  return G_SOURCE_REMOVE;
}

/* This must be called with the agent lock *held*. */
void
component_emit_io_callback (Component *component,
    const guint8 *buf, gsize buf_len)
{
  NiceAgent *agent;
  guint stream_id, component_id;
  NiceAgentRecvFunc io_callback;
  gpointer io_user_data;

  g_assert (component != NULL);
  g_assert (buf != NULL);
  g_assert (buf_len > 0);

  agent = component->agent;
  stream_id = component->stream->id;
  component_id = component->id;

  g_mutex_lock (&component->io_mutex);
  io_callback = component->io_callback;
  io_user_data = component->io_user_data;
  g_mutex_unlock (&component->io_mutex);

  /* Allow this to be called with a NULL io_callback, since the caller can’t
   * lock io_mutex to check beforehand. */
  if (io_callback == NULL)
    return;

  g_assert (NICE_IS_AGENT (agent));
  g_assert (stream_id > 0);
  g_assert (component_id > 0);
  g_assert (io_callback != NULL);

  /* Only allocate a closure if the callback is being deferred to an idle
   * handler. */
  if (g_main_context_is_owner (component->ctx)) {
    /* Thread owns the main context, so invoke the callback directly. */
    agent_unlock_and_emit (agent);
    io_callback (agent, stream_id,
        component_id, buf_len, (gchar *) buf, io_user_data);
    agent_lock ();
  } else {
    IOCallbackData *data;

    g_mutex_lock (&component->io_mutex);

    /* Slow path: Current thread doesn’t own the Component’s context at the
     * moment, so schedule the callback in an idle handler. */
    data = io_callback_data_new (buf, buf_len);
    g_queue_push_tail (&component->pending_io_messages,
        data);  /* transfer ownership */

    nice_debug ("%s: **WARNING: SLOW PATH**", G_STRFUNC);

    component_schedule_io_callback (component);

    g_mutex_unlock (&component->io_mutex);
  }
}

/* Note: Must be called with the io_mutex held. */
static void
component_schedule_io_callback (Component *component)
{
  GSource *source;

  /* Already scheduled or nothing to schedule? */
  if (component->io_callback_id != 0 ||
      g_queue_is_empty (&component->pending_io_messages))
    return;

  /* Add the idle callback. If nice_agent_attach_recv() is called with a
   * NULL callback before this source is dispatched, the source will be
   * destroyed, but any pending data will remain in
   * component->pending_io_messages, ready to be picked up when a callback
   * is re-attached, or if nice_agent_recv() is called. */
  source = g_idle_source_new ();
  g_source_set_priority (source, G_PRIORITY_DEFAULT);
  g_source_set_callback (source, emit_io_callback_cb, component, NULL);
  component->io_callback_id = g_source_attach (source, component->ctx);
  g_source_unref (source);
}

/* Note: Must be called with the io_mutex held. */
static void
component_deschedule_io_callback (Component *component)
{
  /* Already descheduled? */
  if (component->io_callback_id == 0)
    return;

  g_source_remove (component->io_callback_id);
  component->io_callback_id = 0;
}

/**
 * ComponentSource:
 *
 * This is a GSource which wraps a single Component and is dispatched whenever
 * any of its NiceSockets are dispatched, i.e. it proxies all poll() events for
 * every socket in the Component. It is designed for use by GPollableInputStream
 * and GPollableOutputStream, so that a Component can be incorporated into a
 * custom main context iteration.
 *
 * The callbacks dispatched by a ComponentSource have type GPollableSourceFunc.
 *
 * ComponentSource supports adding a GCancellable child source which will
 * additionally dispatch if a provided GCancellable is cancelled.
 *
 * Internally, ComponentSource adds a new GSocketSource for each socket in the
 * Component. Changes to the Component’s list of sockets are detected on each
 * call to component_source_prepare(), which compares a stored age with the
 * current age of the Component’s socket list — if the socket list has changed,
 * the age will have increased (indicating added sockets) or will have been
 * reset to 0 (indicating all sockets have been closed).
 */
typedef struct {
  GSource parent;

  GObject *pollable_stream;  /* owned */

  GWeakRef agent_ref;
  guint stream_id;
  guint component_id;
  guint component_socket_sources_age;

  /* SocketSource, free with free_child_socket_source() */
  GSList *socket_sources;

  GIOCondition condition;
} ComponentSource;

static gboolean
component_source_prepare (GSource *source, gint *timeout_)
{
  ComponentSource *component_source = (ComponentSource *) source;
  NiceAgent *agent;
  Component *component;
  GSList *parentl, *childl;

  agent = g_weak_ref_get (&component_source->agent_ref);
  if (!agent)
    return FALSE;

  /* Needed due to accessing the Component. */
  agent_lock ();

  if (!agent_find_component (agent,
          component_source->stream_id, component_source->component_id, NULL,
          &component))
    goto done;


  if (component->socket_sources_age ==
      component_source->component_socket_sources_age)
    goto done;

  /* If the age has changed, either
   *  - one or more new socket has been prepended
   *  - old sockets have been removed
   */

  /* Add the new child sources. */

  for (parentl = component->socket_sources; parentl; parentl = parentl->next) {
    SocketSource *parent_socket_source = parentl->data;
    SocketSource *child_socket_source;

    /* Iterating the list of socket sources every time isn't a big problem
     * because the number of pairs is limited ~100 normally, so there will
     * rarely be more than 10.
     */
    childl = g_slist_find_custom (component_source->socket_sources,
        parent_socket_source->socket, _find_socket_source);

    /* If we have reached this state, then all sources new sources have been
     * added, because they are always prepended.
     */
    if (childl)
      break;

    child_socket_source = g_slice_new0 (SocketSource);
    child_socket_source->socket = parent_socket_source->socket;
    child_socket_source->source =
        g_socket_create_source (child_socket_source->socket->fileno, G_IO_IN,
            NULL);
    g_source_set_dummy_callback (child_socket_source->source);
    g_source_add_child_source (source, child_socket_source->source);
    g_source_unref (child_socket_source->source);
    component_source->socket_sources =
        g_slist_prepend (component_source->socket_sources, child_socket_source);
  }


  for (childl = component_source->socket_sources;
       childl;) {
    SocketSource *child_socket_source = childl->data;
    GSList *next = childl->next;

    parentl = g_slist_find_custom (component->socket_sources,
      child_socket_source->socket, _find_socket_source);

    /* If this is not a currently used socket, remove the relevant source */
    if (!parentl) {
      g_source_remove_child_source (source, child_socket_source->source);
      g_slice_free (SocketSource, child_socket_source);
      component_source->socket_sources =
          g_slist_delete_link (component_source->socket_sources, childl);
    }

    childl = next;
  }


  /* Update the age. */
  component_source->component_socket_sources_age = component->socket_sources_age;

 done:

  agent_unlock_and_emit (agent);
  g_object_unref (agent);

  /* We can’t be sure if the ComponentSource itself needs to be dispatched until
   * poll() is called on all the child sources. */
  return FALSE;
}

static gboolean
component_source_dispatch (GSource *source, GSourceFunc callback,
    gpointer user_data)
{
  ComponentSource *component_source = (ComponentSource *) source;
  GPollableSourceFunc func = (GPollableSourceFunc) callback;

  return func (component_source->pollable_stream, user_data);
}

static void
free_child_socket_source (gpointer data)
{
  g_slice_free (SocketSource, data);
}

static void
component_source_finalize (GSource *source)
{
  ComponentSource *component_source = (ComponentSource *) source;

  g_slist_free_full (component_source->socket_sources, free_child_socket_source);

  g_weak_ref_clear (&component_source->agent_ref);
  g_object_unref (component_source->pollable_stream);
  component_source->pollable_stream = NULL;
}

static gboolean
component_source_closure_callback (GObject *pollable_stream, gpointer user_data)
{
  GClosure *closure = user_data;
  GValue param_value = G_VALUE_INIT;
  GValue result_value = G_VALUE_INIT;
  gboolean retval;

  g_value_init (&result_value, G_TYPE_BOOLEAN);
  g_value_init (&param_value, G_TYPE_OBJECT);
  g_value_set_object (&param_value, pollable_stream);

  g_closure_invoke (closure, &result_value, 1, &param_value, NULL);
  retval = g_value_get_boolean (&result_value);

  g_value_unset (&param_value);
  g_value_unset (&result_value);

  return retval;
}

static GSourceFuncs component_source_funcs = {
  component_source_prepare,
  NULL,  /* check */
  component_source_dispatch,
  component_source_finalize,
  (GSourceFunc) component_source_closure_callback,
};

/**
 * component_source_new:
 * @agent: a #NiceAgent
 * @stream_id: The stream's id
 * @component_id: The component's number
 * @pollable_stream: a #GPollableInputStream or #GPollableOutputStream to pass
 * to dispatched callbacks
 * @cancellable: (allow-none): a #GCancellable, or %NULL
 *
 * Create a new #ComponentSource, a type of #GSource which proxies poll events
 * from all sockets in the given @component.
 *
 * A callback function of type #GPollableSourceFunc must be connected to the
 * returned #GSource using g_source_set_callback(). @pollable_stream is passed
 * to all callbacks dispatched from the #GSource, and a reference is held on it
 * by the #GSource.
 *
 * The #GSource will automatically update to poll sockets as they’re added to
 * the @component (e.g. during peer discovery).
 *
 * Returns: (transfer full): a new #ComponentSource; unref with g_source_unref()
 */
GSource *
component_input_source_new (NiceAgent *agent, guint stream_id,
    guint component_id, GPollableInputStream *pollable_istream,
    GCancellable *cancellable)
{
  ComponentSource *component_source;

  g_assert (G_IS_POLLABLE_INPUT_STREAM (pollable_istream));

  component_source =
      (ComponentSource *)
          g_source_new (&component_source_funcs, sizeof (ComponentSource));
  g_source_set_name ((GSource *) component_source, "ComponentSource");

  component_source->component_socket_sources_age = 0;
  component_source->pollable_stream = g_object_ref (pollable_istream);
  g_weak_ref_init (&component_source->agent_ref, agent);
  component_source->stream_id = stream_id;
  component_source->component_id = component_id;

  /* Add a cancellable source. */
  if (cancellable != NULL) {
    GSource *cancellable_source;

    cancellable_source = g_cancellable_source_new (cancellable);
    g_source_set_dummy_callback (cancellable_source);
    g_source_add_child_source ((GSource *) component_source,
        cancellable_source);
    g_source_unref (cancellable_source);
  }

  return (GSource *) component_source;
}


TurnServer *
turn_server_new (const gchar *server_ip, guint server_port,
    const gchar *username, const gchar *password, NiceRelayType type)
{
  TurnServer *turn = g_slice_new (TurnServer);

  nice_address_init (&turn->server);

  turn->ref_count = 1;
  if (nice_address_set_from_string (&turn->server, server_ip)) {
    nice_address_set_port (&turn->server, server_port);
  } else {
    g_slice_free (TurnServer, turn);
    return NULL;
  }
  turn->username = g_strdup (username);
  turn->password = g_strdup (password);
  turn->type = type;

  return turn;
}

TurnServer *
turn_server_ref (TurnServer *turn)
{
  turn->ref_count++;

  return turn;
}

void
turn_server_unref (TurnServer *turn)
{
  turn->ref_count--;

  if (turn->ref_count == 0) {
    g_free (turn->username);
    g_free (turn->password);
    g_slice_free (TurnServer, turn);
  }
}
