/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007-2009 Nokia Corporation. All rights reserved.
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
 * @file discovery.c
 * @brief ICE candidate discovery functions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "debug.h"

#include "agent.h"
#include "agent-priv.h"
#include "agent-signals-marshal.h"
#include "component.h"
#include "discovery.h"
#include "stun/usages/bind.h"
#include "stun/usages/turn.h"
#include "socket.h"

static inline int priv_timer_expired (GTimeVal *timer, GTimeVal *now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

/*
 * Frees the CandidateDiscovery structure pointed to
 * by 'user data'. Compatible with g_slist_foreach().
 */
void discovery_free_item (gpointer data, gpointer user_data)
{
  CandidateDiscovery *cand = data;
  g_assert (user_data == NULL);
  g_free (cand->msn_turn_username);
  g_free (cand->msn_turn_password);
  g_slice_free (CandidateDiscovery, cand);
}

/*
 * Frees all discovery related resources for the agent.
 */
void discovery_free (NiceAgent *agent)
{

  g_slist_foreach (agent->discovery_list, discovery_free_item, NULL);
  g_slist_free (agent->discovery_list);
  agent->discovery_list = NULL;
  agent->discovery_unsched_items = 0;

  if (agent->discovery_timer_source != NULL) {
    g_source_destroy (agent->discovery_timer_source);
    g_source_unref (agent->discovery_timer_source);
    agent->discovery_timer_source = NULL;
  }
}

/*
 * Prunes the list of discovery processes for items related
 * to stream 'stream_id'.
 *
 * @return TRUE on success, FALSE on a fatal error
 */
void discovery_prune_stream (NiceAgent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->discovery_list; i ; ) {
    CandidateDiscovery *cand = i->data;
    GSList *next = i->next;

    if (cand->stream->id == stream_id) {
      agent->discovery_list = g_slist_remove (agent->discovery_list, cand);
      discovery_free_item (cand, NULL);
    }
    i = next;
  }

  if (agent->discovery_list == NULL) {
    /* noone using the timer anymore, clean it up */
    discovery_free (agent);
  }
}


/*
 * Frees the CandidateDiscovery structure pointed to
 * by 'user data'. Compatible with g_slist_foreach().
 */
void refresh_free_item (gpointer data, gpointer user_data)
{
  CandidateRefresh *cand = data;
  NiceAgent *agent = cand->agent;
  uint8_t *username;
  size_t username_len;
  uint8_t *password;
  size_t password_len;
  size_t buffer_len = 0;
  StunUsageTurnCompatibility turn_compat = agent_to_turn_compatibility (agent);

  g_assert (user_data == NULL);

  if (cand->timer_source != NULL) {
    g_source_destroy (cand->timer_source);
    g_source_unref (cand->timer_source);
    cand->timer_source = NULL;
  }
  if (cand->tick_source != NULL) {
    g_source_destroy (cand->tick_source);
    g_source_unref (cand->tick_source);
    cand->tick_source = NULL;
  }

  username = (uint8_t *)cand->turn->username;
  username_len = (size_t) strlen (cand->turn->username);
  password = (uint8_t *)cand->turn->password;
  password_len = (size_t) strlen (cand->turn->password);

  if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
      turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
    username = g_base64_decode ((gchar *)username, &username_len);
    password = g_base64_decode ((gchar *)password, &password_len);
  }

  buffer_len = stun_usage_turn_create_refresh (&cand->stun_agent,
      &cand->stun_message,  cand->stun_buffer, sizeof(cand->stun_buffer),
      cand->stun_resp_msg.buffer == NULL ? NULL : &cand->stun_resp_msg, 0,
      username, username_len,
      password, password_len,
      agent_to_turn_compatibility (agent));

  if (buffer_len > 0) {
    StunTransactionId id;

    /* forget the transaction since we don't care about the result and
     * we don't implement retransmissions/timeout */
    stun_message_id (&cand->stun_message, id);
    stun_agent_forget_transaction (&cand->stun_agent, id);

    /* send the refresh twice since we won't do retransmissions */
    nice_socket_send (cand->nicesock, &cand->server,
        buffer_len, (gchar *)cand->stun_buffer);
    if (!nice_socket_is_reliable (cand->nicesock)) {
      nice_socket_send (cand->nicesock, &cand->server,
          buffer_len, (gchar *)cand->stun_buffer);
    }

  }

  if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
      turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
    g_free (username);
    g_free (password);
  }

  g_slice_free (CandidateRefresh, cand);
}

/*
 * Frees all discovery related resources for the agent.
 */
void refresh_free (NiceAgent *agent)
{
  g_slist_foreach (agent->refresh_list, refresh_free_item, NULL);
  g_slist_free (agent->refresh_list);
  agent->refresh_list = NULL;
}

/*
 * Prunes the list of discovery processes for items related
 * to stream 'stream_id'. 
 *
 * @return TRUE on success, FALSE on a fatal error
 */
void refresh_prune_stream (NiceAgent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->refresh_list; i ;) {
    CandidateRefresh *cand = i->data;
    GSList *next = i->next;

    if (cand->stream->id == stream_id) {
      agent->refresh_list = g_slist_remove (agent->refresh_list, cand);
      refresh_free_item (cand, NULL);
    }

    i = next;
  }

}

void refresh_cancel (CandidateRefresh *refresh)
{
  refresh->agent->refresh_list = g_slist_remove (refresh->agent->refresh_list,
      refresh);
  refresh_free_item (refresh, NULL);
}

/*
 * Adds a new local candidate. Implements the candidate pruning
 * defined in ICE spec section 4.1.3 "Eliminating Redundant
 * Candidates" (ID-19).
 */
static gboolean priv_add_local_candidate_pruned (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *candidate)
{
  GSList *i;

  for (i = component->local_candidates; i ; i = i->next) {
    NiceCandidate *c = i->data;

    if (nice_address_equal (&c->base_addr, &candidate->base_addr) &&
	nice_address_equal (&c->addr, &candidate->addr)) {
      nice_debug ("Candidate %p (component-id %u) redundant, ignoring.", candidate, component->id);
      return FALSE;
    }
  }

  component->local_candidates = g_slist_append (component->local_candidates,
      candidate);
  conn_check_add_for_local_candidate(agent, stream_id, component, candidate);

  return TRUE;
}

static guint priv_highest_remote_foundation (Component *component)
{
  GSList *i;
  guint highest = 1;
  gchar foundation[NICE_CANDIDATE_MAX_FOUNDATION];

  for (highest = 1;; highest++) {
    gboolean taken = FALSE;

    g_snprintf (foundation, NICE_CANDIDATE_MAX_FOUNDATION, "%u", highest);
    for (i = component->remote_candidates; i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (strncmp (foundation, cand->foundation,
              NICE_CANDIDATE_MAX_FOUNDATION) == 0) {
        taken = TRUE;
        break;
      }
    }
    if (!taken)
      return highest;
  }

  g_return_val_if_reached (highest);
}

/*
 * Assings a foundation to the candidate.
 *
 * Implements the mechanism described in ICE sect
 * 4.1.1.3 "Computing Foundations" (ID-19).
 */
static void priv_assign_foundation (NiceAgent *agent, NiceCandidate *candidate)
{
  GSList *i, *j, *k;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *component = j->data;
      for (k = component->local_candidates; k; k = k->next) {
	NiceCandidate *n = k->data;
	NiceAddress temp = n->base_addr;

	/* note: candidate must not on the local candidate list */
	g_assert (candidate != n);

	/* note: ports are not to be compared */
	nice_address_set_port (&temp,
               nice_address_get_port (&candidate->base_addr));

	if (candidate->type == n->type &&
            candidate->transport == n->transport &&
            candidate->stream_id == n->stream_id &&
	    nice_address_equal (&candidate->base_addr, &temp) &&
            !(agent->compatibility == NICE_COMPATIBILITY_GOOGLE &&
                n->type == NICE_CANDIDATE_TYPE_RELAYED)) {
	  /* note: currently only one STUN/TURN server per stream at a
	   *       time is supported, so there is no need to check
	   *       for candidates that would otherwise share the
	   *       foundation, but have different STUN/TURN servers */
	  g_strlcpy (candidate->foundation, n->foundation,
              NICE_CANDIDATE_MAX_FOUNDATION);
          if (n->username) {
            g_free (candidate->username);
            candidate->username = g_strdup (n->username);
          }
          if (n->password) {
            g_free (candidate->password);
            candidate->password = g_strdup (n->password);
          }
	  return;
	}
      }
    }
  }

  g_snprintf (candidate->foundation, NICE_CANDIDATE_MAX_FOUNDATION,
      "%u", agent->next_candidate_id++);
}

static void priv_assign_remote_foundation (NiceAgent *agent, NiceCandidate *candidate)
{
  GSList *i, *j, *k;
  guint next_remote_id;
  Component *component = NULL;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *c = j->data;

      if (c->id == candidate->component_id)
        component = c;

      for (k = c->remote_candidates; k; k = k->next) {
	NiceCandidate *n = k->data;
	NiceAddress temp = n->addr;

	/* note: candidate must not on the remote candidate list */
	g_assert (candidate != n);

	/* note: ports are not to be compared */
	nice_address_set_port (&temp,
               nice_address_get_port (&candidate->base_addr));

	if (candidate->type == n->type &&
            candidate->stream_id == n->stream_id &&
	    nice_address_equal (&candidate->addr, &temp)) {
	  /* note: currently only one STUN/TURN server per stream at a
	   *       time is supported, so there is no need to check
	   *       for candidates that would otherwise share the
	   *       foundation, but have different STUN/TURN servers */
	  g_strlcpy (candidate->foundation, n->foundation,
              NICE_CANDIDATE_MAX_FOUNDATION);
          if (n->username) {
            g_free (candidate->username);
            candidate->username = g_strdup (n->username);
          }
          if (n->password) {
            g_free (candidate->password);
            candidate->password = g_strdup (n->password);
          }
	  return;
	}
      }
    }
  }

  if (component) {
    next_remote_id = priv_highest_remote_foundation (component);
    g_snprintf (candidate->foundation, NICE_CANDIDATE_MAX_FOUNDATION,
        "%u", next_remote_id);
  }
}


static
void priv_generate_candidate_credentials (NiceAgent *agent,
    NiceCandidate *candidate)
{

  if (agent->compatibility == NICE_COMPATIBILITY_MSN ||
      agent->compatibility == NICE_COMPATIBILITY_OC2007) {
    guchar username[32];
    guchar password[16];

    g_free (candidate->username);
    g_free (candidate->password);

    nice_rng_generate_bytes (agent->rng, 32, (gchar *)username);
    nice_rng_generate_bytes (agent->rng, 16, (gchar *)password);

    candidate->username = g_base64_encode (username, 32);
    candidate->password = g_base64_encode (password, 16);

  } else if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    gchar username[16];

    g_free (candidate->username);
    g_free (candidate->password);
    candidate->password = NULL;

    nice_rng_generate_bytes_print (agent->rng, 16, (gchar *)username);

    candidate->username = g_strndup (username, 16);
  }


}

/*
 * Creates a local host candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate *discovery_add_local_host_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  NiceSocket *udp_socket = NULL;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = *address;
  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = nice_candidate_jingle_priority (candidate);
  } else if (agent->compatibility == NICE_COMPATIBILITY_MSN ||
             agent->compatibility == NICE_COMPATIBILITY_OC2007)  {
    candidate->priority = nice_candidate_msn_priority (candidate);
  } else {
    candidate->priority = nice_candidate_ice_priority (candidate);
  }

  priv_generate_candidate_credentials (agent, candidate);
  priv_assign_foundation (agent, candidate);

  /* note: candidate username and password are left NULL as stream
     level ufrag/password are used */
  udp_socket = nice_udp_bsd_socket_new (address);
  if (!udp_socket)
    goto errors;


  _priv_set_socket_tos (agent, udp_socket, stream->tos);
  agent_attach_stream_component_socket (agent, stream,
      component, udp_socket);

  candidate->sockptr = udp_socket;
  candidate->addr = udp_socket->addr;
  candidate->base_addr = udp_socket->addr;

  if (!priv_add_local_candidate_pruned (agent, stream_id, component, candidate))
    goto errors;

  component->sockets = g_slist_append (component->sockets, udp_socket);

  return candidate;

errors:
  nice_candidate_free (candidate);
  if (udp_socket)
    nice_socket_free (udp_socket);
  return NULL;
}

/*
 * Creates a server reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate*
discovery_add_server_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  gboolean result = FALSE;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);

  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = nice_candidate_jingle_priority (candidate);
  } else if (agent->compatibility == NICE_COMPATIBILITY_MSN ||
             agent->compatibility == NICE_COMPATIBILITY_OC2007)  {
    candidate->priority = nice_candidate_msn_priority (candidate);
  } else {
    candidate->priority =  nice_candidate_ice_priority_full
        (NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE, 0, component_id);
  }
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;

  /* step: link to the base candidate+socket */
  candidate->sockptr = base_socket;
  candidate->base_addr = base_socket->addr;

  priv_generate_candidate_credentials (agent, candidate);
  priv_assign_foundation (agent, candidate);

  result = priv_add_local_candidate_pruned (agent, stream_id, component, candidate);
  if (result) {
    agent_signal_new_candidate (agent, candidate);
  }
  else {
    /* error: duplicate candidate */
    nice_candidate_free (candidate), candidate = NULL;
  }

  return candidate;
}


/*
 * Creates a server reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate* 
discovery_add_relay_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  TurnServer *turn)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  NiceSocket *relay_socket = NULL;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_RELAYED);

  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = nice_candidate_jingle_priority (candidate);
  } else if (agent->compatibility == NICE_COMPATIBILITY_MSN ||
             agent->compatibility == NICE_COMPATIBILITY_OC2007)  {
    candidate->priority = nice_candidate_msn_priority (candidate);
  } else {
    candidate->priority =  nice_candidate_ice_priority_full
        (NICE_CANDIDATE_TYPE_PREF_RELAYED, 0, component_id);
  }
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->turn = turn;

  /* step: link to the base candidate+socket */
  relay_socket = nice_turn_socket_new (agent->main_context, address,
      base_socket, &turn->server,
      turn->username, turn->password,
      agent_to_turn_socket_compatibility (agent));
  if (!relay_socket)
    goto errors;

  candidate->sockptr = relay_socket;
  candidate->base_addr = base_socket->addr;

  priv_generate_candidate_credentials (agent, candidate);

  /* Google uses the turn username as the candidate username */
  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    g_free (candidate->username);
    candidate->username = g_strdup (turn->username);
  }

  priv_assign_foundation (agent, candidate);

  if (!priv_add_local_candidate_pruned (agent, stream_id, component, candidate))
    goto errors;

  component->sockets = g_slist_append (component->sockets, relay_socket);
  agent_signal_new_candidate (agent, candidate);

  return candidate;

errors:
  nice_candidate_free (candidate);
  if (relay_socket)
    nice_socket_free (relay_socket);
  return NULL;
}

/*
 * Creates a peer reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate*
discovery_add_peer_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  NiceCandidate *local,
  NiceCandidate *remote)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  gboolean result;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

  candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = nice_candidate_jingle_priority (candidate);
  } else if (agent->compatibility == NICE_COMPATIBILITY_MSN ||
             agent->compatibility == NICE_COMPATIBILITY_OC2007)  {
    candidate->priority = nice_candidate_msn_priority (candidate);
  } else {
    candidate->priority = nice_candidate_ice_priority_full
        (NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE, 0, component_id);
  }
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = base_socket->addr;


  priv_assign_foundation (agent, candidate);

  if ((agent->compatibility == NICE_COMPATIBILITY_MSN ||
       agent->compatibility == NICE_COMPATIBILITY_OC2007) &&
      remote && local) {
    guchar *new_username = NULL;
    guchar *decoded_local = NULL;
    guchar *decoded_remote = NULL;
    gsize local_size;
    gsize remote_size;
    g_free(candidate->username);
    g_free(candidate->password);

    decoded_local = g_base64_decode (local->username, &local_size);
    decoded_remote = g_base64_decode (remote->username, &remote_size);

    new_username = g_new0(guchar, local_size + remote_size);
    memcpy(new_username, decoded_local, local_size);
    memcpy(new_username + local_size, decoded_remote, remote_size);

    candidate->username = g_base64_encode (new_username, local_size + remote_size);
    g_free(new_username);
    g_free(decoded_local);
    g_free(decoded_remote);

    candidate->password = g_strdup(local->password);
  } else if (local) {
    g_free(candidate->username);
    g_free(candidate->password);

    candidate->username = g_strdup(local->username);
    candidate->password = g_strdup(local->password);
  }

  /* step: link to the base candidate+socket */
  candidate->sockptr = base_socket;
  candidate->base_addr = base_socket->addr;

  result = priv_add_local_candidate_pruned (agent, stream_id, component, candidate);
  if (result != TRUE) {
    /* error: memory allocation, or duplicate candidate */
    nice_candidate_free (candidate), candidate = NULL;
  }

  return candidate;
}


/*
 * Adds a new peer reflexive candidate to the list of known
 * remote candidates. The candidate is however not paired with
 * existing local candidates.
 *
 * See ICE sect 7.2.1.3 "Learning Peer Reflexive Candidates" (ID-19).
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate *discovery_learn_remote_peer_reflexive_candidate (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  guint32 priority,
  const NiceAddress *remote_address,
  NiceSocket *udp_socket,
  NiceCandidate *local,
  NiceCandidate *remote)
{
  NiceCandidate *candidate;

  /* XXX: for use compiler */
  (void)udp_socket;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

  candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
  candidate->addr = *remote_address;
  candidate->base_addr = *remote_address;

  /* if the check didn't contain the PRIORITY attribute, then the priority will
   * be 0, which is invalid... */
  if (priority != 0) {
    candidate->priority = priority;
  } else if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = nice_candidate_jingle_priority (candidate);
  } else if (agent->compatibility == NICE_COMPATIBILITY_MSN ||
             agent->compatibility == NICE_COMPATIBILITY_OC2007)  {
    candidate->priority = nice_candidate_msn_priority (candidate);
  } else {
    candidate->priority = nice_candidate_ice_priority_full
        (NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE, 0, component->id);
  }
  candidate->stream_id = stream->id;
  candidate->component_id = component->id;


  priv_assign_remote_foundation (agent, candidate);

  if ((agent->compatibility == NICE_COMPATIBILITY_MSN ||
       agent->compatibility == NICE_COMPATIBILITY_OC2007) &&
      remote && local) {
    guchar *new_username = NULL;
    guchar *decoded_local = NULL;
    guchar *decoded_remote = NULL;
    gsize local_size;
    gsize remote_size;
    g_free(candidate->username);
    g_free (candidate->password);

    decoded_local = g_base64_decode (local->username, &local_size);
    decoded_remote = g_base64_decode (remote->username, &remote_size);

    new_username = g_new0(guchar, local_size + remote_size);
    memcpy(new_username, decoded_remote, remote_size);
    memcpy(new_username + remote_size, decoded_local, local_size);

    candidate->username = g_base64_encode (new_username, local_size + remote_size);
    g_free(new_username);
    g_free(decoded_local);
    g_free(decoded_remote);

    candidate->password = g_strdup(remote->password);
  } else if (remote) {
    g_free (candidate->username);
    g_free (candidate->password);
    candidate->username = g_strdup(remote->username);
    candidate->password = g_strdup(remote->password);
  }

  candidate->sockptr = NULL; /* not stored for remote candidates */
  /* note: candidate username and password are left NULL as stream 
     level ufrag/password are used */

  component->remote_candidates = g_slist_append (component->remote_candidates,
      candidate);

  agent_signal_new_remote_candidate (agent, candidate);

  return candidate;
}

/* 
 * Timer callback that handles scheduling new candidate discovery
 * processes (paced by the Ta timer), and handles running of the 
 * existing discovery processes.
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_discovery_tick_unlocked (gpointer pointer)
{
  CandidateDiscovery *cand;
  NiceAgent *agent = pointer;
  GSList *i;
  int not_done = 0; /* note: track whether to continue timer */
  size_t buffer_len = 0;

  {
    static int tick_counter = 0;
    if (tick_counter++ % 50 == 0)
      nice_debug ("Agent %p : discovery tick #%d with list %p (1)", agent, tick_counter, agent->discovery_list);
  }

  for (i = agent->discovery_list; i ; i = i->next) {
    cand = i->data;

    if (cand->pending != TRUE) {
      cand->pending = TRUE;

      if (agent->discovery_unsched_items)
	--agent->discovery_unsched_items;

      {
        gchar tmpbuf[INET6_ADDRSTRLEN];
        nice_address_to_string (&cand->server, tmpbuf);
        nice_debug ("Agent %p : discovery - scheduling cand type %u addr %s.\n",
            agent, cand->type, tmpbuf);
      }
      if (nice_address_is_valid (&cand->server) &&
          (cand->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
              cand->type == NICE_CANDIDATE_TYPE_RELAYED)) {

	agent_signal_component_state_change (agent,
					     cand->stream->id,
					     cand->component->id,
					     NICE_COMPONENT_STATE_GATHERING);

        if (cand->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
          buffer_len = stun_usage_bind_create (&cand->stun_agent,
              &cand->stun_message, cand->stun_buffer, sizeof(cand->stun_buffer));
        } else if (cand->type == NICE_CANDIDATE_TYPE_RELAYED) {
          uint8_t *username = (uint8_t *)cand->turn->username;
          size_t username_len = (size_t) strlen (cand->turn->username);
          uint8_t *password = (uint8_t *)cand->turn->password;
          size_t password_len = (size_t) strlen (cand->turn->password);
          StunUsageTurnCompatibility turn_compat =
              agent_to_turn_compatibility (agent);

          if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
              turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
            username = g_base64_decode ((gchar *)username, &username_len);
            password = g_base64_decode ((gchar *)password, &password_len);
          }

          buffer_len = stun_usage_turn_create (&cand->stun_agent,
              &cand->stun_message,  cand->stun_buffer, sizeof(cand->stun_buffer),
              cand->stun_resp_msg.buffer == NULL ? NULL : &cand->stun_resp_msg,
              STUN_USAGE_TURN_REQUEST_PORT_NORMAL,
              -1, -1,
              username, username_len,
              password, password_len,
              turn_compat);

          if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
              turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
            g_free (cand->msn_turn_username);
            g_free (cand->msn_turn_password);
            cand->msn_turn_username = username;
            cand->msn_turn_password = password;
          }
        }

	if (buffer_len > 0) {
          if (nice_socket_is_reliable (cand->nicesock)) {
            stun_timer_start_reliable (&cand->timer,
                STUN_TIMER_DEFAULT_RELIABLE_TIMEOUT);
          } else {
            stun_timer_start (&cand->timer, 200,
                STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
          }

          /* send the conncheck */
          nice_socket_send (cand->nicesock, &cand->server,
              buffer_len, (gchar *)cand->stun_buffer);

	  /* case: success, start waiting for the result */
	  g_get_current_time (&cand->next_tick);

	} else {
	  /* case: error in starting discovery, start the next discovery */
	  cand->done = TRUE;
	  cand->stun_message.buffer = NULL;
	  cand->stun_message.buffer_len = 0;
	  continue;
	}
      }
      else
	/* allocate relayed candidates */
	g_assert_not_reached ();

      ++not_done; /* note: new discovery scheduled */
    }

    if (cand->done != TRUE) {
      GTimeVal now;

      g_get_current_time (&now);

      if (cand->stun_message.buffer == NULL) {
	nice_debug ("Agent %p : STUN discovery was cancelled, marking discovery done.", agent);
	cand->done = TRUE;
      }
      else if (priv_timer_expired (&cand->next_tick, &now)) {
        switch (stun_timer_refresh (&cand->timer)) {
          case STUN_USAGE_TIMER_RETURN_TIMEOUT:
            {
              /* Time out */
              /* case: error, abort processing */
              StunTransactionId id;

              stun_message_id (&cand->stun_message, id);
              stun_agent_forget_transaction (&cand->stun_agent, id);

              cand->done = TRUE;
              cand->stun_message.buffer = NULL;
              cand->stun_message.buffer_len = 0;
              nice_debug ("Agent %p : bind discovery timed out, aborting discovery item.", agent);
              break;
            }
          case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
            {
              /* case: not ready complete, so schedule next timeout */
              unsigned int timeout = stun_timer_remainder (&cand->timer);

              stun_debug ("STUN transaction retransmitted (timeout %dms).\n",
                  timeout);

              /* retransmit */
              nice_socket_send (cand->nicesock, &cand->server,
                  stun_message_length (&cand->stun_message),
                  (gchar *)cand->stun_buffer);

              /* note: convert from milli to microseconds for g_time_val_add() */
              cand->next_tick = now;
              g_time_val_add (&cand->next_tick, timeout * 1000);

              ++not_done; /* note: retry later */
              break;
            }
          case STUN_USAGE_TIMER_RETURN_SUCCESS:
            {
              unsigned int timeout = stun_timer_remainder (&cand->timer);

              cand->next_tick = now;
              g_time_val_add (&cand->next_tick, timeout * 1000);

              ++not_done; /* note: retry later */
              break;
            }
	}

      } else {
	++not_done; /* note: discovery not expired yet */
      }
    }
  }

  if (not_done == 0) {
    nice_debug ("Agent %p : Candidate gathering FINISHED, stopping discovery timer.", agent);

    discovery_free (agent);

    agent_gathering_done (agent);

    /* note: no pending timers, return FALSE to stop timer */
    return FALSE;
  }

  return TRUE;
}

static gboolean priv_discovery_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  gboolean ret;

  agent_lock();
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in priv_discovery_tick");
    agent_unlock ();
    return FALSE;
  }

  ret = priv_discovery_tick_unlocked (pointer);
  if (ret == FALSE) {
    if (agent->discovery_timer_source != NULL) {
      g_source_destroy (agent->discovery_timer_source);
      g_source_unref (agent->discovery_timer_source);
      agent->discovery_timer_source = NULL;
    }
  }
  agent_unlock();

  return ret;
}

/*
 * Initiates the candidate discovery process by starting
 * the necessary timers.
 *
 * @pre agent->discovery_list != NULL  // unsched discovery items available
 */
void discovery_schedule (NiceAgent *agent)
{
  g_assert (agent->discovery_list != NULL);

  if (agent->discovery_unsched_items > 0) {
    
    if (agent->discovery_timer_source == NULL) {
      /* step: run first iteration immediately */
      gboolean res = priv_discovery_tick_unlocked (agent);
      if (res == TRUE) {
        agent->discovery_timer_source = agent_timeout_add_with_context (agent, agent->timer_ta, priv_discovery_tick, agent);
      }
    }
  }
}
