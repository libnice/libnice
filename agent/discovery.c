/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
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

/**
 * @file discovery.c
 * @brief ICE candidate discovery functions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include "agent.h"
#include "agent-priv.h"
#include "agent-signals-marshal.h"
#include "component.h"
#include "discovery.h"

static inline int priv_timer_expired (GTimeVal *restrict timer, GTimeVal *restrict now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

/**
 * Frees the CandidateDiscovery structure pointed to 
 * by 'user data'. Compatible with g_slist_foreach().
 */
void discovery_free_item (gpointer data, gpointer user_data)
{
  CandidateDiscovery *cand = data;
  g_assert (user_data == NULL);
  cand->server_addr = NULL;
  g_slice_free (CandidateDiscovery, cand);
}

/**
 * Frees all discovery related resources for the agent.
 */
void discovery_free (NiceAgent *agent)
{
  if (agent->discovery_list) {
    GSList *tmp = agent->discovery_list;
    agent->discovery_list = NULL;

    g_slist_foreach (tmp, discovery_free_item, NULL);
    g_slist_free (tmp);

    agent->discovery_unsched_items = 0;
  }
  if (agent->discovery_timer_id)
    g_source_remove (agent->discovery_timer_id),
      agent->discovery_timer_id = 0;
}

/**
 * Prunes the list of discovery processes for items related
 * to stream 'stream_id'. 
 *
 * @return TRUE on success, FALSE on a fatal error
 */
gboolean discovery_prune_stream (NiceAgent *agent, guint stream_id)
{
  CandidateDiscovery *cand;
  GSList *i;

  for (i = agent->discovery_list; i ; ) {
    cand = i->data;

    if (cand->stream->id == stream_id) {
      GSList *next = i->next;
      agent->discovery_list = 
	g_slist_remove (agent->discovery_list, cand);
      discovery_free_item (cand, NULL);
      i = next;
      if (!agent->discovery_list)
	break;
    }
    else
      i = i->next;
  }

  if (agent->discovery_list == NULL) {
    /* return FALSE if there was a memory allocation failure */
    if (i != NULL)
      return FALSE;
    /* noone using the timer anymore, clean it up */
    discovery_free (agent);
  }

  return TRUE;
}

/**
 * Adds a new local candidate. Implements the candidate pruning
 * defined in ICE spec section 4.1.3 "Eliminating Redundant
 * Candidates" (ID-19).
 */
static gboolean priv_add_local_candidate_pruned (Component *component, NiceCandidate *candidate)
{
  GSList *modified_list, *i;

  for (i = component->local_candidates; i ; i = i->next) {
    NiceCandidate *c = i->data;
    
    if (nice_address_equal (&c->base_addr, &candidate->base_addr) &&
	nice_address_equal (&c->addr, &candidate->addr)) {
      g_debug ("Candidate %p (component-id %u) redundant, ignoring.", candidate, component->id);
      return FALSE;
    }
  }

  modified_list= g_slist_append (component->local_candidates,
				 candidate);
  if (modified_list) {
    component->local_candidates = modified_list;
  }

  return TRUE;
}

/**
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
	    nice_address_equal (&candidate->base_addr, &temp)) {
	  /* note: currently only one STUN/TURN server per stream at a
	   *       time is supported, so there is no need to check
	   *       for candidates that would otherwise share the
	   *       foundation, but have different STUN/TURN servers */
	  memcpy (candidate->foundation, n->foundation, NICE_CANDIDATE_MAX_FOUNDATION);
	  return;
	}
      }
    }
  }
      
  g_snprintf (candidate->foundation, NICE_CANDIDATE_MAX_FOUNDATION, "%u", agent->next_candidate_id++);
}

static
void priv_generate_msn_credentials (NiceAgent *agent, NiceCandidate *candidate)
{

  if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
    guchar username[32];
    guchar password[16];

    if (candidate->username)
      g_free (candidate->username);
    if (candidate->password)
      g_free (candidate->password);

    nice_rng_generate_bytes (agent->rng, 32, (gchar *)username);
    nice_rng_generate_bytes (agent->rng, 16, (gchar *)password);

    candidate->username = g_base64_encode (username, 32);
    candidate->password = g_base64_encode (password, 16);

  }


}

/**
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
  NiceUDPSocket *udp_socket = NULL;
  gboolean errors = FALSE;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  if (candidate) {
    NiceUDPSocket *udp_socket = g_slice_new0 (NiceUDPSocket);
    if (udp_socket) {
      candidate->stream_id = stream_id;
      candidate->component_id = component_id;
      candidate->addr = *address;
      candidate->base_addr = *address;
      candidate->priority = nice_candidate_ice_priority (candidate);

      priv_generate_msn_credentials (agent, candidate);
      priv_assign_foundation (agent, candidate);

      /* note: candidate username and password are left NULL as stream 
	 level ufrag/password are used */
      
      if (nice_udp_socket_factory_make (agent->socket_factory,
					udp_socket, address)) {
	priv_attach_stream_component_socket (agent, stream, component,
            udp_socket);

	gboolean result = priv_add_local_candidate_pruned (component, candidate);
	if (result == TRUE) {
	  GSList *modified_list = g_slist_append (component->sockets, udp_socket);
	  if (modified_list) {
	    /* success: store a pointer to the sockaddr */
	    component->sockets = modified_list;
	    candidate->sockptr = udp_socket;
	    candidate->addr = udp_socket->addr;
	    candidate->base_addr = udp_socket->addr;
	    agent_signal_new_candidate (agent, candidate);
	  }
	  else { /* error: list memory allocation */
	    candidate = NULL; /* note: candidate already owned by component */
	  }
	}
	else /* error: memory allocation, or duplicate candidatet */
	  errors = TRUE;
      }
      else /* error: socket factory make */
	errors = TRUE;
    }
    else /* error: udp socket memory allocation */
      errors = TRUE;
  }

  /* clean up after errors */
  if (errors) {
    if (candidate)
      nice_candidate_free (candidate), candidate = NULL;
    if (udp_socket)
      g_slice_free (NiceUDPSocket, udp_socket);
  }
  
  return candidate;
}

/**
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
  NiceUDPSocket *base_socket)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  gboolean result = FALSE;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
  if (candidate) {
    candidate->priority = 
      nice_candidate_ice_priority_full 
        (NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE, 0, component_id);
    candidate->stream_id = stream_id;
    candidate->component_id = component_id;
    candidate->addr = *address;

    /* step: link to the base candidate+socket */
    candidate->sockptr = base_socket;
    candidate->base_addr = base_socket->addr;

    priv_generate_msn_credentials (agent, candidate);
    priv_assign_foundation (agent, candidate);

    result = priv_add_local_candidate_pruned (component, candidate);
    if (result) {
      agent_signal_new_candidate (agent, candidate);
    }
    else {
      /* error: memory allocation, or duplicate candidatet */
      nice_candidate_free (candidate), candidate = NULL;
    }
  }

  return candidate;
}

/**
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
  NiceUDPSocket *base_socket)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
  if (candidate) {
    gboolean result;

    candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
    candidate->priority = 
      nice_candidate_ice_priority_full 
        (NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE, 0, component_id);
    candidate->stream_id = stream_id;
    candidate->component_id = component_id;
    candidate->addr = *address;
    candidate->base_addr = base_socket->addr;

    priv_generate_msn_credentials (agent, candidate);
    priv_assign_foundation (agent, candidate);

    /* step: link to the base candidate+socket */
    candidate->sockptr = base_socket;
    candidate->base_addr = base_socket->addr;

    result = priv_add_local_candidate_pruned (component, candidate);
    if (result != TRUE) {
      /* error: memory allocation, or duplicate candidatet */
      nice_candidate_free (candidate), candidate = NULL;
    }
  }

  return candidate;
}

static guint priv_highest_remote_foundation (Component *component)
{
  GSList *i;
  guint highest = 0;

  for (i = component->remote_candidates; i; i = i->next) {
    NiceCandidate *cand = i->data;
    guint foundation_id = (guint)atoi (cand->foundation);
    if (foundation_id > highest)
      highest = foundation_id;
  }

  return highest;
}

/**
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
  NiceUDPSocket *udp_socket)
{
  NiceCandidate *candidate;

  /* XXX: for use compiler */
  (void)udp_socket;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
  if (candidate) {
    GSList *modified_list;

    guint next_remote_id = priv_highest_remote_foundation (component);

    candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;    
    candidate->addr = *remote_address;
    candidate->base_addr = *remote_address;
    candidate->priority = priority;;
    candidate->stream_id = stream->id;
    candidate->component_id = component->id;

    priv_generate_msn_credentials (agent, candidate);
    g_snprintf (candidate->foundation, NICE_CANDIDATE_MAX_FOUNDATION, "%u", next_remote_id);
    candidate->sockptr = NULL; /* not stored for remote candidates */
    /* note: candidate username and password are left NULL as stream 
             level ufrag/password are used */
      
    modified_list = g_slist_append (component->remote_candidates,
				    candidate);
    if (modified_list) {
      component->remote_candidates = modified_list;
      agent_signal_new_remote_candidate (agent, candidate);
    }
    else { /* error: memory alloc / list */
      nice_candidate_free (candidate), candidate = NULL;
    }
  }

  return candidate;
}

/** 
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
  size_t buffer_len;

#ifndef NDEBUG
  {
    static int tick_counter = 0;
    if (tick_counter++ % 50 == 0)
      g_debug ("Agent %p : discovery tick #%d with list %p (1)", agent, tick_counter, agent->discovery_list);
  }
#endif

  for (i = agent->discovery_list; i ; i = i->next) {
    cand = i->data;

    if (cand->pending != TRUE) {
      cand->pending = TRUE;

      if (agent->discovery_unsched_items)
	--agent->discovery_unsched_items;
      
      g_debug ("Agent %p : discovery - scheduling cand type %u addr %s and socket %d.\n", agent,
               cand->type, cand->server_addr, cand->socket);
      
      if (cand->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
	  cand->server_addr) {
        NiceAddress stun_server;

        /* XXX FIXME TODO: handle error here?! Kai, help me! */
        if (!nice_address_set_from_string (&stun_server, cand->server_addr))
          g_assert_not_reached();
        nice_address_set_port (&stun_server, cand->server_port);

	agent_signal_component_state_change (agent,
					     cand->stream->id,
					     cand->component->id,
					     NICE_COMPONENT_STATE_GATHERING);

        buffer_len = stun_usage_bind_create (&agent->stun_agent,
            &cand->stun_message, cand->stun_buffer, sizeof(cand->stun_buffer));


	if (buffer_len > 0) {
          stun_timer_start (&cand->timer);

          /* send the conncheck */
          nice_udp_socket_send (cand->nicesock, &stun_server,
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
	g_debug ("Agent %p : STUN discovery was cancelled, marking discovery done.", agent);
	cand->done = TRUE;
      }
      else if (priv_timer_expired (&cand->next_tick, &now)) {
        switch (stun_timer_refresh (&cand->timer)) {
          case -1:
            /* case: error, abort processing */
            cand->done = TRUE;
            cand->stun_message.buffer = NULL;
            cand->stun_message.buffer_len = 0;
            g_debug ("Agent %p : Error with stun_bind_elapse(), aborting discovery item.", agent);
            break;
          case 0:
            {
              /* case: not ready complete, so schedule next timeout */
              unsigned int timeout = stun_timer_remainder (&cand->timer);
              NiceAddress stun_server;

              if (!nice_address_set_from_string (&stun_server, cand->server_addr))
                g_assert_not_reached();
              nice_address_set_port (&stun_server, cand->server_port);

              stun_debug ("STUN transaction retransmitted (timeout %dms).\n",
                  timeout);

              /* TODO retransmit */
              nice_udp_socket_send (cand->nicesock, &stun_server,
                  stun_message_length (&cand->stun_message),
                  (gchar *)cand->stun_buffer);

              /* note: convert from milli to microseconds for g_time_val_add() */
              cand->next_tick = now;
              g_time_val_add (&cand->next_tick, timeout * 1000);

              ++not_done; /* note: retry later */
              break;
            }
	}

      }
      else
	++not_done; /* note: discovery not expired yet */
    }
  }

  if (not_done == 0) {
    g_debug ("Agent %p : Candidate gathering FINISHED, stopping discovery timer.", agent);

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

  g_static_rec_mutex_lock (&agent->mutex);
  ret = priv_discovery_tick_unlocked (pointer);
  g_static_rec_mutex_unlock (&agent->mutex);

  return ret;
}

/**
 * Initiates the candidate discovery process by starting
 * the necessary timers.
 *
 * @pre agent->discovery_list != NULL  // unsched discovery items available
 */
void discovery_schedule (NiceAgent *agent)
{
  g_assert (agent->discovery_list != NULL);

  if (agent->discovery_unsched_items > 0) {
    
    if (agent->discovery_timer_id == 0) {
      /* step: run first iteration immediately */
      gboolean res = priv_discovery_tick_unlocked (agent);
      if (res == TRUE) {
        agent->discovery_timer_id = agent_timeout_add_with_context (agent, agent->timer_ta, priv_discovery_tick, agent);
      }
    }
  }
}
