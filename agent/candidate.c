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
 * @file candidate.c
 * @brief ICE candidate functions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#else
#define NICEAPI_EXPORT
#endif

#include <string.h>

#include "agent.h"
#include "component.h"

G_DEFINE_BOXED_TYPE (NiceCandidate, nice_candidate, nice_candidate_copy,
    nice_candidate_free);

/* (ICE 4.1.1 "Gathering Candidates") ""Every candidate is a transport
 * address. It also has a type and a base. Three types are defined and 
 * gathered by this specification - host candidates, server reflexive 
 * candidates, and relayed candidates."" (ID-19) */

NICEAPI_EXPORT NiceCandidate *
nice_candidate_new (NiceCandidateType type)
{
  NiceCandidate *candidate;

  candidate = g_slice_new0 (NiceCandidate);
  candidate->type = type;
  return candidate;
}


NICEAPI_EXPORT void
nice_candidate_free (NiceCandidate *candidate)
{
  /* better way of checking if socket is allocated? */

  if (candidate->username)
    g_free (candidate->username);

  if (candidate->password)
    g_free (candidate->password);

  if (candidate->turn)
    turn_server_unref (candidate->turn);

  g_slice_free (NiceCandidate, candidate);
}


guint32
nice_candidate_jingle_priority (NiceCandidate *candidate)
{
  switch (candidate->type)
    {
    case NICE_CANDIDATE_TYPE_HOST:             return 1000;
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return 900;
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:   return 900;
    case NICE_CANDIDATE_TYPE_RELAYED:          return 500;
    default:                                   return 0;
    }
}

guint32
nice_candidate_msn_priority (NiceCandidate *candidate)
{
  switch (candidate->type)
    {
    case NICE_CANDIDATE_TYPE_HOST:             return 830;
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return 550;
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:   return 550;
    case NICE_CANDIDATE_TYPE_RELAYED:          return 450;
    default:                                   return 0;
    }
}


/*
 * ICE 4.1.2.1. "Recommended Formula" (ID-19):
 * returns number between 1 and 0x7effffff 
 */
guint32
nice_candidate_ice_priority_full (
  // must be ∈ (0, 126) (max 2^7 - 2)
  guint type_preference,
  // must be ∈ (0, 65535) (max 2^16 - 1)
  guint local_preference,
  // must be ∈ (0, 255) (max 2 ^ 8 - 1)
  guint component_id)
{
  return (
      0x1000000 * type_preference +
      0x100 * local_preference +
      (0x100 - component_id));
}

static guint32
nice_candidate_ice_local_preference_full (guint direction_preference,
    guint other_preference)
{
  return (0x2000 * direction_preference +
      other_preference);
}

static guint16
nice_candidate_ice_local_preference (const NiceCandidate *candidate)
{
  guint direction_preference;

  switch (candidate->transport)
    {
      case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
        if (candidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
            candidate->type == NICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED)
          direction_preference = 4;
        else
          direction_preference = 6;
        break;
      case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
        if (candidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
            candidate->type == NICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED)
          direction_preference = 2;
        else
          direction_preference = 4;
        break;
      case NICE_CANDIDATE_TRANSPORT_TCP_SO:
        if (candidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
            candidate->type == NICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED)
          direction_preference = 6;
        else
          direction_preference = 2;
        break;
      case NICE_CANDIDATE_TRANSPORT_UDP:
      default:
        return 1;
        break;
    }

  return nice_candidate_ice_local_preference_full (direction_preference, 1);
}

static guint32
nice_candidate_ms_ice_local_preference_full (guint transport_preference,
    guint direction_preference, guint other_preference)
{
  return 0x1000 * transport_preference +
      0x200 * direction_preference +
      0x1 * other_preference;
}

static guint32
nice_candidate_ms_ice_local_preference (const NiceCandidate *candidate)
{
  guint8 transport_preference = 0;
  guint8 direction_preference = 0;

  switch (candidate->transport)
    {
    case NICE_CANDIDATE_TRANSPORT_TCP_SO:
    case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
      transport_preference = NICE_CANDIDATE_TRANSPORT_MS_PREF_TCP;
      direction_preference = NICE_CANDIDATE_DIRECTION_MS_PREF_ACTIVE;
      break;
    case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
      transport_preference = NICE_CANDIDATE_TRANSPORT_MS_PREF_TCP;
      direction_preference = NICE_CANDIDATE_DIRECTION_MS_PREF_PASSIVE;
      break;
    case NICE_CANDIDATE_TRANSPORT_UDP:
    default:
      transport_preference = NICE_CANDIDATE_TRANSPORT_MS_PREF_UDP;
      break;
    }

  return nice_candidate_ms_ice_local_preference_full(transport_preference,
      direction_preference, 0);
}

static guint8
nice_candidate_ice_type_preference (const NiceCandidate *candidate,
    gboolean reliable, gboolean nat_assisted)
{
  guint8 type_preference;

  switch (candidate->type)
    {
    case NICE_CANDIDATE_TYPE_HOST:
      type_preference = NICE_CANDIDATE_TYPE_PREF_HOST;
      break;
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
      type_preference = NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE;
      break;
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
      if (nat_assisted)
        type_preference = NICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED;
      else
        type_preference = NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE;
      break;
    case NICE_CANDIDATE_TYPE_RELAYED:
      type_preference = NICE_CANDIDATE_TYPE_PREF_RELAYED;
      break;
    default:
      type_preference = 0;
      break;
    }

  if ((reliable && candidate->transport == NICE_CANDIDATE_TRANSPORT_UDP) ||
      (!reliable && candidate->transport != NICE_CANDIDATE_TRANSPORT_UDP)) {
    type_preference = type_preference / 2;
  }

  return type_preference;
}

guint32
nice_candidate_ice_priority (const NiceCandidate *candidate,
    gboolean reliable, gboolean nat_assisted)
{
  guint8 type_preference;
  guint16 local_preference;

  type_preference = nice_candidate_ice_type_preference (candidate, reliable,
      nat_assisted);
  local_preference = nice_candidate_ice_local_preference (candidate);

  return nice_candidate_ice_priority_full (type_preference, local_preference,
      candidate->component_id);
}

guint32
nice_candidate_ms_ice_priority (const NiceCandidate *candidate,
    gboolean reliable, gboolean nat_assisted)
{
  guint8 type_preference;
  guint16 local_preference;

  type_preference = nice_candidate_ice_type_preference (candidate, reliable,
      nat_assisted);
  local_preference = nice_candidate_ms_ice_local_preference (candidate);

  return nice_candidate_ice_priority_full (type_preference, local_preference,
      candidate->component_id);
}

/*
 * Calculates the pair priority as specified in ICE
 * sect 5.7.2. "Computing Pair Priority and Ordering Pairs" (ID-19).
 */
guint64
nice_candidate_pair_priority (guint32 o_prio, guint32 a_prio)
{
  guint32 max = o_prio > a_prio ? o_prio : a_prio;
  guint32 min = o_prio < a_prio ? o_prio : a_prio;
  /* These two constants are here explictly to make some version of GCC happy */
  const guint64 one = 1;
  const guint64 thirtytwo = 32;

  return (one << thirtytwo) * min + 2 * max + (o_prio > a_prio ? 1 : 0);
}

/*
 * Copies a candidate
 */
NICEAPI_EXPORT NiceCandidate *
nice_candidate_copy (const NiceCandidate *candidate)
{
  NiceCandidate *copy;

  g_return_val_if_fail (candidate != NULL, NULL);

  copy = nice_candidate_new (candidate->type);
  memcpy (copy, candidate, sizeof(NiceCandidate));

  copy->turn = NULL;
  copy->username = g_strdup (copy->username);
  copy->password = g_strdup (copy->password);

  return copy;
}
