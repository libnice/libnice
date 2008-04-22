/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
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

#ifndef _CANDIDATE_H
#define _CANDIDATE_H

#include "udp.h"

G_BEGIN_DECLS

#define NICE_CANDIDATE_TYPE_PREF_HOST                 120
#define NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE       110
#define NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE     100
#define NICE_CANDIDATE_TYPE_PREF_RELAYED               60

/* Max foundation size '1*32ice-char' plus terminating NULL, ICE ID-19  */
#define NICE_CANDIDATE_MAX_FOUNDATION                32+1 

typedef enum
{
  NICE_CANDIDATE_TYPE_HOST,
  NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
  NICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
  NICE_CANDIDATE_TYPE_RELAYED,
} NiceCandidateType;

typedef enum
{
  NICE_CANDIDATE_TRANSPORT_UDP,
} NiceCandidateTransport;

typedef struct _NiceCandidate NiceCandidate;

struct _NiceCandidate
{
  NiceCandidateType type;
  NiceCandidateTransport transport;
  NiceAddress addr;
  NiceAddress base_addr;
  guint32 priority;
  guint stream_id;
  guint component_id;
  gchar foundation[NICE_CANDIDATE_MAX_FOUNDATION];
  NiceUDPSocket *sockptr;
  gchar *username;        /* pointer to a NULL-terminated username string */
  gchar *password;        /* pointer to a NULL-terminated password string */
};


NiceCandidate *
nice_candidate_new (NiceCandidateType type);

void
nice_candidate_free (NiceCandidate *candidate);

gfloat
nice_candidate_jingle_priority (NiceCandidate *candidate);

gfloat
nice_candidate_msn_priority (NiceCandidate *candidate);

guint32
nice_candidate_ice_priority_full (guint type_pref, guint local_pref, guint component_id);

guint32
nice_candidate_ice_priority (const NiceCandidate *candidate);

guint64
nice_candidate_pair_priority (guint32 o_prio, guint32 a_prio);

G_END_DECLS

#endif /* _CANDIDATE_H */

