/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2020 Collabora Ltd.
 *  Contact: Youness Alaoui
 *  Contact: Olivier Crete
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

#ifndef __LIBNICE_CANDIDATE_PRIV_H__
#define __LIBNICE_CANDIDATE_PRIV_H__

#include <glib.h>
#include <glib-object.h>

#include "candidate.h"
#include "socket/socket.h"

G_BEGIN_DECLS


/* Constants for determining candidate priorities */
#define NICE_CANDIDATE_TYPE_PREF_HOST                 120
#define NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE       110
#define NICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED         105
#define NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE     100
#define NICE_CANDIDATE_TYPE_PREF_RELAYED_UDP           30
#define NICE_CANDIDATE_TYPE_PREF_RELAYED               20

/* Priority preference constants for MS-ICE compatibility */
#define NICE_CANDIDATE_TRANSPORT_MS_PREF_UDP           15
#define NICE_CANDIDATE_TRANSPORT_MS_PREF_TCP            6
#define NICE_CANDIDATE_DIRECTION_MS_PREF_PASSIVE        2
#define NICE_CANDIDATE_DIRECTION_MS_PREF_ACTIVE         5

typedef struct _NiceCandidateImpl NiceCandidateImpl;
typedef struct _TurnServer TurnServer;

/**
 * TurnServer:
 * @ref_count: Reference count for the structure.
 * @server: The #NiceAddress of the TURN server
 * @username: The TURN username
 * @password: The TURN password
 * @decoded_username: The base64 decoded TURN username
 * @decoded_password: The base64 decoded TURN password
 * @decoded_username_len: The length of @decoded_username
 * @decoded_password_len: The length of @decoded_password
 * @type: The #NiceRelayType of the server
 * @preference: A unique identifier used to compute priority
 *
 * A structure to store the TURN relay settings
 */
struct _TurnServer
{
  gint ref_count;

  NiceAddress server;
  gchar *username;
  gchar *password;
  guint8 *decoded_username;
  guint8 *decoded_password;
  gsize decoded_username_len;
  gsize decoded_password_len;
  NiceRelayType type;
  guint preference;
};


/**
 * NiceCandidateImpl:
 * @c: The #NiceCandidate
 * @turn: The #TurnServer settings if the candidate is
 * of type %NICE_CANDIDATE_TYPE_RELAYED
 * @sockptr: The underlying socket
 * @keepalive_next_tick: The timestamp for the next keepalive
 *
 * A structure to represent an ICE candidate
 */
struct _NiceCandidateImpl
{
  NiceCandidate c;
  TurnServer *turn;
  NiceSocket *sockptr;
  guint64 keepalive_next_tick; /* next tick timestamp */
};


G_END_DECLS

#endif /* __LIBNICE_CANDIDATE_H__ */