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

#ifndef __LIBNICE_CANDIDATE_H__
#define __LIBNICE_CANDIDATE_H__

#include "address.h"
#include <glib.h>
#include <glib-object.h>


/**
 * SECTION:candidate
 * @short_description: ICE candidate representation
 * @see_also: #NiceAddress
 * @stability: Stable
 *
 * A representation of an ICE candidate. Make sure you read the ICE drafts[1] to
 * understand correctly the concept of ICE candidates.
 *
 * [1] http://tools.ietf.org/wg/mmusic/draft-ietf-mmusic-ice/
 */


G_BEGIN_DECLS


/* Max foundation size '1*32ice-char' plus terminating NULL, ICE ID-19  */
/**
 * NICE_CANDIDATE_MAX_FOUNDATION:
 *
 * The maximum size a candidate foundation can have.
 */
#define NICE_CANDIDATE_MAX_FOUNDATION                (32+1)

/**
 * NICE_CANDIDATE_MAX_TURN_SERVERS
 *
 * The maximum number of turns servers.
 */
#define NICE_CANDIDATE_MAX_TURN_SERVERS              8

/**
 * NICE_CANDIDATE_MAX_LOCAL_ADDRESSES
 *
 * The maximum number of local addresses. The constraint is that the
 * maximum number of local addresses and number of turn servers must
 * fit on 9 bits, to ensure candidate priority uniqueness. See also
 * @NICE_CANDIDATE_MAX_TURN_SERVERS. We choose 6 bits for the number of
 * local addresses, and 3 bits for the number of turn servers.
 */
#define NICE_CANDIDATE_MAX_LOCAL_ADDRESSES           64

/**
 * NiceCandidateType:
 * @NICE_CANDIDATE_TYPE_HOST: A host candidate
 * @NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: A server reflexive candidate (or a NAT-assisted candidate)
 * @NICE_CANDIDATE_TYPE_PEER_REFLEXIVE: A peer reflexive candidate
 * @NICE_CANDIDATE_TYPE_RELAYED: A relay candidate
 *
 * An enum representing the type of a candidate
 */
typedef enum
{
  NICE_CANDIDATE_TYPE_HOST,
  NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
  NICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
  NICE_CANDIDATE_TYPE_RELAYED,
} NiceCandidateType;

/**
 * NiceCandidateTransport:
 * @NICE_CANDIDATE_TRANSPORT_UDP: UDP transport
 * @NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE: TCP Active transport
 * @NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE: TCP Passive transport
 * @NICE_CANDIDATE_TRANSPORT_TCP_SO: TCP Simultaneous-Open transport
 *
 * An enum representing the type of transport to use
 */
typedef enum
{
  NICE_CANDIDATE_TRANSPORT_UDP,
  NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE,
  NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE,
  NICE_CANDIDATE_TRANSPORT_TCP_SO,
} NiceCandidateTransport;

/**
 * NiceRelayType:
 * @NICE_RELAY_TYPE_TURN_UDP: A TURN relay using UDP
 * @NICE_RELAY_TYPE_TURN_TCP: A TURN relay using TCP
 * @NICE_RELAY_TYPE_TURN_TLS: A TURN relay using TLS over TCP
 *
 * An enum representing the type of relay to use
 */
typedef enum {
  NICE_RELAY_TYPE_TURN_UDP,
  NICE_RELAY_TYPE_TURN_TCP,
  NICE_RELAY_TYPE_TURN_TLS
} NiceRelayType;


typedef struct _NiceCandidate NiceCandidate;


/**
 * NiceCandidate:
 * @type: The type of candidate
 * @transport: The transport being used for the candidate
 * @addr: The #NiceAddress of the candidate
 * @base_addr: The #NiceAddress of the base address used by the candidate
 * @priority: The priority of the candidate <emphasis> see note </emphasis>
 * @stream_id: The ID of the stream to which belongs the candidate
 * @component_id: The ID of the component to which belongs the candidate
 * @foundation: The foundation of the candidate
 * @username: The candidate-specific username to use (overrides the one set
 * by nice_agent_set_local_credentials() or nice_agent_set_remote_credentials())
 * @password: The candidate-specific password to use (overrides the one set
 * by nice_agent_set_local_credentials() or nice_agent_set_remote_credentials())
 *
 * A structure to represent an ICE candidate
 <note>
   <para>
   The @priority is an integer as specified in the ICE draft 19. If you are
   using the MSN or the GOOGLE compatibility mode (which are based on ICE
   draft 6, which uses a floating point qvalue as priority), then the @priority
   value will represent the qvalue multiplied by 1000.
   </para>
 </note>
 */
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
  gchar *username;        /* pointer to a nul-terminated username string */
  gchar *password;        /* pointer to a nul-terminated password string */
};

/**
 * nice_candidate_new:
 * @type: The #NiceCandidateType of the candidate to create
 *
 * Creates a new candidate. Must be freed with nice_candidate_free()
 *
 * Returns: A new #NiceCandidate
 */
NiceCandidate *
nice_candidate_new (NiceCandidateType type);

/**
 * nice_candidate_free:
 * @candidate: The candidate to free
 *
 * Frees a #NiceCandidate
 */
void
nice_candidate_free (NiceCandidate *candidate);

/**
 * nice_candidate_copy:
 * @candidate: The candidate to copy
 *
 * Makes a copy of a #NiceCandidate
 *
 * Returns: A new #NiceCandidate, a copy of @candidate
 */
NiceCandidate *
nice_candidate_copy (const NiceCandidate *candidate);

/**
 * nice_candidate_equal_target:
 * @candidate1: A candidate
 * @candidate2: A candidate
 *
 * Verifies that the candidates point to the same place, meaning they have
 * the same transport and the same address. It ignores all other aspects.
 *
 * Returns: %TRUE if the candidates point to the same place
 *
 * Since: 0.1.15
 */
gboolean
nice_candidate_equal_target (const NiceCandidate *candidate1,
    const NiceCandidate *candidate2);

  GType nice_candidate_get_type (void);

/**
 * nice_candidate_type_to_string:
 * @type: a #NiceCandidateType
 *
 * Useful for debugging functions, just returns a static string with the
 * candidate type.
 *
 * Returns: a static string with the candidate type
 *
 * Since: 0.1.19
 */
const gchar *
nice_candidate_type_to_string (NiceCandidateType type);

/**
 * nice_candidate_transport_to_string:
 * @transport: a #NiceCandidateTransport
 *
 * Useful for debugging functions, just returns a static string with the
 * candidate transport.
 *
 * Returns: a static string with the candidate transport
 *
 * Since: 0.1.19
 */
const gchar *
nice_candidate_transport_to_string (NiceCandidateTransport transport);

/**
 * nice_candidate_relay_address:
 * @candidate: A relay candidate
 * @addr: The #NiceAddress to fill
 *
 * In case the given candidate is relayed through a TURN server, use this utility function to get
 * its address.
 *
 * Since: 0.1.19
 */
void
nice_candidate_relay_address (const NiceCandidate *candidate, NiceAddress *addr);

/**
 * nice_candidate_stun_server_address:
 * @candidate: A server-reflexive candidate
 * @addr: The #NiceAddress to fill
 *
 * In case the given candidate server-reflexive, use this utility function to get its address. The
 * address will be filled only if the candidate was generated using an STUN server.
 *
 * Returns: TRUE if it's a STUN created ICE candidate, or FALSE if the reflexed's server was not STUN.
 *
 * Since: 0.1.20
 */
gboolean
nice_candidate_stun_server_address (const NiceCandidate *candidate, NiceAddress *addr);

/**
 * NICE_TYPE_CANDIDATE:
 *
 * A boxed type for a #NiceCandidate.
 */
#define NICE_TYPE_CANDIDATE nice_candidate_get_type ()

G_END_DECLS

#endif /* __LIBNICE_CANDIDATE_H__ */

